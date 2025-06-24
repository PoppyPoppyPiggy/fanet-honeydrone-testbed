#!/usr/bin/env python3
"""
FANET Honeydrone Testbed - Web Dashboard
Real-time monitoring and control interface
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import threading

import websockets
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
import sqlite3
import pandas as pd
import plotly.graph_objs as go
import plotly.utils

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(project_root / 'logs' / 'dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'fanet_honeydrone_dashboard_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
bridge_websocket = None
simulation_data = {}
connected_clients = set()
data_dir = project_root / 'data'
config_dir = project_root / 'config'

class DashboardManager:
    """Manages dashboard data and communication"""
    
    def __init__(self):
        self.bridge_url = "ws://localhost:8765"
        self.db_path = data_dir / 'simulation_trace.db'
        self.last_update = None
        self.simulation_status = {
            'running': False,
            'phase': 'initialization',
            'runtime': 0,
            'nodes': {'total': 0, 'compromised': 0},
            'threats': {'total': 0, 'detected': 0},
            'mtd_actions': {'total': 0, 'successful': 0}
        }
        self.bridge_websocket = None
        
    async def connect_to_bridge(self):
        """Connect to NS3 bridge WebSocket"""
        try:
            self.bridge_websocket = await websockets.connect(self.bridge_url)
            logger.info("Connected to NS3 bridge")
            
            # Request initial state
            await self.bridge_websocket.send(json.dumps({
                'type': 'request_status'
            }))
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect to bridge: {e}")
            return False
    
    async def listen_to_bridge(self):
        """Listen for updates from NS3 bridge"""
        try:
            async for message in self.bridge_websocket:
                data = json.loads(message)
                await self.process_bridge_message(data)
        except websockets.exceptions.ConnectionClosed:
            logger.warning("Bridge connection closed")
        except Exception as e:
            logger.error(f"Error listening to bridge: {e}")
    
    async def process_bridge_message(self, data: Dict):
        """Process message from NS3 bridge"""
        msg_type = data.get('type')
        
        if msg_type == 'simulation_update':
            await self.update_simulation_data(data.get('data', {}))
        elif msg_type == 'status_response':
            self.simulation_status.update(data.get('data', {}))
        elif msg_type == 'initial_state':
            await self.update_simulation_data(data.get('data', {}))
        
        # Broadcast to web clients
        socketio.emit('simulation_update', data)
    
    async def update_simulation_data(self, data: Dict):
        """Update internal simulation data"""
        global simulation_data
        simulation_data.update(data)
        self.last_update = datetime.now()
        
        # Update status summary
        if 'nodes' in data:
            self.simulation_status['nodes']['total'] = len(data['nodes'])
            self.simulation_status['nodes']['compromised'] = sum(
                1 for node in data['nodes'] if node.get('is_compromised', False)
            )
        
        if 'threats' in data:
            self.simulation_status['threats']['total'] = len(data['threats'])
            self.simulation_status['threats']['detected'] = sum(
                1 for threat in data['threats'] if threat.get('detected', False)
            )
        
        if 'mtd_actions' in data:
            self.simulation_status['mtd_actions']['total'] = len(data['mtd_actions'])
            self.simulation_status['mtd_actions']['successful'] = sum(
                1 for action in data['mtd_actions'] if action.get('success', False)
            )
    
    def get_database_data(self) -> Dict:
        """Get data from SQLite database"""
        if not self.db_path.exists():
            return {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get recent data
            recent_time = datetime.now() - timedelta(hours=1)
            
            # Nodes data
            nodes_df = pd.read_sql_query("""
                SELECT * FROM nodes 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            """, conn, params=[recent_time])
            
            # Threats data
            threats_df = pd.read_sql_query("""
                SELECT * FROM threats 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            """, conn, params=[recent_time])
            
            # MTD actions data
            mtd_df = pd.read_sql_query("""
                SELECT * FROM mtd_actions 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            """, conn, params=[recent_time])
            
            # Simulation events
            events_df = pd.read_sql_query("""
                SELECT * FROM simulation_events 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 100
            """, conn, params=[recent_time])
            
            conn.close()
            
            return {
                'nodes': nodes_df.to_dict('records') if not nodes_df.empty else [],
                'threats': threats_df.to_dict('records') if not threats_df.empty else [],
                'mtd_actions': mtd_df.to_dict('records') if not mtd_df.empty else [],
                'events': events_df.to_dict('records') if not events_df.empty else []
            }
            
        except Exception as e:
            logger.error(f"Database error: {e}")
            return {}
    
    async def send_command_to_bridge(self, command: Dict):
        """Send command to NS3 bridge"""
        if self.bridge_websocket:
            try:
                await self.bridge_websocket.send(json.dumps(command))
                return True
            except Exception as e:
                logger.error(f"Error sending command: {e}")
                return False
        return False

# Global dashboard manager
dashboard_mgr = DashboardManager()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get current simulation status"""
    return jsonify(dashboard_mgr.simulation_status)

@app.route('/api/data')
def get_data():
    """Get current simulation data"""
    return jsonify(simulation_data)

@app.route('/api/database')
def get_database_data():
    """Get data from database"""
    db_data = dashboard_mgr.get_database_data()
    return jsonify(db_data)

@app.route('/api/charts/network_health')
def network_health_chart():
    """Generate network health chart"""
    db_data = dashboard_mgr.get_database_data()
    nodes = db_data.get('nodes', [])
    
    if not nodes:
        return jsonify({'data': [], 'layout': {}})
    
    # Calculate health metrics
    total_nodes = len(nodes)
    compromised_nodes = sum(1 for node in nodes if node.get('is_compromised', False))
    healthy_nodes = total_nodes - compromised_nodes
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=['Healthy', 'Compromised'],
        values=[healthy_nodes, compromised_nodes],
        marker_colors=['green', 'red']
    )])
    
    fig.update_layout(
        title='Network Health Status',
        font=dict(size=12)
    )
    
    return jsonify(fig.to_dict())

@app.route('/api/charts/threat_timeline')
def threat_timeline_chart():
    """Generate threat timeline chart"""
    db_data = dashboard_mgr.get_database_data()
    threats = db_data.get('threats', [])
    
    if not threats:
        return jsonify({'data': [], 'layout': {}})
    
    # Process threat data
    threat_df = pd.DataFrame(threats)
    threat_df['timestamp'] = pd.to_datetime(threat_df['timestamp'])
    
    # Group by time and threat type
    threat_counts = threat_df.groupby([
        pd.Grouper(key='timestamp', freq='5min'),
        'type'
    ]).size().reset_index(name='count')
    
    # Create timeline chart
    fig = go.Figure()
    
    for threat_type in threat_counts['type'].unique():
        data = threat_counts[threat_counts['type'] == threat_type]
        fig.add_trace(go.Scatter(
            x=data['timestamp'],
            y=data['count'],
            mode='lines+markers',
            name=threat_type.title(),
            line=dict(width=2)
        ))
    
    fig.update_layout(
        title='Threat Detection Timeline',
        xaxis_title='Time',
        yaxis_title='Threat Count',
        font=dict(size=12),
        hovermode='x unified'
    )
    
    return jsonify(fig.to_dict())

@app.route('/api/charts/mtd_effectiveness')
def mtd_effectiveness_chart():
    """Generate MTD effectiveness chart"""
    db_data = dashboard_mgr.get_database_data()
    mtd_actions = db_data.get('mtd_actions', [])
    
    if not mtd_actions:
        return jsonify({'data': [], 'layout': {}})
    
    # Process MTD data
    mtd_df = pd.DataFrame(mtd_actions)
    
    # Group by action type
    effectiveness_by_action = mtd_df.groupby('action').agg({
        'effectiveness': 'mean',
        'cost': 'mean',
        'success': 'sum'
    }).reset_index()
    
    # Create scatter plot
    fig = go.Figure(data=go.Scatter(
        x=effectiveness_by_action['cost'],
        y=effectiveness_by_action['effectiveness'],
        mode='markers',
        marker=dict(
            size=effectiveness_by_action['success'] * 5,
            color=effectiveness_by_action['effectiveness'],
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Effectiveness")
        ),
        text=effectiveness_by_action['action'],
        hovertemplate='<b>%{text}</b><br>' +
                      'Cost: %{x:.2f}<br>' +
                      'Effectiveness: %{y:.2f}<br>' +
                      'Success Count: %{marker.size}<extra></extra>'
    ))
    
    fig.update_layout(
        title='MTD Effectiveness vs Cost',
        xaxis_title='Average Cost',
        yaxis_title='Average Effectiveness',
        font=dict(size=12)
    )
    
    return jsonify(fig.to_dict())

@app.route('/api/charts/energy_levels')
def energy_levels_chart():
    """Generate energy levels chart"""
    db_data = dashboard_mgr.get_database_data()
    nodes = db_data.get('nodes', [])
    
    if not nodes:
        return jsonify({'data': [], 'layout': {}})
    
    # Process node data
    nodes_df = pd.DataFrame(nodes)
    
    # Group by node type
    energy_by_type = nodes_df.groupby('type')['energy_level'].apply(list).to_dict()
    
    # Create box plot
    fig = go.Figure()
    
    for node_type, energy_levels in energy_by_type.items():
        fig.add_trace(go.Box(
            y=energy_levels,
            name=node_type.replace('_', ' ').title(),
            boxpoints='all',
            jitter=0.3,
            pointpos=-1.8
        ))
    
    fig.update_layout(
        title='Energy Levels by Node Type',
        yaxis_title='Energy Level',
        font=dict(size=12)
    )
    
    return jsonify(fig.to_dict())

@app.route('/api/charts/network_topology')
def network_topology_chart():
    """Generate 3D network topology chart"""
    current_data = simulation_data.get('nodes', [])
    
    if not current_data:
        return jsonify({'data': [], 'layout': {}})
    
    # Create 3D scatter plot
    fig = go.Figure()
    
    # Group nodes by type
    node_types = {}
    for node in current_data:
        node_type = node.get('type', 'unknown')
        if node_type not in node_types:
            node_types[node_type] = {'x': [], 'y': [], 'z': [], 'ids': []}
        
        pos = node.get('position', [0, 0, 0])
        node_types[node_type]['x'].append(pos[0])
        node_types[node_type]['y'].append(pos[1])
        node_types[node_type]['z'].append(pos[2])
        node_types[node_type]['ids'].append(node.get('id', 0))
    
    # Color mapping for node types
    colors = {
        'real_drone': 'green',
        'honeypot': 'orange', 
        'gcs': 'blue',
        'relay': 'purple',
        'attacker': 'red'
    }
    
    # Add traces for each node type
    for node_type, data in node_types.items():
        fig.add_trace(go.Scatter3d(
            x=data['x'],
            y=data['y'],
            z=data['z'],
            mode='markers',
            marker=dict(
                size=8,
                color=colors.get(node_type, 'gray'),
                opacity=0.8
            ),
            name=node_type.replace('_', ' ').title(),
            text=[f"Node {id}" for id in data['ids']],
            hovertemplate='<b>%{text}</b><br>' +
                          'Position: (%{x:.1f}, %{y:.1f}, %{z:.1f})<extra></extra>'
        ))
    
    fig.update_layout(
        title='3D Network Topology',
        scene=dict(
            xaxis_title='X Position (m)',
            yaxis_title='Y Position (m)',
            zaxis_title='Z Position (m)'
        ),
        font=dict(size=12)
    )
    
    return jsonify(fig.to_dict())

@app.route('/api/control/start_simulation', methods=['POST'])
def start_simulation():
    """Start simulation with parameters"""
    params = request.json or {}
    
    command = {
        'type': 'start_simulation',
        'params': params
    }
    
    # Send command to bridge
    async def send_command():
        success = await dashboard_mgr.send_command_to_bridge(command)
        return success
    
    # Run async command
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(send_command())
        loop.close()
    except Exception as e:
        logger.error(f"Error in start_simulation: {e}")
        success = False
    
    return jsonify({'success': success})

@app.route('/api/control/stop_simulation', methods=['POST'])
def stop_simulation():
    """Stop running simulation"""
    command = {'type': 'stop_simulation'}
    
    async def send_command():
        success = await dashboard_mgr.send_command_to_bridge(command)
        return success
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(send_command())
        loop.close()
    except Exception as e:
        logger.error(f"Error in stop_simulation: {e}")
        success = False
    
    return jsonify({'success': success})

@app.route('/api/control/inject_threat', methods=['POST'])
def inject_threat():
    """Inject test threat"""
    params = request.json or {}
    
    command = {
        'type': 'inject_threat',
        'params': params
    }
    
    async def send_command():
        success = await dashboard_mgr.send_command_to_bridge(command)
        return success
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(send_command())
        loop.close()
    except Exception as e:
        logger.error(f"Error in inject_threat: {e}")
        success = False
    
    return jsonify({'success': success})

@app.route('/api/control/trigger_mtd', methods=['POST'])
def trigger_mtd():
    """Trigger MTD action"""
    params = request.json or {}
    
    command = {
        'type': 'trigger_mtd',
        'params': params
    }
    
    async def send_command():
        success = await dashboard_mgr.send_command_to_bridge(command)
        return success
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(send_command())
        loop.close()
    except Exception as e:
        logger.error(f"Error in trigger_mtd: {e}")
        success = False
    
    return jsonify({'success': success})

@app.route('/api/export_results')
def export_results():
    """Export current results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = f"dashboard_export_{timestamp}"
    
    # Export data as JSON
    export_data = {
        'timestamp': datetime.now().isoformat(),
        'simulation_status': dashboard_mgr.simulation_status,
        'simulation_data': simulation_data,
        'database_data': dashboard_mgr.get_database_data()
    }
    
    export_path = data_dir / f"{export_dir}.json"
    with open(export_path, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    return jsonify({
        'success': True,
        'export_file': str(export_path),
        'timestamp': timestamp
    })

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Dashboard client connected: {request.sid}")
    connected_clients.add(request.sid)
    
    # Send current status
    emit('simulation_status', dashboard_mgr.simulation_status)
    emit('simulation_data', simulation_data)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Dashboard client disconnected: {request.sid}")
    connected_clients.discard(request.sid)

@socketio.on('request_update')
def handle_request_update():
    """Handle update request from client"""
    emit('simulation_status', dashboard_mgr.simulation_status)
    emit('simulation_data', simulation_data)
    emit('database_data', dashboard_mgr.get_database_data())

# Background task to maintain bridge connection
def background_bridge_task():
    """Background task to maintain connection with NS3 bridge"""
    async def maintain_connection():
        while True:
            try:
                if not dashboard_mgr.bridge_websocket:
                    logger.info("Attempting to connect to NS3 bridge...")
                    await dashboard_mgr.connect_to_bridge()
                
                if dashboard_mgr.bridge_websocket:
                    await dashboard_mgr.listen_to_bridge()
                else:
                    await asyncio.sleep(5)  # Wait before retrying
                    
            except Exception as e:
                logger.error(f"Bridge connection error: {e}")
                dashboard_mgr.bridge_websocket = None
                await asyncio.sleep(5)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(maintain_connection())

# Start background task in separate thread
bridge_thread = threading.Thread(target=background_bridge_task, daemon=True)
bridge_thread.start()

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='FANET Honeydrone Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--bridge-url', default='ws://localhost:8765', 
                       help='NS3 bridge WebSocket URL')
    
    args = parser.parse_args()
    
    # Update bridge URL
    dashboard_mgr.bridge_url = args.bridge_url
    
    logger.info(f"Starting FANET Honeydrone Dashboard on {args.host}:{args.port}")
    logger.info(f"Bridge URL: {args.bridge_url}")
    
    # Create necessary directories
    data_dir.mkdir(exist_ok=True)
    (project_root / 'logs').mkdir(exist_ok=True)
    
    # Run the app
    socketio.run(app, host=args.host, port=args.port, debug=args.debug)