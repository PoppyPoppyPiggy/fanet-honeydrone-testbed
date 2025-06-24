#!/usr/bin/env python3
"""
NS3-FANET Honeydrone Bridge - Complete Integration
Bridges NS-3 simulation with FANET Honeydrone Testbed ecosystem
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

import json
import time
import subprocess
import threading
import asyncio
import logging
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import socket
import pickle

# Third-party imports
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from mpl_toolkits.mplot3d import Axes3D
import websockets

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))
sys.path.insert(0, str(PROJECT_ROOT))

# Import testbed components
try:
    from src.honeydrone_network_manager import HoneydroneNetworkManager
    from src.enhanced_mtd import EnhancedMTDEngine
    from src.cti_analysis_engine import CTIAnalysisEngine
    from src.phase_transition_manager import PhaseStateManager
    from src.dvds_connector import DVDSConnector
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import testbed components: {e}")
    logger.info("Running in standalone mode")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(PROJECT_ROOT / 'logs' / 'ns3_bridge.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NodeType(Enum):
    """Node types in FANET network"""
    REAL_DRONE = "real_drone"
    HONEYPOT = "honeypot"
    GCS = "gcs"
    RELAY = "relay"
    ATTACKER = "attacker"

class ThreatType(Enum):
    """Types of threats in the network"""
    JAMMING = "jamming"
    SPOOFING = "spoofing"
    EAVESDROPPING = "eavesdropping"
    DOS = "dos"
    MITM = "mitm"
    PHYSICAL_CAPTURE = "physical_capture"
    ROUTING_ATTACK = "routing_attack"
    SYBIL_ATTACK = "sybil_attack"

class MTDAction(Enum):
    """Moving Target Defense actions"""
    FREQUENCY_HOPPING = "frequency_hopping"
    ROUTE_MUTATION = "route_mutation"
    IDENTITY_ROTATION = "identity_rotation"
    POWER_ADJUSTMENT = "power_adjustment"
    TOPOLOGY_SHUFFLE = "topology_shuffle"
    CHANNEL_SWITCHING = "channel_switching"

class SimulationPhase(Enum):
    """Simulation phases"""
    INITIALIZATION = "initialization"
    NORMAL_OPERATION = "normal_operation"
    UNDER_ATTACK = "under_attack"
    MTD_ACTIVE = "mtd_active"
    RECOVERY = "recovery"

@dataclass
class NetworkNode:
    """Represents a network node"""
    id: int
    type: NodeType
    position: List[float]  # [x, y, z]
    energy_level: float = 1.0
    is_compromised: bool = False
    transmission_power: float = 20.0  # dBm
    frequency: float = 2.4  # GHz
    mobility_model: str = "static"
    velocity: List[float] = None  # [vx, vy, vz] m/s
    last_seen: datetime = None
    honeypot_activated: bool = False
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()
        if self.velocity is None:
            self.velocity = [0.0, 0.0, 0.0]

@dataclass
class ThreatEvent:
    """Represents a threat event"""
    id: str
    type: ThreatType
    source_node: int
    target_node: int
    timestamp: datetime
    severity: float  # 0.0 to 1.0
    detected: bool = False
    mitigated: bool = False
    description: str = ""

@dataclass
class MTDEvent:
    """Represents an MTD action"""
    id: str
    action: MTDAction
    target_nodes: List[int]
    timestamp: datetime
    effectiveness: float = 0.0
    cost: float = 0.0
    success: bool = True

class NS3FANETBridge:
    """Enhanced Bridge between NS3 simulation and FANET Honeydrone Testbed"""
    
    def __init__(self, project_dir: str = None):
        self.project_dir = Path(project_dir) if project_dir else PROJECT_ROOT
        self.ns3_dir = self.project_dir / 'ns-allinone-3.40' / 'ns-3.40'
        self.config_dir = self.project_dir / 'config'
        self.logs_dir = self.project_dir / 'logs'
        self.data_dir = self.project_dir / 'data'
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        # Simulation files
        self.results_file = self.data_dir / 'simulation_results.json'
        self.animation_file = self.data_dir / 'fanet_animation.xml'
        self.trace_file = self.data_dir / 'simulation_trace.db'
        
        # Load configurations
        self.load_configurations()
        
        # Initialize components
        self.initialize_components()
        
        # Simulation state
        self.is_running = False
        self.simulation_process = None
        self.current_phase = SimulationPhase.INITIALIZATION
        self.simulation_start_time = None
        
        # Data structures
        self.nodes: Dict[int, NetworkNode] = {}
        self.threats: List[ThreatEvent] = []
        self.mtd_actions: List[MTDEvent] = []
        self.network_topology = {}
        
        # Real-time communication
        self.websocket_port = 8765
        self.connected_clients = set()
        self.bridge_socket = None
        
        # Visualization components
        self.fig = None
        self.ax = None
        self.animation_running = False
        
        # Database connection
        self.init_database()
        
        logger.info("NS3 FANET Bridge initialized")
    
    def load_configurations(self):
        """Load all configuration files"""
        self.configs = {}
        config_files = [
            'network_config.json',
            'mtd_config.json',
            'cti_config.json',
            'phase_config.json'
        ]
        
        for config_file in config_files:
            config_path = self.config_dir / config_file
            try:
                with open(config_path, 'r') as f:
                    config_name = config_file.replace('.json', '')
                    self.configs[config_name] = json.load(f)
                logger.info(f"Loaded configuration: {config_file}")
            except FileNotFoundError:
                logger.warning(f"Configuration file not found: {config_file}")
                self.configs[config_name] = {}
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {config_file}: {e}")
                self.configs[config_name] = {}
    
    def initialize_components(self):
        """Initialize testbed components"""
        self.components = {}
        
        try:
            # Initialize Network Manager
            self.components['network_manager'] = HoneydroneNetworkManager(
                config=self.configs.get('network_config', {})
            )
            
            # Initialize MTD Engine
            self.components['mtd_engine'] = EnhancedMTDEngine(
                config=self.configs.get('mtd_config', {})
            )
            
            # Initialize CTI Engine
            self.components['cti_engine'] = CTIAnalysisEngine(
                config=self.configs.get('cti_config', {})
            )
            
            # Initialize Phase Manager
            self.components['phase_manager'] = PhaseTransactionManager(
                config=self.configs.get('phase_config', {})
            )
            
            # Initialize DVDS Connector
            self.components['dvds_connector'] = DVDSConnector()
            
            logger.info("All testbed components initialized successfully")
            
        except Exception as e:
            logger.warning(f"Some components could not be initialized: {e}")
            logger.info("Bridge will operate in limited mode")
    
    def init_database(self):
        """Initialize SQLite database for trace storage"""
        try:
            self.db_conn = sqlite3.connect(self.trace_file, check_same_thread=False)
            cursor = self.db_conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS nodes (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    x REAL, y REAL, z REAL,
                    energy_level REAL,
                    is_compromised BOOLEAN,
                    transmission_power REAL,
                    frequency REAL,
                    timestamp DATETIME
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    source_node INTEGER,
                    target_node INTEGER,
                    severity REAL,
                    detected BOOLEAN,
                    mitigated BOOLEAN,
                    timestamp DATETIME
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mtd_actions (
                    id TEXT PRIMARY KEY,
                    action TEXT,
                    target_nodes TEXT,
                    effectiveness REAL,
                    cost REAL,
                    success BOOLEAN,
                    timestamp DATETIME
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS simulation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    description TEXT,
                    phase TEXT,
                    timestamp DATETIME
                )
            ''')
            
            self.db_conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self.db_conn = None
    
    def check_ns3_installation(self) -> bool:
        """Check if NS3 is properly installed"""
        ns3_executable = self.ns3_dir / 'ns3'
        waf_executable = self.ns3_dir / 'waf'
        
        # Check for ns3 command or waf
        if ns3_executable.exists():
            try:
                result = subprocess.run(
                    [str(ns3_executable), '--version'], 
                    capture_output=True, text=True, timeout=10,
                    cwd=self.ns3_dir
                )
                if result.returncode == 0:
                    logger.info(f"NS3 found: {result.stdout.strip()}")
                    return True
            except Exception as e:
                logger.warning(f"NS3 command failed: {e}")
        
        # Try waf as fallback
        if waf_executable.exists():
            try:
                result = subprocess.run(
                    ['python3', str(waf_executable), '--version'], 
                    capture_output=True, text=True, timeout=10,
                    cwd=self.ns3_dir
                )
                if result.returncode == 0:
                    logger.info("NS3 waf build system found")
                    return True
            except Exception as e:
                logger.warning(f"Waf command failed: {e}")
        
        logger.error("NS3 installation not found or not working")
        return False
    
    def prepare_simulation_files(self):
        """Prepare NS3 simulation files"""
        scratch_dir = self.ns3_dir / 'scratch'
        
        # Copy simulation files
        simulation_files = [
            'fanet_honeydrone_simulation.cc',
            'fanet_simulation.cc'
        ]
        
        for sim_file in simulation_files:
            source_file = self.project_dir / sim_file
            target_file = scratch_dir / sim_file
            
            if source_file.exists():
                import shutil
                shutil.copy2(source_file, target_file) 
                logger.info(f"Copied {sim_file} to NS3 scratch directory")
            else:
                logger.warning(f"Simulation file not found: {sim_file}")
    
    async def start_simulation(self, 
                             duration: int = 300,
                             num_drones: int = 10, 
                             num_honeypots: int = 5,
                             attack_scenario: str = "mixed") -> bool:
        """Start NS3 simulation with enhanced parameters"""
        
        if not self.check_ns3_installation():
            logger.error("Cannot start simulation: NS3 not properly installed")
            return False
        
        logger.info("Starting enhanced NS3 FANET simulation...")
        self.simulation_start_time = datetime.now()
        
        # Prepare simulation environment
        self.prepare_simulation_files()
        
        # Choose simulation file based on requirements
        sim_name = "fanet_honeydrone_simulation"
        
        # Build simulation if needed
        if not await self.build_simulation(sim_name):
            logger.error("Failed to build simulation")
            return False
        
        # Prepare simulation arguments
        sim_args = [
            f'--nDrones={num_drones}',
            f'--nHoneypots={num_honeypots}',
            f'--simTime={duration}',
            f'--attackScenario={attack_scenario}',
            f'--enableMTD=true',
            f'--traceFile={self.trace_file}',
            f'--animationFile={self.animation_file}',
            f'--resultsFile={self.results_file}'
        ]
        
        # Start simulation process
        try:
            ns3_cmd = self.ns3_dir / 'ns3'
            if ns3_cmd.exists():
                cmd = [str(ns3_cmd), 'run', sim_name] + ['--'] + sim_args
            else:
                # Fallback to waf
                cmd = ['python3', 'waf', '--run', f'{sim_name}'] + sim_args
            
            self.simulation_process = subprocess.Popen(
                cmd,
                cwd=self.ns3_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.is_running = True
            self.current_phase = SimulationPhase.NORMAL_OPERATION
            
            logger.info(f"Simulation started (PID: {self.simulation_process.pid})")
            
            # Start monitoring and communication threads
            asyncio.create_task(self.monitor_simulation())
            asyncio.create_task(self.handle_real_time_communication())
            
            # Log simulation start
            self.log_simulation_event("simulation_started", 
                                     f"Started with {num_drones} drones, {num_honeypots} honeypots")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start simulation: {e}")
            return False
    
    async def build_simulation(self, sim_name: str) -> bool:
        """Build NS3 simulation"""
        try:
            ns3_cmd = self.ns3_dir / 'ns3'
            
            if ns3_cmd.exists():
                # Use ns3 command
                build_cmd = [str(ns3_cmd), 'build', sim_name]
            else:
                # Use waf
                build_cmd = ['python3', 'waf', 'build']
            
            logger.info("Building NS3 simulation...")
            result = subprocess.run(
                build_cmd,
                cwd=self.ns3_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                logger.info("Simulation built successfully")
                return True
            else:
                logger.error(f"Build failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Build timeout")
            return False
        except Exception as e:
            logger.error(f"Build error: {e}")
            return False
    
    async def monitor_simulation(self):
        """Monitor running simulation and process outputs"""
        logger.info("Starting simulation monitoring")
        
        while self.is_running and self.simulation_process:
            try:
                # Check if process is still running
                if self.simulation_process.poll() is not None:
                    self.is_running = False
                    self.current_phase = SimulationPhase.RECOVERY
                    logger.info("Simulation process completed")
                    break
                
                # Read stdout
                if self.simulation_process.stdout:
                    line = self.simulation_process.stdout.readline()
                    if line:
                        await self.process_simulation_output(line.strip())
                
                # Check for updated results
                if self.results_file.exists():
                    await self.load_simulation_results()
                
                # Process testbed components
                await self.process_testbed_integration()
                
                await asyncio.sleep(0.1)  # Small delay to prevent excessive CPU usage
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                break
        
        logger.info("Simulation monitoring stopped")
    
    async def process_simulation_output(self, line: str):
        """Process NS3 simulation output line"""
        logger.debug(f"NS3: {line}")
        
        # Parse special output formats
        if line.startswith("THREAT_DETECTED:"):
            await self.handle_threat_detection(line)
        elif line.startswith("MTD_ACTION:"):
            await self.handle_mtd_action(line)
        elif line.startswith("NODE_UPDATE:"):
            await self.handle_node_update(line)
        elif line.startswith("PHASE_CHANGE:"):
            await self.handle_phase_change(line)
    
    async def handle_threat_detection(self, line: str):
        """Handle threat detection from NS3"""
        try:
            # Parse threat information from NS3 output
            # Format: THREAT_DETECTED:type:source:target:severity
            parts = line.split(':')
            if len(parts) >= 5:
                threat = ThreatEvent(
                    id=f"threat_{datetime.now().timestamp()}",
                    type=ThreatType(parts[1]),
                    source_node=int(parts[2]),
                    target_node=int(parts[3]),
                    severity=float(parts[4]),
                    timestamp=datetime.now(),
                    detected=True
                )
                
                self.threats.append(threat)
                self.store_threat_in_db(threat)
                
                # Trigger MTD response if configured
                if 'mtd_engine' in self.components:
                    await self.trigger_mtd_response(threat)
                
                logger.warning(f"Threat detected: {threat.type.value} from node {threat.source_node}")
                
        except Exception as e:
            logger.error(f"Error processing threat detection: {e}")
    
    async def handle_mtd_action(self, line: str):
        """Handle MTD action from NS3"""
        try:
            # Parse MTD action information
            # Format: MTD_ACTION:action:nodes:effectiveness:cost
            parts = line.split(':')
            if len(parts) >= 5:
                mtd_event = MTDEvent(
                    id=f"mtd_{datetime.now().timestamp()}",
                    action=MTDAction(parts[1]),
                    target_nodes=[int(n) for n in parts[2].split(',')],
                    effectiveness=float(parts[3]),
                    cost=float(parts[4]),
                    timestamp=datetime.now()
                )
                
                self.mtd_actions.append(mtd_event)
                self.store_mtd_in_db(mtd_event)
                
                logger.info(f"MTD action executed: {mtd_event.action.value}")
                
        except Exception as e:
            logger.error(f"Error processing MTD action: {e}")
    
    async def handle_node_update(self, line: str):
        """Handle node status update from NS3"""
        try:
            # Parse node update information
            # Format: NODE_UPDATE:id:x:y:z:energy:compromised
            parts = line.split(':')
            if len(parts) >= 7:
                node_id = int(parts[1])
                
                if node_id in self.nodes:
                    node = self.nodes[node_id]
                    node.position = [float(parts[2]), float(parts[3]), float(parts[4])]
                    node.energy_level = float(parts[5])
                    node.is_compromised = parts[6].lower() == 'true'
                    node.last_seen = datetime.now()
                else:
                    # Create new node
                    self.nodes[node_id] = NetworkNode(
                        id=node_id,
                        type=NodeType.REAL_DRONE,  # Default, will be updated
                        position=[float(parts[2]), float(parts[3]), float(parts[4])],
                        energy_level=float(parts[5]),
                        is_compromised=parts[6].lower() == 'true'
                    )
                
                self.store_node_in_db(self.nodes[node_id])
                
        except Exception as e:
            logger.error(f"Error processing node update: {e}")
    
    async def handle_phase_change(self, line: str):
        """Handle simulation phase change"""
        try:
            # Format: PHASE_CHANGE:new_phase
            parts = line.split(':')
            if len(parts) >= 2:
                new_phase = SimulationPhase(parts[1])
                old_phase = self.current_phase
                self.current_phase = new_phase
                
                self.log_simulation_event("phase_change", 
                                         f"Phase changed from {old_phase.value} to {new_phase.value}")
                
                logger.info(f"Simulation phase changed to: {new_phase.value}")
                
        except Exception as e:
            logger.error(f"Error processing phase change: {e}")
    
    async def load_simulation_results(self):
        """Load and process simulation results from JSON file"""
        try:
            if self.results_file.stat().st_mtime > getattr(self, '_last_results_mtime', 0):
                with open(self.results_file, 'r') as f:
                    results = json.load(f)
                
                # Update internal state
                self.update_from_results(results)
                
                # Broadcast to WebSocket clients
                await self.broadcast_update(results)
                
                self._last_results_mtime = self.results_file.stat().st_mtime
                
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.debug(f"Results file not ready: {e}")
        except Exception as e:
            logger.error(f"Error loading results: {e}")
    
    def update_from_results(self, results: Dict):
        """Update internal state from simulation results"""
        # Update nodes
        for node_data in results.get('nodes', []):
            node_id = node_data['id']
            if node_id not in self.nodes:
                self.nodes[node_id] = NetworkNode(
                    id=node_id,
                    type=NodeType(node_data.get('type', 'real_drone')),
                    position=node_data.get('position', [0, 0, 0]),
                    energy_level=node_data.get('energy_level', 1.0),
                    is_compromised=node_data.get('is_compromised', False)
                )
            else:
                # Update existing node
                node = self.nodes[node_id]
                node.position = node_data.get('position', node.position)
                node.energy_level = node_data.get('energy_level', node.energy_level)
                node.is_compromised = node_data.get('is_compromised', node.is_compromised)
                node.last_seen = datetime.now()
        
        # Update network topology
        self.network_topology = results.get('topology', {})
    
    async def process_testbed_integration(self):
        """Process integration with testbed components"""
        try:
            # Update network manager
            if 'network_manager' in self.components:
                await self.sync_with_network_manager()
            
            # Process CTI analysis
            if 'cti_engine' in self.components and self.threats:
                await self.process_cti_analysis()
            
            # Update phase manager
            if 'phase_manager' in self.components:
                await self.update_phase_manager()
            
        except Exception as e:
            logger.error(f"Testbed integration error: {e}")
    
    async def sync_with_network_manager(self):
        """Synchronize with network manager"""
        try:
            network_mgr = self.components['network_manager']
            
            # Send current node states
            for node in self.nodes.values():
                await network_mgr.update_node_status(
                    node.id, 
                    {
                        'position': node.position,
                        'energy': node.energy_level,
                        'compromised': node.is_compromised,
                        'type': node.type.value
                    }
                )
        except Exception as e:
            logger.error(f"Network manager sync error: {e}")
    
    async def process_cti_analysis(self):
        """Process threats through CTI analysis"""
        try:
            cti_engine = self.components['cti_engine']
            
            # Analyze recent threats
            recent_threats = [t for t in self.threats 
                            if (datetime.now() - t.timestamp).seconds < 60]
            
            if recent_threats:
                threat_data = [asdict(t) for t in recent_threats]
                analysis_result = await cti_engine.analyze_threats(threat_data)
                
                logger.info(f"CTI Analysis: {analysis_result}")
                
        except Exception as e:
            logger.error(f"CTI analysis error: {e}")
    
    async def trigger_mtd_response(self, threat: ThreatEvent):
        """Trigger MTD response to detected threat"""
        try:
            if 'mtd_engine' in self.components:
                mtd_engine = self.components['mtd_engine']
                
                # Determine appropriate MTD action
                mtd_action = await mtd_engine.select_mtd_action(
                    threat_type=threat.type.value,
                    threat_severity=threat.severity,
                    affected_nodes=[threat.target_node]
                )
                
                if mtd_action:
                    # Execute MTD action
                    success = await mtd_engine.execute_mtd_action(mtd_action)
                    
                    # Send MTD command to NS3 simulation
                    await self.send_mtd_command_to_ns3(mtd_action)
                    
                    logger.info(f"MTD response triggered: {mtd_action}")
                
        except Exception as e:
            logger.error(f"MTD trigger error: {e}")
    
    async def send_mtd_command_to_ns3(self, mtd_action: Dict):
        """Send MTD command to running NS3 simulation"""
        try:
            # This would require a communication channel with NS3
            # Could be implemented via named pipes, sockets, or shared files
            command = {
                'type': 'mtd_command',
                'action': mtd_action,
                'timestamp': datetime.now().isoformat()
            }
            
            # Write command to file that NS3 can read
            command_file = self.data_dir / 'mtd_commands.json'
            with open(command_file, 'a') as f:
                f.write(json.dumps(command) + '\n')
                
        except Exception as e:
            logger.error(f"Error sending MTD command to NS3: {e}")
    
    def store_threat_in_db(self, threat: ThreatEvent):
        """Store threat event in database"""
        if not self.db_conn:
            return
        
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO threats 
                (id, type, source_node, target_node, severity, detected, mitigated, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.id, threat.type.value, threat.source_node, threat.target_node,
                threat.severity, threat.detected, threat.mitigated, threat.timestamp
            ))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Database error storing threat: {e}")
    
    def store_mtd_in_db(self, mtd_event: MTDEvent):
        """Store MTD event in database"""
        if not self.db_conn:
            return
        
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO mtd_actions 
                (id, action, target_nodes, effectiveness, cost, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                mtd_event.id, mtd_event.action.value, ','.join(map(str, mtd_event.target_nodes)),
                mtd_event.effectiveness, mtd_event.cost, mtd_event.success, mtd_event.timestamp
            ))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Database error storing MTD: {e}")
    
    def store_node_in_db(self, node: NetworkNode):
        """Store node state in database"""
        if not self.db_conn:
            return

        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO nodes 
                (id, type, x, y, z, energy_level, is_compromised, transmission_power, frequency, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                node.id,
                node.type.value,
                node.position[0],
                node.position[1],
                node.position[2],
                node.energy_level,
                node.is_compromised,
                node.transmission_power,
                node.frequency,
                datetime.utcnow().isoformat()
            ))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Database error storing MTD: {e}")
