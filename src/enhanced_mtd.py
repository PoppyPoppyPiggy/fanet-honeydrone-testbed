#!/usr/bin/env python3
"""Enhanced MTD Engine with Advanced Features"""

import asyncio
import random
import time
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
import threading
from collections import deque, defaultdict
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of threats"""
    NETWORK_SCAN = "network_scan"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos_attack"
    MALWARE = "malware_injection"
    MAN_IN_MIDDLE = "mitm_attack"
    SIGNAL_JAMMING = "signal_jamming"
    GPS_SPOOFING = "gps_spoofing"
    COMMAND_INJECTION = "command_injection"

class MTDAction(Enum):
    """MTD Actions"""
    IP_SHUFFLE = "ip_shuffle"
    PORT_SHUFFLE = "port_shuffle"
    FREQUENCY_HOPPING = "frequency_hopping"
    ROUTE_MUTATION = "route_mutation"
    PROTOCOL_SWITCH = "protocol_switch"
    ENCRYPTION_CHANGE = "encryption_change"
    TOPOLOGY_MORPH = "topology_morph"
    DECOY_DEPLOYMENT = "decoy_deployment"
    SERVICE_MIGRATION = "service_migration"
    TRAFFIC_OBFUSCATION = "traffic_obfuscation"
    NO_ACTION = "no_action"

class Severity(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatEvent:
    """Threat event data structure"""
    threat_id: str
    threat_type: ThreatType
    severity: Severity
    confidence: float
    source_ip: str
    target_node: str
    timestamp: datetime
    indicators: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'threat_id': self.threat_id,
            'threat_type': self.threat_type.value,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'source_ip': self.source_ip,
            'target_node': self.target_node,
            'timestamp': self.timestamp.isoformat(),
            'indicators': self.indicators
        }

@dataclass
class MTDActionResult:
    """MTD action execution result"""
    action: MTDAction
    success: bool
    execution_time: float
    energy_cost: float
    effectiveness: float
    side_effects: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'action': self.action.value,
            'success': self.success,
            'execution_time': self.execution_time,
            'energy_cost': self.energy_cost,
            'effectiveness': self.effectiveness,
            'side_effects': self.side_effects
        }

@dataclass
class NetworkNode:
    """Network node representation"""
    node_id: str
    node_type: str  # "drone", "gcs", "relay"
    position: Tuple[float, float, float]
    security_level: float
    energy_level: float
    is_compromised: bool = False
    last_seen: datetime = None
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()

class ThreatDetector:
    """Advanced threat detection system"""
    
    def __init__(self):
        self.detection_patterns = {
            ThreatType.NETWORK_SCAN: ["port_scan", "service_enum", "host_discovery"],
            ThreatType.BRUTE_FORCE: ["failed_auth", "password_spray", "credential_stuffing"],
            ThreatType.DDoS: ["flood_attack", "bandwidth_exhaustion", "resource_depletion"],
            ThreatType.MALWARE: ["suspicious_binary", "payload_injection", "code_execution"],
            ThreatType.MAN_IN_MIDDLE: ["certificate_mismatch", "arp_spoofing", "dns_hijack"],
            ThreatType.SIGNAL_JAMMING: ["signal_interference", "carrier_jamming", "protocol_disruption"],
            ThreatType.GPS_SPOOFING: ["position_anomaly", "satellite_spoofing", "navigation_attack"],
            ThreatType.COMMAND_INJECTION: ["command_execution", "privilege_escalation", "system_compromise"]
        }
        
        self.threat_history = deque(maxlen=1000)
        self.detection_rates = defaultdict(lambda: 0.7)  # Base detection rate
        
    def detect_threats(self, network_state: Dict) -> List[ThreatEvent]:
        """Detect threats based on network state"""
        threats = []
        current_time = datetime.now()
        
        # Simulate multiple concurrent threats
        for _ in range(random.randint(0, 3)):
            if random.random() < 0.3:  # 30% chance of threat per cycle
                threat_type = random.choice(list(ThreatType))
                severity = self._calculate_severity(threat_type, network_state)
                
                threat = ThreatEvent(
                    threat_id=f"THR_{int(time.time()*1000)}_{random.randint(1000,9999)}",
                    threat_type=threat_type,
                    severity=severity,
                    confidence=random.uniform(0.6, 0.95),
                    source_ip=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    target_node=f"drone_{random.randint(1,10)}",
                    timestamp=current_time,
                    indicators=random.sample(self.detection_patterns[threat_type], 
                                           random.randint(1, len(self.detection_patterns[threat_type])))
                )
                
                threats.append(threat)
                self.threat_history.append(threat)
        
        return threats
    
    def _calculate_severity(self, threat_type: ThreatType, network_state: Dict) -> Severity:
        """Calculate threat severity based on context"""
        base_severity = {
            ThreatType.NETWORK_SCAN: Severity.LOW,
            ThreatType.BRUTE_FORCE: Severity.MEDIUM,
            ThreatType.DDoS: Severity.HIGH,
            ThreatType.MALWARE: Severity.CRITICAL,
            ThreatType.MAN_IN_MIDDLE: Severity.HIGH,
            ThreatType.SIGNAL_JAMMING: Severity.HIGH,
            ThreatType.GPS_SPOOFING: Severity.CRITICAL,
            ThreatType.COMMAND_INJECTION: Severity.CRITICAL
        }
        
        severity = base_severity[threat_type]
        
        # Escalate severity based on network conditions
        if network_state.get('compromised_nodes', 0) > 2:
            severity = Severity(min(4, severity.value + 1))
        
        if network_state.get('energy_level', 1.0) < 0.3:
            severity = Severity(min(4, severity.value + 1))
        
        return severity

class MTDExecutor:
    """Advanced MTD action executor"""
    
    def __init__(self):
        self.action_costs = {
            MTDAction.IP_SHUFFLE: 0.05,
            MTDAction.PORT_SHUFFLE: 0.02,
            MTDAction.FREQUENCY_HOPPING: 0.08,
            MTDAction.ROUTE_MUTATION: 0.06,
            MTDAction.PROTOCOL_SWITCH: 0.12,
            MTDAction.ENCRYPTION_CHANGE: 0.10,
            MTDAction.TOPOLOGY_MORPH: 0.25,
            MTDAction.DECOY_DEPLOYMENT: 0.15,
            MTDAction.SERVICE_MIGRATION: 0.20,
            MTDAction.TRAFFIC_OBFUSCATION: 0.07,
            MTDAction.NO_ACTION: 0.00
        }
        
        self.action_effectiveness = {
            MTDAction.IP_SHUFFLE: 0.6,
            MTDAction.PORT_SHUFFLE: 0.4,
            MTDAction.FREQUENCY_HOPPING: 0.8,
            MTDAction.ROUTE_MUTATION: 0.7,
            MTDAction.PROTOCOL_SWITCH: 0.75,
            MTDAction.ENCRYPTION_CHANGE: 0.85,
            MTDAction.TOPOLOGY_MORPH: 0.9,
            MTDAction.DECOY_DEPLOYMENT: 0.65,
            MTDAction.SERVICE_MIGRATION: 0.8,
            MTDAction.TRAFFIC_OBFUSCATION: 0.5,
            MTDAction.NO_ACTION: 0.0
        }
        
        self.execution_history = deque(maxlen=500)
        
    async def execute_action(self, action: MTDAction, context: Dict) -> MTDActionResult:
        """Execute MTD action with realistic simulation"""
        start_time = time.time()
        
        # Simulate execution delay
        execution_delay = random.uniform(0.1, 0.5) * self.action_costs[action] * 10
        await asyncio.sleep(execution_delay)
        
        # Calculate success probability
        base_success = 0.85
        if context.get('network_stability', 1.0) < 0.5:
            base_success -= 0.2
        if context.get('energy_level', 1.0) < 0.3:
            base_success -= 0.1
            
        success = random.random() < base_success
        
        # Calculate actual effectiveness
        effectiveness = self.action_effectiveness[action]
        if success:
            effectiveness *= random.uniform(0.8, 1.2)  # Add some variance
        else:
            effectiveness *= 0.1  # Reduced effectiveness on failure
            
        # Generate side effects
        side_effects = []
        if action in [MTDAction.TOPOLOGY_MORPH, MTDAction.SERVICE_MIGRATION]:
            if random.random() < 0.3:
                side_effects.append("temporary_connectivity_loss")
        if action == MTDAction.FREQUENCY_HOPPING:
            if random.random() < 0.2:
                side_effects.append("interference_with_other_systems")
        
        result = MTDActionResult(
            action=action,
            success=success,
            execution_time=time.time() - start_time,
            energy_cost=self.action_costs[action],
            effectiveness=effectiveness,
            side_effects=side_effects
        )
        
        self.execution_history.append(result)
        return result

class DecisionEngine:
    """Intelligent MTD decision engine"""
    
    def __init__(self):
        self.threat_action_mapping = {
            ThreatType.NETWORK_SCAN: [MTDAction.IP_SHUFFLE, MTDAction.PORT_SHUFFLE, MTDAction.DECOY_DEPLOYMENT],
            ThreatType.BRUTE_FORCE: [MTDAction.IP_SHUFFLE, MTDAction.ENCRYPTION_CHANGE, MTDAction.SERVICE_MIGRATION],
            ThreatType.DDoS: [MTDAction.ROUTE_MUTATION, MTDAction.TRAFFIC_OBFUSCATION, MTDAction.TOPOLOGY_MORPH],
            ThreatType.MALWARE: [MTDAction.SERVICE_MIGRATION, MTDAction.TOPOLOGY_MORPH, MTDAction.PROTOCOL_SWITCH],
            ThreatType.MAN_IN_MIDDLE: [MTDAction.ENCRYPTION_CHANGE, MTDAction.ROUTE_MUTATION, MTDAction.FREQUENCY_HOPPING],
            ThreatType.SIGNAL_JAMMING: [MTDAction.FREQUENCY_HOPPING, MTDAction.ROUTE_MUTATION, MTDAction.PROTOCOL_SWITCH],
            ThreatType.GPS_SPOOFING: [MTDAction.ROUTE_MUTATION, MTDAction.TOPOLOGY_MORPH, MTDAction.SERVICE_MIGRATION],
            ThreatType.COMMAND_INJECTION: [MTDAction.SERVICE_MIGRATION, MTDAction.TOPOLOGY_MORPH, MTDAction.ENCRYPTION_CHANGE]
        }
        
        self.action_cooldowns = defaultdict(float)
        self.recent_actions = deque(maxlen=20)
        
    def select_action(self, threats: List[ThreatEvent], network_state: Dict) -> MTDAction:
        """Select optimal MTD action based on threats and network state"""
        if not threats:
            return MTDAction.NO_ACTION
        
        # Sort threats by severity and confidence
        sorted_threats = sorted(threats, 
                              key=lambda t: (t.severity.value, t.confidence), 
                              reverse=True)
        
        primary_threat = sorted_threats[0]
        
        # Get candidate actions for the primary threat
        candidate_actions = self.threat_action_mapping.get(primary_threat.threat_type, [MTDAction.NO_ACTION])
        
        # Filter out actions in cooldown
        current_time = time.time()
        available_actions = [
            action for action in candidate_actions 
            if current_time - self.action_cooldowns[action] > 30  # 30 second cooldown
        ]
        
        if not available_actions:
            available_actions = [MTDAction.NO_ACTION]
        
        # Score actions based on multiple factors
        scored_actions = []
        for action in available_actions:
            score = self._score_action(action, primary_threat, network_state)
            scored_actions.append((action, score))
        
        # Select best action
        best_action = max(scored_actions, key=lambda x: x[1])[0]
        
        # Update cooldown
        self.action_cooldowns[best_action] = current_time
        self.recent_actions.append((best_action, primary_threat.threat_type))
        
        return best_action
    
    def _score_action(self, action: MTDAction, threat: ThreatEvent, network_state: Dict) -> float:
        """Score an action based on various factors"""
        score = 0.0
        
        # Base effectiveness against threat type
        if action in self.threat_action_mapping.get(threat.threat_type, []):
            score += 0.8
        
        # Severity bonus
        score += threat.severity.value * 0.2
        
        # Confidence factor
        score += threat.confidence * 0.3
        
        # Energy consideration
        energy_level = network_state.get('energy_level', 1.0)
        if energy_level < 0.5:
            # Penalize high-cost actions when energy is low
            energy_cost = {
                MTDAction.TOPOLOGY_MORPH: 0.25,
                MTDAction.SERVICE_MIGRATION: 0.20,
                MTDAction.DECOY_DEPLOYMENT: 0.15,
                MTDAction.ENCRYPTION_CHANGE: 0.10,
                MTDAction.PROTOCOL_SWITCH: 0.12,
                MTDAction.FREQUENCY_HOPPING: 0.08,
                MTDAction.TRAFFIC_OBFUSCATION: 0.07,
                MTDAction.ROUTE_MUTATION: 0.06,
                MTDAction.IP_SHUFFLE: 0.05,
                MTDAction.PORT_SHUFFLE: 0.02,
                MTDAction.NO_ACTION: 0.00
            }
            score -= energy_cost.get(action, 0) * 2
        
        # Avoid repetitive actions
        recent_action_types = [a[0] for a in list(self.recent_actions)[-5:]]
        if recent_action_types.count(action) > 2:
            score -= 0.3
        
        return score

class EnhancedMTDEngine:
    """Enhanced MTD Engine with advanced capabilities"""
    
    def __init__(self):
        self.threat_detector = ThreatDetector()
        self.mtd_executor = MTDExecutor()
        self.decision_engine = DecisionEngine()
        
        # Network state simulation
        self.network_nodes = self._initialize_network()
        self.network_state = {
            'total_nodes': len(self.network_nodes),
            'compromised_nodes': 0,
            'energy_level': 1.0,
            'network_stability': 1.0,
            'active_threats': []
        }
        
        # Engine state
        self.is_running = False
        self.start_time = None
        self.total_threats_detected = 0
        self.total_actions_executed = 0
        self.successful_mitigations = 0
        
        # Real-time metrics
        self.metrics = {
            'threats_per_minute': deque(maxlen=60),
            'actions_per_minute': deque(maxlen=60),
            'average_response_time': deque(maxlen=100),
            'system_health': 1.0
        }
        
        # Advanced features
        self.adaptive_thresholds = True
        self.learning_mode = True
        self.multi_threading = True
        
    def _initialize_network(self) -> Dict[str, NetworkNode]:
        """Initialize simulated network nodes"""
        nodes = {}
        
        # Create drone nodes
        for i in range(1, 11):
            nodes[f"drone_{i}"] = NetworkNode(
                node_id=f"drone_{i}",
                node_type="drone",
                position=(random.uniform(-100, 100), random.uniform(-100, 100), random.uniform(10, 100)),
                security_level=random.uniform(0.7, 1.0),
                energy_level=random.uniform(0.8, 1.0)
            )
        
        # Create ground control stations
        for i in range(1, 3):
            nodes[f"gcs_{i}"] = NetworkNode(
                node_id=f"gcs_{i}",
                node_type="gcs",
                position=(random.uniform(-50, 50), random.uniform(-50, 50), 0),
                security_level=random.uniform(0.8, 1.0),
                energy_level=1.0
            )
        
        return nodes
    
    async def start(self):
        """Start the enhanced MTD engine"""
        if self.is_running:
            logger.warning("MTD Engine is already running")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        
        logger.info("🚁 Enhanced MTD Engine Started")
        logger.info(f"📡 Monitoring {len(self.network_nodes)} network nodes")
        logger.info(f"🛡️ {len(list(MTDAction))} MTD actions available")
        logger.info(f"🎯 {len(list(ThreatType))} threat types supported")
        
        # Start concurrent tasks
        tasks = [
            asyncio.create_task(self._main_detection_loop()),
            asyncio.create_task(self._network_state_monitor()),
            asyncio.create_task(self._metrics_collector()),
            asyncio.create_task(self._adaptive_learning_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("MTD Engine tasks cancelled")
    
    async def _main_detection_loop(self):
        """Main threat detection and response loop"""
        while self.is_running:
            try:
                cycle_start = time.time()
                
                # Detect threats
                threats = self.threat_detector.detect_threats(self.network_state)
                
                if threats:
                    self.total_threats_detected += len(threats)
                    self.network_state['active_threats'].extend(threats)
                    
                    for threat in threats:
                        logger.warning(f"🚨 THREAT DETECTED: {threat.threat_type.value.upper()} "
                                     f"(Severity: {threat.severity.name}, "
                                     f"Confidence: {threat.confidence:.2f}, "
                                     f"Target: {threat.target_node})")
                    
                    # Select and execute MTD action
                    action = self.decision_engine.select_action(threats, self.network_state)
                    
                    if action != MTDAction.NO_ACTION:
                        logger.info(f"🛡️ EXECUTING MTD ACTION: {action.value.upper()}")
                        
                        result = await self.mtd_executor.execute_action(action, self.network_state)
                        self.total_actions_executed += 1
                        
                        if result.success:
                            self.successful_mitigations += 1
                            self._update_network_state_after_action(result, threats)
                            
                            logger.info(f"✅ ACTION SUCCESS: {action.value.upper()} "
                                      f"(Effectiveness: {result.effectiveness:.2f}, "
                                      f"Energy Cost: {result.energy_cost:.3f})")
                        else:
                            logger.error(f"❌ ACTION FAILED: {action.value.upper()}")
                
                # Clean up old threats
                current_time = datetime.now()
                self.network_state['active_threats'] = [
                    t for t in self.network_state['active_threats']
                    if current_time - t.timestamp < timedelta(minutes=5)
                ]
                
                # Update metrics
                cycle_time = time.time() - cycle_start
                self.metrics['average_response_time'].append(cycle_time)
                
                # Adaptive sleep based on threat level
                sleep_time = self._calculate_adaptive_sleep()
                await asyncio.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in detection loop: {e}")
                await asyncio.sleep(1)
    
    async def _network_state_monitor(self):
        """Monitor and update network state"""
        while self.is_running:
            try:
                # Update node states
                for node in self.network_nodes.values():
                    # Simulate energy drain
                    if node.node_type == "drone":
                        node.energy_level = max(0, node.energy_level - random.uniform(0.001, 0.005))
                    
                    # Simulate security events
                    if random.random() < 0.01:  # 1% chance per cycle
                        node.security_level = max(0, node.security_level - random.uniform(0.05, 0.15))
                
                # Update overall network state
                total_energy = sum(node.energy_level for node in self.network_nodes.values())
                self.network_state['energy_level'] = total_energy / len(self.network_nodes)
                
                compromised_count = sum(1 for node in self.network_nodes.values() if node.is_compromised)
                self.network_state['compromised_nodes'] = compromised_count
                
                # Calculate network stability
                avg_security = sum(node.security_level for node in self.network_nodes.values()) / len(self.network_nodes)
                threat_impact = len(self.network_state['active_threats']) * 0.1
                self.network_state['network_stability'] = max(0, avg_security - threat_impact)
                
                await asyncio.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                logger.error(f"Error in network state monitor: {e}")
                await asyncio.sleep(5)
    
    async def _metrics_collector(self):
        """Collect and analyze performance metrics"""
        while self.is_running:
            try:
                # Calculate threats per minute
                current_minute = int(time.time() / 60)
                recent_threats = [
                    t for t in self.threat_detector.threat_history
                    if int(t.timestamp.timestamp() / 60) == current_minute
                ]
                self.metrics['threats_per_minute'].append(len(recent_threats))
                
                # Calculate actions per minute
                recent_actions = [
                    r for r in self.mtd_executor.execution_history
                    if int(time.time() - r.execution_time) < 60
                ]
                self.metrics['actions_per_minute'].append(len(recent_actions))
                
                # Update system health
                self._calculate_system_health()
                
                await asyncio.sleep(60)  # Update every minute
                
            except Exception as e:
                logger.error(f"Error in metrics collector: {e}")
                await asyncio.sleep(60)
    
    async def _adaptive_learning_loop(self):
        """Adaptive learning and optimization"""
        while self.is_running:
            try:
                if self.learning_mode and len(self.mtd_executor.execution_history) > 10:
                    # Analyze action effectiveness
                    recent_results = list(self.mtd_executor.execution_history)[-20:]
                    
                    for action in MTDAction:
                        action_results = [r for r in recent_results if r.action == action]
                        if action_results:
                            avg_effectiveness = sum(r.effectiveness for r in action_results) / len(action_results)
                            success_rate = sum(1 for r in action_results if r.success) / len(action_results)
                            
                            # Update action effectiveness in executor
                            if success_rate < 0.5:
                                self.mtd_executor.action_effectiveness[action] *= 0.95
                            elif success_rate > 0.8:
                                self.mtd_executor.action_effectiveness[action] = min(1.0, 
                                    self.mtd_executor.action_effectiveness[action] * 1.05)
                
                await asyncio.sleep(300)  # Learn every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in adaptive learning: {e}")
                await asyncio.sleep(300)
    
    def _calculate_adaptive_sleep(self) -> float:
        """Calculate adaptive sleep time based on threat level"""
        base_sleep = 0.5  # Base 500ms
        
        threat_count = len(self.network_state['active_threats'])
        if threat_count == 0:
            return base_sleep * 2  # Slower when no threats
        elif threat_count > 5:
            return base_sleep * 0.2  # Faster when many threats
        else:
            return base_sleep * (1 - threat_count * 0.1)
    
    def _update_network_state_after_action(self, result: MTDActionResult, threats: List[ThreatEvent]):
        """Update network state after successful MTD action"""
        # Reduce threat impact
        for threat in threats:
            if result.effectiveness > 0.7:
                # High effectiveness - mark threat as mitigated
                if threat in self.network_state['active_threats']:
                    self.network_state['active_threats'].remove(threat)
        
        # Update energy
        self.network_state['energy_level'] = max(0, 
            self.network_state['energy_level'] - result.energy_cost)
        
        # Temporary stability impact
        if result.side_effects:
            self.network_state['network_stability'] = max(0,
                self.network_state['network_stability'] - 0.1)
    
    def _calculate_system_health(self):
        """Calculate overall system health metric"""
        energy_health = self.network_state['energy_level']
        stability_health = self.network_state['network_stability']
        threat_health = max(0, 1 - len(self.network_state['active_threats']) * 0.1)
        
        avg_response_time = np.mean(list(self.metrics['average_response_time'])) if self.metrics['average_response_time'] else 0
        response_health = max(0, 1 - avg_response_time)
        
        self.metrics['system_health'] = (energy_health + stability_health + threat_health + response_health) / 4
    
    def stop(self):
        """Stop the MTD engine"""
        self.is_running = False
        logger.info("🛑 Enhanced MTD Engine Stopped")
        
        # Print final statistics
        if self.start_time:
            runtime = datetime.now() - self.start_time
            logger.info(f"📊 FINAL STATISTICS:")
            logger.info(f"   Runtime: {runtime}")
            logger.info(f"   Threats Detected: {self.total_threats_detected}")
            logger.info(f"   Actions Executed: {self.total_actions_executed}")
            logger.info(f"   Success Rate: {self.successful_mitigations/max(1,self.total_actions_executed)*100:.1f}%")
            logger.info(f"   System Health: {self.metrics['system_health']:.2f}")
    
    def get_status(self) -> Dict:
        """Get current engine status"""
        return {
            'running': self.is_running,
            'uptime': str(datetime.now() - self.start_time) if self.start_time else "0:00:00",
            'network_state': self.network_state,
            'total_threats': self.total_threats_detected,
            'total_actions': self.total_actions_executed,
            'success_rate': self.successful_mitigations/max(1,self.total_actions_executed),
            'system_health': self.metrics['system_health'],
            'active_nodes': len([n for n in self.network_nodes.values() if not n.is_compromised])
        }

if __name__ == "__main__":
    async def main():
        engine = EnhancedMTDEngine()
        
        try:
            await engine.start()
        except KeyboardInterrupt:
            engine.stop()

    # Run the enhanced MTD engine
    asyncio.run(main())