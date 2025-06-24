# scripts/dvds_bridge.py
import asyncio
import json
import logging
import socket
import threading
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import sys
import os
from pathlib import Path

# 프로젝트 루트 디렉토리를 Python 경로에 추가
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

# 프로젝트 모듈 임포트
try:
    from ns3_fanet_bridge import NS3FANETBridge, PacketInfo, PacketType, ProtocolType
    from honeydrone_network_manager import HoneydroneNetworkManager, DroneType
except ImportError as e:
    print(f"모듈 임포트 오류: {e}")
    sys.exit(1)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(project_root / 'logs' / 'dvds_bridge.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AttackScenario:
    """공격 시나리오 정의"""
    name: str
    description: str
    target_types: List[str]
    duration: int
    intensity: str  # low, medium, high, critical
    techniques: List[str]
    expected_packets: int
    detection_signatures: List[str]

class EnhancedDVDSSimulator:
    """향상된 DVDS 시뮬레이터"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8888)
        
        # 공격 시나리오 데이터베이스
        self.attack_scenarios = self._load_attack_scenarios()
        
        # 활성 공격 추적
        self.active_attacks: Dict[str, Dict[str, Any]] = {}
        self.attack_history: List[Dict[str, Any]] = []
        
        # 네트워크 상태
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.client_connections: List[socket.socket] = []
        
        # 통계
        self.stats = {
            'total_attacks_launched': 0,
            'successful_attacks': 0,
            'detected_attacks': 0,
            'total_packets_generated': 0,
            'start_time': None
        }
    
    def _load_attack_scenarios(self) -> Dict[str, AttackScenario]:
        """공격 시나리오 로드"""
        scenarios = {
            'network_reconnaissance': AttackScenario(
                name='Network Reconnaissance',
                description='Systematic scanning of drone network topology and services',
                target_types=['virtual', 'dummy', 'real'],
                duration=60,
                intensity='low',
                techniques=['port_scan', 'service_enumeration', 'topology_discovery'],
                expected_packets=50,
                detection_signatures=['rapid_connection_attempts', 'port_scanning_pattern']
            ),
            
            'denial_of_service': AttackScenario(
                name='Denial of Service Attack',
                description='Overwhelming target drone with excessive traffic',
                target_types=['dummy', 'virtual'],
                duration=45,
                intensity='high',
                techniques=['udp_flood', 'tcp_syn_flood', 'bandwidth_exhaustion'],
                expected_packets=500,
                detection_signatures=['high_packet_rate', 'resource_exhaustion']
            ),
            
            'man_in_the_middle': AttackScenario(
                name='Man-in-the-Middle Attack',
                description='Intercepting and manipulating drone communications',
                target_types=['virtual', 'dummy'],
                duration=120,
                intensity='medium',
                techniques=['arp_spoofing', 'dns_hijacking', 'packet_manipulation'],
                expected_packets=80,
                detection_signatures=['routing_anomalies', 'certificate_mismatch']
            ),
            
            'command_injection': AttackScenario(
                name='Remote Command Injection',
                description='Injecting malicious commands into drone control systems',
                target_types=['dummy'],
                duration=30,
                intensity='critical',
                techniques=['buffer_overflow', 'code_injection', 'privilege_escalation'],
                expected_packets=20,
                detection_signatures=['abnormal_command_patterns', 'privilege_escalation_attempts']
            ),
            
            'data_exfiltration': AttackScenario(
                name='Sensitive Data Exfiltration',
                description='Stealing flight data, mission parameters, and sensor information',
                target_types=['dummy', 'virtual'],
                duration=180,
                intensity='medium',
                techniques=['steganography', 'covert_channels', 'data_compression'],
                expected_packets=100,
                detection_signatures=['unusual_data_patterns', 'unauthorized_data_access']
            ),
            
            'gps_spoofing': AttackScenario(
                name='GPS Spoofing Attack',
                description='Manipulating drone GPS signals to cause navigation errors',
                target_types=['dummy', 'virtual'],
                duration=90,
                intensity='high',
                techniques=['signal_jamming', 'false_gps_signals', 'navigation_hijacking'],
                expected_packets=60,
                detection_signatures=['gps_signal_anomalies', 'navigation_inconsistencies']
            ),
            
            'firmware_exploitation': AttackScenario(
                name='Firmware Exploitation',
                description='Exploiting vulnerabilities in drone firmware',
                target_types=['dummy'],
                duration=150,
                intensity='critical',
                techniques=['firmware_reverse_engineering', 'bootloader_attack', 'persistent_backdoor'],
                expected_packets=40,
                detection_signatures=['firmware_integrity_violation', 'unauthorized_system_access']
            ),
            
            'swarm_disruption': AttackScenario(
                name='Swarm Coordination Disruption',
                description='Disrupting communication between multiple drones in a swarm',
                target_types=['virtual', 'dummy'],
                duration=75,
                intensity='high',
                techniques=['coordination_jamming', 'consensus_manipulation', 'leader_isolation'],
                expected_packets=150,
                detection_signatures=['swarm_coordination_anomalies', 'consensus_failures']
            )
        }
        
        return scenarios
    
    async def start_server(self):
        """DVDS 서버 시작"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            
            self.is_running = True
            self.stats['start_time'] = datetime.now()
            
            logger.info(f"🎯 DVDS 서버 시작됨: {self.host}:{self.port}")
            print(f"📡 사용 가능한 공격 시나리오: {len(self.attack_scenarios)}개")
            for name, scenario in self.attack_scenarios.items():
                print(f"  - {name}: {scenario.description[:50]}...")
            
            # 클라이언트 연결 처리 루프
            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    logger.info(f"클라이언트 연결: {addr}")
                    
                    # 각 클라이언트를 별도 스레드에서 처리
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.is_running:
                        logger.error(f"클라이언트 연결 처리 오류: {e}")
                    
        except Exception as e:
            logger.error(f"DVDS 서버 시작 실패: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_client(self, client_socket: socket.socket, addr):
        """클라이언트 요청 처리"""
        try:
            self.client_connections.append(client_socket)
            
            while self.is_running:
                try:
                    # 클라이언트로부터 명령 수신
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    command = data.decode('utf-8').strip()
                    logger.debug(f"명령 수신 from {addr}: {command}")
                    
                    # 명령 처리
                    response = self._process_command(command, addr)
                    
                    # 응답 전송
                    client_socket.send(response.encode('utf-8'))
                    
                except ConnectionResetError:
                    break
                except Exception as e:
                    logger.error(f"클라이언트 처리 오류 ({addr}): {e}")
                    break
                    
        finally:
            try:
                client_socket.close()
                if client_socket in self.client_connections:
                    self.client_connections.remove(client_socket)
                logger.info(f"클라이언트 연결 종료: {addr}")
            except:
                pass
    
    def _process_command(self, command: str, client_addr) -> str:
        """명령 처리"""
        try:
            parts = command.split(':')
            cmd = parts[0].upper()
            
            if cmd == 'STATUS':
                return self._get_status()
                
            elif cmd == 'LIST_SCENARIOS':
                return self._list_scenarios()
                
            elif cmd == 'ATTACK' and len(parts) >= 3:
                target_drone = parts[1]
                scenario_name = parts[2]
                return self._launch_attack(target_drone, scenario_name, client_addr)
                
            elif cmd == 'STOP_ATTACK' and len(parts) >= 2:
                attack_id = parts[1]
                return self._stop_attack(attack_id)
                
            elif cmd == 'SCAN' and len(parts) >= 2:
                target_network = parts[1]
                return self._perform_scan(target_network)
                
            elif cmd == 'INJECT_PACKET' and len(parts) >= 4:
                source = parts[1]
                target = parts[2]
                payload = parts[3]
                return self._inject_packet(source, target, payload)
                
            elif cmd == 'GET_STATS':
                return self._get_statistics()
                
            elif cmd == 'HELP':
                return self._get_help()
                
            else:
                return f"ERROR:Unknown command: {cmd}"
                
        except Exception as e:
            logger.error(f"명령 처리 오류: {e}")
            return f"ERROR:Command processing failed: {str(e)}"
    
    def _get_status(self) -> str:
        """상태 정보 반환"""
        active_count = len(self.active_attacks)
        uptime = (datetime.now() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
        
        return f"STATUS:Active attacks: {active_count}, Uptime: {uptime:.0f}s, Scenarios: {len(self.attack_scenarios)}"
    
    def _list_scenarios(self) -> str:
        """사용 가능한 시나리오 목록"""
        scenarios_info = []
        for name, scenario in self.attack_scenarios.items():
            scenarios_info.append(f"{name}|{scenario.intensity}|{scenario.duration}s|{','.join(scenario.target_types)}")
        
        return f"SCENARIOS:{';'.join(scenarios_info)}"
    
    def _launch_attack(self, target_drone: str, scenario_name: str, client_addr) -> str:
        """공격 실행"""
        if scenario_name not in self.attack_scenarios:
            return f"ERROR:Unknown scenario: {scenario_name}"
        
        scenario = self.attack_scenarios[scenario_name]
        attack_id = f"{scenario_name}_{target_drone}_{int(time.time())}"
        
        # 공격 레코드 생성
        attack_record = {
            'attack_id': attack_id,
            'scenario_name': scenario_name,
            'target_drone': target_drone,
            'start_time': datetime.now(),
            'duration': scenario.duration,
            'client_addr': client_addr,
            'status': 'active',
            'packets_sent': 0,
            'techniques_used': scenario.techniques.copy(),
            'detection_triggered': False
        }
        
        self.active_attacks[attack_id] = attack_record
        self.stats['total_attacks_launched'] += 1
        
        # 공격 시뮬레이션 시작 (백그라운드)
        threading.Thread(
            target=self._simulate_attack,
            args=(attack_id, scenario),
            daemon=True
        ).start()
        
        logger.warning(f"🚨 공격 시작: {scenario_name} -> {target_drone} (ID: {attack_id})")
        
        return f"ATTACK_SUCCESS:{attack_id}:Duration {scenario.duration}s:Intensity {scenario.intensity}"
    
    def _simulate_attack(self, attack_id: str, scenario: AttackScenario):
        """공격 시뮬레이션"""
        try:
            attack_record = self.active_attacks[attack_id]
            total_packets = scenario.expected_packets
            interval = scenario.duration / total_packets
            
            start_time = time.time()
            
            for i in range(total_packets):
                if attack_id not in self.active_attacks or self.active_attacks[attack_id]['status'] != 'active':
                    break
                
                # 패킷 전송 시뮬레이션
                packet_data = self._generate_attack_packet(scenario, i)
                
                # 패킷 카운터 증가
                attack_record['packets_sent'] += 1
                self.stats['total_packets_generated'] += 1
                
                # 탐지 확률 체크
                if random.random() < 0.1:  # 10% 확률로 탐지 시그니처 트리거
                    attack_record['detection_triggered'] = True
                    logger.info(f"탐지 시그니처 트리거: {attack_id}")
                
                # 진행률 로깅
                if (i + 1) % max(1, total_packets // 5) == 0:
                    progress = (i + 1) / total_packets * 100
                    logger.debug(f"공격 진행률 ({attack_id}): {progress:.1f}%")
                
                time.sleep(interval)
            
            # 공격 완료
            elapsed_time = time.time() - start_time
            attack_record['status'] = 'completed'
            attack_record['end_time'] = datetime.now()
            attack_record['actual_duration'] = elapsed_time
            
            # 성공률 결정
            success_rate = random.uniform(0.6, 0.95) if attack_record['detection_triggered'] else random.uniform(0.8, 1.0)
            attack_record['success_rate'] = success_rate
            
            if success_rate > 0.7:
                self.stats['successful_attacks'] += 1
            
            if attack_record['detection_triggered']:
                self.stats['detected_attacks'] += 1
            
            # 히스토리에 추가
            self.attack_history.append(attack_record.copy())
            
            # 활성 공격에서 제거
            del self.active_attacks[attack_id]
            
            logger.info(f"공격 완료: {attack_id} (성공률: {success_rate:.2f}, 탐지: {attack_record['detection_triggered']})")
            
        except Exception as e:
            logger.error(f"공격 시뮬레이션 오류 ({attack_id}): {e}")
            if attack_id in self.active_attacks:
                self.active_attacks[attack_id]['status'] = 'failed'
    
    def _generate_attack_packet(self, scenario: AttackScenario, packet_index: int) -> Dict[str, Any]:
        """공격 패킷 생성"""
        # 시나리오에 따른 패킷 특성
        packet_characteristics = {
            'network_reconnaissance': {
                'size_range': (64, 128),
                'protocol': 'TCP',
                'flags': ['SYN'],
                'payload_type': 'scan_probe'
            },
            'denial_of_service': {
                'size_range': (1024, 2048),
                'protocol': 'UDP',
                'flags': ['FLOOD'],
                'payload_type': 'junk_data'
            },
            'man_in_the_middle': {
                'size_range': (256, 512),
                'protocol': 'TCP',
                'flags': ['PSH', 'ACK'],
                'payload_type': 'intercepted_data'
            },
            'command_injection': {
                'size_range': (128, 256),
                'protocol': 'TCP',
                'flags': ['PSH', 'ACK'],
                'payload_type': 'malicious_command'
            },
            'data_exfiltration': {
                'size_range': (512, 1024),
                'protocol': 'HTTPS',
                'flags': ['PSH', 'ACK'],
                'payload_type': 'encrypted_data'
            },
            'gps_spoofing': {
                'size_range': (32, 64),
                'protocol': 'UDP',
                'flags': ['GPS'],
                'payload_type': 'fake_coordinates'
            },
            'firmware_exploitation': {
                'size_range': (256, 512),
                'protocol': 'TCP',
                'flags': ['PSH', 'ACK'],
                'payload_type': 'exploit_code'
            },
            'swarm_disruption': {
                'size_range': (128, 256),
                'protocol': 'UDP',
                'flags': ['BROADCAST'],
                'payload_type': 'coordination_noise'
            }
        }
        
        char = packet_characteristics.get(scenario.name.lower().replace(' ', '_'), 
                                        packet_characteristics['network_reconnaissance'])
        
        size = random.randint(*char['size_range'])
        
        return {
            'packet_id': f"{scenario.name}_{packet_index}_{int(time.time())}",
            'size': size,
            'protocol': char['protocol'],
            'flags': char['flags'],
            'payload_type': char['payload_type'],
            'timestamp': datetime.now().isoformat(),
            'sequence': packet_index,
            'attack_signature': scenario.name
        }
    
    def _stop_attack(self, attack_id: str) -> str:
        """공격 중지"""
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id]['status'] = 'stopped'
            self.active_attacks[attack_id]['end_time'] = datetime.now()
            
            logger.info(f"공격 중지: {attack_id}")
            return f"ATTACK_STOPPED:{attack_id}"
        else:
            return f"ERROR:Attack not found: {attack_id}"
    
    def _perform_scan(self, target_network: str) -> str:
        """네트워크 스캔 수행"""
        # 가상의 스캔 결과 생성
        discovered_drones = []
        
        # 랜덤한 수의 드론 발견 시뮬레이션
        num_drones = random.randint(3, 8)
        
        for i in range(num_drones):
            drone_info = {
                'drone_id': f"target_drone_{i+1}",
                'ip_address': f"192.168.1.{100+i}",
                'drone_type': random.choice(['virtual', 'dummy', 'real']),
                'vulnerability_level': random.choice(['low', 'medium', 'high']),
                'open_ports': random.sample([22, 23, 80, 443, 8080, 9000], random.randint(2, 4)),
                'services': random.sample(['ssh', 'telnet', 'http', 'https', 'drone_api', 'control_interface'], random.randint(1, 3))
            }
            discovered_drones.append(drone_info)
        
        scan_result = {
            'scan_id': f"scan_{int(time.time())}",
            'target_network': target_network,
            'discovered_drones': discovered_drones,
            'scan_duration': random.uniform(10, 30),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"네트워크 스캔 완료: {len(discovered_drones)}개 드론 발견")
        
        # 결과를 간단한 형태로 반환
        result_summary = []
        for drone in discovered_drones:
            result_summary.append(f"{drone['drone_id']}:{drone['vulnerability_level']}:{len(drone['open_ports'])}")
        
        return f"SCAN_RESULT:{','.join(result_summary)}"
    
    def _inject_packet(self, source: str, target: str, payload: str) -> str:
        """패킷 주입"""
        packet_id = f"injected_{int(time.time())}"
        
        injection_record = {
            'packet_id': packet_id,
            'source': source,
            'target': target,
            'payload': payload,
            'timestamp': datetime.now(),
            'size': len(payload.encode('utf-8')),
            'type': 'manual_injection'
        }
        
        # 패킷 주입 시뮬레이션
        success_rate = random.uniform(0.7, 0.95)
        
        if success_rate > 0.8:
            logger.info(f"패킷 주입 성공: {source} -> {target} ({packet_id})")
            return f"PACKET_INJECTED:{packet_id}:Success"
        else:
            logger.warning(f"패킷 주입 실패: {source} -> {target} ({packet_id})")
            return f"PACKET_INJECTION_FAILED:{packet_id}:Network error"
    
    def _get_statistics(self) -> str:
        """통계 정보 반환"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
        
        stats_data = {
            'uptime_seconds': int(uptime),
            'total_attacks_launched': self.stats['total_attacks_launched'],
            'successful_attacks': self.stats['successful_attacks'],
            'detected_attacks': self.stats['detected_attacks'],
            'total_packets_generated': self.stats['total_packets_generated'],
            'active_attacks': len(self.active_attacks),
            'completed_attacks': len(self.attack_history),
            'success_rate': (self.stats['successful_attacks'] / max(1, self.stats['total_attacks_launched'])) * 100,
            'detection_rate': (self.stats['detected_attacks'] / max(1, self.stats['total_attacks_launched'])) * 100
        }
        
        stats_str = '|'.join([f"{k}:{v}" for k, v in stats_data.items()])
        return f"STATS:{stats_str}"
    
    def _get_help(self) -> str:
        """도움말 반환"""
        commands = [
            "STATUS - Get server status",
            "LIST_SCENARIOS - List available attack scenarios",
            "ATTACK:target_drone:scenario_name - Launch attack",
            "STOP_ATTACK:attack_id - Stop active attack",
            "SCAN:target_network - Perform network scan",
            "INJECT_PACKET:source:target:payload - Inject custom packet",
            "GET_STATS - Get detailed statistics",
            "HELP - Show this help"
        ]
        
        return f"HELP:{';'.join(commands)}"
    
    def stop_server(self):
        """서버 중지"""
        self.is_running = False
        
        # 모든 활성 공격 중지
        for attack_id in list(self.active_attacks.keys()):
            self.active_attacks[attack_id]['status'] = 'stopped'
        
        # 클라이언트 연결 종료
        for client in self.client_connections:
            try:
                client.close()
            except:
                pass
        
        # 서버 소켓 종료
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("DVDS 서버 중지됨")
    
    def get_status_summary(self) -> Dict[str, Any]:
        """상태 요약 반환"""
        return {
            'is_running': self.is_running,
            'active_attacks': len(self.active_attacks),
            'total_scenarios': len(self.attack_scenarios),
            'statistics': self.stats,
            'recent_attacks': self.attack_history[-5:] if self.attack_history else []
        }

class DVDSBridgeRunner:
    """DVDS 브리지 실행기"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.dvds_simulator = EnhancedDVDSSimulator(self.config.get('dvds', {}))
        self.ns3_bridge: Optional[NS3FANETBridge] = None
        self.honeydrone_manager: Optional[HoneydroneNetworkManager] = None
        
        # 연동 상태
        self.integration_active = False
        self.integration_task: Optional[asyncio.Task] = None
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """설정 로드"""
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"설정 파일 로드 실패: {e}")
        
        # 기본 설정
        return {
            'dvds': {
                'host': '0.0.0.0',
                'port': 8888
            },
            'integration': {
                'ns3_bridge_enabled': True,
                'honeydrone_integration': True,
                'auto_attack_mapping': True,
                'real_time_analysis': True
            }
        }
    
    async def start_integrated_system(self):
        """통합 시스템 시작"""
        logger.info("🚀 DVDS 통합 시스템 시작 중...")
        
        # DVDS 시뮬레이터 시작
        dvds_task = asyncio.create_task(self.dvds_simulator.start_server())
        
        # 잠시 대기 (서버 시작 완료)
        await asyncio.sleep(2)
        
        # NS-3 브리지 초기화 (설정된 경우)
        if self.config.get('integration', {}).get('ns3_bridge_enabled', True):
            try:
                # NS-3 브리지 설정 파일이 있는지 확인
                ns3_config_path = project_root / 'config' / 'ns3_config.json'
                if ns3_config_path.exists():
                    self.ns3_bridge = NS3FANETBridge(str(ns3_config_path))
                    logger.info("NS-3 브리지 초기화됨")
                else:
                    logger.warning("NS-3 설정 파일을 찾을 수 없습니다")
            except Exception as e:
                logger.error(f"NS-3 브리지 초기화 실패: {e}")
        
        # 허니드론 매니저 초기화 (설정된 경우)
        if self.config.get('integration', {}).get('honeydrone_integration', True):
            try:
                network_config_path = project_root / 'config' / 'network_config.json'
                if network_config_path.exists():
                    self.honeydrone_manager = HoneydroneNetworkManager(str(network_config_path))
                    await self.honeydrone_manager.start()
                    logger.info("허니드론 네트워크 매니저 초기화됨")
                else:
                    logger.warning("네트워크 설정 파일을 찾을 수 없습니다")
            except Exception as e:
                logger.error(f"허니드론 매니저 초기화 실패: {e}")
        
        # 연동 모니터링 시작
        if self.config.get('integration', {}).get('auto_attack_mapping', True):
            self.integration_task = asyncio.create_task(self._integration_monitor())
        
        self.integration_active = True
        logger.info("✅ DVDS 통합 시스템 시작 완료")
        
        try:
            # DVDS 서버 실행 (메인 루프)
            await dvds_task
        except KeyboardInterrupt:
            logger.info("사용자에 의해 중단됨")
        finally:
            await self.stop_integrated_system()
    
    async def _integration_monitor(self):
        """연동 모니터링"""
        try:
            while self.integration_active:
                # DVDS 활성 공격과 NS-3/허니드론 데이터 연동
                if self.dvds_simulator.active_attacks and self.ns3_bridge:
                    await self._sync_attacks_with_ns3()
                
                # 허니드론 네트워크 상태와 DVDS 공격 동기화
                if self.honeydrone_manager:
                    await self._sync_with_honeydrone_network()
                
                await asyncio.sleep(5)  # 5초마다 동기화
                
        except asyncio.CancelledError:
            logger.info("연동 모니터링이 취소되었습니다")
        except Exception as e:
            logger.error(f"연동 모니터링 오류: {e}")
    
    async def _sync_attacks_with_ns3(self):
        """NS-3와 공격 동기화"""
        try:
            for attack_id, attack_data in self.dvds_simulator.active_attacks.items():
                scenario_name = attack_data['scenario_name']
                target_drone = attack_data['target_drone']
                
                # NS-3에 공격 패킷 주입
                if hasattr(self.ns3_bridge, 'inject_attack_packet'):
                    success = self.ns3_bridge.inject_attack_packet(
                        source_id="attacker_node",
                        dest_id=target_drone,
                        attack_type=scenario_name
                    )
                    
                    if success:
                        logger.debug(f"NS-3에 공격 패킷 주입: {scenario_name} -> {target_drone}")
            
        except Exception as e:
            logger.error(f"NS-3 동기화 오류: {e}")
    
    async def _sync_with_honeydrone_network(self):
        """허니드론 네트워크와 동기화"""
        try:
            # 허니드론 네트워크의 드론 상태 확인
            network_status = self.honeydrone_manager.get_all_drones_status()
            
            # 타협된 드론이 있으면 DVDS 공격 성공률 증가
            compromised_count = network_status.get('compromised_count', 0)
            
            if compromised_count > 0:
                for attack_id, attack_data in self.dvds_simulator.active_attacks.items():
                    if attack_data['target_drone'] in [d for d, info in network_status.get('drones', {}).items() 
                                                     if info.get('state') == 'compromised']:
                        # 공격 성공률 증가
                        attack_data['success_boost'] = 0.2
                        logger.info(f"공격 성공률 증가: {attack_id} (타겟 드론 타협됨)")
            
        except Exception as e:
            logger.error(f"허니드론 네트워크 동기화 오류: {e}")
    
    async def stop_integrated_system(self):
        """통합 시스템 중지"""
        logger.info("🛑 DVDS 통합 시스템 중지 중...")
        
        self.integration_active = False
        
        # 연동 모니터링 중지
        if self.integration_task:
            self.integration_task.cancel()
            try:
                await self.integration_task
            except asyncio.CancelledError:
                pass
        
        # 각 컴포넌트 중지
        if self.honeydrone_manager:
            await self.honeydrone_manager.stop()
        
        if self.ns3_bridge:
            await self.ns3_bridge.stop()
        
        # DVDS 시뮬레이터 중지
        self.dvds_simulator.stop_server()
        
        logger.info("✅ DVDS 통합 시스템 중지 완료")
    
    def get_integration_status(self) -> Dict[str, Any]:
        """연동 상태 반환"""
        status = {
            'integration_active': self.integration_active,
            'dvds_status': self.dvds_simulator.get_status_summary(),
            'ns3_bridge_available': self.ns3_bridge is not None,
            'honeydrone_manager_available': self.honeydrone_manager is not None
        }
        
        if self.honeydrone_manager:
            status['honeydrone_status'] = self.honeydrone_manager.get_system_health()
        
        if self.ns3_bridge:
            status['ns3_status'] = {
                'is_running': self.ns3_bridge.is_running,
                'packets_analyzed': self.ns3_bridge.analysis_stats.get('packets_analyzed', 0),
                'attacks_detected': self.ns3_bridge.analysis_stats.get('attacks_detected', 0)
            }
        
        return status

# CLI 인터페이스
def print_banner():
    """배너 출력"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🎯 DVDS - Damn Vulnerable Drone Simulator                  ║
    ║   📡 Enhanced Edition with NS-3 & Honeydrone Integration     ║
    ║                                                               ║
    ║   FANET 허니드론 네트워크 테스트베드                              ║
    ║   실시간 공격 시뮬레이션 및 패킷 분석 시스템                          ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_help():
    """도움말 출력"""
    help_text = """
📋 DVDS 브리지 사용법:

🚀 실행 모드:
  --server-only       DVDS 서버만 실행
  --integrated        통합 모드 (NS-3 + 허니드론 + DVDS)
  --config FILE       설정 파일 지정

🎯 사용 가능한 공격 시나리오:
  • network_reconnaissance  - 네트워크 정찰
  • denial_of_service       - 서비스 거부 공격
  • man_in_the_middle      - 중간자 공격
  • command_injection      - 명령 주입 공격
  • data_exfiltration      - 데이터 유출
  • gps_spoofing          - GPS 스푸핑
  • firmware_exploitation  - 펌웨어 익스플로잇
  • swarm_disruption      - 군집 통신 방해

📡 클라이언트 연결:
  telnet localhost 8888
  
  명령어:
  STATUS                           - 서버 상태
  LIST_SCENARIOS                   - 시나리오 목록
  ATTACK:target_drone:scenario     - 공격 실행
  SCAN:network_range              - 네트워크 스캔
  GET_STATS                       - 통계 정보

🔗 연동 기능:
  ✓ NS-3 실시간 패킷 분석
  ✓ 허니드론 네트워크 상태 동기화
  ✓ 자동 공격 매핑 및 탐지
  ✓ 애니메이션 기반 시각화
    """
    print(help_text)

async def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DVDS Bridge - Enhanced Drone Attack Simulator')
    parser.add_argument('--mode', choices=['server-only', 'integrated'], default='integrated',
                       help='실행 모드 선택')
    parser.add_argument('--config', type=str, help='설정 파일 경로')
    parser.add_argument('--port', type=int, default=8888, help='DVDS 서버 포트')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='DVDS 서버 호스트')
    parser.add_argument('--help-extended', action='store_true', help='확장 도움말 표시')
    
    args = parser.parse_args()
    
    if args.help_extended:
        print_help()
        return
    
    print_banner()
    
    # 설정 파일 준비
    config = {
        'dvds': {
            'host': args.host,
            'port': args.port
        },
        'integration': {
            'ns3_bridge_enabled': args.mode == 'integrated',
            'honeydrone_integration': args.mode == 'integrated',
            'auto_attack_mapping': True,
            'real_time_analysis': True
        }
    }
    
    if args.config:
        config_path = args.config
    else:
        # 임시 설정 파일 생성
        config_path = '/tmp/dvds_bridge_config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    # DVDS 브리지 실행기 생성
    bridge_runner = DVDSBridgeRunner(config_path)
    
    try:
        if args.mode == 'server-only':
            logger.info("🎯 DVDS 서버 전용 모드로 시작...")
            await bridge_runner.dvds_simulator.start_server()
        else:
            logger.info("🚀 DVDS 통합 모드로 시작...")
            await bridge_runner.start_integrated_system()
            
    except KeyboardInterrupt:
        logger.info("\n⏹️  사용자에 의해 중단됨")
    except Exception as e:
        logger.error(f"❌ 실행 오류: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if args.mode == 'integrated':
            await bridge_runner.stop_integrated_system()
        else:
            bridge_runner.dvds_simulator.stop_server()
        
        logger.info("🏁 DVDS 브리지 종료됨")

if __name__ == "__main__":
    # 로그 디렉토리 생성
    (project_root / 'logs').mkdir(exist_ok=True)
    
    # 이벤트 루프 실행
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 안녕히 가세요!")
    except Exception as e:
        print(f"❌ 심각한 오류: {e}")
        import traceback
        traceback.print_exc()# scripts/dvds_bridge.