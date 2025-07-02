# core/dvd_integration/enhanced_cti_collector.py - 10개 공격 시나리오 CTI 자동 수집기
import asyncio
import json
import subprocess
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import docker
import psutil
import re
import xml.etree.ElementTree as ET
from core.base import research_collector, AttackEvent, AttackType
from core.cti.stix_generator import STIXGenerator

@dataclass
class EnhancedDVDAttackLog:
    timestamp: datetime
    attack_scenario: str  # 10개 시나리오 중 하나
    attack_type: str
    mitre_techniques: List[str]
    source_ip: str
    target_component: str
    attack_vector: str
    payload: Dict[str, Any]
    success: bool
    detection_status: str
    severity: int
    raw_log: str
    evidence_artifacts: Dict[str, Any]

@dataclass
class MITREMapping:
    technique_id: str
    technique_name: str
    tactic: str
    attack_phase: str
    confidence: float

@dataclass
class CTIReport:
    id: str
    attack_scenario: str
    mitre_mappings: List[MITREMapping]
    iocs: List[Dict[str, Any]]
    attack_timeline: List[EnhancedDVDAttackLog]
    threat_assessment: Dict[str, Any]
    stix_bundle: Optional[str] = None
    created_at: datetime = datetime.now()

class Enhanced10ScenarioDVDCTICollector:
    """DVD 환경에서 10개 공격 시나리오 CTI 자동 수집 시스템"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # DVD 환경 설정
        self.dvd_container_name = config.get('dvd_container', 'damn-vulnerable-drone')
        self.docker_client = docker.from_env()
        
        # STIX 생성기
        self.stix_generator = STIXGenerator()
        
        # 10개 공격 시나리오 패턴 정의
        self.attack_scenarios = self._initialize_10_attack_scenarios()
        
        # CTI 데이터베이스
        self.collected_cti: List[CTIReport] = []
        self.active_attacks: Dict[str, Dict] = {}
        
        # 실시간 모니터링 상태
        self.monitoring_active = False
        self.collection_stats = {
            'total_events': 0,
            'scenarios_detected': 0,
            'cti_generated': 0,
            'stix_reports': 0
        }
    
    def _initialize_10_attack_scenarios(self) -> Dict[str, Dict]:
        """10개 공격 시나리오 패턴 정의"""
        return {
            '1_passive_reconnaissance': {
                'category': 'A',
                'log_patterns': [
                    r'Wireless scan.*802\.11.*detected',
                    r'MAVLink.*discovery.*protocol',
                    r'GPS.*telemetry.*captured'
                ],
                'network_patterns': [
                    r'nmap.*scan.*14550',
                    r'airodump.*capture.*packets',
                    r'MAVLINK.*HEARTBEAT.*sysid'
                ],
                'mitre_techniques': ['T1595.002', 'T1040', 'T1056.001'],
                'severity': 3,
                'expected_artifacts': ['wireless_scan_results', 'mavlink_packets', 'gps_coordinates']
            },
            
            '2_communication_disruption': {
                'category': 'B',
                'log_patterns': [
                    r'Network.*flooding.*detected',
                    r'Communication.*link.*lost',
                    r'UDP.*flood.*attack'
                ],
                'network_patterns': [
                    r'iperf.*flooding.*14550',
                    r'hping3.*flood.*GCS',
                    r'Denial.*service.*mavlink'
                ],
                'mitre_techniques': ['T1018', 'T1498.001', 'T1489'],
                'severity': 4,
                'expected_artifacts': ['flood_packets', 'connection_logs', 'service_status']
            },
            
            '3_companion_compromise': {
                'category': 'C',
                'log_patterns': [
                    r'Web.*login.*attempt.*admin',
                    r'SSH.*brute.*force.*detected',
                    r'Unauthorized.*access.*companion'
                ],
                'network_patterns': [
                    r'hydra.*ssh.*brute.*force',
                    r'dirb.*web.*enumeration',
                    r'nc.*reverse.*shell'
                ],
                'mitre_techniques': ['T1018', 'T1110.001', 'T1059.004'],
                'severity': 5,
                'expected_artifacts': ['login_attempts', 'shell_commands', 'file_access']
            },
            
            '4_gps_spoofing': {
                'category': 'D',
                'log_patterns': [
                    r'GPS.*invalid.*position.*detected',
                    r'EKF.*GPS.*quality.*poor',
                    r'Navigation.*system.*compromised'
                ],
                'network_patterns': [
                    r'hackrf.*gps.*spoof',
                    r'gps-sdr-sim.*transmit',
                    r'NMEA.*fake.*sentences'
                ],
                'mitre_techniques': ['T1200', 'T1491.002', 'T1565.002'],
                'severity': 5,
                'expected_artifacts': ['gps_signals', 'position_drift', 'satellite_data']
            },
            
            '5_mavlink_exploitation': {
                'category': 'C',
                'log_patterns': [
                    r'MAVLink.*injection.*detected',
                    r'Unauthorized.*command.*received',
                    r'Flight.*mode.*changed.*unexpected'
                ],
                'network_patterns': [
                    r'mavproxy.*command.*injection',
                    r'COMMAND_LONG.*malicious',
                    r'SET_MODE.*unauthorized'
                ],
                'mitre_techniques': ['T1040', 'T1071.004', 'T1565.001'],
                'severity': 5,
                'expected_artifacts': ['mavlink_commands', 'flight_logs', 'mode_changes']
            },
            
            '6_sensor_deception': {
                'category': 'D',
                'log_patterns': [
                    r'Battery.*status.*anomaly',
                    r'Critical.*error.*spoofed',
                    r'Emergency.*landing.*triggered'
                ],
                'network_patterns': [
                    r'BATTERY_STATUS.*fake',
                    r'SYS_STATUS.*manipulated',
                    r'STATUSTEXT.*emergency.*fake'
                ],
                'mitre_techniques': ['T1565.002', 'T1565.002', 'T1565.001'],
                'severity': 4,
                'expected_artifacts': ['sensor_readings', 'system_status', 'error_messages']
            },
            
            '7_video_intelligence': {
                'category': 'A',
                'log_patterns': [
                    r'Video.*stream.*intercepted',
                    r'Camera.*feed.*captured',
                    r'RTSP.*hijack.*detected'
                ],
                'network_patterns': [
                    r'ffmpeg.*rtsp.*capture',
                    r'gstreamer.*video.*dump',
                    r'vlc.*stream.*save'
                ],
                'mitre_techniques': ['T1113', 'T1041', 'T1005'],
                'severity': 3,
                'expected_artifacts': ['video_frames', 'stream_metadata', 'flight_logs']
            },
            
            '8_resource_exhaustion': {
                'category': 'B',
                'log_patterns': [
                    r'ROS.*topic.*flooding.*detected',
                    r'System.*resources.*exhausted',
                    r'Takeoff.*sequence.*blocked'
                ],
                'network_patterns': [
                    r'rostopic.*pub.*flood',
                    r'CPU.*usage.*100%',
                    r'Memory.*allocation.*failed'
                ],
                'mitre_techniques': ['T1498.002', 'T1499.004', 'T1565.002'],
                'severity': 4,
                'expected_artifacts': ['system_metrics', 'ros_logs', 'resource_usage']
            },
            
            '9_rth_hijacking': {
                'category': 'C',
                'log_patterns': [
                    r'Return.*home.*coordinates.*changed',
                    r'Geofence.*boundary.*modified',
                    r'Home.*position.*override.*detected'
                ],
                'network_patterns': [
                    r'SET_HOME_POSITION.*malicious',
                    r'MISSION_ITEM.*waypoint.*inject',
                    r'FENCE_POINT.*boundary.*modify'
                ],
                'mitre_techniques': ['T1071.004', 'T1565.001', 'T1491.001'],
                'severity': 5,
                'expected_artifacts': ['home_coordinates', 'mission_waypoints', 'fence_data']
            },
            
            '10_apt_drone_threat': {
                'category': 'D',
                'log_patterns': [
                    r'Multi.*vector.*attack.*detected',
                    r'Persistent.*threat.*identified',
                    r'Navigation.*system.*corrupted'
                ],
                'network_patterns': [
                    r'coordinated.*attack.*multiple',
                    r'stealth.*mode.*persistence',
                    r'data.*destruction.*gps'
                ],
                'mitre_techniques': ['T1565.002', 'T1565.002', 'T1565.002', 'T1485'],
                'severity': 5,
                'expected_artifacts': ['attack_coordination', 'persistence_mechanisms', 'data_corruption']
            }
        }
    
    async def start_comprehensive_collection(self):
        """10개 시나리오 종합 CTI 수집 시작"""
        self.logger.info("=== DVD 10개 공격 시나리오 CTI 수집 시작 ===")
        self.monitoring_active = True
        self.collection_stats['start_time'] = datetime.now()
        
        # DVD 컨테이너 확인
        container = await self._get_dvd_container()
        if not container:
            self.logger.error("DVD 컨테이너를 찾을 수 없습니다")
            return False
        
        # 병렬 모니터링 태스크 시작
        tasks = [
            asyncio.create_task(self._monitor_attack_scenarios(container)),
            asyncio.create_task(self._monitor_system_logs(container)),
            asyncio.create_task(self._monitor_network_traffic(container)),
            asyncio.create_task(self._periodic_cti_generation()),
            asyncio.create_task(self._execute_scenario_simulations(container))
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"CTI 수집 오류: {e}")
        finally:
            self.monitoring_active = False
    
    async def _execute_scenario_simulations(self, container):
        """10개 시나리오 시뮬레이션 실행"""
        self.logger.info("📡 10개 공격 시나리오 시뮬레이션 시작")
        
        for scenario_name, scenario_config in self.attack_scenarios.items():
            try:
                self.logger.info(f"시나리오 실행: {scenario_name}")
                
                # 시나리오별 공격 실행
                attack_result = await self._execute_attack_scenario(container, scenario_name, scenario_config)
                
                if attack_result['success']:
                    # 실시간 로그 분석
                    await self._analyze_scenario_logs(container, scenario_name)
                    
                    # CTI 데이터 수집
                    await self._collect_scenario_cti(scenario_name, attack_result)
                
                # 시나리오 간 간격
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"시나리오 {scenario_name} 실행 오류: {e}")
    
    async def _execute_attack_scenario(self, container, scenario_name: str, scenario_config: Dict) -> Dict:
        """개별 공격 시나리오 실행"""
        attack_result = {
            'scenario': scenario_name,
            'success': False,
            'start_time': datetime.now(),
            'artifacts': [],
            'logs': []
        }
        
        try:
            if scenario_name == '1_passive_reconnaissance':
                # 패시브 정찰 시뮬레이션
                attack_result['success'] = await self._simulate_passive_recon(container)
                
            elif scenario_name == '2_communication_disruption':
                # 통신 방해 시뮬레이션
                attack_result['success'] = await self._simulate_comm_disruption(container)
                
            elif scenario_name == '3_companion_compromise':
                # 컴패니언 컴퓨터 침해 시뮬레이션
                attack_result['success'] = await self._simulate_companion_compromise(container)
                
            elif scenario_name == '4_gps_spoofing':
                # GPS 스푸핑 시뮬레이션
                attack_result['success'] = await self._simulate_gps_spoofing(container)
                
            elif scenario_name == '5_mavlink_exploitation':
                # MAVLink 익스플로잇 시뮬레이션
                attack_result['success'] = await self._simulate_mavlink_exploit(container)
                
            elif scenario_name == '6_sensor_deception':
                # 센서 기만 시뮬레이션
                attack_result['success'] = await self._simulate_sensor_deception(container)
                
            elif scenario_name == '7_video_intelligence':
                # 비디오 인텔리전스 시뮬레이션
                attack_result['success'] = await self._simulate_video_intel(container)
                
            elif scenario_name == '8_resource_exhaustion':
                # 리소스 고갈 시뮬레이션
                attack_result['success'] = await self._simulate_resource_exhaustion(container)
                
            elif scenario_name == '9_rth_hijacking':
                # RTH 하이재킹 시뮬레이션
                attack_result['success'] = await self._simulate_rth_hijacking(container)
                
            elif scenario_name == '10_apt_drone_threat':
                # APT 드론 위협 시뮬레이션
                attack_result['success'] = await self._simulate_apt_threat(container)
            
            attack_result['end_time'] = datetime.now()
            attack_result['duration'] = (attack_result['end_time'] - attack_result['start_time']).total_seconds()
            
        except Exception as e:
            self.logger.error(f"시나리오 {scenario_name} 실행 중 오류: {e}")
            attack_result['error'] = str(e)
        
        return attack_result
    
    async def _simulate_passive_recon(self, container) -> bool:
        """패시브 정찰 시뮬레이션"""
        try:
            # 1. 무선 네트워크 스캔 시뮬레이션
            scan_cmd = "echo 'Wireless scan 802.11 networks detected' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, scan_cmd)
            
            # 2. MAVLink 프로토콜 발견 시뮬레이션
            mavlink_cmd = "echo 'MAVLink discovery protocol version 2.0' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, mavlink_cmd)
            
            # 3. GPS 텔레메트리 캡처 시뮬레이션
            gps_cmd = "echo 'GPS telemetry captured: lat=37.7749, lon=-122.4194' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, gps_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"패시브 정찰 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_comm_disruption(self, container) -> bool:
        """통신 방해 시뮬레이션"""
        try:
            # 1. 네트워크 플러딩 시뮬레이션
            flood_cmd = "echo 'Network flooding detected on port 14550' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, flood_cmd)
            
            # 2. 통신 링크 손실 시뮬레이션
            link_cmd = "echo 'Communication link lost to GCS' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, link_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"통신 방해 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_companion_compromise(self, container) -> bool:
        """컴패니언 컴퓨터 침해 시뮬레이션"""
        try:
            # 1. 웹 로그인 시도 시뮬레이션
            login_cmd = "echo 'Web login attempt admin:admin from 192.168.1.100' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, login_cmd)
            
            # 2. SSH 무차별 대입 시뮬레이션
            ssh_cmd = "echo 'SSH brute force detected: 50 attempts' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, ssh_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"컴패니언 침해 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_gps_spoofing(self, container) -> bool:
        """GPS 스푸핑 시뮬레이션"""
        try:
            # 1. GPS 신호 이상 시뮬레이션
            gps_cmd = "echo 'GPS invalid position detected: lat=0.0, lon=0.0' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, gps_cmd)
            
            # 2. EKF GPS 품질 저하 시뮬레이션
            ekf_cmd = "echo 'EKF2 IMU1: GPS quality poor, satellites=2' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, ekf_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"GPS 스푸핑 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_mavlink_exploit(self, container) -> bool:
        """MAVLink 익스플로잇 시뮬레이션"""
        try:
            # 1. MAVLink 명령 주입 시뮬레이션
            inject_cmd = "echo 'MAVLink injection detected: COMMAND_LONG id=21' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, inject_cmd)
            
            # 2. 비행 모드 변경 시뮬레이션
            mode_cmd = "echo 'Flight mode changed unexpected: LAND->RTL' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, mode_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"MAVLink 익스플로잇 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_sensor_deception(self, container) -> bool:
        """센서 기만 시뮬레이션"""
        try:
            # 1. 배터리 상태 이상 시뮬레이션
            battery_cmd = "echo 'Battery status anomaly: 100% -> 5% sudden drop' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, battery_cmd)
            
            # 2. 응급 착륙 트리거 시뮬레이션
            emergency_cmd = "echo 'Emergency landing triggered by fake critical error' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, emergency_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"센서 기만 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_video_intel(self, container) -> bool:
        """비디오 인텔리전스 시뮬레이션"""
        try:
            # 1. 비디오 스트림 가로채기 시뮬레이션
            video_cmd = "echo 'Video stream intercepted: rtsp://192.168.1.2:8554/stream' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, video_cmd)
            
            # 2. 카메라 피드 캡처 시뮬레이션
            camera_cmd = "echo 'Camera feed captured: 1920x1080 30fps' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, camera_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"비디오 인텔리전스 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_resource_exhaustion(self, container) -> bool:
        """리소스 고갈 시뮬레이션"""
        try:
            # 1. ROS 토픽 플러딩 시뮬레이션
            ros_cmd = "echo 'ROS topic flooding detected: /camera/image_raw' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, ros_cmd)
            
            # 2. 시스템 리소스 고갈 시뮬레이션
            resource_cmd = "echo 'System resources exhausted: CPU=98%, Memory=95%' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, resource_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"리소스 고갈 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_rth_hijacking(self, container) -> bool:
        """RTH 하이재킹 시뮬레이션"""
        try:
            # 1. 홈 포지션 변경 시뮬레이션
            home_cmd = "echo 'Return home coordinates changed: (37.7749,-122.4194) -> (40.7128,-74.0060)' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, home_cmd)
            
            # 2. 지오펜스 경계 수정 시뮬레이션
            fence_cmd = "echo 'Geofence boundary modified: radius 500m -> 5000m' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, fence_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"RTH 하이재킹 시뮬레이션 오류: {e}")
            return False
    
    async def _simulate_apt_threat(self, container) -> bool:
        """APT 드론 위협 시뮬레이션"""
        try:
            # 1. 다중 벡터 공격 시뮬레이션
            apt_cmd = "echo 'Multi vector attack detected: GPS+MAVLink+Battery spoofing' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, apt_cmd)
            
            # 2. 지속적 위협 식별 시뮬레이션
            persist_cmd = "echo 'Persistent threat identified: stealth mode active' >> /var/log/attack_simulation.log"
            await self._execute_container_command(container, persist_cmd)
            
            return True
        except Exception as e:
            self.logger.error(f"APT 위협 시뮬레이션 오류: {e}")
            return False
    
    async def _execute_container_command(self, container, command: str):
        """컨테이너 내부 명령 실행"""
        try:
            exec_result = container.exec_run(f'/bin/bash -c "{command}"')
            return exec_result.exit_code == 0
        except Exception as e:
            self.logger.error(f"컨테이너 명령 실행 오류: {e}")
            return False
    
    async def _monitor_attack_scenarios(self, container):
        """공격 시나리오 모니터링"""
        while self.monitoring_active:
            try:
                # 공격 시뮬레이션 로그 확인
                exec_result = container.exec_run('cat /var/log/attack_simulation.log')
                
                if exec_result.exit_code == 0:
                    log_content = exec_result.output.decode()
                    await self._analyze_attack_logs(log_content)
                
                await asyncio.sleep(5)
                
            except Exception as e:
                self.logger.debug(f"시나리오 모니터링 오류: {e}")
                await asyncio.sleep(10)
    
    async def _analyze_attack_logs(self, log_content: str):
        """공격 로그 분석"""
        for scenario_name, scenario_config in self.attack_scenarios.items():
            for pattern in scenario_config['log_patterns']:
                matches = re.finditer(pattern, log_content, re.MULTILINE | re.IGNORECASE)
                
                for match in matches:
                    await self._process_scenario_detection(scenario_name, match.group(), scenario_config)
    
    async def _process_scenario_detection(self, scenario_name: str, log_line: str, scenario_config: Dict):
        """시나리오 탐지 처리"""
        try:
            attack_log = EnhancedDVDAttackLog(
                timestamp=datetime.now(),
                attack_scenario=scenario_name,
                attack_type=scenario_config['category'],
                mitre_techniques=scenario_config['mitre_techniques'],
                source_ip=self._extract_source_ip(log_line),
                target_component='drone_system',
                attack_vector='simulation',
                payload={'log_line': log_line},
                success=True,
                detection_status='detected',
                severity=scenario_config['severity'],
                raw_log=log_line,
                evidence_artifacts={}
            )
            
            # CTI 레포트에 추가
            await self._add_to_cti_report(attack_log)
            
            self.collection_stats['scenarios_detected'] += 1
            self.logger.info(f"시나리오 탐지: {scenario_name}")
            
        except Exception as e:
            self.logger.error(f"시나리오 탐지 처리 오류: {e}")
    
    async def _add_to_cti_report(self, attack_log: EnhancedDVDAttackLog):
        """CTI 레포트에 공격 로그 추가"""
        scenario_name = attack_log.attack_scenario
        
        # 기존 레포트 찾기 또는 새로 생성
        existing_report = None
        for report in self.collected_cti:
            if report.attack_scenario == scenario_name:
                existing_report = report
                break
        
        if not existing_report:
            # 새 CTI 레포트 생성
            mitre_mappings = []
            for tech_id in attack_log.mitre_techniques:
                mitre_mappings.append(MITREMapping(
                    technique_id=tech_id,
                    technique_name=self._get_mitre_technique_name(tech_id),
                    tactic=self._get_mitre_tactic(tech_id),
                    attack_phase=self._get_attack_phase(tech_id),
                    confidence=0.8
                ))
            
            new_report = CTIReport(
                id=f"cti_{scenario_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                attack_scenario=scenario_name,
                mitre_mappings=mitre_mappings,
                iocs=[],
                attack_timeline=[attack_log],
                threat_assessment={}
            )
            
            self.collected_cti.append(new_report)
            self.collection_stats['cti_generated'] += 1
        else:
            # 기존 레포트에 추가
            existing_report.attack_timeline.append(attack_log)
    
    async def _generate_comprehensive_cti_report(self) -> Dict[str, Any]:
        """종합 CTI 레포트 생성"""
        report = {
            'collection_summary': {
                'total_scenarios': len(self.attack_scenarios),
                'detected_scenarios': self.collection_stats['scenarios_detected'],
                'cti_reports_generated': len(self.collected_cti),
                'collection_period': {
                    'start': self.collection_stats.get('start_time', datetime.now()).isoformat(),
                    'end': datetime.now().isoformat()
                }
            },
            'scenario_analysis': {},
            'mitre_coverage': {},
            'threat_landscape': {},
            'stix_bundles': []
        }
        
        # 시나리오별 분석
        for scenario_name in self.attack_scenarios.keys():
            scenario_reports = [r for r in self.collected_cti if r.attack_scenario == scenario_name]
            
            if scenario_reports:
                report['scenario_analysis'][scenario_name] = {
                    'detection_count': len(scenario_reports),
                    'total_events': sum(len(r.attack_timeline) for r in scenario_reports),
                    'severity_average': sum(
                        sum(log.severity for log in r.attack_timeline) / len(r.attack_timeline)
                        for r in scenario_reports
                    ) / len(scenario_reports),
                    'mitre_techniques': list(set(
                        tech for r in scenario_reports for tech in r.attack_timeline[0].mitre_techniques
                    ))
                }
        
        # MITRE 커버리지 분석
        all_techniques = set()
        for report_item in self.collected_cti:
            for log in report_item.attack_timeline:
                all_techniques.update(log.mitre_techniques)
        
        report['mitre_coverage'] = {
            'total_techniques_covered': len(all_techniques),
            'techniques_list': list(all_techniques),
            'tactic_distribution': self._analyze_tactic_distribution(all_techniques)
        }
        
        # STIX 번들 생성
        for cti_report in self.collected_cti:
            stix_bundle = await self._generate_stix_bundle(cti_report)
            if stix_bundle:
                report['stix_bundles'].append({
                    'scenario': cti_report.attack_scenario,
                    'bundle_id': stix_bundle.get('id'),
                    'objects_count': len(stix_bundle.get('objects', []))
                })
                
                # CTI 레포트에 STIX 번들 저장
                cti_report.stix_bundle = json.dumps(stix_bundle, indent=2)
        
        return report
    
    async def _generate_stix_bundle(self, cti_report: CTIReport) -> Optional[Dict]:
        """STIX 번들 생성"""
        try:
            stix_data = {
                'attack_scenario': cti_report.attack_scenario,
                'mitre_techniques': [m.technique_id for m in cti_report.mitre_mappings],
                'timeline': [asdict(log) for log in cti_report.attack_timeline],
                'iocs': cti_report.iocs
            }
            
            stix_bundle = self.stix_generator.create_stix_bundle(stix_data)
            self.collection_stats['stix_reports'] += 1
            
            return stix_bundle
            
        except Exception as e:
            self.logger.error(f"STIX 번들 생성 오류: {e}")
            return None
    
    def _get_mitre_technique_name(self, technique_id: str) -> str:
        """MITRE 기법 이름 반환"""
        technique_names = {
            'T1595.002': 'Active Scanning: Vulnerability Scanning',
            'T1040': 'Network Sniffing',
            'T1056.001': 'Input Capture: Keylogging',
            'T1018': 'Remote System Discovery',
            'T1498.001': 'Network Denial of Service: Direct Network Flood',
            'T1489': 'Service Stop',
            'T1110.001': 'Brute Force: Password Guessing',
            'T1059.004': 'Command and Scripting Interpreter: Unix Shell',
            'T1200': 'Hardware Additions',
            'T1491.002': 'Defacement: External Defacement',
            'T1565.002': 'Data Manipulation: Transmitted Data Manipulation',
            'T1071.004': 'Application Layer Protocol: DNS',
            'T1565.001': 'Data Manipulation: Stored Data Manipulation',
            'T1113': 'Screen Capture',
            'T1041': 'Exfiltration Over C2 Channel',
            'T1005': 'Data from Local System',
            'T1498.002': 'Network Denial of Service: Reflection Amplification',
            'T1499.004': 'Endpoint Denial of Service: Application or System Exploitation',
            'T1491.001': 'Defacement: Internal Defacement',
            'T1485': 'Data Destruction'
        }
        return technique_names.get(technique_id, technique_id)
    
    def _get_mitre_tactic(self, technique_id: str) -> str:
        """MITRE 전술 반환"""
        tactic_mapping = {
            'T1595.002': 'Reconnaissance',
            'T1040': 'Discovery',
            'T1056.001': 'Collection',
            'T1018': 'Discovery',
            'T1498.001': 'Impact',
            'T1489': 'Impact',
            'T1110.001': 'Credential Access',
            'T1059.004': 'Execution',
            'T1200': 'Initial Access',
            'T1491.002': 'Impact',
            'T1565.002': 'Impact',
            'T1071.004': 'Command and Control',
            'T1565.001': 'Impact',
            'T1113': 'Collection',
            'T1041': 'Exfiltration',
            'T1005': 'Collection',
            'T1498.002': 'Impact',
            'T1499.004': 'Impact',
            'T1491.001': 'Impact',
            'T1485': 'Impact'
        }
        return tactic_mapping.get(technique_id, 'Unknown')
    
    def _get_attack_phase(self, technique_id: str) -> str:
        """공격 단계 반환"""
        if technique_id in ['T1595.002', 'T1040', 'T1056.001']:
            return 'reconnaissance'
        elif technique_id in ['T1018', 'T1110.001']:
            return 'initial_access'
        elif technique_id in ['T1059.004', 'T1071.004']:
            return 'execution'
        elif technique_id in ['T1200', 'T1565.002', 'T1565.001']:
            return 'persistence'
        else:
            return 'impact'
    
    def _analyze_tactic_distribution(self, techniques: set) -> Dict[str, int]:
        """전술 분포 분석"""
        tactics = {}
        for tech in techniques:
            tactic = self._get_mitre_tactic(tech)
            tactics[tactic] = tactics.get(tactic, 0) + 1
        return tactics
    
    def _extract_source_ip(self, log_line: str) -> str:
        """로그에서 소스 IP 추출"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, log_line)
        return matches[0] if matches else 'simulation'
    
    async def _get_dvd_container(self):
        """DVD 컨테이너 조회"""
        try:
            return self.docker_client.containers.get(self.dvd_container_name)
        except Exception as e:
            self.logger.error(f"DVD 컨테이너 조회 오류: {e}")
            return None
    
    async def _monitor_system_logs(self, container):
        """시스템 로그 모니터링"""
        # 기존 구현 유지
        pass
    
    async def _monitor_network_traffic(self, container):
        """네트워크 트래픽 모니터링"""
        # 기존 구현 유지
        pass
    
    async def _periodic_cti_generation(self):
        """주기적 CTI 생성"""
        while self.monitoring_active:
            try:
                await asyncio.sleep(300)  # 5분마다
                await self._update_cti_reports()
            except Exception as e:
                self.logger.error(f"주기적 CTI 생성 오류: {e}")
    
    async def _update_cti_reports(self):
        """CTI 레포트 업데이트"""
        # CTI 레포트 정리 및 업데이트 로직
        pass

# 사용 예제
async def main():
    """Enhanced DVD CTI 수집기 실행 예제"""
    config = {
        'dvd_container': 'damn-vulnerable-drone',
        'log_directory': './enhanced_dvd_cti_logs',
        'collection_interval': 5,
        'analysis_interval': 300
    }
    
    collector = Enhanced10ScenarioDVDCTICollector(config)
    
    try:
        print("=== DVD 10개 공격 시나리오 CTI 자동 수집 시작 ===")
        await collector.start_comprehensive_collection()
        
        # 최종 레포트 생성
        final_report = await collector._generate_comprehensive_cti_report()
        
        print("=== CTI 수집 완료 - 최종 리포트 ===")
        print(json.dumps(final_report, indent=2, default=str))
        
    except KeyboardInterrupt:
        print("수집 중지 요청됨")
    finally:
        collector.monitoring_active = False
        print("DVD CTI 수집 완료")

if __name__ == "__main__":
    asyncio.run(main())