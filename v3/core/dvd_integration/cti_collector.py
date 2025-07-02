# DVD (Damn Vulnerable Drone) 기반 CTI 자동 수집 시스템
# core/dvd_integration/cti_collector.py

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

@dataclass
class DVDAttackLog:
    timestamp: datetime
    attack_type: str
    source_ip: str
    target_component: str
    attack_vector: str
    payload: Dict[str, Any]
    success: bool
    detection_status: str
    severity: int
    raw_log: str

@dataclass
class DVDSystemEvent:
    timestamp: datetime
    event_type: str
    component: str
    details: Dict[str, Any]
    criticality: str

@dataclass
class CollectedCTI:
    id: str
    attack_scenario: str
    mitre_techniques: List[str]
    iocs: List[Dict[str, Any]]
    attack_timeline: List[DVDAttackLog]
    system_events: List[DVDSystemEvent]
    evidence_artifacts: Dict[str, Any]
    threat_assessment: Dict[str, Any]
    created_at: datetime

class DVDCTICollector:
    """DVD 환경에서 CTI 자동 수집 시스템"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # DVD 환경 설정
        self.dvd_container_name = config.get('dvd_container', 'damn-vulnerable-drone')
        self.docker_client = docker.from_env()
        
        # 로그 수집 경로
        self.log_paths = {
            'ardupilot': '/opt/ardupilot/logs',
            'companion': '/home/ubuntu/companion_logs',
            'mavproxy': '/home/ubuntu/.mavproxy',
            'network': '/var/log/wireshark',
            'system': '/var/log'
        }
        
        # CTI 데이터베이스
        self.collected_cti: List[CollectedCTI] = []
        self.active_attacks: Dict[str, Dict] = {}
        
        # 공격 패턴 매칭
        self.attack_patterns = self._initialize_attack_patterns()
        
        # 실시간 모니터링 상태
        self.monitoring_active = False
        self.collection_stats = {
            'total_events': 0,
            'attacks_detected': 0,
            'cti_generated': 0,
            'false_positives': 0
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, Dict]:
        """DVD 공격 패턴 정의"""
        return {
            'gps_spoofing': {
                'log_patterns': [
                    r'GPS: Invalid position.*lat.*lon.*',
                    r'GPS_RAW_INT.*satellites_visible: (\d+)',
                    r'EKF2 IMU\d: GPS quality poor'
                ],
                'network_patterns': [
                    r'GPS.*NMEA.*\$GP(GGA|RMC|GSA)',
                    r'mavlink.*GPS_RAW_INT.*lat: (-?\d+\.\d+)'
                ],
                'mitre_techniques': ['T1200', 'T1565.002'],
                'severity': 5
            },
            'mavlink_injection': {
                'log_patterns': [
                    r'MAVLink.*COMMAND_LONG.*command: (\d+)',
                    r'Mode change to.*AUTO|GUIDED|LAND',
                    r'Armed: (True|False)',
                    r'Mission item.*waypoint'
                ],
                'network_patterns': [
                    r'mavlink.*COMMAND_LONG.*',
                    r'mavlink.*SET_POSITION_TARGET.*',
                    r'mavlink.*MISSION_ITEM.*'
                ],
                'mitre_techniques': ['T1071.004', 'T1565.001'],
                'severity': 5
            },
            'wifi_deauth': {
                'log_patterns': [
                    r'wlan.*deauthenticated.*',
                    r'NetworkManager.*disconnected.*',
                    r'Link quality.*Signal level.*'
                ],
                'network_patterns': [
                    r'IEEE 802\.11.*Deauthentication',
                    r'wlan.*CTRL-EVENT-DISCONNECTED'
                ],
                'mitre_techniques': ['T1498.001', 'T1489'],
                'severity': 3
            },
            'battery_spoofing': {
                'log_patterns': [
                    r'BATTERY_STATUS.*voltage: (\d+).*remaining: (\d+)',
                    r'Power.*Battery.*critical',
                    r'Low battery.*landing'
                ],
                'network_patterns': [
                    r'mavlink.*BATTERY_STATUS.*'
                ],
                'mitre_techniques': ['T1565.002'],
                'severity': 4
            },
            'camera_hijack': {
                'log_patterns': [
                    r'gstreamer.*pipeline.*error',
                    r'v4l2.*device.*busy',
                    r'camera.*stream.*unauthorized'
                ],
                'network_patterns': [
                    r'RTSP.*unauthorized.*',
                    r'HTTP.*camera.*access.*denied'
                ],
                'mitre_techniques': ['T1113', 'T1041'],
                'severity': 3
            },
            'companion_compromise': {
                'log_patterns': [
                    r'sshd.*authentication failure.*',
                    r'sudo.*authentication failure.*',
                    r'login.*authentication failure.*',
                    r'Failed password.*'
                ],
                'network_patterns': [
                    r'SSH.*login.*attempt.*',
                    r'HTTP.*brute.*force.*'
                ],
                'mitre_techniques': ['T1110.001', 'T1059.004'],
                'severity': 5
            }
        }
    
    async def start_collection(self):
        """CTI 수집 시작"""
        self.logger.info("DVD CTI 수집 시작")
        self.monitoring_active = True
        
        # DVD 컨테이너 상태 확인
        await self._verify_dvd_environment()
        
        # 로그 디렉토리 생성
        await self._setup_log_directories()
        
        # 실시간 모니터링 태스크들 시작
        tasks = [
            self._monitor_system_logs(),
            self._monitor_network_traffic(),
            self._monitor_mavlink_messages(),
            self._monitor_file_system_changes(),
            self._periodic_cti_analysis()
        ]
        
        await asyncio.gather(*tasks)
    
    async def stop_collection(self):
        """CTI 수집 중지"""
        self.logger.info("DVD CTI 수집 중지")
        self.monitoring_active = False
        
        # 최종 CTI 리포트 생성
        final_report = await self._generate_final_report()
        await self._save_cti_report(final_report)
    
    async def _verify_dvd_environment(self):
        """DVD 환경 검증"""
        try:
            container = self.docker_client.containers.get(self.dvd_container_name)
            if container.status != 'running':
                container.start()
                await asyncio.sleep(5)  # 컨테이너 시작 대기
            
            # ArduPilot SITL 상태 확인
            exec_result = container.exec_run('pgrep -f "arducopter.py"')
            if exec_result.exit_code != 0:
                self.logger.warning("ArduPilot SITL이 실행되지 않음")
                await self._start_ardupilot_sitl(container)
            
            self.logger.info("DVD 환경 검증 완료")
            
        except docker.errors.NotFound:
            raise RuntimeError(f"DVD 컨테이너 '{self.dvd_container_name}'를 찾을 수 없음")
    
    async def _setup_log_directories(self):
        """로그 디렉토리 설정"""
        log_dir = Path(self.config.get('log_directory', './dvd_logs'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        for log_type in ['attacks', 'system', 'network', 'mavlink', 'cti']:
            (log_dir / log_type).mkdir(exist_ok=True)
    
    async def _monitor_system_logs(self):
        """시스템 로그 실시간 모니터링"""
        while self.monitoring_active:
            try:
                container = self.docker_client.containers.get(self.dvd_container_name)
                
                # 시스템 로그 수집
                for log_type, path in self.log_paths.items():
                    await self._collect_log_files(container, log_type, path)
                
                await asyncio.sleep(5)  # 5초마다 수집
                
            except Exception as e:
                self.logger.error(f"시스템 로그 모니터링 오류: {e}")
                await asyncio.sleep(10)
    
    async def _collect_log_files(self, container, log_type: str, path: str):
        """특정 경로의 로그 파일 수집"""
        try:
            # 컨테이너 내부 로그 파일 목록 조회
            exec_result = container.exec_run(f'find {path} -name "*.log" -type f -newermt "1 minute ago"')
            
            if exec_result.exit_code == 0:
                log_files = exec_result.output.decode().strip().split('\n')
                
                for log_file in log_files:
                    if log_file:
                        await self._analyze_log_file(container, log_file, log_type)
        
        except Exception as e:
            self.logger.debug(f"로그 수집 오류 ({log_type}): {e}")
    
    async def _analyze_log_file(self, container, log_file: str, log_type: str):
        """개별 로그 파일 분석"""
        try:
            # 로그 파일 내용 읽기
            exec_result = container.exec_run(f'tail -n 50 {log_file}')
            
            if exec_result.exit_code == 0:
                log_content = exec_result.output.decode()
                
                # 공격 패턴 매칭
                detected_attacks = await self._match_attack_patterns(log_content, log_type)
                
                for attack in detected_attacks:
                    await self._process_detected_attack(attack)
        
        except Exception as e:
            self.logger.debug(f"로그 파일 분석 오류: {e}")
    
    async def _match_attack_patterns(self, log_content: str, log_type: str) -> List[Dict]:
        """로그에서 공격 패턴 매칭"""
        detected_attacks = []
        
        for attack_type, patterns in self.attack_patterns.items():
            log_patterns = patterns.get('log_patterns', [])
            
            for pattern in log_patterns:
                matches = re.finditer(pattern, log_content, re.MULTILINE | re.IGNORECASE)
                
                for match in matches:
                    attack_log = DVDAttackLog(
                        timestamp=datetime.now(),
                        attack_type=attack_type,
                        source_ip=self._extract_source_ip(log_content),
                        target_component=log_type,
                        attack_vector=f"log_pattern_{pattern}",
                        payload={"matched_text": match.group(), "pattern": pattern},
                        success=True,  # 로그에 기록된 것은 성공한 것으로 간주
                        detection_status="detected",
                        severity=patterns['severity'],
                        raw_log=log_content
                    )
                    
                    detected_attacks.append(attack_log)
        
        return detected_attacks
    
    async def _monitor_network_traffic(self):
        """네트워크 트래픽 실시간 모니터링"""
        while self.monitoring_active:
            try:
                # Wireshark/tshark를 사용한 패킷 캡처
                await self._capture_network_packets()
                await asyncio.sleep(10)  # 10초마다 분석
                
            except Exception as e:
                self.logger.error(f"네트워크 모니터링 오류: {e}")
                await asyncio.sleep(30)
    
    async def _capture_network_packets(self):
        """네트워크 패킷 캡처 및 분석"""
        try:
            container = self.docker_client.containers.get(self.dvd_container_name)
            
            # tshark를 사용한 MAVLink 패킷 캡처
            cmd = 'tshark -i any -f "udp port 14550" -c 100 -T json'
            exec_result = container.exec_run(cmd, stream=False)
            
            if exec_result.exit_code == 0:
                packets = json.loads(exec_result.output.decode())
                await self._analyze_captured_packets(packets)
        
        except Exception as e:
            self.logger.debug(f"패킷 캡처 오류: {e}")
    
    async def _analyze_captured_packets(self, packets: List[Dict]):
        """캡처된 패킷 분석"""
        for packet in packets:
            try:
                # MAVLink 메시지 추출
                if 'mavlink' in str(packet).lower():
                    await self._analyze_mavlink_packet(packet)
                
                # 기타 의심스러운 트래픽 분석
                await self._analyze_suspicious_traffic(packet)
                
            except Exception as e:
                self.logger.debug(f"패킷 분석 오류: {e}")
    
    async def _monitor_mavlink_messages(self):
        """MAVLink 메시지 실시간 모니터링"""
        while self.monitoring_active:
            try:
                container = self.docker_client.containers.get(self.dvd_container_name)
                
                # MAVProxy 로그 모니터링
                mavproxy_log = f"{self.log_paths['mavproxy']}/mav.log"
                exec_result = container.exec_run(f'tail -f -n 10 {mavproxy_log}')
                
                if exec_result.exit_code == 0:
                    messages = exec_result.output.decode().split('\n')
                    
                    for message in messages:
                        if message.strip():
                            await self._analyze_mavlink_message(message)
                
                await asyncio.sleep(2)
                
            except Exception as e:
                self.logger.debug(f"MAVLink 모니터링 오류: {e}")
                await asyncio.sleep(10)
    
    async def _analyze_mavlink_message(self, message: str):
        """MAVLink 메시지 분석"""
        try:
            # 의심스러운 명령 탐지
            suspicious_commands = [
                'COMMAND_LONG', 'SET_POSITION_TARGET', 'MISSION_ITEM',
                'SET_MODE', 'COMPONENT_ARM_DISARM'
            ]
            
            for cmd in suspicious_commands:
                if cmd in message:
                    attack_log = DVDAttackLog(
                        timestamp=datetime.now(),
                        attack_type='mavlink_injection',
                        source_ip=self._extract_ip_from_message(message),
                        target_component='autopilot',
                        attack_vector=f'mavlink_{cmd}',
                        payload={'command': cmd, 'message': message},
                        success=True,
                        detection_status='detected',
                        severity=4,
                        raw_log=message
                    )
                    
                    await self._process_detected_attack(attack_log)
        
        except Exception as e:
            self.logger.debug(f"MAVLink 메시지 분석 오류: {e}")
    
    async def _monitor_file_system_changes(self):
        """파일 시스템 변경 모니터링"""
        while self.monitoring_active:
            try:
                container = self.docker_client.containers.get(self.dvd_container_name)
                
                # inotify를 사용한 파일 변경 감지
                critical_paths = [
                    '/etc/passwd', '/etc/shadow', '/home/ubuntu/.ssh',
                    '/opt/ardupilot', '/usr/bin', '/etc/systemd'
                ]
                
                for path in critical_paths:
                    await self._check_file_changes(container, path)
                
                await asyncio.sleep(30)  # 30초마다 체크
                
            except Exception as e:
                self.logger.debug(f"파일 시스템 모니터링 오류: {e}")
                await asyncio.sleep(60)
    
    async def _check_file_changes(self, container, path: str):
        """특정 경로의 파일 변경 확인"""
        try:
            # 파일 수정 시간 확인
            cmd = f'find {path} -type f -mmin -30'  # 30분 내 수정된 파일
            exec_result = container.exec_run(cmd)
            
            if exec_result.exit_code == 0:
                changed_files = exec_result.output.decode().strip().split('\n')
                
                for file_path in changed_files:
                    if file_path:
                        await self._analyze_file_change(file_path)
        
        except Exception as e:
            self.logger.debug(f"파일 변경 확인 오류: {e}")
    
    async def _process_detected_attack(self, attack_log: DVDAttackLog):
        """탐지된 공격 처리"""
        try:
            self.collection_stats['attacks_detected'] += 1
            
            # 활성 공격 추적
            attack_id = f"{attack_log.attack_type}_{attack_log.timestamp.strftime('%Y%m%d_%H%M%S')}"
            
            if attack_id not in self.active_attacks:
                self.active_attacks[attack_id] = {
                    'start_time': attack_log.timestamp,
                    'attack_type': attack_log.attack_type,
                    'events': [],
                    'evidence': []
                }
            
            self.active_attacks[attack_id]['events'].append(attack_log)
            
            # CTI 생성 조건 확인
            if len(self.active_attacks[attack_id]['events']) >= 3:
                await self._generate_cti_from_attack(attack_id)
            
            self.logger.info(f"공격 탐지: {attack_log.attack_type} from {attack_log.source_ip}")
            
        except Exception as e:
            self.logger.error(f"공격 처리 오류: {e}")
    
    async def _generate_cti_from_attack(self, attack_id: str):
        """공격으로부터 CTI 생성"""
        try:
            attack_data = self.active_attacks[attack_id]
            attack_events = attack_data['events']
            
            if not attack_events:
                return
            
            # IOC 추출
            iocs = await self._extract_iocs(attack_events)
            
            # MITRE 기법 매핑
            mitre_techniques = self._get_mitre_techniques(attack_events[0].attack_type)
            
            # 공격 타임라인 구성
            timeline = sorted(attack_events, key=lambda x: x.timestamp)
            
            # 위협 평가
            threat_assessment = await self._assess_threat_level(attack_events)
            
            # 증거 수집
            evidence = await self._collect_evidence_artifacts(attack_events)
            
            # CTI 객체 생성
            cti = CollectedCTI(
                id=f"dvd_cti_{attack_id}",
                attack_scenario=attack_events[0].attack_type,
                mitre_techniques=mitre_techniques,
                iocs=iocs,
                attack_timeline=timeline,
                system_events=[],  # 필요시 시스템 이벤트 추가
                evidence_artifacts=evidence,
                threat_assessment=threat_assessment,
                created_at=datetime.now()
            )
            
            self.collected_cti.append(cti)
            self.collection_stats['cti_generated'] += 1
            
            # CTI 저장
            await self._save_cti_data(cti)
            
            self.logger.info(f"CTI 생성 완료: {cti.id}")
            
        except Exception as e:
            self.logger.error(f"CTI 생성 오류: {e}")
    
    async def _extract_iocs(self, attack_events: List[DVDAttackLog]) -> List[Dict[str, Any]]:
        """공격 이벤트에서 IOC 추출"""
        iocs = []
        
        for event in attack_events:
            # IP 주소 IOC
            if event.source_ip and event.source_ip != 'unknown':
                iocs.append({
                    'type': 'ip',
                    'value': event.source_ip,
                    'confidence': 0.8,
                    'first_seen': event.timestamp.isoformat(),
                    'context': f"Source of {event.attack_type} attack"
                })
            
            # 페이로드 IOC
            if event.payload:
                for key, value in event.payload.items():
                    if isinstance(value, str) and len(value) > 5:
                        iocs.append({
                            'type': 'command',
                            'value': value,
                            'confidence': 0.7,
                            'first_seen': event.timestamp.isoformat(),
                            'context': f"Attack payload: {key}"
                        })
        
        return iocs
    
    def _get_mitre_techniques(self, attack_type: str) -> List[str]:
        """공격 유형에 대한 MITRE 기법 반환"""
        return self.attack_patterns.get(attack_type, {}).get('mitre_techniques', [])
    
    async def _assess_threat_level(self, attack_events: List[DVDAttackLog]) -> Dict[str, Any]:
        """위협 수준 평가"""
        max_severity = max(event.severity for event in attack_events)
        attack_frequency = len(attack_events)
        unique_sources = len(set(event.source_ip for event in attack_events))
        
        threat_level = min(5, max_severity + (attack_frequency // 10) + (unique_sources // 3))
        
        return {
            'threat_level': threat_level,
            'severity_score': max_severity,
            'attack_frequency': attack_frequency,
            'unique_sources': unique_sources,
            'assessment_time': datetime.now().isoformat(),
            'risk_factors': self._identify_risk_factors(attack_events)
        }
    
    def _identify_risk_factors(self, attack_events: List[DVDAttackLog]) -> List[str]:
        """위험 요소 식별"""
        factors = []
        
        # 고심각도 공격
        if any(event.severity >= 4 for event in attack_events):
            factors.append("high_severity_attack")
        
        # 다중 벡터 공격
        attack_types = set(event.attack_type for event in attack_events)
        if len(attack_types) > 1:
            factors.append("multi_vector_attack")
        
        # 지속적 공격
        time_span = max(event.timestamp for event in attack_events) - min(event.timestamp for event in attack_events)
        if time_span.total_seconds() > 300:  # 5분 이상
            factors.append("persistent_attack")
        
        return factors
    
    async def _collect_evidence_artifacts(self, attack_events: List[DVDAttackLog]) -> Dict[str, Any]:
        """증거 아티팩트 수집"""
        artifacts = {
            'log_samples': [],
            'network_captures': [],
            'file_changes': [],
            'system_snapshots': []
        }
        
        try:
            container = self.docker_client.containers.get(self.dvd_container_name)
            
            # 로그 샘플 수집
            for event in attack_events[:5]:  # 최대 5개 이벤트
                artifacts['log_samples'].append({
                    'timestamp': event.timestamp.isoformat(),
                    'type': event.attack_type,
                    'content': event.raw_log[:500]  # 최대 500자
                })
            
            # 시스템 스냅샷
            snapshot = await self._capture_system_snapshot(container)
            artifacts['system_snapshots'].append(snapshot)
            
        except Exception as e:
            self.logger.debug(f"증거 수집 오류: {e}")
        
        return artifacts
    
    async def _capture_system_snapshot(self, container) -> Dict[str, Any]:
        """시스템 스냅샷 캡처"""
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'processes': [],
            'network_connections': [],
            'file_permissions': []
        }
        
        try:
            # 실행 중인 프로세스
            exec_result = container.exec_run('ps aux')
            if exec_result.exit_code == 0:
                snapshot['processes'] = exec_result.output.decode().split('\n')[:20]
            
            # 네트워크 연결
            exec_result = container.exec_run('netstat -tuln')
            if exec_result.exit_code == 0:
                snapshot['network_connections'] = exec_result.output.decode().split('\n')[:20]
        
        except Exception as e:
            self.logger.debug(f"스냅샷 캡처 오류: {e}")
        
        return snapshot
    
    async def _periodic_cti_analysis(self):
        """주기적 CTI 분석"""
        while self.monitoring_active:
            try:
                # 1시간마다 종합 분석
                await self._analyze_attack_patterns()
                await self._update_threat_landscape()
                await self._cleanup_old_data()
                
                await asyncio.sleep(3600)  # 1시간 대기
                
            except Exception as e:
                self.logger.error(f"주기적 분석 오류: {e}")
                await asyncio.sleep(1800)  # 30분 후 재시도
    
    async def _analyze_attack_patterns(self):
        """공격 패턴 분석"""
        try:
            # 최근 24시간 공격 분석
            cutoff_time = datetime.now() - timedelta(hours=24)
            recent_attacks = [
                attack for attack_id, attack in self.active_attacks.items()
                if attack['start_time'] >= cutoff_time
            ]
            
            if recent_attacks:
                # 공격 트렌드 분석
                attack_types = {}
                for attack in recent_attacks:
                    attack_type = attack['attack_type']
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                self.logger.info(f"24시간 공격 트렌드: {attack_types}")
        
        except Exception as e:
            self.logger.error(f"패턴 분석 오류: {e}")
    
    async def _save_cti_data(self, cti: CollectedCTI):
        """CTI 데이터 저장"""
        try:
            log_dir = Path(self.config.get('log_directory', './dvd_logs'))
            cti_file = log_dir / 'cti' / f"{cti.id}.json"
            
            with open(cti_file, 'w') as f:
                json.dump(asdict(cti), f, indent=2, default=str)
            
            self.logger.info(f"CTI 저장됨: {cti_file}")
            
        except Exception as e:
            self.logger.error(f"CTI 저장 오류: {e}")
    
    async def _generate_final_report(self) -> Dict[str, Any]:
        """최종 CTI 리포트 생성"""
        return {
            'collection_period': {
                'start': self.collection_stats.get('start_time', datetime.now()).isoformat(),
                'end': datetime.now().isoformat()
            },
            'statistics': self.collection_stats,
            'total_cti_collected': len(self.collected_cti),
            'attack_summary': self._summarize_attacks(),
            'threat_landscape': self._analyze_threat_landscape(),
            'recommendations': self._generate_recommendations()
        }
    
    def _summarize_attacks(self) -> Dict[str, Any]:
        """공격 요약"""
        attack_summary = {}
        
        for cti in self.collected_cti:
            attack_type = cti.attack_scenario
            if attack_type not in attack_summary:
                attack_summary[attack_type] = {
                    'count': 0,
                    'total_events': 0,
                    'unique_sources': set(),
                    'severity_levels': []
                }
            
            attack_summary[attack_type]['count'] += 1
            attack_summary[attack_type]['total_events'] += len(cti.attack_timeline)
            
            for event in cti.attack_timeline:
                attack_summary[attack_type]['unique_sources'].add(event.source_ip)
                attack_summary[attack_type]['severity_levels'].append(event.severity)
        
        # set을 list로 변환 (JSON 직렬화용)
        for attack_type in attack_summary:
            attack_summary[attack_type]['unique_sources'] = len(attack_summary[attack_type]['unique_sources'])
            attack_summary[attack_type]['avg_severity'] = (
                sum(attack_summary[attack_type]['severity_levels']) / 
                len(attack_summary[attack_type]['severity_levels'])
                if attack_summary[attack_type]['severity_levels'] else 0
            )
        
        return attack_summary
    
    def _extract_source_ip(self, log_content: str) -> str:
        """로그에서 소스 IP 추출"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, log_content)
        return matches[0] if matches else 'unknown'
    
    def _extract_ip_from_message(self, message: str) -> str:
        """메시지에서 IP 추출"""
        return self._extract_source_ip(message)

# DVD CTI 수집기 사용 예제
async def main():
    """DVD CTI 수집 시스템 실행 예제"""
    
    config = {
        'dvd_container': 'damn-vulnerable-drone',
        'log_directory': './dvd_cti_logs',
        'collection_interval': 5,
        'analysis_interval': 300
    }
    
    collector = DVDCTICollector(config)
    
    try:
        print("DVD CTI 수집 시작...")
        await collector.start_collection()
        
    except KeyboardInterrupt:
        print("수집 중지 요청됨")
        
    finally:
        await collector.stop_collection()
        print("DVD CTI 수집 완료")

if __name__ == "__main__":
    asyncio.run(main())