# core/cti/analysis_engine.py
import re
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

@dataclass
class IOC:  # Indicator of Compromise
    type: str  # 'ip', 'domain', 'hash', 'command'
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    context: Dict[str, Any]

@dataclass
class MitreMapping:
    tactic: str
    technique: str
    technique_id: str
    sub_technique: Optional[str] = None
    confidence: float = 1.0

@dataclass
class ThreatIntelligence:
    id: str
    attack_type: AttackType
    iocs: List[IOC]
    mitre_mappings: List[MitreMapping]
    severity: int  # 1-5
    description: str
    recommendations: List[str]
    created_at: datetime
    updated_at: datetime

class CTIAnalysisEngine(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus):
        super().__init__(config)
        self.event_bus = event_bus
        self.threat_intelligence_db: Dict[str, ThreatIntelligence] = {}
        self.ioc_patterns = self._load_ioc_patterns()
        self.mitre_mappings = self._load_mitre_mappings()
        
    async def start(self):
        """CTI 분석 엔진 시작"""
        self._running = True
        self.logger.info("CTI Analysis Engine started")
        
        # DVDs 로그 모니터링 시작
        asyncio.create_task(self._monitor_dvds_logs())
        
    async def stop(self):
        """CTI 분석 엔진 중지"""
        self._running = False
        self.logger.info("CTI Analysis Engine stopped")
    
    async def status(self) -> Dict[str, Any]:
        """CTI 엔진 상태"""
        return {
            'total_threats': len(self.threat_intelligence_db),
            'recent_threats': len([t for t in self.threat_intelligence_db.values() 
                                 if t.updated_at > datetime.now() - timedelta(hours=24)]),
            'high_severity_threats': len([t for t in self.threat_intelligence_db.values() 
                                        if t.severity >= 4])
        }
    
    async def analyze_dvds_log(self, log_entry: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """DVDs 로그 엔트리 분석"""
        try:
            # 공격 유형 식별
            attack_type = self._identify_attack_type(log_entry)
            if not attack_type:
                return None
            
            # IOC 추출
            iocs = self._extract_iocs(log_entry)
            
            # MITRE ATT&CK 매핑
            mitre_mappings = self._map_to_mitre(attack_type, log_entry)
            
            # 위협 정보 생성
            threat_intel = ThreatIntelligence(
                id=f"cti_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.threat_intelligence_db)}",
                attack_type=attack_type,
                iocs=iocs,
                mitre_mappings=mitre_mappings,
                severity=self._calculate_severity(attack_type, log_entry),
                description=self._generate_description(attack_type, log_entry),
                recommendations=self._generate_recommendations(attack_type),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # 데이터베이스에 저장
            self.threat_intelligence_db[threat_intel.id] = threat_intel
            
            # 이벤트 발생
            await self.event_bus.publish('threat_detected', {
                'threat_intel': threat_intel,
                'log_entry': log_entry
            })
            
            return threat_intel
            
        except Exception as e:
            self.logger.error(f"Error analyzing DVDs log: {e}")
            return None
    
    async def get_threat_intelligence(self, threat_id: str) -> Optional[ThreatIntelligence]:
        """위협 정보 조회"""
        return self.threat_intelligence_db.get(threat_id)
    
    async def search_threats(self, 
                           attack_type: Optional[AttackType] = None,
                           severity_min: int = 1,
                           time_range_hours: int = 24) -> List[ThreatIntelligence]:
        """위협 정보 검색"""
        cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
        
        results = []
        for threat in self.threat_intelligence_db.values():
            if threat.updated_at < cutoff_time:
                continue
            if attack_type and threat.attack_type != attack_type:
                continue
            if threat.severity < severity_min:
                continue
            results.append(threat)
        
        return sorted(results, key=lambda t: t.updated_at, reverse=True)
    
    async def generate_stix_report(self, threat_id: str) -> Dict[str, Any]:
        """STIX 2.1 형식으로 위협 정보 변환"""
        threat = await self.get_threat_intelligence(threat_id)
        if not threat:
            return {}
        
        stix_objects = []
        
        # Attack Pattern 객체
        for mapping in threat.mitre_mappings:
            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{threat.id}-{mapping.technique_id.lower()}",
                "created": threat.created_at.isoformat(),
                "modified": threat.updated_at.isoformat(),
                "name": f"{threat.attack_type.value.replace('_', ' ').title()}",
                "description": threat.description,
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": mapping.tactic.lower().replace(' ', '-')
                }],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": mapping.technique_id
                }]
            }
            stix_objects.append(attack_pattern)
        
        # Indicator 객체들
        for ioc in threat.iocs:
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{threat.id}-{hash(ioc.value)}",
                "created": ioc.first_seen.isoformat(),
                "modified": ioc.last_seen.isoformat(),
                "pattern": f"[{ioc.type}:value = '{ioc.value}']",
                "labels": ["malicious-activity"],
                "confidence": int(ioc.confidence * 100)
            }
            stix_objects.append(indicator)
        
        # Bundle 생성
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{threat.id}",
            "objects": stix_objects
        }
        
        return stix_bundle
    
    def _identify_attack_type(self, log_entry: Dict[str, Any]) -> Optional[AttackType]:
        """로그 엔트리에서 공격 유형 식별"""
        event_type = log_entry.get('event_type', '').lower()
        
        attack_mapping = {
            'gps_spoofing': AttackType.GPS_SPOOFING,
            'mavlink_injection': AttackType.MAVLINK_INJECTION,
            'wifi_deauth': AttackType.WIFI_DEAUTH,
            'battery_spoofing': AttackType.BATTERY_SPOOFING,
            'camera_hijack': AttackType.CAMERA_HIJACK
        }
        
        return attack_mapping.get(event_type)
    
    def _extract_iocs(self, log_entry: Dict[str, Any]) -> List[IOC]:
        """로그에서 침해 지표 추출"""
        iocs = []
        timestamp = datetime.fromisoformat(log_entry.get('timestamp', datetime.now().isoformat()))
        
        # IP 주소 추출
        source_ip = log_entry.get('source_ip')
        if source_ip and self._is_valid_ip(source_ip):
            iocs.append(IOC(
                type='ip',
                value=source_ip,
                confidence=0.8,
                first_seen=timestamp,
                last_seen=timestamp,
                context={'source': 'dvds_log', 'role': 'attacker_ip'}
            ))
        
        # 명령어 추출
        payload = log_entry.get('payload', {})
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, str) and len(value) > 5:
                    iocs.append(IOC(
                        type='command',
                        value=value,
                        confidence=0.6,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        context={'source': 'dvds_log', 'parameter': key}
                    ))
        
        return iocs
    
    def _map_to_mitre(self, attack_type: AttackType, log_entry: Dict[str, Any]) -> List[MitreMapping]:
        """공격을 MITRE ATT&CK 프레임워크에 매핑"""
        mappings = {
            AttackType.GPS_SPOOFING: [
                MitreMapping("Impair Process Control", "Spoof Reporting Message", "T0856", confidence=0.9)
            ],
            AttackType.MAVLINK_INJECTION: [
                MitreMapping("Command and Control", "Unauthorized Command Message", "T0855", confidence=0.95)
            ],
            AttackType.WIFI_DEAUTH: [
                MitreMapping("Initial Access", "Wireless Compromise", "T0860", confidence=0.8)
            ],
            AttackType.BATTERY_SPOOFING: [
                MitreMapping("Impact", "Manipulation of Control", "T0831", confidence=0.7)
            ],
            AttackType.CAMERA_HIJACK: [
                MitreMapping("Collection", "Audio Capture", "T1123", confidence=0.8)
            ]
        }
        
        return mappings.get(attack_type, [])
    
    def _calculate_severity(self, attack_type: AttackType, log_entry: Dict[str, Any]) -> int:
        """공격 심각도 계산 (1-5)"""
        base_severity = {
            AttackType.GPS_SPOOFING: 5,
            AttackType.MAVLINK_INJECTION: 4,
            AttackType.WIFI_DEAUTH: 3,
            AttackType.BATTERY_SPOOFING: 4,
            AttackType.CAMERA_HIJACK: 3
        }
        
        severity = base_severity.get(attack_type, 3)
        
        # 탐지 상태에 따른 조정
        if log_entry.get('detection_status') == 'undetected':
            severity = min(5, severity + 1)
        
        return severity
    
    def _generate_description(self, attack_type: AttackType, log_entry: Dict[str, Any]) -> str:
        """공격 설명 생성"""
        descriptions = {
            AttackType.GPS_SPOOFING: "GPS 신호 스푸핑을 통한 드론 항법 시스템 조작 시도",
            AttackType.MAVLINK_INJECTION: "MAVLink 프로토콜을 통한 악의적 명령 주입",
            AttackType.WIFI_DEAUTH: "Wi-Fi 연결 해제 공격을 통한 통신 방해",
            AttackType.BATTERY_SPOOFING: "배터리 상태 정보 조작을 통한 시스템 오작동 유도",
            AttackType.CAMERA_HIJACK: "카메라 피드 하이재킹을 통한 정보 수집"
        }
        
        base_desc = descriptions.get(attack_type, "알 수 없는 공격 유형")
        
        # 추가 컨텍스트 정보
        target = log_entry.get('target_component', 'unknown')
        source_ip = log_entry.get('source_ip', 'unknown')
        
        return f"{base_desc}. 대상: {target}, 공격자 IP: {source_ip}"
    
    def _generate_recommendations(self, attack_type: AttackType) -> List[str]:
        """대응 권고사항 생성"""
        recommendations = {
            AttackType.GPS_SPOOFING: [
                "GPS 신호 인증 메커니즘 구현",
                "다중 위치 추정 시스템 활용",
                "GPS 재밍 탐지 시스템 배치"
            ],
            AttackType.MAVLINK_INJECTION: [
                "MAVLink 통신 암호화 적용",
                "명령 인증 체계 구현",
                "비정상 명령 패턴 모니터링 강화"
            ],
            AttackType.WIFI_DEAUTH: [
                "802.11w (Management Frame Protection) 활성화",
                "다중 통신 채널 구성",
                "연결 복구 자동화 시스템 구현"
            ],
            AttackType.BATTERY_SPOOFING: [
                "배터리 상태 검증 로직 강화",
                "다중 센서 기반 배터리 모니터링",
                "비정상 배터리 데이터 알림 시스템"
            ],
            AttackType.CAMERA_HIJACK: [
                "카메라 접근 권한 강화",
                "영상 스트림 암호화",
                "비정상 접근 모니터링"
            ]
        }
        
        return recommendations.get(attack_type, ["보안 모니터링 강화"])
    
    def _load_ioc_patterns(self) -> Dict[str, str]:
        """IOC 패턴 로드"""
        return {
            'ip_pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain_pattern': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'hash_pattern': r'\b[a-fA-F0-9]{32,64}\b'
        }
    
    def _load_mitre_mappings(self) -> Dict[str, Any]:
        """MITRE ATT&CK 매핑 정보 로드"""
        # 실제로는 외부 파일에서 로드
        return {}
    
    def _is_valid_ip(self, ip: str) -> bool:
        """IP 주소 유효성 검사"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    async def _monitor_dvds_logs(self):
        """DVDs 로그 모니터링"""
        # 실제 구현에서는 파일 시스템 또는 로그 스트림 모니터링
        while self._running:
            try:
                # 샘플 로그 처리 (실제로는 DVDs에서 수신)
                sample_log = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "gps_spoofing",
                    "source_ip": "192.168.1.100",
                    "target_component": "flight_controller",
                    "attack_vector": "fake_gps_injection",
                    "payload": {
                        "latitude": 37.7749,
                        "longitude": -122.4194,
                        "altitude": 100.0
                    },
                    "severity": "high",
                    "detection_status": "undetected"
                }
                
                await self.analyze_dvds_log(sample_log)
                
            except Exception as e:
                self.logger.error(f"Error monitoring DVDs logs: {e}")
            
            await asyncio.sleep(10)  # 10초마다 체크