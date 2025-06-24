# src/cti_analysis_engine.py
import json
import re
import time
import logging
import hashlib
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from enum import Enum
import yara
from pathlib import Path

logger = logging.getLogger(__name__)

class ThreatSeverity(Enum):
    """위협 심각도"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AttackPhase(Enum):
    """MITRE ATT&CK"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str  # ip, domain, hash, url, etc.
    value: str
    confidence: float  # 0.0 - 1.0
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MITRETechnique:
    """MITRE ATT&CK 기술"""
    technique_id: str  # T1234
    name: str
    tactic: AttackPhase
    description: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)

@dataclass
class AttackPattern:
    """공격 패턴"""
    pattern_id: str
    name: str
    severity: ThreatSeverity
    techniques: List[MITRETechnique]
    iocs: List[IOC]
    timeline: List[Tuple[datetime, str]]  # (timestamp, event)
    attack_vector: str
    target_assets: List[str]
    confidence_score: float = 0.0
    first_detected: Optional[datetime] = None
    last_activity: Optional[datetime] = None

@dataclass
class ThreatIntelligence:
    """위협 인텔리전스"""
    threat_id: str
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    attack_patterns: List[AttackPattern] = field(default_factory=list)
    ttps: List[MITRETechnique] = field(default_factory=list)  # Tactics, Techniques, Procedures
    iocs: List[IOC] = field(default_factory=list)
    severity: ThreatSeverity = ThreatSeverity.LOW
    confidence: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    source_logs: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

class YARAAnalyzer:
    """YARA 룰 기반 분석기"""
    
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.compiled_rules: Optional[yara.Rules] = None
        self.rule_metadata: Dict[str, Dict] = {}
        self._load_rules()
    
    def _load_rules(self):
        """YARA 룰 로드"""
        try:
            if self.rules_path.is_file():
                # 단일 룰 파일
                self.compiled_rules = yara.compile(filepath=str(self.rules_path))
            elif self.rules_path.is_dir():
                # 룰 디렉토리
                rule_files = {}
                for rule_file in self.rules_path.glob("*.yar"):
                    rule_files[rule_file.stem] = str(rule_file)
                
                if rule_files:
                    self.compiled_rules = yara.compile(filepaths=rule_files)
            
            logger.info(f"YARA rules loaded from {self.rules_path}")
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self._create_default_rules()
    
    def _create_default_rules(self):
        """기본 YARA 룰 생성"""
        default_rules = '''
        rule DroneAttack_NetworkScan {
            meta:
                description = "Detects network scanning activities targeting drone networks"
                severity = "medium"
                mitre_technique = "T1046"
                attack_phase = "discovery"
            
            strings:
                $scan1 = "nmap" nocase
                $scan2 = "masscan" nocase
                $scan3 = "zmap" nocase
                $port_scan = /(\\d{1,3}\\.){3}\\d{1,3}:\\d{1,5}/
            
            condition:
                any of ($scan*) or $port_scan
        }
        
        rule DroneAttack_CommandInjection {
            meta:
                description = "Detects command injection attempts"
                severity = "high"
                mitre_technique = "T1059"
                attack_phase = "execution"
            
            strings:
                $cmd1 = ";rm -rf" nocase
                $cmd2 = "|nc " nocase
                $cmd3 = "&& curl" nocase
                $cmd4 = "$(whoami)" nocase
                $cmd5 = "`id`" nocase
            
            condition:
                any of them
        }
        
        rule DroneAttack_CredentialAccess {
            meta:
                description = "Detects credential access attempts"
                severity = "high"
                mitre_technique = "T1110"
                attack_phase = "credential-access"
            
            strings:
                $brute1 = "hydra" nocase
                $brute2 = "john" nocase
                $brute3 = "hashcat" nocase
                $pass1 = "password" nocase
                $pass2 = "admin" nocase
                $pass3 = "root" nocase
            
            condition:
                any of ($brute*) or 2 of ($pass*)
        }
        
        rule DroneAttack_DataExfiltration {
            meta:
                description = "Detects data exfiltration activities"
                severity = "critical"
                mitre_technique = "T1041"
                attack_phase = "exfiltration"
            
            strings:
                $exfil1 = "base64" nocase
                $exfil2 = "wget" nocase
                $exfil3 = "curl -X POST" nocase
                $data1 = ".tar.gz"
                $data2 = ".zip"
            
            condition:
                any of ($exfil*) and any of ($data*)
        }
        '''
        
        try:
            self.compiled_rules = yara.compile(source=default_rules)
            logger.info("Default YARA rules created")
        except Exception as e:
            logger.error(f"Failed to create default YARA rules: {e}")
    
    def analyze(self, data: Union[str, bytes]) -> List[Dict[str, Any]]:
        """데이터 분석"""
        if not self.compiled_rules:
            return []
        
        matches = []
        try:
            if isinstance(data, str):
                data = data.encode('utf-8', errors='ignore')
            
            yara_matches = self.compiled_rules.match(data=data)
            
            for match in yara_matches:
                match_info = {
                    'rule_name': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'matched_data': instance.matched_data.decode('utf-8', errors='ignore')
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                matches.append(match_info)
            
        except Exception as e:
            logger.error(f"YARA analysis failed: {e}")
        
        return matches

class MITREMapper:
    """MITRE ATT&CK 프레임워크 매퍼"""
    
    def __init__(self, mitre_data_path: Optional[str] = None):
        self.techniques: Dict[str, Dict] = {}
        self.tactics: Dict[str, Dict] = {}
        self.technique_to_tactic: Dict[str, List[str]] = defaultdict(list)
        
        if mitre_data_path:
            self._load_mitre_data(mitre_data_path)
        else:
            self._load_default_mitre_data()
    
    def _load_mitre_data(self, data_path: str):
        """MITRE 데이터 로드"""
        try:
            with open(data_path, 'r', encoding='utf-8') as f:
                mitre_data = json.load(f)
            
            # 기술 및 전술 정보 파싱
            for item in mitre_data.get('objects', []):
                if item.get('type') == 'attack-pattern':
                    technique_id = self._extract_technique_id(item)
                    if technique_id:
                        self.techniques[technique_id] = item
                        
                        # 전술 매핑
                        for phase in item.get('kill_chain_phases', []):
                            tactic = phase.get('phase_name')
                            if tactic:
                                self.technique_to_tactic[technique_id].append(tactic)
                
                elif item.get('type') == 'x-mitre-tactic':
                    tactic_name = item.get('x_mitre_shortname')
                    if tactic_name:
                        self.tactics[tactic_name] = item
            
            logger.info(f"Loaded {len(self.techniques)} MITRE techniques")
            
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            self._load_default_mitre_data()
    
    def _load_default_mitre_data(self):
        """기본 MITRE 데이터 로드"""
        # 주요 기술들의 간소화된 매핑
        default_techniques = {
            'T1046': {
                'name': 'Network Service Scanning',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts',
                'tactics': ['discovery']
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'description': 'Adversaries may abuse command and script interpreters',
                'tactics': ['execution']
            },
            'T1110': {
                'name': 'Brute Force',
                'description': 'Adversaries may use brute force techniques to gain access',
                'tactics': ['credential-access']
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel',
                'tactics': ['exfiltration']
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer',
                'tactics': ['initial-access']
            },
            'T1055': {
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes',
                'tactics': ['defense-evasion', 'privilege-escalation']
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'description': 'Adversaries may communicate using application layer protocols',
                'tactics': ['command-and-control']
            }
        }
        
        for tech_id, info in default_techniques.items():
            self.techniques[tech_id] = info
            for tactic in info['tactics']:
                self.technique_to_tactic[tech_id].append(tactic)
    
    def _extract_technique_id(self, technique_data: Dict) -> Optional[str]:
        """기술 ID 추출"""
        external_refs = technique_data.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """기술 정보 반환"""
        return self.techniques.get(technique_id)
    
    def get_tactics_for_technique(self, technique_id: str) -> List[str]:
        """기술에 대한 전술 목록 반환"""
        return self.technique_to_tactic.get(technique_id, [])
    
    def map_to_mitre(self, indicators: List[str]) -> List[MITRETechnique]:
        """지표를 MITRE 기술로 매핑"""
        mapped_techniques = []
        
        # 간단한 키워드 기반 매핑
        keyword_mappings = {
            'nmap': 'T1046',
            'scan': 'T1046',
            'brute': 'T1110',
            'password': 'T1110',
            'injection': 'T1059',
            'command': 'T1059',
            'exfiltration': 'T1041',
            'data transfer': 'T1041',
            'exploit': 'T1190',
            'vulnerability': 'T1190'
        }
        
        detected_techniques = set()
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            for keyword, technique_id in keyword_mappings.items():
                if keyword in indicator_lower and technique_id not in detected_techniques:
                    technique_info = self.get_technique_info(technique_id)
                    if technique_info:
                        tactics = self.get_tactics_for_technique(technique_id)
                        primary_tactic = tactics[0] if tactics else 'unknown'
                        
                        try:
                            attack_phase = AttackPhase(primary_tactic)
                        except ValueError:
                            attack_phase = AttackPhase.DISCOVERY
                        
                        mitre_technique = MITRETechnique(
                            technique_id=technique_id,
                            name=technique_info.get('name', f'Technique {technique_id}'),
                            tactic=attack_phase,
                            description=technique_info.get('description', ''),
                            confidence=0.7,
                            evidence=[indicator]
                        )
                        
                        mapped_techniques.append(mitre_technique)
                        detected_techniques.add(technique_id)
        
        return mapped_techniques

class LogAnalyzer:
    """로그 분석기"""
    
    def __init__(self):
        self.patterns = {
            'ip_address': re.compile(r'(?:\d{1,3}\.){3}\d{1,3}'),
            'domain': re.compile(r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'url': re.compile(r'https?://[^\s]+'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'port': re.compile(r':(\d{1,5})\b'),
            'file_path': re.compile(r'[/\\](?:[^/\\]+[/\\])*[^/\\]+'),
            'command': re.compile(r'(?:sudo|su|bash|sh|cmd|powershell)\s+[^\n]+', re.IGNORECASE)
        }
    
    def extract_iocs(self, log_data: str, source: str = "log_analysis") -> List[IOC]:
        """로그에서 IOC 추출"""
        iocs = []
        current_time = datetime.now()
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(log_data)
            
            for match in matches:
                # 중복 제거 및 검증
                if isinstance(match, tuple):
                    value = match[0] if match else continue
                else:
                    value = match
                
                if self._validate_ioc(ioc_type, value):
                    confidence = self._calculate_ioc_confidence(ioc_type, value, log_data)
                    
                    ioc = IOC(
                        ioc_type=ioc_type,
                        value=value,
                        confidence=confidence,
                        first_seen=current_time,
                        last_seen=current_time,
                        source=source,
                        tags=self._generate_ioc_tags(ioc_type, value),
                        context={'log_context': self._extract_context(log_data, value)}
                    )
                    
                    iocs.append(ioc)
        
        return self._deduplicate_iocs(iocs)
    
    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        """IOC 유효성 검증"""
        if ioc_type == 'ip_address':
            try:
                parts = value.split('.')
                return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
            except:
                return False
        
        elif ioc_type == 'domain':
            return len(value) > 3 and '.' in value and not value.startswith('.')
        
        elif ioc_type.startswith('hash_'):
            return len(value) in {32, 40, 64} and all(c in '0123456789abcdefABCDEF' for c in value)
        
        elif ioc_type == 'port':
            try:
                port_num = int(value)
                return 1 <= port_num <= 65535
            except:
                return False
        
        return len(value) > 0
    
    def _calculate_ioc_confidence(self, ioc_type: str, value: str, context: str) -> float:
        """IOC 신뢰도 계산"""
        base_confidence = 0.5
        
        # 타입별 기본 신뢰도
        type_confidence = {
            'hash_sha256': 0.9,
            'hash_sha1': 0.8,
            'hash_md5': 0.7,
            'ip_address': 0.6,
            'url': 0.7,
            'domain': 0.6,
            'email': 0.5,
            'port': 0.4,
            'file_path': 0.5,
            'command': 0.8
        }
        
        confidence = type_confidence.get(ioc_type, base_confidence)
        
        # 컨텍스트 기반 조정
        suspicious_keywords = ['attack', 'malware', 'exploit', 'backdoor', 'trojan', 'virus']
        context_lower = context.lower()
        
        for keyword in suspicious_keywords:
            if keyword in context_lower:
                confidence = min(1.0, confidence + 0.1)
        
        return confidence
    
    def _generate_ioc_tags(self, ioc_type: str, value: str) -> List[str]:
        """IOC 태그 생성"""
        tags = [ioc_type]
        
        if ioc_type == 'ip_address':
            # 사설 IP 확인
            if value.startswith(('10.', '172.', '192.168.')):
                tags.append('private_ip')
            else:
                tags.append('public_ip')
        
        elif ioc_type == 'domain':
            if any(suspicious in value.lower() for suspicious in ['temp', 'tmp', 'test', 'malware']):
                tags.append('suspicious')
        
        elif ioc_type == 'port':
            common_ports = {
                '22': 'ssh', '23': 'telnet', '25': 'smtp', '53': 'dns',
                '80': 'http', '110': 'pop3', '143': 'imap', '443': 'https',
                '993': 'imaps', '995': 'pop3s'
            }
            if value in common_ports:
                tags.append(common_ports[value])
        
        return tags
    
    def _extract_context(self, log_data: str, value: str) -> str:
        """IOC 주변 컨텍스트 추출"""
        lines = log_data.split('\n')
        context_lines = []
        
        for line in lines:
            if value in line:
                context_lines.append(line.strip())
        
        return ' | '.join(context_lines[:3])  # 최대 3줄
    
    def _deduplicate_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """IOC 중복 제거"""
        seen = set()
        deduplicated = []
        
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen.add(key)
                deduplicated.append(ioc)
        
        return deduplicated

class AttackCorrelator:
    """공격 상관관계 분석기"""
    
    def __init__(self):
        self.attack_patterns_db: Dict[str, AttackPattern] = {}
        self.correlation_rules = self._load_correlation_rules()
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """상관관계 규칙 로드"""
        return {
            'time_window': 300,  # 5분 윈도우
            'min_events': 2,
            'severity_escalation': {
                'multiple_techniques': 0.3,
                'cross_tactic': 0.2,
                'persistent_activity': 0.4
            }
        }
    
    def correlate_events(self, techniques: List[MITRETechnique], 
                        iocs: List[IOC], timeline: List[Tuple[datetime, str]]) -> List[AttackPattern]:
        """이벤트 상관관계 분석"""
        patterns = []
        
        if not techniques:
            return patterns
        
        # 시간 기반 그룹핑
        time_groups = self._group_by_time(timeline)
        
        for group_time, events in time_groups.items():
            # 그룹 내 기술들 분석
            group_techniques = [t for t in techniques if any(ev in t.evidence for _, ev in events)]
            group_iocs = [ioc for ioc in iocs if any(ioc.value in ev for _, ev in events)]
            
            if len(group_techniques) >= self.correlation_rules['min_events']:
                pattern = self._create_attack_pattern(group_techniques, group_iocs, events)
                patterns.append(pattern)
        
        return patterns
    
    def _group_by_time(self, timeline: List[Tuple[datetime, str]]) -> Dict[datetime, List[Tuple[datetime, str]]]:
        """시간 윈도우로 이벤트 그룹핑"""
        groups = defaultdict(list)
        window = timedelta(seconds=self.correlation_rules['time_window'])
        
        sorted_timeline = sorted(timeline, key=lambda x: x[0])
        
        current_group_start = None
        for timestamp, event in sorted_timeline:
            if current_group_start is None or timestamp - current_group_start > window:
                current_group_start = timestamp
            
            groups[current_group_start].append((timestamp, event))
        
        return dict(groups)
    
    def _create_attack_pattern(self, techniques: List[MITRETechnique], 
                             iocs: List[IOC], events: List[Tuple[datetime, str]]) -> AttackPattern:
        """공격 패턴 생성"""
        pattern_id = self._generate_pattern_id(techniques, events)
        
        # 심각도 계산
        severity = self._calculate_pattern_severity(techniques)
        
        # 공격 벡터 추정
        attack_vector = self._estimate_attack_vector(techniques, iocs)
        
        # 타겟 자산 추정
        target_assets = self._estimate_target_assets(iocs, events)
        
        # 신뢰도 계산
        confidence = self._calculate_pattern_confidence(techniques, iocs, events)
        
        pattern_name = self._generate_pattern_name(techniques)
        
        return AttackPattern(
            pattern_id=pattern_id,
            name=pattern_name,
            severity=severity,
            techniques=techniques,
            iocs=iocs,
            timeline=events,
            attack_vector=attack_vector,
            target_assets=target_assets,
            confidence_score=confidence,
            first_detected=min(ts for ts, _ in events) if events else datetime.now(),
            last_activity=max(ts for ts, _ in events) if events else datetime.now()
        )
    
    def _generate_pattern_id(self, techniques: List[MITRETechnique], 
                           events: List[Tuple[datetime, str]]) -> str:
        """패턴 ID 생성"""
        content = ''.join([t.technique_id for t in techniques])
        content += ''.join([ev for _, ev in events[:5]])  # 처음 5개 이벤트
        
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _calculate_pattern_severity(self, techniques: List[MITRETechnique]) -> ThreatSeverity:
        """패턴 심각도 계산"""
        # 고위험 전술들
        high_risk_tactics = {
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.PRIVILEGE_ESCALATION,
            AttackPhase.CREDENTIAL_ACCESS,
            AttackPhase.EXFILTRATION,
            AttackPhase.IMPACT
        }
        
        tactics_present = set(t.tactic for t in techniques)
        high_risk_count = len(tactics_present.intersection(high_risk_tactics))
        
        if high_risk_count >= 3:
            return ThreatSeverity.CRITICAL
        elif high_risk_count >= 2:
            return ThreatSeverity.HIGH
        elif high_risk_count >= 1:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _estimate_attack_vector(self, techniques: List[MITRETechnique], iocs: List[IOC]) -> str:
        """공격 벡터 추정"""
        # 기술 기반 공격 벡터 추정
        network_techniques = ['T1046', 'T1071', 'T1041']
        web_techniques = ['T1190', 'T1059']
        
        technique_ids = [t.technique_id for t in techniques]
        
        if any(tid in network_techniques for tid in technique_ids):
            return "network"
        elif any(tid in web_techniques for tid in technique_ids):
            return "web"
        else:
            return "unknown"
    
    def _estimate_target_assets(self, iocs: List[IOC], 
                              events: List[Tuple[datetime, str]]) -> List[str]:
        """타겟 자산 추정"""
        assets = set()
        
        # IOC에서 자산 추출
        for ioc in iocs:
            if ioc.ioc_type == 'ip_address':
                assets.add(f"host_{ioc.value}")
            elif ioc.ioc_type == 'domain':
                assets.add(f"service_{ioc.value}")
        
        # 이벤트에서 자산 추출
        for _, event in events:
            if 'drone' in event.lower():
                assets.add('drone_network')
            if 'fanet' in event.lower():
                assets.add('fanet_infrastructure')
        
        return list(assets)
    
    def _calculate_pattern_confidence(self, techniques: List[MITRETechnique], 
                                    iocs: List[IOC], events: List[Tuple[datetime, str]]) -> float:
        """패턴 신뢰도 계산"""
        # 기본 신뢰도
        base_confidence = 0.5
        
        # 기술 수에 따른 가중치
        technique_weight = min(0.3, len(techniques) * 0.1)
        
        # IOC 품질에 따른 가중치
        ioc_weight = sum(ioc.confidence for ioc in iocs) / len(iocs) * 0.2 if iocs else 0
        
        # 이벤트 수에 따른 가중치
        event_weight = min(0.2, len(events) * 0.05)
        
        total_confidence = base_confidence + technique_weight + ioc_weight + event_weight
        
        return min(1.0, total_confidence)
    
    def _generate_pattern_name(self, techniques: List[MITRETechnique]) -> str:
        """패턴 이름 생성"""
        if not techniques:
            return "Unknown Attack Pattern"
        
        # 주요 전술 기반 이름 생성
        tactics = [t.tactic for t in techniques]
        tactic_counts = Counter(tactics)
        primary_tactic = tactic_counts.most_common(1)[0][0]
        
        tactic_names = {
            AttackPhase.RECONNAISSANCE: "Reconnaissance Attack",
            AttackPhase.INITIAL_ACCESS: "Initial Access Attack",
            AttackPhase.EXECUTION: "Code Execution Attack",
            AttackPhase.PERSISTENCE: "Persistence Attack",
            AttackPhase.PRIVILEGE_ESCALATION: "Privilege Escalation Attack",
            AttackPhase.DEFENSE_EVASION: "Defense Evasion Attack",
            AttackPhase.CREDENTIAL_ACCESS: "Credential Theft Attack",
            AttackPhase.DISCOVERY: "Discovery Attack",
            AttackPhase.LATERAL_MOVEMENT: "Lateral Movement Attack",
            AttackPhase.COLLECTION: "Data Collection Attack",
            AttackPhase.COMMAND_AND_CONTROL: "C2 Communication Attack",
            AttackPhase.EXFILTRATION: "Data Exfiltration Attack",
            AttackPhase.IMPACT: "Impact Attack"
        }
        
        return tactic_names.get(primary_tactic, "Multi-Stage Attack")

class CTIAnalysisEngine:
    """CTI 분석 엔진 메인 클래스"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        
        # 컴포넌트 초기화
        yara_rules_path = self.config.get('yara_rules_path', 'config/yara_rules/')
        self.yara_analyzer = YARAAnalyzer(yara_rules_path)
        
        mitre_data_path = self.config.get('mitre_data_path')
        self.mitre_mapper = MITREMapper(mitre_data_path)
        
        self.log_analyzer = LogAnalyzer()
        self.correlator = AttackCorrelator()
        
        # 상태 관리
        self.threat_intelligence_db: Dict[str, ThreatIntelligence] = {}
        self.recent_analysis: List[Dict[str, Any]] = []
        
        # 통계
        self.total_analyses = 0
        self.threats_detected = 0
        self.false_positives = 0
        
        # 콜백
        self.on_threat_detected: Optional[callable] = None
        self.on_analysis_complete: Optional[callable] = None
    
    def _load_config(self) -> Dict[str, Any]:
        """설정 로드"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load CTI config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """기본 설정"""
        return {
            'yara_rules_path': 'config/yara_rules/',
            'mitre_data_path': None,
            'analysis_thresholds': {
                'min_confidence': 0.3,
                'min_severity': 'LOW',
                'correlation_window': 300
            },
            'retention_days': 30,
            'max_recent_analyses': 1000
        }
    
    async def analyze_log_data(self, log_data: str, source: str = "unknown") -> ThreatIntelligence:
        """로그 데이터 분석"""
        analysis_start = time.time()
        
        try:
            # YARA 룰 분석
            yara_matches = self.yara_analyzer.analyze(log_data)
            
            # IOC 추출
            iocs = self.log_analyzer.extract_iocs(log_data, source)
            
            # 이벤트 타임라인 생성
            timeline = self._extract_timeline(log_data)
            
            # MITRE 기술 매핑
            indicators = [match['rule_name'] for match in yara_matches]
            indicators.extend([f"{ioc.ioc_type}:{ioc.value}" for ioc in iocs])
            
            techniques = self.mitre_mapper.map_to_mitre(indicators)
            
            # YARA 메타데이터에서 추가 기술 추출
            for match in yara_matches:
                meta = match.get('meta', {})
                mitre_tech = meta.get('mitre_technique')
                if mitre_tech:
                    existing_ids = [t.technique_id for t in techniques]
                    if mitre_tech not in existing_ids:
                        tech_info = self.mitre_mapper.get_technique_info(mitre_tech)
                        if tech_info:
                            tactics = self.mitre_mapper.get_tactics_for_technique(mitre_tech)
                            primary_tactic = tactics[0] if tactics else 'discovery'
                            
                            try:
                                attack_phase = AttackPhase(primary_tactic)
                            except ValueError:
                                attack_phase = AttackPhase.DISCOVERY
                            
                            technique = MITRETechnique(
                                technique_id=mitre_tech,
                                name=tech_info.get('name', f'Technique {mitre_tech}'),
                                tactic=attack_phase,
                                description=tech_info.get('description', ''),
                                confidence=0.8,
                                evidence=[match['rule_name']]
                            )
                            techniques.append(technique)
            
            # 공격 패턴 상관관계 분석
            attack_patterns = self.correlator.correlate_events(techniques, iocs, timeline)
            
            # 위협 인텔리전스 생성
            threat_intel = self._create_threat_intelligence(
                techniques, iocs, attack_patterns, log_data, source
            )
            
            # 분석 결과 저장
            self.threat_intelligence_db[threat_intel.threat_id] = threat_intel
            
            # 통계 업데이트
            self.total_analyses += 1
            if threat_intel.severity != ThreatSeverity.LOW:
                self.threats_detected += 1
            
            # 최근 분석 기록
            analysis_result = {
                'timestamp': datetime.now(),
                'threat_id': threat_intel.threat_id,
                'severity': threat_intel.severity.name,
                'confidence': threat_intel.confidence,
                'techniques_count': len(techniques),
                'iocs_count': len(iocs),
                'analysis_time': time.time() - analysis_start,
                'source': source
            }
            
            self.recent_analysis.append(analysis_result)
            
            # 최대 개수 제한
            max_recent = self.config.get('max_recent_analyses', 1000)
            if len(self.recent_analysis) > max_recent:
                self.recent_analysis = self.recent_analysis[-max_recent:]
            
            # 콜백 호출
            if self.on_analysis_complete:
                self.on_analysis_complete(threat_intel)
            
            if (threat_intel.severity != ThreatSeverity.LOW and 
                self.on_threat_detected):
                self.on_threat_detected(threat_intel)
            
            logger.info(f"CTI analysis completed: {threat_intel.threat_id}, "
                       f"severity: {threat_intel.severity.name}")
            
            return threat_intel
            
        except Exception as e:
            logger.error(f"CTI analysis failed: {e}")
            # 빈 위협 인텔리전스 반환
            return ThreatIntelligence(
                threat_id=f"error_{int(time.time())}",
                severity=ThreatSeverity.LOW,
                confidence=0.0,
                source_logs=[f"Error during analysis: {str(e)}"]
            )
    
    def _extract_timeline(self, log_data: str) -> List[Tuple[datetime, str]]:
        """로그에서 타임라인 추출"""
        timeline = []
        lines = log_data.split('\n')
        
        # 간단한 타임스탬프 패턴들
        timestamp_patterns = [
            re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'),  # YYYY-MM-DD HH:MM:SS
            re.compile(r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'),  # MM/DD/YYYY HH:MM:SS
            re.compile(r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})')         # Mon DD HH:MM:SS
        ]
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp = None
            for pattern in timestamp_patterns:
                match = pattern.search(line)
                if match:
                    try:
                        timestamp_str = match.group(1)
                        # 다양한 형식 파싱 시도
                        for fmt in ['%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%b %d %H:%M:%S']:
                            try:
                                if fmt == '%b %d %H:%M:%S':
                                    # 연도 추가
                                    timestamp_str = f"{datetime.now().year} {timestamp_str}"
                                    fmt = '%Y %b %d %H:%M:%S'
                                timestamp = datetime.strptime(timestamp_str, fmt)
                                break
                            except ValueError:
                                continue
                        break
                    except Exception:
                        continue
            
            if not timestamp:
                timestamp = datetime.now()  # 기본값
            
            timeline.append((timestamp, line))
        
        return sorted(timeline, key=lambda x: x[0])
    
    def _create_threat_intelligence(self, techniques: List[MITRETechnique], 
                                  iocs: List[IOC], attack_patterns: List[AttackPattern],
                                  log_data: str, source: str) -> ThreatIntelligence:
        """위협 인텔리전스 생성"""
        threat_id = f"threat_{int(time.time())}_{hashlib.md5(log_data.encode()).hexdigest()[:8]}"
        
        # 전체 심각도 계산
        if attack_patterns:
            max_severity = max(pattern.severity for pattern in attack_patterns)
        elif techniques:
            # 기술 기반 심각도 추정
            high_risk_techniques = ['T1190', 'T1059', 'T1041', 'T1055']
            if any(t.technique_id in high_risk_techniques for t in techniques):
                max_severity = ThreatSeverity.HIGH
            else:
                max_severity = ThreatSeverity.MEDIUM
        else:
            max_severity = ThreatSeverity.LOW
        
        # 전체 신뢰도 계산
        confidences = []
        if techniques:
            confidences.extend([t.confidence for t in techniques])
        if iocs:
            confidences.extend([ioc.confidence for ioc in iocs])
        if attack_patterns:
            confidences.extend([p.confidence_score for p in attack_patterns])
        
        overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        # 권장사항 생성
        recommendations = self._generate_recommendations(techniques, attack_patterns, max_severity)
        
        return ThreatIntelligence(
            threat_id=threat_id,
            attack_patterns=attack_patterns,
            ttps=techniques,
            iocs=iocs,
            severity=max_severity,
            confidence=overall_confidence,
            source_logs=[f"Source: {source}"],
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, techniques: List[MITRETechnique], 
                                attack_patterns: List[AttackPattern], 
                                severity: ThreatSeverity) -> List[str]:
        """권장사항 생성"""
        recommendations = []
        
        technique_ids = [t.technique_id for t in techniques]
        
        # 기술별 권장사항
        if 'T1046' in technique_ids:
            recommendations.append("네트워크 스캔 탐지: 네트워크 모니터링 강화 및 포트 스캔 차단")
        
        if 'T1059' in technique_ids:
            recommendations.append("명령 실행 탐지: 애플리케이션 허용목록 적용 및 명령 실행 모니터링")
        
        if 'T1110' in technique_ids:
            recommendations.append("무차별 대입 공격: 계정 잠금 정책 강화 및 다중 인증 적용")
        
        if 'T1041' in technique_ids:
            recommendations.append("데이터 유출: 네트워크 트래픽 모니터링 및 DLP 솔루션 적용")
        
        # 심각도별 일반 권장사항
        if severity == ThreatSeverity.CRITICAL:
            recommendations.append("긴급 대응: 즉시 보안팀 알림 및 시스템 격리 검토")
            recommendations.append("MTD 활성화: 공격 표면 변경을 위한 즉시 MTD 정책 적용")
        
        elif severity == ThreatSeverity.HIGH:
            recommendations.append("높은 우선순위 대응: 상세 분석 및 추가 모니터링 강화")
            recommendations.append("MTD 강화: 현재 MTD 정책의 강도 증가")
        
        elif severity == ThreatSeverity.MEDIUM:
            recommendations.append("중간 우선순위 대응: 로그 분석 및 관련 시스템 점검")
        
        # 공격 패턴별 권장사항
        for pattern in attack_patterns:
            if 'network' in pattern.attack_vector.lower():
                recommendations.append("네트워크 보안: 방화벽 규칙 검토 및 네트워크 분할 강화")
            
            if 'web' in pattern.attack_vector.lower():
                recommendations.append("웹 보안: WAF 설정 점검 및 웹 애플리케이션 보안 강화")
        
        # 중복 제거
        return list(set(recommendations))
    
    # 외부 인터페이스 메서드들
    
    def get_threat_by_id(self, threat_id: str) -> Optional[ThreatIntelligence]:
        """위협 ID로 조회"""
        return self.threat_intelligence_db.get(threat_id)
    
    def get_recent_threats(self, count: int = 10, 
                          min_severity: ThreatSeverity = ThreatSeverity.LOW) -> List[ThreatIntelligence]:
        """최근 위협 목록"""
        threats = list(self.threat_intelligence_db.values())
        
        # 필터링
        filtered = [t for t in threats if t.severity.value >= min_severity.value]
        
        # 정렬 (최신순)
        sorted_threats = sorted(filtered, key=lambda x: x.updated_at, reverse=True)
        
        return sorted_threats[:count]
    
    def search_threats(self, query: str, field: str = 'all') -> List[ThreatIntelligence]:
        """위협 검색"""
        results = []
        query_lower = query.lower()
        
        for threat in self.threat_intelligence_db.values():
            match = False
            
            if field == 'all' or field == 'techniques':
                if any(query_lower in t.name.lower() or query_lower in t.technique_id.lower() 
                      for t in threat.ttps):
                    match = True
            
            if field == 'all' or field == 'iocs':
                if any(query_lower in ioc.value.lower() for ioc in threat.iocs):
                    match = True
            
            if field == 'all' or field == 'threat_actor':
                if threat.threat_actor and query_lower in threat.threat_actor.lower():
                    match = True
            
            if field == 'all' or field == 'campaign':
                if threat.campaign and query_lower in threat.campaign.lower():
                    match = True
            
            if match:
                results.append(threat)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """분석 통계 정보"""
        threats = list(self.threat_intelligence_db.values())
        
        # 심각도별 통계
        severity_counts = Counter(t.severity for t in threats)
        
        # 기술별 통계
        technique_counts = Counter()
        for threat in threats:
            for technique in threat.ttps:
                technique_counts[technique.technique_id] += 1
        
        # 전술별 통계
        tactic_counts = Counter()
        for threat in threats:
            for technique in threat.ttps:
                tactic_counts[technique.tactic] += 1
        
        # IOC 타입별 통계
        ioc_type_counts = Counter()
        for threat in threats:
            for ioc in threat.iocs:
                ioc_type_counts[ioc.ioc_type] += 1
        
        # 최근 24시간 활동
        recent_threats = [
            t for t in threats 
            if (datetime.now() - t.updated_at).total_seconds() < 86400
        ]
        
        return {
            'total_analyses': self.total_analyses,
            'total_threats': len(threats),
            'threats_detected': self.threats_detected,
            'false_positives': self.false_positives,
            'recent_24h_threats': len(recent_threats),
            'severity_distribution': {
                severity.name: count for severity, count in severity_counts.items()
            },
            'top_techniques': dict(technique_counts.most_common(10)),
            'top_tactics': {
                tactic.name: count for tactic, count in tactic_counts.most_common()
            },
            'ioc_types': dict(ioc_type_counts),
            'average_confidence': (
                sum(t.confidence for t in threats) / len(threats) 
                if threats else 0.0
            ),
            'recent_analysis_summary': self.recent_analysis[-10:] if self.recent_analysis else []
        }
    
    def export_threat_data(self, threat_ids: Optional[List[str]] = None, 
                          format_type: str = 'json') -> str:
        """위협 데이터 내보내기"""
        if threat_ids:
            threats = [self.threat_intelligence_db[tid] for tid in threat_ids 
                      if tid in self.threat_intelligence_db]
        else:
            threats = list(self.threat_intelligence_db.values())
        
        if format_type == 'json':
            # JSON 직렬화 가능한 형태로 변환
            export_data = []
            for threat in threats:
                threat_dict = asdict(threat)
                
                # datetime 객체 문자열로 변환
                threat_dict['created_at'] = threat_dict['created_at'].isoformat()
                threat_dict['updated_at'] = threat_dict['updated_at'].isoformat()
                
                # Enum 값을 문자열로 변환
                threat_dict['severity'] = threat_dict['severity'].name
                
                for pattern in threat_dict['attack_patterns']:
                    pattern['severity'] = pattern['severity'].name
                    if pattern['first_detected']:
                        pattern['first_detected'] = pattern['first_detected'].isoformat()
                    if pattern['last_activity']:
                        pattern['last_activity'] = pattern['last_activity'].isoformat()
                    
                    for technique in pattern['techniques']:
                        technique['tactic'] = technique['tactic'].name
                    
                    for event_time, event_desc in pattern['timeline']:
                        # 이미 튜플이므로 수정 필요
                        pass
                
                for technique in threat_dict['ttps']:
                    technique['tactic'] = technique['tactic'].name
                
                for ioc in threat_dict['iocs']:
                    ioc['first_seen'] = ioc['first_seen'].isoformat()
                    ioc['last_seen'] = ioc['last_seen'].isoformat()
                
                export_data.append(threat_dict)
            
            return json.dumps(export_data, indent=2, ensure_ascii=False)
        
        elif format_type == 'csv':
            # CSV는 평면 구조로 변환
            import io
            import csv
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # 헤더
            writer.writerow([
                'threat_id', 'severity', 'confidence', 'threat_actor', 'campaign',
                'techniques_count', 'iocs_count', 'attack_patterns_count',
                'created_at', 'updated_at'
            ])
            
            # 데이터
            for threat in threats:
                writer.writerow([
                    threat.threat_id,
                    threat.severity.name,
                    threat.confidence,
                    threat.threat_actor or '',
                    threat.campaign or '',
                    len(threat.ttps),
                    len(threat.iocs),
                    len(threat.attack_patterns),
                    threat.created_at.isoformat(),
                    threat.updated_at.isoformat()
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def cleanup_old_data(self, retention_days: Optional[int] = None):
        """오래된 데이터 정리"""
        if retention_days is None:
            retention_days = self.config.get('retention_days', 30)
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # 오래된 위협 인텔리전스 제거
        old_threat_ids = [
            tid for tid, threat in self.threat_intelligence_db.items()
            if threat.updated_at < cutoff_date
        ]
        
        for tid in old_threat_ids:
            del self.threat_intelligence_db[tid]
        
        # 오래된 분석 기록 제거
        self.recent_analysis = [
            analysis for analysis in self.recent_analysis
            if analysis['timestamp'] > cutoff_date
        ]
        
        logger.info(f"Cleaned up {len(old_threat_ids)} old threats and analysis records")
    
    def update_threat_feedback(self, threat_id: str, is_false_positive: bool, 
                             feedback_notes: str = ""):
        """위협 피드백 업데이트"""
        if threat_id in self.threat_intelligence_db:
            threat = self.threat_intelligence_db[threat_id]
            
            if is_false_positive:
                self.false_positives += 1
                threat.confidence = max(0.0, threat.confidence - 0.2)
                threat.severity = ThreatSeverity.LOW
            else:
                threat.confidence = min(1.0, threat.confidence + 0.1)
            
            threat.updated_at = datetime.now()
            
            # 피드백 노트 추가
            if feedback_notes:
                threat.recommendations.append(f"Feedback: {feedback_notes}")
            
            logger.info(f"Updated threat feedback: {threat_id}, false_positive: {is_false_positive}")
        else:
            logger.warning(f"Threat ID not found for feedback: {threat_id}")
    
    def get_threat_trends(self, days: int = 7) -> Dict[str, Any]:
        """위협 트렌드 분석"""
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_threats = [
            t for t in self.threat_intelligence_db.values()
            if t.created_at > cutoff_date
        ]
        
        # 일별 위협 수
        daily_counts = defaultdict(int)
        for threat in recent_threats:
            date_key = threat.created_at.date().isoformat()
            daily_counts[date_key] += 1
        
        # 심각도 트렌드
        severity_trends = defaultdict(lambda: defaultdict(int))
        for threat in recent_threats:
            date_key = threat.created_at.date().isoformat()
            severity_trends[date_key][threat.severity.name] += 1
        
        # 기술 트렌드
        technique_trends = Counter()
        for threat in recent_threats:
            for technique in threat.ttps:
                technique_trends[technique.technique_id] += 1
        
        return {
            'period_days': days,
            'total_threats': len(recent_threats),
            'daily_threat_counts': dict(daily_counts),
            'severity_trends': {
                date: dict(severities) for date, severities in severity_trends.items()
            },
            'trending_techniques': dict(technique_trends.most_common(10)),
            'average_confidence': (
                sum(t.confidence for t in recent_threats) / len(recent_threats)
                if recent_threats else 0.0
            )
        }


# 사용 예시 및 테스트
if __name__ == "__main__":
    import asyncio
    
    async def test_cti_engine():
        """CTI 엔진 테스트"""
        # 테스트 설정
        test_config = {
            'yara_rules_path': 'test_rules.yar',
            'analysis_thresholds': {
                'min_confidence': 0.3,
                'min_severity': 'LOW'
            }
        }
        
        with open('test_cti_config.json', 'w') as f:
            json.dump(test_config, f)
        
        # CTI 엔진 생성
        engine = CTIAnalysisEngine('test_cti_config.json')
        
        # 콜백 설정
        def on_threat(threat):
            print(f"🚨 Threat detected: {threat.threat_id}, "
                  f"Severity: {threat.severity.name}, "
                  f"Confidence: {threat.confidence:.2f}")
        
        def on_analysis(threat):
            print(f"📊 Analysis complete: {threat.threat_id}, "
                  f"Techniques: {len(threat.ttps)}, "
                  f"IOCs: {len(threat.iocs)}")
        
        engine.on_threat_detected = on_threat
        engine.on_analysis_complete = on_analysis
        
        # 테스트 로그 데이터
        test_logs = [
            """
2024-06-23 14:30:15 [INFO] Drone network scan detected from 192.168.1.100
2024-06-23 14:30:16 [WARN] Suspicious nmap activity targeting ports 22,80,443
2024-06-23 14:30:17 [ERROR] Failed login attempt: admin/password123
2024-06-23 14:30:18 [ALERT] Command injection attempt: ; rm -rf /tmp/*
            """,
            """
2024-06-23 14:35:20 [WARN] Data exfiltration detected
2024-06-23 14:35:21 [INFO] Base64 encoded data transmission to evil.example.com
2024-06-23 14:35:22 [ERROR] Unauthorized file access: /etc/passwd
2024-06-23 14:35:23 [ALERT] Malware hash detected: a1b2c3d4e5f6789012345678901234567890abcd
            """,
            """
2024-06-23 14:40:30 [INFO] Normal drone telemetry received
2024-06-23 14:40:31 [INFO] Flight path updated successfully
2024-06-23 14:40:32 [INFO] Battery level: 85%
            """
        ]
        
        print("🔍 Starting CTI analysis tests...")
        
        # 로그 분석 테스트
        for i, log_data in enumerate(test_logs):
            print(f"\n--- Test {i+1}: Log Analysis ---")
            threat_intel = await engine.analyze_log_data(log_data, f"test_source_{i+1}")
            
            print(f"Threat ID: {threat_intel.threat_id}")
            print(f"Severity: {threat_intel.severity.name}")
            print(f"Confidence: {threat_intel.confidence:.3f}")
            print(f"Techniques: {[t.technique_id for t in threat_intel.ttps]}")
            print(f"IOCs: {len(threat_intel.iocs)}")
            print(f"Recommendations: {len(threat_intel.recommendations)}")
            
            if threat_intel.recommendations:
                print("Top recommendations:")
                for rec in threat_intel.recommendations[:3]:
                    print(f"  - {rec}")
        
        # 통계 출력
        print("\n--- Statistics ---")
        stats = engine.get_statistics()
        print(f"Total analyses: {stats['total_analyses']}")
        print(f"Threats detected: {stats['threats_detected']}")
        print(f"Severity distribution: {stats['severity_distribution']}")
        print(f"Top techniques: {stats['top_techniques']}")
        
        # 트렌드 분석
        print("\n--- Threat Trends ---")
        trends = engine.get_threat_trends(days=1)
        print(f"Threats in last day: {trends['total_threats']}")
        print(f"Trending techniques: {trends['trending_techniques']}")
        
        # 검색 테스트
        print("\n--- Search Test ---")
        search_results = engine.search_threats("nmap", "techniques")
        print(f"Search results for 'nmap': {len(search_results)} threats found")
        
        # 데이터 내보내기 테스트
        print("\n--- Export Test ---")
        json_export = engine.export_threat_data(format_type='json')
        print(f"JSON export size: {len(json_export)} characters")
        
        print("\n✅ CTI engine tests completed!")
    
    # 테스트 실행
    # asyncio.run(test_cti_engine())