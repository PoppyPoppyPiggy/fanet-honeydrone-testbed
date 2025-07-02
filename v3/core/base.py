# core/base.py - 업데이트된 기본 클래스 및 데이터 모델
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Callable
from datetime import datetime
from enum import Enum
import asyncio
import logging
import json
import uuid

# 기본 열거형 정의
class AttackType(Enum):
    GPS_SPOOFING = "gps_spoofing"
    MAVLINK_INJECTION = "mavlink_injection"
    WIFI_DEAUTH = "wifi_deauth"
    BATTERY_SPOOFING = "battery_spoofing"
    CAMERA_HIJACK = "camera_hijack"
    COMPANION_COMPROMISE = "companion_compromise"
    FIRMWARE_INJECTION = "firmware_injection"
    SIGNAL_JAMMING = "signal_jamming"

class MTDStrategyType(Enum):
    IP_HOPPING = "ip_hopping"
    PORT_RANDOMIZATION = "port_randomization"
    FREQUENCY_HOPPING = "frequency_hopping"
    TOPOLOGY_MUTATION = "topology_mutation"
    SERVICE_MIGRATION = "service_migration"
    PROTOCOL_SWITCHING = "protocol_switching"
    ENCRYPTION_ROTATION = "encryption_rotation"
    DECOY_DEPLOYMENT = "decoy_deployment"

class DroneState(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    DEFENDING = "defending"
    MIGRATING = "migrating"
    DECOY = "decoy"

class BattlefieldEnvironment(Enum):
    FAVOURABLE = "favourable"      # 호의적: 아군 우세, 낮은 위협
    NEUTRAL = "neutral"            # 중립적: 균형, 중간 위협
    UNFAVOURABLE = "unfavourable"  # 불호의적: 적군 우세, 높은 위협

class PhaseType(Enum):
    HONEY_INFILTRATION = "phase_1_honey_infiltration"
    ENEMY_DETECTION = "phase_2_enemy_detection"
    INFORMATION_REVERSING = "phase_3_information_reversing"
    MTD_HONEY_DEPLOYMENT = "phase_4_mtd_honey_deployment"
    COORDINATED_FLIGHT = "phase_5_coordinated_flight"
    SECOND_DETECTION = "phase_6_second_detection"
    REGULAR_MISSION = "phase_7_regular_mission"
    MERGE_COMPLETION = "phase_8_merge_completion"

# 기본 데이터 모델
@dataclass
class Position3D:
    x: float
    y: float
    z: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    def distance_to(self, other: 'Position3D') -> float:
        """다른 위치까지의 3D 거리 계산"""
        return ((self.x - other.x)**2 + (self.y - other.y)**2 + (self.z - other.z)**2)**0.5

@dataclass
class NetworkConfig:
    ip_address: str
    port: int
    subnet: str
    gateway: str
    interface: str
    encryption_key: Optional[str] = None
    protocol_version: str = "v1.0"
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class MTDStatus:
    active_strategies: List[MTDStrategyType]
    last_change: datetime
    change_frequency: float
    cost_factor: float
    effectiveness_score: float = 0.0
    total_activations: int = 0

@dataclass
class SecurityState:
    threat_level: int  # 0-5
    attack_detected: bool
    attack_type: Optional[AttackType]
    last_attack: Optional[datetime]
    compromised: bool
    vulnerability_score: float = 0.0
    detection_confidence: float = 0.0

@dataclass
class DroneCapabilities:
    """드론 능력 정의"""
    flight_time: float  # 분
    max_speed: float   # m/s
    communication_range: float  # m
    payload_capacity: float  # kg
    sensor_types: List[str]
    mtd_capable: bool = True
    honeypot_enabled: bool = False

@dataclass
class DroneNode:
    id: str
    position: Position3D
    battery_level: float
    network_config: NetworkConfig
    mtd_status: MTDStatus
    security_state: SecurityState
    state: DroneState = DroneState.ACTIVE
    capabilities: Optional[DroneCapabilities] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    def update_last_seen(self):
        """마지막 확인 시간 업데이트"""
        self.last_seen = datetime.now()

@dataclass
class AttackEvent:
    """공격 이벤트 정보"""
    id: str
    timestamp: datetime
    attack_type: AttackType
    source_ip: str
    target_node: str
    success: bool
    severity: int
    details: Dict[str, Any]
    detection_method: str
    response_actions: List[str] = field(default_factory=list)

@dataclass
class MTDActionResult:
    """MTD 액션 실행 결과"""
    action_id: str
    strategy: MTDStrategyType
    target_node: str
    success: bool
    execution_time: float
    cost: float
    effectiveness: float
    side_effects: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

# 기본 매니저 클래스
class BaseManager(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._running = False
        self.start_time: Optional[datetime] = None
        self.metrics = {}
        
    @abstractmethod
    async def start(self):
        """매니저 시작"""
        self._running = True
        self.start_time = datetime.now()
        self.logger.info(f"{self.__class__.__name__} started")
        
    @abstractmethod
    async def stop(self):
        """매니저 중지"""
        self._running = False
        self.logger.info(f"{self.__class__.__name__} stopped")
        
    @abstractmethod
    async def status(self) -> Dict[str, Any]:
        """현재 상태 반환"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        return {
            'running': self._running,
            'uptime_seconds': uptime,
            'metrics': self.metrics
        }
    
    def update_metric(self, key: str, value: Any):
        """메트릭 업데이트"""
        self.metrics[key] = value

# 향상된 이벤트 시스템
class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.event_history: List[Dict[str, Any]] = []
        self.max_history = 1000
        
    def subscribe(self, event_type: str, callback: Callable):
        """이벤트 구독"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
        
    def unsubscribe(self, event_type: str, callback: Callable):
        """이벤트 구독 해제"""
        if event_type in self.subscribers:
            self.subscribers[event_type].remove(callback)
    
    async def publish(self, event_type: str, data: Any):
        """이벤트 발행"""
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
            'id': str(uuid.uuid4())
        }
        
        # 이벤트 히스토리 저장
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history.pop(0)
        
        # 구독자들에게 이벤트 전달
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    logging.error(f"Error in event callback for {event_type}: {e}")
    
    def get_event_history(self, event_type: Optional[str] = None, 
                         limit: int = 100) -> List[Dict[str, Any]]:
        """이벤트 히스토리 조회"""
        events = self.event_history
        if event_type:
            events = [e for e in events if e['type'] == event_type]
        return events[-limit:]

# 실험 및 평가를 위한 기본 클래스
class ExperimentManager(BaseManager):
    """실험 관리 기본 클래스"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.experiment_id = str(uuid.uuid4())
        self.experiment_data = {}
        self.results = {}
        
    async def setup_experiment(self, experiment_config: Dict[str, Any]):
        """실험 설정"""
        self.experiment_data = experiment_config
        self.logger.info(f"Experiment setup: {experiment_config.get('name', 'Unknown')}")
        
    async def run_experiment(self) -> Dict[str, Any]:
        """실험 실행 (하위 클래스에서 구현)"""
        raise NotImplementedError
        
    async def collect_results(self) -> Dict[str, Any]:
        """결과 수집"""
        return {
            'experiment_id': self.experiment_id,
            'results': self.results,
            'timestamp': datetime.now().isoformat()
        }

# 성능 메트릭 수집기
class MetricsCollector:
    """성능 메트릭 수집 및 관리"""
    
    def __init__(self):
        self.metrics: Dict[str, List[Dict[str, Any]]] = {}
        self.aggregated_metrics: Dict[str, Any] = {}
        
    def record_metric(self, metric_name: str, value: float, 
                     timestamp: Optional[datetime] = None, 
                     tags: Optional[Dict[str, str]] = None):
        """메트릭 기록"""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = []
            
        entry = {
            'value': value,
            'timestamp': timestamp or datetime.now(),
            'tags': tags or {}
        }
        
        self.metrics[metric_name].append(entry)
        
    def get_metric_stats(self, metric_name: str, 
                        time_window_minutes: Optional[int] = None) -> Dict[str, float]:
        """메트릭 통계 계산"""
        if metric_name not in self.metrics:
            return {}
            
        values = self.metrics[metric_name]
        
        # 시간 윈도우 필터링
        if time_window_minutes:
            cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
            values = [v for v in values if v['timestamp'] >= cutoff_time]
            
        if not values:
            return {}
            
        numeric_values = [v['value'] for v in values]
        
        return {
            'count': len(numeric_values),
            'min': min(numeric_values),
            'max': max(numeric_values),
            'mean': sum(numeric_values) / len(numeric_values),
            'latest': numeric_values[-1] if numeric_values else 0
        }
        
    def export_metrics(self, format_type: str = 'json') -> str:
        """메트릭 내보내기"""
        if format_type == 'json':
            return json.dumps(self.metrics, default=str, indent=2)
        # 다른 형식 지원 가능
        return str(self.metrics)

# 논문 작성을 위한 연구 데이터 수집기
class ResearchDataCollector:
    """논문 작성을 위한 연구 데이터 수집 및 분석"""
    
    def __init__(self):
        self.attack_data: List[AttackEvent] = []
        self.mtd_data: List[MTDActionResult] = []
        self.network_data: List[Dict[str, Any]] = []
        self.performance_data: List[Dict[str, Any]] = []
        
    def record_attack(self, attack_event: AttackEvent):
        """공격 이벤트 기록"""
        self.attack_data.append(attack_event)
        
    def record_mtd_action(self, mtd_result: MTDActionResult):
        """MTD 액션 결과 기록"""
        self.mtd_data.append(mtd_result)
        
    def record_network_state(self, network_state: Dict[str, Any]):
        """네트워크 상태 기록"""
        self.network_data.append({
            **network_state,
            'timestamp': datetime.now()
        })
        
    def record_performance(self, performance_metrics: Dict[str, Any]):
        """성능 데이터 기록"""
        self.performance_data.append({
            **performance_metrics,
            'timestamp': datetime.now()
        })
        
    def generate_research_report(self) -> Dict[str, Any]:
        """연구 보고서 생성"""
        from datetime import timedelta
        
        # 공격 분석
        attack_analysis = self._analyze_attacks()
        
        # MTD 효과성 분석
        mtd_analysis = self._analyze_mtd_effectiveness()
        
        # 네트워크 성능 분석
        network_analysis = self._analyze_network_performance()
        
        # 전체 시스템 효과성
        system_effectiveness = self._calculate_system_effectiveness()
        
        return {
            'report_generated': datetime.now().isoformat(),
            'data_period': self._get_data_period(),
            'attack_analysis': attack_analysis,
            'mtd_analysis': mtd_analysis,
            'network_analysis': network_analysis,
            'system_effectiveness': system_effectiveness,
            'recommendations': self._generate_recommendations()
        }
        
    def _analyze_attacks(self) -> Dict[str, Any]:
        """공격 데이터 분석"""
        if not self.attack_data:
            return {'total_attacks': 0}
            
        total_attacks = len(self.attack_data)
        successful_attacks = len([a for a in self.attack_data if a.success])
        
        attack_types = {}
        for attack in self.attack_data:
            attack_type = attack.attack_type.value
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
        return {
            'total_attacks': total_attacks,
            'successful_attacks': successful_attacks,
            'success_rate': successful_attacks / total_attacks if total_attacks > 0 else 0,
            'attack_types_distribution': attack_types,
            'average_severity': sum(a.severity for a in self.attack_data) / total_attacks
        }
        
    def _analyze_mtd_effectiveness(self) -> Dict[str, Any]:
        """MTD 효과성 분석"""
        if not self.mtd_data:
            return {'total_mtd_actions': 0}
            
        total_actions = len(self.mtd_data)
        successful_actions = len([m for m in self.mtd_data if m.success])
        
        strategy_effectiveness = {}
        for mtd in self.mtd_data:
            strategy = mtd.strategy.value
            if strategy not in strategy_effectiveness:
                strategy_effectiveness[strategy] = {'total': 0, 'successful': 0, 'avg_effectiveness': 0}
            
            strategy_effectiveness[strategy]['total'] += 1
            if mtd.success:
                strategy_effectiveness[strategy]['successful'] += 1
            strategy_effectiveness[strategy]['avg_effectiveness'] += mtd.effectiveness
            
        # 평균 계산
        for strategy in strategy_effectiveness:
            data = strategy_effectiveness[strategy]
            data['success_rate'] = data['successful'] / data['total'] if data['total'] > 0 else 0
            data['avg_effectiveness'] /= data['total'] if data['total'] > 0 else 1
            
        return {
            'total_mtd_actions': total_actions,
            'successful_actions': successful_actions,
            'overall_success_rate': successful_actions / total_actions if total_actions > 0 else 0,
            'strategy_effectiveness': strategy_effectiveness,
            'average_cost': sum(m.cost for m in self.mtd_data) / total_actions if total_actions > 0 else 0,
            'average_execution_time': sum(m.execution_time for m in self.mtd_data) / total_actions if total_actions > 0 else 0
        }
        
    def _analyze_network_performance(self) -> Dict[str, Any]:
        """네트워크 성능 분석"""
        if not self.network_data:
            return {'no_network_data': True}
            
        # 기본 네트워크 메트릭 분석
        latencies = [d.get('latency', 0) for d in self.network_data if 'latency' in d]
        throughputs = [d.get('throughput', 0) for d in self.network_data if 'throughput' in d]
        packet_loss_rates = [d.get('packet_loss_rate', 0) for d in self.network_data if 'packet_loss_rate' in d]
        
        return {
            'avg_latency': sum(latencies) / len(latencies) if latencies else 0,
            'avg_throughput': sum(throughputs) / len(throughputs) if throughputs else 0,
            'avg_packet_loss_rate': sum(packet_loss_rates) / len(packet_loss_rates) if packet_loss_rates else 0,
            'network_samples': len(self.network_data)
        }
        
    def _calculate_system_effectiveness(self) -> Dict[str, Any]:
        """전체 시스템 효과성 계산"""
        # 공격 차단률
        attack_prevention_rate = 0
        if self.attack_data:
            prevented_attacks = len([a for a in self.attack_data if not a.success])
            attack_prevention_rate = prevented_attacks / len(self.attack_data)
            
        # MTD 반응성
        mtd_response_time = 0
        if self.mtd_data:
            mtd_response_time = sum(m.execution_time for m in self.mtd_data) / len(self.mtd_data)
            
        # 시스템 오버헤드
        system_overhead = 0
        if self.mtd_data:
            system_overhead = sum(m.cost for m in self.mtd_data) / len(self.mtd_data)
            
        # 전체 효과성 점수 (0-1)
        effectiveness_score = (
            attack_prevention_rate * 0.4 +  # 40% 가중치
            (1 - min(mtd_response_time / 10, 1)) * 0.3 +  # 30% 가중치 (10초 기준)
            (1 - min(system_overhead, 1)) * 0.3  # 30% 가중치
        )
        
        return {
            'attack_prevention_rate': attack_prevention_rate,
            'avg_mtd_response_time': mtd_response_time,
            'avg_system_overhead': system_overhead,
            'overall_effectiveness_score': effectiveness_score
        }
        
    def _generate_recommendations(self) -> List[str]:
        """개선 권고사항 생성"""
        recommendations = []
        
        # 공격 분석 기반 권고
        if self.attack_data:
            success_rate = len([a for a in self.attack_data if a.success]) / len(self.attack_data)
            if success_rate > 0.3:
                recommendations.append("공격 성공률이 높습니다. MTD 전략을 더 적극적으로 적용하세요.")
                
        # MTD 분석 기반 권고
        if self.mtd_data:
            avg_cost = sum(m.cost for m in self.mtd_data) / len(self.mtd_data)
            if avg_cost > 0.5:
                recommendations.append("MTD 비용이 높습니다. 비용 효율적인 전략을 우선적으로 고려하세요.")
                
        if not recommendations:
            recommendations.append("시스템이 안정적으로 운영되고 있습니다.")
            
        return recommendations
        
    def _get_data_period(self) -> Dict[str, str]:
        """데이터 수집 기간 반환"""
        all_timestamps = []
        
        for attack in self.attack_data:
            all_timestamps.append(attack.timestamp)
        for mtd in self.mtd_data:
            all_timestamps.append(mtd.timestamp)
        for network in self.network_data:
            if 'timestamp' in network:
                all_timestamps.append(network['timestamp'])
                
        if all_timestamps:
            return {
                'start': min(all_timestamps).isoformat(),
                'end': max(all_timestamps).isoformat()
            }
        return {'start': 'N/A', 'end': 'N/A'}

# 전역 연구 데이터 수집기 인스턴스
research_collector = ResearchDataCollector()