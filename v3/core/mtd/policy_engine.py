# core/mtd/policy_engine.py - 연구 기능이 통합된 MTD 정책 엔진
import random
import asyncio
import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from core.base import (
    BaseManager, MTDStrategyType, AttackType, EventBus, 
    MTDActionResult, research_collector, MetricsCollector,
    BattlefieldEnvironment, PhaseType
)

@dataclass
class MTDAction:
    strategy: MTDStrategyType
    target_node: str
    parameters: Dict[str, Any]
    cost: float
    expected_effectiveness: float
    priority: int = 1
    execution_time_estimate: float = 0.0
    prerequisites: List[str] = field(default_factory=list)

@dataclass
class TriggerCondition:
    condition_type: str  # 'attack_detected', 'time_based', 'energy_based', 'threat_level'
    threshold: float
    operator: str  # '>', '<', '==', '!='
    window_size: int = 1  # 시간 윈도우 (초)

@dataclass
class MTDPolicy:
    """MTD 정책 정의"""
    name: str
    triggers: List[TriggerCondition]
    actions: List[MTDAction]
    cooldown_period: float = 30.0  # 재실행 방지 기간 (초)
    max_executions_per_hour: int = 10
    battlefield_environments: List[BattlefieldEnvironment] = field(default_factory=lambda: list(BattlefieldEnvironment))
    phase_restrictions: List[PhaseType] = field(default_factory=list)

@dataclass
class MTDDecisionContext:
    """MTD 의사결정 컨텍스트"""
    current_attacks: List[Dict[str, Any]]
    network_state: Dict[str, Any]
    system_performance: Dict[str, Any]
    recent_mtd_actions: List[MTDActionResult]
    battlefield_environment: BattlefieldEnvironment
    current_phase: PhaseType
    threat_intelligence: List[Dict[str, Any]]

class MTDPolicyEngine(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus, network_manager):
        super().__init__(config)
        self.event_bus = event_bus
        self.network_manager = network_manager
        self.active_policies: List[MTDPolicy] = []
        self.action_history: List[MTDActionResult] = []
        self.metrics_collector = MetricsCollector()
        
        # 강화학습 에이전트 (나중에 연동)
        self.rl_agent = None
        self.rl_enabled = config.get('enable_reinforcement_learning', False)
        
        # 정책 실행 제한
        self.policy_execution_counts = {}
        self.last_execution_times = {}
        
        # 전장 환경 및 단계별 적응
        self.current_battlefield_env = BattlefieldEnvironment.NEUTRAL
        self.current_phase = PhaseType.HONEY_INFILTRATION
        
        # 연구 및 실험 설정
        self.experiment_mode = False
        self.effectiveness_tracking = {}
        self.strategy_performance_history = {strategy.value: [] for strategy in MTDStrategyType}
        
        # 위협 상황별 전략 매핑
        self.threat_strategy_mapping = self._initialize_threat_strategy_mapping()
        
        # 정책 초기화
        self._initialize_default_policies()
        
    async def start(self):
        """MTD 엔진 시작"""
        await super().start()
        
        # 이벤트 구독
        self.event_bus.subscribe('attack_detected', self._handle_attack_detected)
        self.event_bus.subscribe('node_compromised', self._handle_node_compromised)
        self.event_bus.subscribe('honeypot_triggered', self._handle_honeypot_triggered)
        self.event_bus.subscribe('phase_changed', self._handle_phase_changed)
        self.event_bus.subscribe('battlefield_environment_changed', self._handle_environment_changed)
        
        # 주기적 MTD 실행
        asyncio.create_task(self._periodic_mtd_execution())
        asyncio.create_task(self._policy_effectiveness_analysis())
        
        # 강화학습 모듈 초기화
        if self.rl_enabled:
            await self._initialize_rl_agent()
    
    async def stop(self):
        """MTD 엔진 중지"""
        await super().stop()
        
        # 최종 실험 데이터 수집
        if self.experiment_mode:
            await self._collect_final_mtd_data()
    
    async def status(self) -> Dict[str, Any]:
        """MTD 엔진 상태"""
        base_status = await super().status()
        
        mtd_status = {
            'active_policies': len(self.active_policies),
            'total_actions_executed': len(self.action_history),
            'last_action': self.action_history[-1].__dict__ if self.action_history else None,
            'average_cost': self._calculate_average_cost(),
            'average_effectiveness': self._calculate_average_effectiveness(),
            'strategy_distribution': self._get_strategy_distribution(),
            'current_battlefield_environment': self.current_battlefield_env.value,
            'current_phase': self.current_phase.value,
            'rl_enabled': self.rl_enabled,
            'experiment_mode': self.experiment_mode
        }
        
        return {**base_status, **mtd_status}
    
    def _initialize_threat_strategy_mapping(self) -> Dict[AttackType, List[MTDStrategyType]]:
        """위협별 효과적인 MTD 전략 매핑"""
        return {
            AttackType.GPS_SPOOFING: [
                MTDStrategyType.FREQUENCY_HOPPING,
                MTDStrategyType.TOPOLOGY_MUTATION,
                MTDStrategyType.SERVICE_MIGRATION
            ],
            AttackType.MAVLINK_INJECTION: [
                MTDStrategyType.PROTOCOL_SWITCHING,
                MTDStrategyType.ENCRYPTION_ROTATION,
                MTDStrategyType.PORT_RANDOMIZATION
            ],
            AttackType.WIFI_DEAUTH: [
                MTDStrategyType.FREQUENCY_HOPPING,
                MTDStrategyType.TOPOLOGY_MUTATION,
                MTDStrategyType.PROTOCOL_SWITCHING
            ],
            AttackType.BATTERY_SPOOFING: [
                MTDStrategyType.SERVICE_MIGRATION,
                MTDStrategyType.DECOY_DEPLOYMENT,
                MTDStrategyType.ENCRYPTION_ROTATION
            ],
            AttackType.CAMERA_HIJACK: [
                MTDStrategyType.SERVICE_MIGRATION,
                MTDStrategyType.PORT_RANDOMIZATION,
                MTDStrategyType.ENCRYPTION_ROTATION
            ],
            AttackType.COMPANION_COMPROMISE: [
                MTDStrategyType.SERVICE_MIGRATION,
                MTDStrategyType.TOPOLOGY_MUTATION,
                MTDStrategyType.IP_HOPPING,
                MTDStrategyType.DECOY_DEPLOYMENT
            ]
        }
    
    def _initialize_default_policies(self):
        """기본 MTD 정책 초기화"""
        
        # 1. 공격 탐지 시 즉시 대응 정책
        immediate_response_policy = MTDPolicy(
            name="immediate_attack_response",
            triggers=[
                TriggerCondition("attack_detected", 0.7, ">", window_size=1)
            ],
            actions=[
                MTDAction(
                    strategy=MTDStrategyType.IP_HOPPING,
                    target_node="auto_select",
                    parameters={"urgency": "high"},
                    cost=0.3,
                    expected_effectiveness=0.8,
                    priority=1
                )
            ],
            cooldown_period=10.0,
            max_executions_per_hour=20
        )
        
        # 2. 허니팟 트리거 시 미끼 배치 정책
        honeypot_response_policy = MTDPolicy(
            name="honeypot_decoy_deployment",
            triggers=[
                TriggerCondition("honeypot_triggered", 1, "==", window_size=5)
            ],
            actions=[
                MTDAction(
                    strategy=MTDStrategyType.DECOY_DEPLOYMENT,
                    target_node="honeypot_vicinity",
                    parameters={"decoy_count": 2, "authenticity_level": 0.8},
                    cost=0.4,
                    expected_effectiveness=0.7,
                    priority=2
                ),
                MTDAction(
                    strategy=MTDStrategyType.TOPOLOGY_MUTATION,
                    target_node="network_cluster",
                    parameters={"mutation_intensity": 0.6},
                    cost=0.5,
                    expected_effectiveness=0.6,
                    priority=3
                )
            ],
            cooldown_period=60.0,
            max_executions_per_hour=5
        )
        
        # 3. 시간 기반 예방적 MTD 정책
        proactive_mtd_policy = MTDPolicy(
            name="proactive_periodic_mtd",
            triggers=[
                TriggerCondition("time_based", 300, ">", window_size=1)  # 5분마다
            ],
            actions=[
                MTDAction(
                    strategy=MTDStrategyType.PORT_RANDOMIZATION,
                    target_node="all_active",
                    parameters={"randomization_scope": "service_ports"},
                    cost=0.1,
                    expected_effectiveness=0.4,
                    priority=5
                )
            ],
            cooldown_period=180.0,
            max_executions_per_hour=12,
            battlefield_environments=[BattlefieldEnvironment.UNFAVOURABLE, BattlefieldEnvironment.NEUTRAL]
        )
        
        # 4. 고위협 상황 대응 정책
        high_threat_policy = MTDPolicy(
            name="high_threat_response",
            triggers=[
                TriggerCondition("threat_level", 4, ">=", window_size=10)
            ],
            actions=[
                MTDAction(
                    strategy=MTDStrategyType.SERVICE_MIGRATION,
                    target_node="high_value_targets",
                    parameters={"migration_distance": "far", "redundancy": True},
                    cost=0.8,
                    expected_effectiveness=0.9,
                    priority=1
                ),
                MTDAction(
                    strategy=MTDStrategyType.ENCRYPTION_ROTATION,
                    target_node="all_communications",
                    parameters={"key_strength": "maximum", "rotation_frequency": "high"},
                    cost=0.3,
                    expected_effectiveness=0.85,
                    priority=2
                )
            ],
            cooldown_period=30.0,
            max_executions_per_hour=8
        )
        
        # 5. 전장 환경별 적응 정책
        unfavorable_environment_policy = MTDPolicy(
            name="unfavorable_environment_adaptation",
            triggers=[
                TriggerCondition("environment_threat", 0.8, ">", window_size=30)
            ],
            actions=[
                MTDAction(
                    strategy=MTDStrategyType.TOPOLOGY_MUTATION,
                    target_node="entire_network",
                    parameters={"aggressiveness": 0.9, "stealth_mode": True},
                    cost=0.7,
                    expected_effectiveness=0.8,
                    priority=1
                ),
                MTDAction(
                    strategy=MTDStrategyType.FREQUENCY_HOPPING,
                    target_node="all_communications",
                    parameters={"hop_rate": "maximum", "pattern": "unpredictable"},
                    cost=0.4,
                    expected_effectiveness=0.75,
                    priority=2
                )
            ],
            cooldown_period=45.0,
            max_executions_per_hour=6,
            battlefield_environments=[BattlefieldEnvironment.UNFAVOURABLE]
        )
        
        self.active_policies = [
            immediate_response_policy,
            honeypot_response_policy,
            proactive_mtd_policy,
            high_threat_policy,
            unfavorable_environment_policy
        ]
    
    async def execute_mtd_action(self, action: MTDAction) -> MTDActionResult:
        """MTD 액션 실행"""
        start_time = datetime.now()
        action_id = f"mtd_{start_time.strftime('%Y%m%d_%H%M%S')}_{len(self.action_history)}"
        
        try:
            # 전제 조건 확인
            if not await self._check_action_prerequisites(action):
                return MTDActionResult(
                    action_id=action_id,
                    strategy=action.strategy,
                    target_node=action.target_node,
                    success=False,
                    execution_time=0.0,
                    cost=0.0,
                    effectiveness=0.0,
                    side_effects=["prerequisites_not_met"]
                )
            
            # 실제 MTD 전략 실행
            success = await self._execute_strategy(action)
            
            # 실행 시간 및 비용 계산
            execution_time = (datetime.now() - start_time).total_seconds()
            actual_cost = self._calculate_actual_cost(action, execution_time)
            
            # 효과성 측정
            effectiveness = await self._measure_effectiveness(action, success)
            
            # 부작용 탐지
            side_effects = await self._detect_side_effects(action)
            
            # 결과 객체 생성
            result = MTDActionResult(
                action_id=action_id,
                strategy=action.strategy,
                target_node=action.target_node,
                success=success,
                execution_time=execution_time,
                cost=actual_cost,
                effectiveness=effectiveness,
                side_effects=side_effects
            )
            
            # 이력에 추가
            self.action_history.append(result)
            
            # 전략별 성능 기록
            self.strategy_performance_history[action.strategy.value].append({
                'success': success,
                'effectiveness': effectiveness,
                'cost': actual_cost,
                'timestamp': start_time
            })
            
            # 이벤트 발행
            await self.event_bus.publish('mtd_action_executed', {
                'result': result.__dict__,
                'action': action.__dict__
            })
            
            # 연구 데이터 수집
            if self.experiment_mode:
                research_collector.record_mtd_action(result)
            
            # 메트릭 기록
            self.metrics_collector.record_metric(f'mtd_success_{action.strategy.value}', 1.0 if success else 0.0)
            self.metrics_collector.record_metric('mtd_execution_time', execution_time)
            self.metrics_collector.record_metric('mtd_cost', actual_cost)
            self.metrics_collector.record_metric('mtd_effectiveness', effectiveness)
            
            self.logger.info(f"MTD 액션 실행 완료: {action.strategy.value} -> 성공: {success}, 효과성: {effectiveness:.2f}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"MTD 액션 실행 실패: {e}")
            
            # 실패 결과 반환
            return MTDActionResult(
                action_id=action_id,
                strategy=action.strategy,
                target_node=action.target_node,
                success=False,
                execution_time=(datetime.now() - start_time).total_seconds(),
                cost=0.0,
                effectiveness=0.0,
                side_effects=[f"execution_error: {str(e)}"]
            )
    
    async def _check_action_prerequisites(self, action: MTDAction) -> bool:
        """액션 전제 조건 확인"""
        if not action.prerequisites:
            return True
        
        for prerequisite in action.prerequisites:
            if prerequisite == "network_stable":
                if not await self._is_network_stable():
                    return False
            elif prerequisite == "sufficient_energy":
                if not await self._has_sufficient_energy(action.target_node):
                    return False
            elif prerequisite == "no_ongoing_mtd":
                if await self._has_ongoing_mtd_actions():
                    return False
        
        return True
    
    async def _execute_strategy(self, action: MTDAction) -> bool:
        """실제 MTD 전략 실행"""
        strategy = action.strategy
        target = action.target_node
        params = action.parameters
        
        try:
            if strategy == MTDStrategyType.IP_HOPPING:
                return await self._execute_ip_hopping(target, params)
            elif strategy == MTDStrategyType.PORT_RANDOMIZATION:
                return await self._execute_port_randomization(target, params)
            elif strategy == MTDStrategyType.FREQUENCY_HOPPING:
                return await self._execute_frequency_hopping(target, params)
            elif strategy == MTDStrategyType.TOPOLOGY_MUTATION:
                return await self._execute_topology_mutation(target, params)
            elif strategy == MTDStrategyType.SERVICE_MIGRATION:
                return await self._execute_service_migration(target, params)
            elif strategy == MTDStrategyType.PROTOCOL_SWITCHING:
                return await self._execute_protocol_switching(target, params)
            elif strategy == MTDStrategyType.ENCRYPTION_ROTATION:
                return await self._execute_encryption_rotation(target, params)
            elif strategy == MTDStrategyType.DECOY_DEPLOYMENT:
                return await self._execute_decoy_deployment(target, params)
            else:
                self.logger.warning(f"알 수 없는 MTD 전략: {strategy}")
                return False
                
        except Exception as e:
            self.logger.error(f"MTD 전략 {strategy.value} 실행 오류: {e}")
            return False
    
    async def _execute_ip_hopping(self, target: str, params: Dict[str, Any]) -> bool:
        """IP 주소 호핑 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            
            # 새로운 IP 주소 생성
            new_config = self.network_manager._generate_network_config(node.position)
            old_ip = node.network_config.ip_address
            
            # IP 변경
            node.network_config.ip_address = new_config.ip_address
            node.network_config.last_updated = datetime.now()
            
            # MTD 상태 업데이트
            if MTDStrategyType.IP_HOPPING not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.IP_HOPPING)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"IP 호핑 실행 - {node_id}: {old_ip} -> {new_config.ip_address}")
        
        return success_count > 0
    
    async def _execute_port_randomization(self, target: str, params: Dict[str, Any]) -> bool:
        """포트 랜덤화 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        randomization_scope = params.get('randomization_scope', 'all_ports')
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            old_port = node.network_config.port
            
            # 포트 범위 결정
            if randomization_scope == 'service_ports':
                new_port = random.randint(8000, 9000)
            elif randomization_scope == 'high_ports':
                new_port = random.randint(49152, 65535)
            else:
                new_port = random.randint(1024, 65535)
            
            # 포트 변경
            node.network_config.port = new_port
            node.network_config.last_updated = datetime.now()
            
            # MTD 상태 업데이트
            if MTDStrategyType.PORT_RANDOMIZATION not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.PORT_RANDOMIZATION)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"포트 랜덤화 실행 - {node_id}: {old_port} -> {new_port}")
        
        return success_count > 0
    
    async def _execute_frequency_hopping(self, target: str, params: Dict[str, Any]) -> bool:
        """주파수 호핑 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        hop_rate = params.get('hop_rate', 'normal')
        pattern = params.get('pattern', 'pseudo_random')
        
        # 주파수 대역 정의
        frequency_bands = {
            'normal': [2412, 2437, 2462, 5180, 5200, 5220],  # MHz
            'maximum': [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 
                       5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320]
        }
        
        available_frequencies = frequency_bands.get(hop_rate, frequency_bands['normal'])
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            
            # 새 주파수 선택
            if pattern == 'unpredictable':
                new_frequency = random.choice(available_frequencies)
            else:
                # 의사 랜덤 패턴
                seed = hash(node_id + str(datetime.now().hour)) % len(available_frequencies)
                new_frequency = available_frequencies[seed]
            
            # 주파수 설정 (시뮬레이션)
            if 'radio_config' not in node.network_config.__dict__:
                node.network_config.__dict__['radio_config'] = {}
            node.network_config.__dict__['radio_config']['frequency'] = new_frequency
            node.network_config.last_updated = datetime.now()
            
            # MTD 상태 업데이트
            if MTDStrategyType.FREQUENCY_HOPPING not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.FREQUENCY_HOPPING)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"주파수 호핑 실행 - {node_id}: {new_frequency} MHz")
        
        return success_count > 0
    
    async def _execute_topology_mutation(self, target: str, params: Dict[str, Any]) -> bool:
        """토폴로지 변형 실행"""
        mutation_intensity = params.get('mutation_intensity', 0.5)
        stealth_mode = params.get('stealth_mode', False)
        
        if target == "entire_network":
            target_nodes = list(self.network_manager.nodes.keys())
        else:
            target_nodes = await self._resolve_target_nodes(target)
        
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            
            # 위치 변형 계산
            if stealth_mode:
                # 은밀한 변형 (작은 변화)
                max_displacement = 20.0 * mutation_intensity
            else:
                # 일반 변형
                max_displacement = 50.0 * mutation_intensity
            
            # 새 위치 생성
            from core.base import Position3D
            new_position = Position3D(
                x=node.position.x + random.uniform(-max_displacement, max_displacement),
                y=node.position.y + random.uniform(-max_displacement, max_displacement),
                z=max(10, node.position.z + random.uniform(-max_displacement/2, max_displacement/2))
            )
            
            # 위치 업데이트
            await self.network_manager.update_node_position(node_id, new_position)
            
            # MTD 상태 업데이트
            if MTDStrategyType.TOPOLOGY_MUTATION not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.TOPOLOGY_MUTATION)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"토폴로지 변형 실행 - {node_id}: 위치 변경 (강도: {mutation_intensity})")
        
        return success_count > 0
    
    async def _execute_service_migration(self, target: str, params: Dict[str, Any]) -> bool:
        """서비스 마이그레이션 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        migration_distance = params.get('migration_distance', 'medium')
        redundancy = params.get('redundancy', False)
        
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
            
            # 마이그레이션 대상 노드 선택
            available_nodes = [nid for nid in self.network_manager.nodes.keys() 
                              if nid != node_id and 
                              self.network_manager.nodes[nid].state.value == 'active']
            
            if not available_nodes:
                continue
            
            # 거리 기준으로 노드 선택
            source_node = self.network_manager.nodes[node_id]
            
            if migration_distance == 'far':
                # 가장 먼 노드 선택
                target_node_id = max(available_nodes, 
                                   key=lambda nid: source_node.position.distance_to(
                                       self.network_manager.nodes[nid].position))
            elif migration_distance == 'near':
                # 가장 가까운 노드 선택
                target_node_id = min(available_nodes,
                                   key=lambda nid: source_node.position.distance_to(
                                       self.network_manager.nodes[nid].position))
            else:
                # 중간 거리 노드 선택
                target_node_id = random.choice(available_nodes)
            
            # 서비스 마이그레이션 시뮬레이션
            migration_success = await self._simulate_service_migration(node_id, target_node_id, redundancy)
            
            if migration_success:
                # MTD 상태 업데이트
                node = self.network_manager.nodes[node_id]
                if MTDStrategyType.SERVICE_MIGRATION not in node.mtd_status.active_strategies:
                    node.mtd_status.active_strategies.append(MTDStrategyType.SERVICE_MIGRATION)
                node.mtd_status.last_change = datetime.now()
                node.mtd_status.total_activations += 1
                
                success_count += 1
                
                self.logger.debug(f"서비스 마이그레이션 실행 - {node_id} -> {target_node_id}")
        
        return success_count > 0
    
    async def _execute_protocol_switching(self, target: str, params: Dict[str, Any]) -> bool:
        """프로토콜 전환 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        
        # 사용 가능한 프로토콜
        protocols = ['MAVLink_v1', 'MAVLink_v2', 'Custom_Secure', 'Mesh_Protocol', 'Quantum_Safe']
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            
            # 현재 프로토콜과 다른 프로토콜 선택
            current_protocol = node.network_config.protocol_version
            available_protocols = [p for p in protocols if p != current_protocol]
            
            if not available_protocols:
                continue
            
            new_protocol = random.choice(available_protocols)
            
            # 프로토콜 변경
            node.network_config.protocol_version = new_protocol
            node.network_config.last_updated = datetime.now()
            
            # MTD 상태 업데이트
            if MTDStrategyType.PROTOCOL_SWITCHING not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.PROTOCOL_SWITCHING)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"프로토콜 전환 실행 - {node_id}: {current_protocol} -> {new_protocol}")
        
        return success_count > 0
    
    async def _execute_encryption_rotation(self, target: str, params: Dict[str, Any]) -> bool:
        """암호화 키 순환 실행"""
        target_nodes = await self._resolve_target_nodes(target)
        key_strength = params.get('key_strength', 'standard')
        rotation_frequency = params.get('rotation_frequency', 'normal')
        
        # 키 길이 결정
        key_lengths = {
            'standard': 128,
            'high': 256,
            'maximum': 512
        }
        key_length = key_lengths.get(key_strength, 128)
        
        success_count = 0
        
        for node_id in target_nodes:
            if node_id not in self.network_manager.nodes:
                continue
                
            node = self.network_manager.nodes[node_id]
            
            # 새 암호화 키 생성
            new_key = self._generate_encryption_key(key_length)
            
            # 키 업데이트
            node.network_config.encryption_key = new_key
            node.network_config.last_updated = datetime.now()
            
            # MTD 상태 업데이트
            if MTDStrategyType.ENCRYPTION_ROTATION not in node.mtd_status.active_strategies:
                node.mtd_status.active_strategies.append(MTDStrategyType.ENCRYPTION_ROTATION)
            node.mtd_status.last_change = datetime.now()
            node.mtd_status.total_activations += 1
            
            success_count += 1
            
            self.logger.debug(f"암호화 순환 실행 - {node_id}: 새 키 생성 ({key_length}bit)")
        
        return success_count > 0
    
    async def _execute_decoy_deployment(self, target: str, params: Dict[str, Any]) -> bool:
        """미끼 배치 실행"""
        decoy_count = params.get('decoy_count', 2)
        authenticity_level = params.get('authenticity_level', 0.7)
        
        # 기준점 결정
        if target == "honeypot_vicinity":
            # 허니팟 노드 주변에 배치
            honeypot_nodes = [node for node in self.network_manager.nodes.values()
                             if node.capabilities and node.capabilities.honeypot_enabled]
            if not honeypot_nodes:
                return False
            reference_node = random.choice(honeypot_nodes)
        else:
            target_nodes = await self._resolve_target_nodes(target)
            if not target_nodes:
                return False
            reference_node = self.network_manager.nodes[target_nodes[0]]
        
        success_count = 0
        
        for i in range(decoy_count):
            # 미끼 위치 생성 (기준점 주변)
            from core.base import Position3D
            decoy_position = Position3D(
                x=reference_node.position.x + random.uniform(-100, 100),
                y=reference_node.position.y + random.uniform(-100, 100),
                z=max(10, reference_node.position.z + random.uniform(-30, 30))
            )
            
            # 미끼 노드 생성
            decoy_id = f"decoy_{datetime.now().strftime('%H%M%S')}_{i}"
            
            try:
                await self.network_manager.add_node(
                    decoy_id, 
                    decoy_position, 
                    node_type='honeypot'  # 미끼도 허니팟으로 분류
                )
                
                # 미끼 특성 설정
                decoy_node = self.network_manager.nodes[decoy_id]
                decoy_node.security_state.vulnerability_score = authenticity_level
                
                success_count += 1
                
                self.logger.debug(f"미끼 배치 실행 - {decoy_id}: 인증도 {authenticity_level}")
                
            except Exception as e:
                self.logger.error(f"미끼 {decoy_id} 배치 실패: {e}")
        
        return success_count > 0
    
    def _generate_encryption_key(self, length: int) -> str:
        """암호화 키 생성"""
        import secrets
        return secrets.token_hex(length // 8)
    
    async def _simulate_service_migration(self, source_id: str, target_id: str, redundancy: bool) -> bool:
        """서비스 마이그레이션 시뮬레이션"""
        # 실제 구현에서는 서비스 중단, 데이터 전송, 복구 과정을 시뮬레이션
        
        # 간단한 성공/실패 모델
        base_success_rate = 0.85
        
        # 거리 기반 성공률 조정
        source_node = self.network_manager.nodes[source_id]
        target_node = self.network_manager.nodes[target_id]
        distance = source_node.position.distance_to(target_node.position)
        
        if distance > 200:  # 200m 이상 거리
            base_success_rate *= 0.8
        
        # 배터리 상태 고려
        if source_node.battery_level < 30 or target_node.battery_level < 30:
            base_success_rate *= 0.7
        
        # 중복성 옵션
        if redundancy:
            base_success_rate = min(0.98, base_success_rate * 1.2)
        
        # 시뮬레이션 지연
        await asyncio.sleep(random.uniform(0.5, 2.0))
        
        return random.random() < base_success_rate
    
    async def _resolve_target_nodes(self, target: str) -> List[str]:
        """타겟 노드 해석"""
        if target == "auto_select":
            # 가장 위험한 노드 선택
            threat_nodes = [(nid, node.security_state.threat_level) 
                           for nid, node in self.network_manager.nodes.items()
                           if node.state.value == 'active']
            if threat_nodes:
                threat_nodes.sort(key=lambda x: x[1], reverse=True)
                return [threat_nodes[0][0]]
            return []
        
        elif target == "all_active":
            return [nid for nid, node in self.network_manager.nodes.items() 
                   if node.state.value == 'active']
        
        elif target == "high_value_targets":
            return [nid for nid, node in self.network_manager.nodes.items()
                   if (node.capabilities and 
                       hasattr(node.capabilities, 'node_type') and
                       'high_value' in str(node.capabilities.__dict__))]
        
        elif target == "network_cluster":
            # 중심 노드들 선택
            active_nodes = [nid for nid, node in self.network_manager.nodes.items() 
                           if node.state.value == 'active']
            return active_nodes[:len(active_nodes)//2]  # 절반 선택
        
        elif target in self.network_manager.nodes:
            return [target]
        
        else:
            return []
    
    async def _measure_effectiveness(self, action: MTDAction, success: bool) -> float:
        """MTD 효과성 측정"""
        if not success:
            return 0.0
        
        base_effectiveness = action.expected_effectiveness
        
        # 전략별 효과성 조정
        strategy_modifiers = {
            MTDStrategyType.IP_HOPPING: 1.0,
            MTDStrategyType.PORT_RANDOMIZATION: 0.9,
            MTDStrategyType.FREQUENCY_HOPPING: 1.1,
            MTDStrategyType.TOPOLOGY_MUTATION: 1.2,
            MTDStrategyType.SERVICE_MIGRATION: 1.3,
            MTDStrategyType.PROTOCOL_SWITCHING: 1.1,
            MTDStrategyType.ENCRYPTION_ROTATION: 1.2,
            MTDStrategyType.DECOY_DEPLOYMENT: 0.8
        }
        
        modifier = strategy_modifiers.get(action.strategy, 1.0)
        
        # 전장 환경별 조정
        env_modifiers = {
            BattlefieldEnvironment.FAVOURABLE: 1.1,
            BattlefieldEnvironment.NEUTRAL: 1.0,
            BattlefieldEnvironment.UNFAVOURABLE: 0.9
        }
        
        env_modifier = env_modifiers.get(self.current_battlefield_env, 1.0)
        
        # 최근 공격 활동 고려
        recent_attacks = len([a for a in self.action_history[-10:] if a.success])
        urgency_modifier = 1.0 + (recent_attacks * 0.1)
        
        # 최종 효과성 계산
        final_effectiveness = min(1.0, base_effectiveness * modifier * env_modifier * urgency_modifier)
        
        return final_effectiveness
    
    def _calculate_actual_cost(self, action: MTDAction, execution_time: float) -> float:
        """실제 비용 계산"""
        base_cost = action.cost
        
        # 실행 시간 기반 추가 비용
        time_cost = execution_time * 0.01  # 초당 0.01 비용
        
        # 전략별 비용 조정
        strategy_cost_modifiers = {
            MTDStrategyType.IP_HOPPING: 1.0,
            MTDStrategyType.PORT_RANDOMIZATION: 0.8,
            MTDStrategyType.FREQUENCY_HOPPING: 1.2,
            MTDStrategyType.TOPOLOGY_MUTATION: 1.5,
            MTDStrategyType.SERVICE_MIGRATION: 2.0,
            MTDStrategyType.PROTOCOL_SWITCHING: 1.3,
            MTDStrategyType.ENCRYPTION_ROTATION: 1.1,
            MTDStrategyType.DECOY_DEPLOYMENT: 1.4
        }
        
        modifier = strategy_cost_modifiers.get(action.strategy, 1.0)
        
        return min(1.0, (base_cost + time_cost) * modifier)
    
    async def _detect_side_effects(self, action: MTDAction) -> List[str]:
        """부작용 탐지"""
        side_effects = []
        
        # 네트워크 성능 영향
        if action.strategy in [MTDStrategyType.TOPOLOGY_MUTATION, MTDStrategyType.SERVICE_MIGRATION]:
            if random.random() < 0.3:  # 30% 확률
                side_effects.append("temporary_connectivity_loss")
        
        # 에너지 소모 증가
        if action.cost > 0.5:
            side_effects.append("increased_energy_consumption")
        
        # 지연 증가
        if action.strategy in [MTDStrategyType.ENCRYPTION_ROTATION, MTDStrategyType.PROTOCOL_SWITCHING]:
            if random.random() < 0.2:  # 20% 확률
                side_effects.append("increased_latency")
        
        return side_effects
    
    async def _handle_attack_detected(self, attack_data: Dict[str, Any]):
        """공격 탐지 시 MTD 대응"""
        attack_type = attack_data.get('attack_type')
        target_node = attack_data.get('target_node', attack_data.get('node_id'))
        
        self.logger.info(f"공격 탐지됨: {attack_type} -> {target_node}")
        
        # 적절한 MTD 전략 선택
        if isinstance(attack_type, str):
            try:
                attack_enum = AttackType(attack_type)
            except ValueError:
                attack_enum = None
        else:
            attack_enum = attack_type
        
        if attack_enum and attack_enum in self.threat_strategy_mapping:
            recommended_strategies = self.threat_strategy_mapping[attack_enum]
            
            # 가장 효과적인 전략 선택
            best_strategy = self._select_best_strategy(recommended_strategies, target_node)
            
            if best_strategy:
                action = MTDAction(
                    strategy=best_strategy,
                    target_node=target_node,
                    parameters={'trigger': 'attack_detected', 'urgency': 'high'},
                    cost=0.4,
                    expected_effectiveness=0.8,
                    priority=1
                )
                
                # 즉시 실행
                result = await self.execute_mtd_action(action)
                
                # 연구 데이터에 공격-대응 연관성 기록
                if self.experiment_mode:
                    research_collector.record_attack({
                        'id': f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        'timestamp': datetime.now(),
                        'attack_type': attack_enum,
                        'source_ip': attack_data.get('source_ip', 'unknown'),
                        'target_node': target_node,
                        'success': attack_data.get('success', False),
                        'severity': attack_data.get('severity', 3),
                        'details': attack_data,
                        'detection_method': 'honeypot' if 'honeypot' in str(attack_data) else 'network_monitoring',
                        'response_actions': [result.action_id] if result.success else []
                    })
    
    def _select_best_strategy(self, strategies: List[MTDStrategyType], target_node: str) -> Optional[MTDStrategyType]:
        """최적 전략 선택"""
        if not strategies:
            return None
        
        # 최근 성능 기록 기반 선택
        strategy_scores = {}
        
        for strategy in strategies:
            performance_history = self.strategy_performance_history.get(strategy.value, [])
            
            if performance_history:
                # 최근 10개 기록의 평균 효과성
                recent_records = performance_history[-10:]
                avg_effectiveness = sum(r['effectiveness'] for r in recent_records) / len(recent_records)
                success_rate = sum(1 for r in recent_records if r['success']) / len(recent_records)
                
                # 종합 점수
                strategy_scores[strategy] = avg_effectiveness * 0.7 + success_rate * 0.3
            else:
                # 기본 점수 (전략별 기대 효과성)
                default_scores = {
                    MTDStrategyType.SERVICE_MIGRATION: 0.8,
                    MTDStrategyType.TOPOLOGY_MUTATION: 0.7,
                    MTDStrategyType.ENCRYPTION_ROTATION: 0.75,
                    MTDStrategyType.FREQUENCY_HOPPING: 0.7,
                    MTDStrategyType.PROTOCOL_SWITCHING: 0.65,
                    MTDStrategyType.IP_HOPPING: 0.6,
                    MTDStrategyType.PORT_RANDOMIZATION: 0.5,
                    MTDStrategyType.DECOY_DEPLOYMENT: 0.55
                }
                strategy_scores[strategy] = default_scores.get(strategy, 0.5)
        
        # 최고 점수 전략 반환
        return max(strategy_scores.keys(), key=lambda s: strategy_scores[s])
    
    async def _handle_honeypot_triggered(self, honeypot_data: Dict[str, Any]):
        """허니팟 트리거 시 대응"""
        node_id = honeypot_data.get('node_id')
        attack_details = honeypot_data.get('attack_details', {})
        
        self.logger.info(f"허니팟 트리거됨: {node_id}")
        
        # 미끼 배치 전략 실행
        decoy_action = MTDAction(
            strategy=MTDStrategyType.DECOY_DEPLOYMENT,
            target_node="honeypot_vicinity",
            parameters={
                'decoy_count': 3,
                'authenticity_level': 0.9,
                'trigger': 'honeypot_triggered'
            },
            cost=0.5,
            expected_effectiveness=0.7,
            priority=2
        )
        
        await self.execute_mtd_action(decoy_action)
    
    async def _handle_phase_changed(self, phase_data: Dict[str, Any]):
        """단계 변경 시 처리"""
        new_phase = PhaseType(phase_data.get('phase'))
        self.current_phase = new_phase
        
        self.logger.info(f"단계 변경됨: {new_phase.value}")
        
        # 단계별 MTD 정책 활성화/비활성화
        await self._adjust_policies_for_phase(new_phase)
    
    async def _handle_environment_changed(self, env_data: Dict[str, Any]):
        """전장 환경 변경 시 처리"""
        new_env = BattlefieldEnvironment(env_data.get('environment'))
        self.current_battlefield_env = new_env
        
        self.logger.info(f"전장 환경 변경됨: {new_env.value}")
        
        # 환경별 MTD 적극성 조정
        await self._adjust_policies_for_environment(new_env)
    
    async def _adjust_policies_for_phase(self, phase: PhaseType):
        """단계별 정책 조정"""
        # 단계별 정책 활성화 규칙
        phase_policy_rules = {
            PhaseType.HONEY_INFILTRATION: ['proactive_periodic_mtd'],
            PhaseType.ENEMY_DETECTION: ['immediate_attack_response', 'honeypot_decoy_deployment'],
            PhaseType.MTD_HONEY_DEPLOYMENT: ['high_threat_response', 'unfavorable_environment_adaptation'],
            PhaseType.COORDINATED_FLIGHT: ['proactive_periodic_mtd'],
            PhaseType.SECOND_DETECTION: ['immediate_attack_response', 'high_threat_response'],
            PhaseType.REGULAR_MISSION: ['proactive_periodic_mtd'],
        }
        
        active_policy_names = phase_policy_rules.get(phase, [])
        
        # 정책 활성화/비활성화
        for policy in self.active_policies:
            if policy.name in active_policy_names:
                policy.cooldown_period = max(5.0, policy.cooldown_period * 0.7)  # 빠른 반응
            else:
                policy.cooldown_period = min(300.0, policy.cooldown_period * 1.3)  # 느린 반응
    
    async def _adjust_policies_for_environment(self, env: BattlefieldEnvironment):
        """환경별 정책 조정"""
        env_adjustments = {
            BattlefieldEnvironment.FAVOURABLE: {
                'cooldown_multiplier': 1.2,  # 느린 반응
                'effectiveness_bonus': 0.1
            },
            BattlefieldEnvironment.NEUTRAL: {
                'cooldown_multiplier': 1.0,
                'effectiveness_bonus': 0.0
            },
            BattlefieldEnvironment.UNFAVOURABLE: {
                'cooldown_multiplier': 0.6,  # 빠른 반응
                'effectiveness_bonus': -0.1
            }
        }
        
        adjustment = env_adjustments.get(env, env_adjustments[BattlefieldEnvironment.NEUTRAL])
        
        for policy in self.active_policies:
            if env in policy.battlefield_environments or not policy.battlefield_environments:
                policy.cooldown_period *= adjustment['cooldown_multiplier']
                # 효과성 조정은 실행 시 적용
    
    async def _periodic_mtd_execution(self):
        """주기적 MTD 실행"""
        while self._running:
            try:
                current_time = datetime.now()
                
                # 활성 정책들 확인
                for policy in self.active_policies:
                    # 쿨다운 확인
                    last_execution = self.last_execution_times.get(policy.name)
                    if (last_execution and 
                        (current_time - last_execution).total_seconds() < policy.cooldown_period):
                        continue
                    
                    # 실행 횟수 제한 확인
                    hour_key = current_time.strftime('%Y-%m-%d-%H')
                    execution_count = self.policy_execution_counts.get(f"{policy.name}_{hour_key}", 0)
                    if execution_count >= policy.max_executions_per_hour:
                        continue
                    
                    # 트리거 조건 확인
                    should_execute = await self._check_policy_triggers(policy)
                    
                    if should_execute:
                        # 정책 실행
                        await self._execute_policy(policy)
                        
                        # 실행 기록 업데이트
                        self.last_execution_times[policy.name] = current_time
                        self.policy_execution_counts[f"{policy.name}_{hour_key}"] = execution_count + 1
                
                await asyncio.sleep(10)  # 10초마다 확인
                
            except Exception as e:
                self.logger.error(f"주기적 MTD 실행 오류: {e}")
                await asyncio.sleep(30)
    
    async def _check_policy_triggers(self, policy: MTDPolicy) -> bool:
        """정책 트리거 조건 확인"""
        for trigger in policy.triggers:
            if not await self._evaluate_trigger_condition(trigger):
                return False
        return True
    
    async def _evaluate_trigger_condition(self, condition: TriggerCondition) -> bool:
        """트리거 조건 평가"""
        condition_type = condition.condition_type
        threshold = condition.threshold
        operator = condition.operator
        
        if condition_type == "time_based":
            # 마지막 MTD 실행으로부터의 시간
            if not self.action_history:
                return True
            
            last_action_time = self.action_history[-1].timestamp
            time_diff = (datetime.now() - last_action_time).total_seconds()
            
            return self._compare_values(time_diff, threshold, operator)
        
        elif condition_type == "attack_detected":
            # 최근 공격 탐지율
            recent_actions = [a for a in self.action_history[-10:] 
                             if 'attack_detected' in str(a.__dict__)]
            detection_rate = len(recent_actions) / 10.0
            
            return self._compare_values(detection_rate, threshold, operator)
        
        elif condition_type == "threat_level":
            # 평균 위협 수준
            if not self.network_manager.nodes:
                return False
            
            threat_levels = [node.security_state.threat_level 
                           for node in self.network_manager.nodes.values()]
            avg_threat = sum(threat_levels) / len(threat_levels)
            
            return self._compare_values(avg_threat, threshold, operator)
        
        elif condition_type == "honeypot_triggered":
            # 허니팟 트리거 수
            recent_honeypot_triggers = len([a for a in self.action_history[-condition.window_size:]
                                          if 'honeypot' in str(a.__dict__)])
            
            return self._compare_values(recent_honeypot_triggers, threshold, operator)
        
        return False
    
    def _compare_values(self, value: float, threshold: float, operator: str) -> bool:
        """값 비교"""
        if operator == '>':
            return value > threshold
        elif operator == '<':
            return value < threshold
        elif operator == '>=':
            return value >= threshold
        elif operator == '<=':
            return value <= threshold
        elif operator == '==':
            return abs(value - threshold) < 0.001
        elif operator == '!=':
            return abs(value - threshold) >= 0.001
        return False
    
    async def _execute_policy(self, policy: MTDPolicy):
        """정책 실행"""
        self.logger.info(f"MTD 정책 실행: {policy.name}")
        
        # 우선순위에 따라 액션 정렬
        sorted_actions = sorted(policy.actions, key=lambda a: a.priority)
        
        for action in sorted_actions:
            try:
                result = await self.execute_mtd_action(action)
                
                if result.success:
                    self.logger.debug(f"정책 액션 성공: {action.strategy.value}")
                else:
                    self.logger.warning(f"정책 액션 실패: {action.strategy.value}")
                    
            except Exception as e:
                self.logger.error(f"정책 액션 실행 오류: {e}")
    
    async def _policy_effectiveness_analysis(self):
        """정책 효과성 분석"""
        while self._running:
            try:
                if len(self.action_history) >= 10:  # 충분한 데이터가 있을 때
                    # 전략별 성능 분석
                    strategy_analysis = self._analyze_strategy_performance()
                    
                    # 정책별 성능 분석
                    policy_analysis = self._analyze_policy_performance()
                    
                    # 연구 데이터 수집
                    if self.experiment_mode:
                        analysis_data = {
                            'strategy_performance': strategy_analysis,
                            'policy_performance': policy_analysis,
                            'total_actions': len(self.action_history),
                            'overall_success_rate': self._calculate_overall_success_rate(),
                            'analysis_timestamp': datetime.now()
                        }
                        research_collector.record_performance(analysis_data)
                    
                    # 메트릭 업데이트
                    self.update_metric('strategy_analysis', strategy_analysis)
                    self.update_metric('policy_analysis', policy_analysis)
                
                await asyncio.sleep(300)  # 5분마다 분석
                
            except Exception as e:
                self.logger.error(f"효과성 분석 오류: {e}")
                await asyncio.sleep(600)
    
    def _analyze_strategy_performance(self) -> Dict[str, Any]:
        """전략별 성능 분석"""
        strategy_stats = {}
        
        for strategy in MTDStrategyType:
            strategy_name = strategy.value
            history = self.strategy_performance_history.get(strategy_name, [])
            
            if history:
                recent_history = history[-20:]  # 최근 20개 기록
                
                success_rate = sum(1 for r in recent_history if r['success']) / len(recent_history)
                avg_effectiveness = sum(r['effectiveness'] for r in recent_history) / len(recent_history)
                avg_cost = sum(r['cost'] for r in recent_history) / len(recent_history)
                
                # 효율성 점수 (효과성/비용)
                efficiency_score = avg_effectiveness / max(avg_cost, 0.1)
                
                strategy_stats[strategy_name] = {
                    'execution_count': len(history),
                    'recent_success_rate': success_rate,
                    'average_effectiveness': avg_effectiveness,
                    'average_cost': avg_cost,
                    'efficiency_score': efficiency_score,
                    'last_execution': max(r['timestamp'] for r in recent_history).isoformat() if recent_history else None
                }
            else:
                strategy_stats[strategy_name] = {
                    'execution_count': 0,
                    'recent_success_rate': 0.0,
                    'average_effectiveness': 0.0,
                    'average_cost': 0.0,
                    'efficiency_score': 0.0,
                    'last_execution': None
                }
        
        return strategy_stats
    
    def _analyze_policy_performance(self) -> Dict[str, Any]:
        """정책별 성능 분석"""
        policy_stats = {}
        
        for policy in self.active_policies:
            policy_name = policy.name
            
            # 정책에 의해 실행된 액션들 찾기
            policy_actions = [action for action in self.action_history
                             if any(param.get('trigger') == policy_name 
                                   for param in [action.__dict__.get('parameters', {})])]
            
            if policy_actions:
                success_rate = sum(1 for a in policy_actions if a.success) / len(policy_actions)
                avg_effectiveness = sum(a.effectiveness for a in policy_actions) / len(policy_actions)
                avg_response_time = sum(a.execution_time for a in policy_actions) / len(policy_actions)
                
                policy_stats[policy_name] = {
                    'total_executions': len(policy_actions),
                    'success_rate': success_rate,
                    'average_effectiveness': avg_effectiveness,
                    'average_response_time': avg_response_time,
                    'last_execution': max(a.timestamp for a in policy_actions).isoformat()
                }
            else:
                policy_stats[policy_name] = {
                    'total_executions': 0,
                    'success_rate': 0.0,
                    'average_effectiveness': 0.0,
                    'average_response_time': 0.0,
                    'last_execution': None
                }
        
        return policy_stats
    
    def _calculate_average_cost(self) -> float:
        """평균 비용 계산"""
        if not self.action_history:
            return 0.0
        
        recent_actions = self.action_history[-50:]  # 최근 50개
        return sum(action.cost for action in recent_actions) / len(recent_actions)
    
    def _calculate_average_effectiveness(self) -> float:
        """평균 효과성 계산"""
        if not self.action_history:
            return 0.0
        
        recent_actions = self.action_history[-50:]  # 최근 50개
        return sum(action.effectiveness for action in recent_actions) / len(recent_actions)
    
    def _calculate_overall_success_rate(self) -> float:
        """전체 성공률 계산"""
        if not self.action_history:
            return 0.0
        
        successful_actions = sum(1 for action in self.action_history if action.success)
        return successful_actions / len(self.action_history)
    
    def _get_strategy_distribution(self) -> Dict[str, int]:
        """전략별 실행 분포"""
        distribution = {}
        
        for action in self.action_history:
            strategy_name = action.strategy.value
            distribution[strategy_name] = distribution.get(strategy_name, 0) + 1
        
        return distribution
    
    # 실험 및 연구 지원 메서드들
    async def start_experiment(self, experiment_config: Dict[str, Any]):
        """MTD 실험 시작"""
        self.experiment_mode = True
        experiment_name = experiment_config.get('name', 'mtd_experiment')
        
        self.logger.info(f"MTD 실험 시작: {experiment_name}")
        
        # 실험별 정책 조정
        if 'mtd_aggressiveness' in experiment_config:
            aggressiveness = experiment_config['mtd_aggressiveness']
            await self._adjust_aggressiveness(aggressiveness)
        
        if 'strategy_focus' in experiment_config:
            focus_strategies = experiment_config['strategy_focus']
            await self._focus_on_strategies(focus_strategies)
        
        if 'response_time_target' in experiment_config:
            target_time = experiment_config['response_time_target']
            await self._optimize_for_response_time(target_time)
        
        # 실험 시작 이벤트
        await self.event_bus.publish('mtd_experiment_started', {
            'experiment_name': experiment_name,
            'config': experiment_config,
            'mtd_engine': 'policy_engine'
        })
    
    async def stop_experiment(self):
        """MTD 실험 중지"""
        if not self.experiment_mode:
            return
        
        self.experiment_mode = False
        
        # 최종 성과 수집
        final_performance = {
            'total_actions': len(self.action_history),
            'success_rate': self._calculate_overall_success_rate(),
            'average_effectiveness': self._calculate_average_effectiveness(),
            'average_cost': self._calculate_average_cost(),
            'strategy_performance': self._analyze_strategy_performance(),
            'experiment_duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        }
        
        research_collector.record_performance({
            'experiment_end': datetime.now(),
            'final_mtd_performance': final_performance
        })
        
        self.logger.info("MTD 실험 완료")
        
        await self.event_bus.publish('mtd_experiment_stopped', {
            'final_performance': final_performance
        })
    
    async def _adjust_aggressiveness(self, aggressiveness: float):
        """MTD 적극성 조정 (0.0 - 1.0)"""
        for policy in self.active_policies:
            # 쿨다운 시간 조정 (적극적일수록 짧게)
            base_cooldown = policy.cooldown_period
            policy.cooldown_period = base_cooldown * (1.0 - aggressiveness * 0.7)
            
            # 시간당 최대 실행 횟수 조정
            base_executions = policy.max_executions_per_hour
            policy.max_executions_per_hour = int(base_executions * (1.0 + aggressiveness))
    
    async def _focus_on_strategies(self, focus_strategies: List[str]):
        """특정 전략에 집중"""
        for policy in self.active_policies:
            adjusted_actions = []
            
            for action in policy.actions:
                if action.strategy.value in focus_strategies:
                    # 집중 전략의 우선순위 상승
                    action.priority = max(1, action.priority - 1)
                    action.expected_effectiveness *= 1.2  # 20% 효과성 증가
                else:
                    # 기타 전략의 우선순위 하락
                    action.priority += 1
                    action.expected_effectiveness *= 0.9  # 10% 효과성 감소
                
                adjusted_actions.append(action)
            
            policy.actions = adjusted_actions
    
    async def _optimize_for_response_time(self, target_time: float):
        """응답 시간 최적화"""
        for policy in self.active_policies:
            # 빠른 전략 우선
            policy.actions.sort(key=lambda a: a.execution_time_estimate)
            
            # 쿨다운 단축
            policy.cooldown_period = min(policy.cooldown_period, target_time)
    
    async def get_experiment_results(self) -> Dict[str, Any]:
        """실험 결과 조회"""
        if not self.experiment_mode:
            return {'error': 'No active experiment'}
        
        current_time = datetime.now()
        experiment_duration = (current_time - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'experiment_active': True,
            'duration_seconds': experiment_duration,
            'total_actions': len(self.action_history),
            'current_success_rate': self._calculate_overall_success_rate(),
            'current_effectiveness': self._calculate_average_effectiveness(),
            'current_cost': self._calculate_average_cost(),
            'strategy_distribution': self._get_strategy_distribution(),
            'recent_performance': self._get_recent_performance_trend(),
            'policy_execution_stats': self._get_policy_execution_stats()
        }
    
    def _get_recent_performance_trend(self, window_size: int = 20) -> Dict[str, List[float]]:
        """최근 성능 트렌드"""
        if len(self.action_history) < window_size:
            return {}
        
        recent_actions = self.action_history[-window_size:]
        
        # 시간순으로 효과성과 비용 트렌드
        effectiveness_trend = [action.effectiveness for action in recent_actions]
        cost_trend = [action.cost for action in recent_actions]
        success_trend = [1.0 if action.success else 0.0 for action in recent_actions]
        
        return {
            'effectiveness_trend': effectiveness_trend,
            'cost_trend': cost_trend,
            'success_trend': success_trend,
            'timestamps': [action.timestamp.isoformat() for action in recent_actions]
        }
    
    def _get_policy_execution_stats(self) -> Dict[str, Any]:
        """정책 실행 통계"""
        current_hour = datetime.now().strftime('%Y-%m-%d-%H')
        
        stats = {}
        for policy in self.active_policies:
            hour_key = f"{policy.name}_{current_hour}"
            executions_this_hour = self.policy_execution_counts.get(hour_key, 0)
            last_execution = self.last_execution_times.get(policy.name)
            
            stats[policy.name] = {
                'executions_this_hour': executions_this_hour,
                'max_executions_per_hour': policy.max_executions_per_hour,
                'cooldown_period': policy.cooldown_period,
                'last_execution': last_execution.isoformat() if last_execution else None,
                'can_execute_now': (
                    executions_this_hour < policy.max_executions_per_hour and
                    (not last_execution or 
                     (datetime.now() - last_execution).total_seconds() >= policy.cooldown_period)
                )
            }
        
        return stats
    
    # 강화학습 연동 메서드들
    async def _initialize_rl_agent(self):
        """강화학습 에이전트 초기화"""
        try:
            from core.rl_adaptation.rl_mtd_integration import MTDRLAgent
            
            rl_config = self.config.get('rl_config', {})
            self.rl_agent = MTDRLAgent(rl_config)
            
            self.logger.info("강화학습 에이전트 초기화 완료")
            
        except ImportError as e:
            self.logger.warning(f"강화학습 모듈을 불러올 수 없음: {e}")
            self.rl_enabled = False
        except Exception as e:
            self.logger.error(f"강화학습 에이전트 초기화 실패: {e}")
            self.rl_enabled = False
    
    async def get_rl_recommended_action(self, context: MTDDecisionContext) -> Optional[MTDAction]:
        """강화학습 기반 액션 추천"""
        if not self.rl_enabled or not self.rl_agent:
            return None
        
        try:
            # 컨텍스트를 RL 상태로 변환
            from core.rl_adaptation.rl_mtd_integration import MTDState
            
            rl_state = MTDState(
                attack_detected=len(context.current_attacks) > 0,
                attack_type=context.current_attacks[0].get('attack_type', 'none') if context.current_attacks else 'none',
                attack_success_rate=context.current_attacks[0].get('success_rate', 0.0) if context.current_attacks else 0.0,
                system_load=context.system_performance.get('cpu_usage', 0.5),
                network_latency=context.network_state.get('average_latency', 50.0),
                previous_mtd_actions=[r.strategy.value for r in context.recent_mtd_actions[-5:]],
                time_since_last_attack=context.network_state.get('time_since_last_attack', 3600.0),
                threat_level=max([threat.get('severity', 1) for threat in context.threat_intelligence], default=1),
                active_connections=context.network_state.get('active_nodes', 5),
                resource_usage=context.system_performance.get('resource_usage', 0.3)
            )
            
            # RL 에이전트에서 액션 선택
            action_index = self.rl_agent.select_action(rl_state, training=False)
            recommended_strategy = list(MTDStrategyType)[action_index]
            
            # MTD 액션으로 변환
            rl_action = MTDAction(
                strategy=recommended_strategy,
                target_node="auto_select",
                parameters={'source': 'reinforcement_learning'},
                cost=0.3,
                expected_effectiveness=0.7,
                priority=1
            )
            
            return rl_action
            
        except Exception as e:
            self.logger.error(f"RL 액션 추천 실패: {e}")
            return None
    
    async def provide_rl_feedback(self, action: MTDAction, result: MTDActionResult, 
                                 context_before: MTDDecisionContext, 
                                 context_after: MTDDecisionContext):
        """강화학습에 피드백 제공"""
        if not self.rl_enabled or not self.rl_agent:
            return
        
        try:
            from core.rl_adaptation.rl_mtd_integration import MTDState
            
            # 이전 상태
            state_before = MTDState(
                attack_detected=len(context_before.current_attacks) > 0,
                attack_type=context_before.current_attacks[0].get('attack_type', 'none') if context_before.current_attacks else 'none',
                attack_success_rate=context_before.current_attacks[0].get('success_rate', 0.0) if context_before.current_attacks else 0.0,
                system_load=context_before.system_performance.get('cpu_usage', 0.5),
                network_latency=context_before.network_state.get('average_latency', 50.0),
                previous_mtd_actions=[r.strategy.value for r in context_before.recent_mtd_actions[-5:]],
                time_since_last_attack=context_before.network_state.get('time_since_last_attack', 3600.0),
                threat_level=max([threat.get('severity', 1) for threat in context_before.threat_intelligence], default=1),
                active_connections=context_before.network_state.get('active_nodes', 5),
                resource_usage=context_before.system_performance.get('resource_usage', 0.3)
            )
            
            # 이후 상태
            state_after = MTDState(
                attack_detected=len(context_after.current_attacks) > 0,
                attack_type=context_after.current_attacks[0].get('attack_type', 'none') if context_after.current_attacks else 'none',
                attack_success_rate=context_after.current_attacks[0].get('success_rate', 0.0) if context_after.current_attacks else 0.0,
                system_load=context_after.system_performance.get('cpu_usage', 0.5),
                network_latency=context_after.network_state.get('average_latency', 50.0),
                previous_mtd_actions=[r.strategy.value for r in context_after.recent_mtd_actions[-5:]],
                time_since_last_attack=context_after.network_state.get('time_since_last_attack', 3600.0),
                threat_level=max([threat.get('severity', 1) for threat in context_after.threat_intelligence], default=1),
                active_connections=context_after.network_state.get('active_nodes', 5),
                resource_usage=context_after.system_performance.get('resource_usage', 0.3)
            )
            
            # 액션 인덱스
            action_index = list(MTDStrategyType).index(action.strategy)
            
            # 보상 계산
            reward = self.rl_agent.calculate_reward(
                state_before, action_index, state_after,
                attack_prevented=result.success and len(context_after.current_attacks) < len(context_before.current_attacks),
                mtd_success=result.success
            )
            
            # 경험 저장
            self.rl_agent.remember(
                state_before, action_index, reward, state_after,
                done=False  # 연속적인 환경이므로 episode 종료 없음
            )
            
            # 주기적 학습
            if len(self.rl_agent.memory) >= self.rl_agent.batch_size:
                loss = self.rl_agent.replay()
                if loss:
                    self.metrics_collector.record_metric('rl_training_loss', loss)
            
        except Exception as e:
            self.logger.error(f"RL 피드백 제공 실패: {e}")
    
    # 유틸리티 메서드들
    async def _is_network_stable(self) -> bool:
        """네트워크 안정성 확인"""
        if not hasattr(self.network_manager, 'network_performance'):
            return True
        
        performance = self.network_manager.network_performance
        
        # 패킷 전달률이 80% 이상이고 토폴로지가 안정적이면 안정
        return (performance.get('packet_delivery_ratio', 0) > 0.8 and
                performance.get('topology_stability', 0) > 0.7)
    
    async def _has_sufficient_energy(self, target_node: str) -> bool:
        """충분한 에너지 확인"""
        if target_node == "auto_select" or target_node == "all_active":
            # 전체 노드 평균 배터리 확인
            if not self.network_manager.nodes:
                return False
            
            avg_battery = sum(node.battery_level for node in self.network_manager.nodes.values()) / len(self.network_manager.nodes)
            return avg_battery > 30.0  # 30% 이상
        
        elif target_node in self.network_manager.nodes:
            node = self.network_manager.nodes[target_node]
            return node.battery_level > 20.0  # 20% 이상
        
        return True  # 알 수 없는 경우 허용
    
    async def _has_ongoing_mtd_actions(self) -> bool:
        """진행 중인 MTD 액션 확인"""
        # 최근 30초 내에 실행된 액션이 있는지 확인
        if not self.action_history:
            return False
        
        last_action_time = self.action_history[-1].timestamp
        time_diff = (datetime.now() - last_action_time).total_seconds()
        
        return time_diff < 30.0
    
    async def _collect_final_mtd_data(self):
        """최종 MTD 데이터 수집"""
        final_data = {
            'mtd_engine_final_state': {
                'total_actions_executed': len(self.action_history),
                'final_success_rate': self._calculate_overall_success_rate(),
                'final_effectiveness': self._calculate_average_effectiveness(),
                'final_cost': self._calculate_average_cost(),
                'strategy_distribution': self._get_strategy_distribution(),
                'strategy_performance': self._analyze_strategy_performance(),
                'policy_performance': self._analyze_policy_performance(),
                'rl_enabled': self.rl_enabled,
                'experiment_duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            },
            'action_history_summary': {
                'most_used_strategy': max(self._get_strategy_distribution().items(), key=lambda x: x[1])[0] if self.action_history else None,
                'most_effective_strategy': self._get_most_effective_strategy(),
                'least_costly_strategy': self._get_least_costly_strategy(),
                'fastest_strategy': self._get_fastest_strategy()
            }
        }
        
        research_collector.record_performance(final_data)
    
    def _get_most_effective_strategy(self) -> Optional[str]:
        """가장 효과적인 전략"""
        strategy_effectiveness = {}
        
        for action in self.action_history:
            strategy = action.strategy.value
            if strategy not in strategy_effectiveness:
                strategy_effectiveness[strategy] = []
            strategy_effectiveness[strategy].append(action.effectiveness)
        
        if not strategy_effectiveness:
            return None
        
        avg_effectiveness = {s: sum(values)/len(values) 
                           for s, values in strategy_effectiveness.items()}
        
        return max(avg_effectiveness.items(), key=lambda x: x[1])[0]
    
    def _get_least_costly_strategy(self) -> Optional[str]:
        """가장 비용 효율적인 전략"""
        strategy_costs = {}
        
        for action in self.action_history:
            strategy = action.strategy.value
            if strategy not in strategy_costs:
                strategy_costs[strategy] = []
            strategy_costs[strategy].append(action.cost)
        
        if not strategy_costs:
            return None
        
        avg_costs = {s: sum(values)/len(values) 
                    for s, values in strategy_costs.items()}
        
        return min(avg_costs.items(), key=lambda x: x[1])[0]
    
    def _get_fastest_strategy(self) -> Optional[str]:
        """가장 빠른 전략"""
        strategy_times = {}
        
        for action in self.action_history:
            strategy = action.strategy.value
            if strategy not in strategy_times:
                strategy_times[strategy] = []
            strategy_times[strategy].append(action.execution_time)
        
        if not strategy_times:
            return None
        
        avg_times = {s: sum(values)/len(values) 
                    for s, values in strategy_times.items()}
        
        return min(avg_times.items(), key=lambda x: x[1])[0]