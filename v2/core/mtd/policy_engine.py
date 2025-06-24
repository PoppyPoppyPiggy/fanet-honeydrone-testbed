# core/mtd/policy_engine.py
import random
from typing import List, Tuple
from dataclasses import dataclass
from core.base import BaseManager, MTDStrategyType

@dataclass
class MTDAction:
    strategy: MTDStrategyType
    target_node: str
    parameters: Dict[str, Any]
    cost: float
    expected_effectiveness: float

@dataclass
class TriggerCondition:
    condition_type: str  # 'attack_detected', 'time_based', 'energy_based'
    threshold: float
    operator: str  # '>', '<', '==', '!='

class MTDPolicyEngine(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus, network_manager):
        super().__init__(config)
        self.event_bus = event_bus
        self.network_manager = network_manager
        self.active_policies: List[MTDPolicy] = []
        self.action_history: List[MTDAction] = []
        
        # 강화학습 에이전트 (나중에 구현)
        self.rl_agent = None
        
    async def start(self):
        """MTD 엔진 시작"""
        self._running = True
        self.logger.info("MTD Policy Engine started")
        
        # 이벤트 구독
        self.event_bus.subscribe('attack_detected', self._handle_attack_detected)
        self.event_bus.subscribe('node_compromised', self._handle_node_compromised)
        
        # 주기적 MTD 실행
        asyncio.create_task(self._periodic_mtd_execution())
    
    async def stop(self):
        """MTD 엔진 중지"""
        self._running = False
        self.logger.info("MTD Policy Engine stopped")
    
    async def status(self) -> Dict[str, Any]:
        """MTD 엔진 상태"""
        return {
            'active_policies': len(self.active_policies),
            'total_actions': len(self.action_history),
            'last_action': self.action_history[-1] if self.action_history else None,
            'avg_cost': sum(a.cost for a in self.action_history[-10:]) / min(10, len(self.action_history))
        }
    
    async def execute_mtd_action(self, action: MTDAction) -> bool:
        """MTD 액션 실행"""
        try:
            if action.strategy == MTDStrategyType.IP_HOPPING:
                success = await self._execute_ip_hopping(action)
            elif action.strategy == MTDStrategyType.PORT_RANDOMIZATION:
                success = await self._execute_port_randomization(action)
            elif action.strategy == MTDStrategyType.FREQUENCY_HOPPING:
                success = await self._execute_frequency_hopping(action)
            elif action.strategy == MTDStrategyType.TOPOLOGY_MUTATION:
                success = await self._execute_topology_mutation(action)
            elif action.strategy == MTDStrategyType.SERVICE_MIGRATION:
                success = await self._execute_service_migration(action)
            else:
                self.logger.warning(f"Unknown MTD strategy: {action.strategy}")
                return False
            
            if success:
                self.action_history.append(action)
                await self.event_bus.publish('mtd_action_executed', {
                    'action': action,
                    'timestamp': datetime.now()
                })
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to execute MTD action: {e}")
            return False
    
    async def _execute_ip_hopping(self, action: MTDAction) -> bool:
        """IP 주소 호핑 실행"""
        node_id = action.target_node
        if node_id not in self.network_manager.nodes:
            return False
        
        node = self.network_manager.nodes[node_id]
        
        # 새로운 IP 주소 생성
        new_position = Position3D(
            x=random.uniform(-100, 100),
            y=random.uniform(-100, 100),
            z=node.position.z  # Z축은 유지
        )
        
        # 가상의 네트워크 주소 변경
        old_config = node.network_config
        new_config = self.network_manager._generate_network_config(new_position)
        node.network_config = new_config
        
        self.logger.info(f"IP hopping executed for {node_id}: {old_config.ip_address} -> {new_config.ip_address}")
        return True
    
    async def _execute_port_randomization(self, action: MTDAction) -> bool:
        """포트 랜덤화 실행"""
        node_id = action.target_node
        if node_id not in self.network_manager.nodes:
            return False
        
        node = self.network_manager.nodes[node_id]
        old_port = node.network_config.port
        
        # 새로운 포트 할당 (8000-9000 범위)
        new_port = random.randint(8000, 9000)
        node.network_config.port = new_port
        
        self.logger.info(f"Port randomization executed for {node_id}: {old_port} -> {new_port}")
        return True
    
    async def _execute_frequency_hopping(self, action: MTDAction) -> bool:
        """주파수 호핑 실행"""
        node_id = action.target_node
        if node_id not in self.network_manager.nodes:
            return False
        
        # 주파수 변경 시뮬레이션 (실제로는 무선 인터페이스 설정 변경)
        frequencies = [2412, 2437, 2462, 5180, 5200, 5220]  # MHz
        new_frequency = random.choice(frequencies)
        
        self.logger.info(f"Frequency hopping executed for {node_id}: new frequency {new_frequency} MHz")
        return True
    
    async def _execute_topology_mutation(self, action: MTDAction) -> bool:
        """토폴로지 변형 실행"""
        node_id = action.target_node
        if node_id not in self.network_manager.nodes:
            return False
        
        node = self.network_manager.nodes[node_id]
        
        # 노드 위치를 크게 변경하여 연결성 변화
        new_position = Position3D(
            x=node.position.x + random.uniform(-50, 50),
            y=node.position.y + random.uniform(-50, 50),
            z=node.position.z + random.uniform(-20, 20)
        )
        
        await self.network_manager.update_node_position(node_id, new_position)
        
        self.logger.info(f"Topology mutation executed for {node_id}")
        return True
    
    async def _execute_service_migration(self, action: MTDAction) -> bool:
        """서비스 마이그레이션 실행"""
        node_id = action.target_node
        if node_id not in self.network_manager.nodes:
            return False
        
        # 서비스를 다른 노드로 마이그레이션 시뮬레이션
        available_nodes = [nid for nid in self.network_manager.nodes.keys() if nid != node_id]
        if not available_nodes:
            return False
        
        target_node = random.choice(available_nodes)
        
        self.logger.info(f"Service migration executed: {node_id} -> {target_node}")
        return True
    
    async def _handle_attack_detected(self, attack_data: Dict[str, Any]):
        """공격 탐지 시 MTD 대응"""
        attack_type = attack_data.get('attack_type')
        target_node = attack_data.get('target_node')
        
        # 공격 유형에 따른 MTD 전략 선택
        if attack_type == AttackType.GPS_SPOOFING:
            strategy = MTDStrategyType.TOPOLOGY_MUTATION
        elif attack_type == AttackType.MAVLINK_INJECTION:
            strategy = MTDStrategyType.PORT_RANDOMIZATION
        else:
            strategy = MTDStrategyType.IP_HOPPING
        
        action = MTDAction(
            strategy=strategy,
            target_node=target_node,
            parameters={'trigger': 'attack_detected'},
            cost=0.3,
            expected_effectiveness=0.8
        )
        
        await self.execute_mtd_action(action)
    
    async def _handle_node_compromised(self, compromise_data: Dict[str, Any]):
        """노드 침해 시 격리 및 마이그레이션"""
        compromised_node = compromise_data.get('node_id')
        
        # 서비스 마이그레이션 실행
        migration_action = MTDAction(
            strategy=MTDStrategyType.SERVICE_MIGRATION,
            target_node=compromised_node,
            parameters={'trigger': 'node_compromised'},
            cost=0.8,
            expected_effectiveness=0.9
        )
        
        await self.execute_mtd_action(migration_action)
    
    async def _periodic_mtd_execution(self):
        """주기적 MTD 실행"""
        while self._running:
            # 시간 기반 MTD 전략 실행
            for node_id in self.network_manager.nodes:
                if random.random() < 0.1:  # 10% 확률로 랜덤 MTD
                    strategy = random.choice(list(MTDStrategyType))
                    action = MTDAction(
                        strategy=strategy,
                        target_node=node_id,
                        parameters={'trigger': 'periodic'},
                        cost=0.2,
                        expected_effectiveness=0.5
                    )
                    await self.execute_mtd_action(action)
            
            await asyncio.sleep(30)  # 30초마다 실행