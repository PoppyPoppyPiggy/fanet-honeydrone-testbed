# core/honeydrone/network_manager.py
import math
import random
from typing import Set
from core.base import BaseManager, DroneNode, Position3D, NetworkConfig, MTDStatus, SecurityState, DroneState

class HoneydroneNetworkManager(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus):
        super().__init__(config)
        self.event_bus = event_bus
        self.nodes: Dict[str, DroneNode] = {}
        self.topology_matrix: Dict[str, Dict[str, float]] = {}
        self.network_range = config.get('network_range', '10.0.0.0/16')
        self.communication_range = config.get('communication_range', 100.0)
        
    async def start(self):
        """네트워크 매니저 시작"""
        self._running = True
        self.logger.info("Honeydrone Network Manager started")
        
        # 초기 노드 생성
        await self._initialize_nodes()
        
        # 주기적 상태 업데이트 시작
        asyncio.create_task(self._periodic_update())
    
    async def stop(self):
        """네트워크 매니저 중지"""
        self._running = False
        self.logger.info("Honeydrone Network Manager stopped")
    
    async def status(self) -> Dict[str, Any]:
        """현재 네트워크 상태 반환"""
        return {
            'node_count': len(self.nodes),
            'active_nodes': len([n for n in self.nodes.values() if n.state == DroneState.ACTIVE]),
            'compromised_nodes': len([n for n in self.nodes.values() if n.state == DroneState.COMPROMISED]),
            'topology_changes': self._calculate_topology_stability()
        }
    
    async def add_node(self, node_id: str, position: Position3D) -> DroneNode:
        """새 드론 노드 추가"""
        network_config = self._generate_network_config(position)
        mtd_status = MTDStatus(
            active_strategies=[],
            last_change=datetime.now(),
            change_frequency=1.0,
            cost_factor=0.0
        )
        security_state = SecurityState(
            threat_level=0,
            attack_detected=False,
            attack_type=None,
            last_attack=None,
            compromised=False
        )
        
        node = DroneNode(
            id=node_id,
            position=position,
            battery_level=100.0,
            network_config=network_config,
            mtd_status=mtd_status,
            security_state=security_state
        )
        
        self.nodes[node_id] = node
        await self._update_topology()
        
        await self.event_bus.publish('node_added', {
            'node_id': node_id,
            'position': position,
            'network_config': network_config
        })
        
        return node
    
    async def update_node_position(self, node_id: str, new_position: Position3D):
        """노드 위치 업데이트"""
        if node_id not in self.nodes:
            raise ValueError(f"Node {node_id} not found")
        
        old_position = self.nodes[node_id].position
        self.nodes[node_id].position = new_position
        
        # 에너지 소모 계산
        distance = self._calculate_distance(old_position, new_position)
        energy_cost = distance * 0.1  # 단순한 에너지 모델
        self.nodes[node_id].battery_level = max(0, self.nodes[node_id].battery_level - energy_cost)
        
        # 네트워크 구성 업데이트 (3D 좌표 기반)
        self.nodes[node_id].network_config = self._generate_network_config(new_position)
        
        await self._update_topology()
        
        await self.event_bus.publish('node_moved', {
            'node_id': node_id,
            'old_position': old_position,
            'new_position': new_position,
            'energy_cost': energy_cost
        })
    
    async def get_connected_nodes(self, node_id: str) -> Set[str]:
        """특정 노드와 연결된 노드들 반환"""
        if node_id not in self.nodes:
            return set()
        
        connected = set()
        node_position = self.nodes[node_id].position
        
        for other_id, other_node in self.nodes.items():
            if other_id != node_id:
                distance = self._calculate_distance(node_position, other_node.position)
                if distance <= self.communication_range:
                    # 에너지 기반 통신 가능성 체크
                    if self._can_communicate(node_id, other_id):
                        connected.add(other_id)
        
        return connected
    
    def _generate_network_config(self, position: Position3D) -> NetworkConfig:
        """3D 위치를 네트워크 주소로 매핑"""
        # X축 -> 서브넷, Y축 -> 호스트, Z축 -> 포트 오프셋
        subnet_x = int(abs(position.x) % 256)
        host_y = int(abs(position.y) % 256)
        port_offset = int(abs(position.z) % 100) * 10
        
        ip_address = f"10.{subnet_x}.{host_y}.1"
        port = 8000 + port_offset
        subnet = f"10.{subnet_x}.{host_y}.0/24"
        gateway = f"10.{subnet_x}.{host_y}.254"
        
        return NetworkConfig(
            ip_address=ip_address,
            port=port,
            subnet=subnet,
            gateway=gateway,
            interface=f"fanet{subnet_x}"
        )
    
    def _calculate_distance(self, pos1: Position3D, pos2: Position3D) -> float:
        """3D 유클리드 거리 계산"""
        return math.sqrt(
            (pos1.x - pos2.x)**2 + 
            (pos1.y - pos2.y)**2 + 
            (pos1.z - pos2.z)**2
        )
    
    def _can_communicate(self, node1_id: str, node2_id: str) -> bool:
        """두 노드 간 통신 가능성 체크 (에너지 기반)"""
        node1 = self.nodes[node1_id]
        node2 = self.nodes[node2_id]
        
        # 배터리 레벨이 낮으면 통신 범위 감소
        battery_factor1 = node1.battery_level / 100.0
        battery_factor2 = node2.battery_level / 100.0
        
        effective_range = self.communication_range * min(battery_factor1, battery_factor2)
        distance = self._calculate_distance(node1.position, node2.position)
        
        return distance <= effective_range
    
    async def _initialize_nodes(self):
        """초기 노드 설정"""
        node_count = self.config.get('initial_node_count', 6)
        
        for i in range(node_count):
            position = Position3D(
                x=random.uniform(-100, 100),
                y=random.uniform(-100, 100),
                z=random.uniform(10, 100)
            )
            await self.add_node(f"drone_{i}", position)
    
    async def _update_topology(self):
        """네트워크 토폴로지 업데이트"""
        self.topology_matrix = {}
        
        for node_id in self.nodes:
            self.topology_matrix[node_id] = {}
            for other_id in self.nodes:
                if node_id != other_id:
                    distance = self._calculate_distance(
                        self.nodes[node_id].position,
                        self.nodes[other_id].position
                    )
                    self.topology_matrix[node_id][other_id] = distance
    
    def _calculate_topology_stability(self) -> float:
        """토폴로지 안정성 계산"""
        if len(self.nodes) < 2:
            return 1.0
        
        connected_pairs = 0
        total_pairs = 0
        
        for node_id in self.nodes:
            for other_id in self.nodes:
                if node_id != other_id:
                    total_pairs += 1
                    if self._can_communicate(node_id, other_id):
                        connected_pairs += 1
        
        return connected_pairs / total_pairs if total_pairs > 0 else 0.0
    
    async def _periodic_update(self):
        """주기적 상태 업데이트"""
        while self._running:
            # 배터리 자연 소모
            for node in self.nodes.values():
                node.battery_level = max(0, node.battery_level - 0.1)
            
            # 토폴로지 업데이트
            await self._update_topology()
            
            # 상태 이벤트 발생
            await self.event_bus.publish('network_updated', await self.status())
            
            await asyncio.sleep(5)  # 5초마다 업데이트