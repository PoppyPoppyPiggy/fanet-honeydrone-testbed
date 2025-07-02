# core/honeydrone/network_manager.py - 향상된 허니드론 네트워크 매니저
import math
import random
import asyncio
from datetime import datetime, timedelta
from typing import Set, List, Tuple, Optional
from core.base import (
    BaseManager, DroneNode, Position3D, NetworkConfig, MTDStatus, 
    SecurityState, DroneState, DroneCapabilities, EventBus, 
    research_collector, MetricsCollector
)

class HoneydroneNetworkManager(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus):
        super().__init__(config)
        self.event_bus = event_bus
        self.nodes: Dict[str, DroneNode] = {}
        self.topology_matrix: Dict[str, Dict[str, float]] = {}
        self.network_range = config.get('network_range', '10.0.0.0/16')
        self.communication_range = config.get('communication_range', 100.0)
        self.metrics_collector = MetricsCollector()
        
        # 허니드론 특화 설정
        self.honeypot_ratio = config.get('honeypot_ratio', 0.3)  # 30% 허니팟
        self.decoy_capabilities = config.get('decoy_capabilities', {
            'fake_vulnerabilities': True,
            'traffic_simulation': True,
            'behavioral_mimicry': True
        })
        
        # 네트워크 성능 추적
        self.network_performance = {
            'packet_delivery_ratio': 0.0,
            'average_latency': 0.0,
            'throughput': 0.0,
            'topology_stability': 0.0
        }
        
        # 실험 데이터 수집
        self.experiment_active = False
        self.data_collection_interval = config.get('data_collection_interval', 30)
        
    async def start(self):
        """네트워크 매니저 시작"""
        await super().start()
        
        # 초기 노드 생성
        await self._initialize_network_topology()
        
        # 주기적 업데이트 태스크 시작
        asyncio.create_task(self._periodic_network_update())
        asyncio.create_task(self._periodic_data_collection())
        
        # 허니팟 노드 배치
        await self._deploy_honeypot_nodes()
        
    async def stop(self):
        """네트워크 매니저 중지"""
        await super().stop()
        
        # 최종 데이터 수집
        if self.experiment_active:
            await self._collect_final_experiment_data()
    
    async def status(self) -> Dict[str, Any]:
        """현재 네트워크 상태 반환"""
        base_status = await super().status()
        
        network_status = {
            'node_count': len(self.nodes),
            'active_nodes': len([n for n in self.nodes.values() if n.state == DroneState.ACTIVE]),
            'honeypot_nodes': len([n for n in self.nodes.values() if n.capabilities and n.capabilities.honeypot_enabled]),
            'compromised_nodes': len([n for n in self.nodes.values() if n.state == DroneState.COMPROMISED]),
            'network_performance': self.network_performance,
            'topology_stability': self._calculate_topology_stability(),
            'communication_graph': self._get_communication_graph_stats()
        }
        
        return {**base_status, **network_status}
    
    async def add_node(self, node_id: str, position: Position3D, 
                      node_type: str = 'regular', 
                      capabilities: Optional[DroneCapabilities] = None) -> DroneNode:
        """드론 노드 추가 (타입별 특성 적용)"""
        
        # 네트워크 설정 생성
        network_config = self._generate_network_config(position)
        
        # MTD 상태 초기화
        mtd_status = MTDStatus(
            active_strategies=[],
            last_change=datetime.now(),
            change_frequency=1.0,
            cost_factor=0.0,
            effectiveness_score=0.0
        )
        
        # 보안 상태 초기화
        security_state = SecurityState(
            threat_level=0,
            attack_detected=False,
            attack_type=None,
            last_attack=None,
            compromised=False,
            vulnerability_score=0.0 if node_type != 'honeypot' else 0.8,  # 허니팟은 취약하게 설정
            detection_confidence=0.0
        )
        
        # 노드 타입별 능력 설정
        if not capabilities:
            capabilities = self._generate_capabilities_by_type(node_type)
        
        # 드론 노드 생성
        node = DroneNode(
            id=node_id,
            position=position,
            battery_level=100.0,
            network_config=network_config,
            mtd_status=mtd_status,
            security_state=security_state,
            state=DroneState.ACTIVE,
            capabilities=capabilities
        )
        
        self.nodes[node_id] = node
        await self._update_topology()
        
        # 이벤트 발행
        await self.event_bus.publish('node_added', {
            'node_id': node_id,
            'node_type': node_type,
            'position': {'x': position.x, 'y': position.y, 'z': position.z},
            'capabilities': capabilities.__dict__ if capabilities else None
        })
        
        # 메트릭 업데이트
        self.metrics_collector.record_metric('nodes_total', len(self.nodes))
        self.update_metric('total_nodes', len(self.nodes))
        
        return node
    
    def _generate_capabilities_by_type(self, node_type: str) -> DroneCapabilities:
        """노드 타입별 능력 생성"""
        base_capabilities = DroneCapabilities(
            flight_time=30.0,  # 30분
            max_speed=15.0,    # 15 m/s
            communication_range=100.0,  # 100m
            payload_capacity=2.0,  # 2kg
            sensor_types=['camera', 'gps', 'imu'],
            mtd_capable=True,
            honeypot_enabled=False
        )
        
        if node_type == 'honeypot':
            # 허니팟 노드: 의도적으로 취약하게 설정
            base_capabilities.honeypot_enabled = True
            base_capabilities.sensor_types.extend(['fake_military_sensor', 'decoy_payload'])
            
        elif node_type == 'high_value':
            # 고부가가치 노드: 강력한 능력
            base_capabilities.flight_time = 60.0
            base_capabilities.max_speed = 25.0
            base_capabilities.payload_capacity = 5.0
            base_capabilities.sensor_types.extend(['lidar', 'thermal', 'radar'])
            
        elif node_type == 'scout':
            # 정찰 노드: 빠르고 은밀
            base_capabilities.max_speed = 30.0
            base_capabilities.communication_range = 150.0
            base_capabilities.sensor_types.extend(['long_range_camera'])
            
        return base_capabilities
    
    async def update_node_position(self, node_id: str, new_position: Position3D):
        """노드 위치 업데이트 (에너지 모델 포함)"""
        if node_id not in self.nodes:
            raise ValueError(f"Node {node_id} not found")
        
        old_position = self.nodes[node_id].position
        node = self.nodes[node_id]
        
        # 이동 거리 계산
        distance = old_position.distance_to(new_position)
        
        # 에너지 소모 모델 (드론 특성 반영)
        if node.capabilities:
            speed = min(distance / 1.0, node.capabilities.max_speed)  # 1초 간격 가정
            energy_cost_per_meter = 0.1 + (speed / node.capabilities.max_speed) * 0.2
            energy_cost = distance * energy_cost_per_meter
            
            # 고도 변화에 따른 추가 에너지 소모
            altitude_change = abs(new_position.z - old_position.z)
            energy_cost += altitude_change * 0.15
        else:
            energy_cost = distance * 0.1  # 기본 에너지 모델
        
        # 배터리 업데이트
        node.battery_level = max(0, node.battery_level - energy_cost)
        node.position = new_position
        node.update_last_seen()
        
        # 저배터리 상태 처리
        if node.battery_level < 20.0 and node.state == DroneState.ACTIVE:
            node.state = DroneState.INACTIVE
            await self.event_bus.publish('node_low_battery', {
                'node_id': node_id,
                'battery_level': node.battery_level
            })
        
        # 네트워크 구성 업데이트 (위치 기반)
        node.network_config = self._generate_network_config(new_position)
        
        # 토폴로지 업데이트
        await self._update_topology()
        
        # 이벤트 발행
        await self.event_bus.publish('node_moved', {
            'node_id': node_id,
            'old_position': {'x': old_position.x, 'y': old_position.y, 'z': old_position.z},
            'new_position': {'x': new_position.x, 'y': new_position.y, 'z': new_position.z},
            'distance_moved': distance,
            'energy_cost': energy_cost,
            'battery_remaining': node.battery_level
        })
        
        # 연구 데이터 수집
        if self.experiment_active:
            research_collector.record_network_state({
                'node_id': node_id,
                'position': new_position.__dict__,
                'battery_level': node.battery_level,
                'energy_cost': energy_cost,
                'movement_distance': distance
            })
    
    async def get_connected_nodes(self, node_id: str) -> Set[str]:
        """연결된 노드들 반환 (3D 통신 모델)"""
        if node_id not in self.nodes:
            return set()
        
        connected = set()
        source_node = self.nodes[node_id]
        
        for other_id, other_node in self.nodes.items():
            if other_id != node_id and other_node.state == DroneState.ACTIVE:
                # 3D 거리 기반 연결성 체크
                distance = source_node.position.distance_to(other_node.position)
                
                # 통신 범위 내 && 에너지 충분 && 신호 품질 좋음
                if (distance <= self._get_effective_communication_range(source_node) and 
                    self._can_communicate(node_id, other_id) and
                    self._check_signal_quality(source_node, other_node, distance)):
                    connected.add(other_id)
        
        return connected
    
    def _get_effective_communication_range(self, node: DroneNode) -> float:
        """효과적 통신 범위 계산 (배터리, 환경 고려)"""
        base_range = self.communication_range
        
        if node.capabilities:
            base_range = node.capabilities.communication_range
        
        # 배터리 레벨에 따른 범위 조정
        battery_factor = max(0.3, node.battery_level / 100.0)  # 최소 30% 범위 보장
        
        # MTD 상태에 따른 조정 (일부 MTD는 통신 범위 영향)
        mtd_factor = 1.0
        if hasattr(node.mtd_status, 'active_strategies'):
            for strategy in node.mtd_status.active_strategies:
                if strategy.value in ['frequency_hopping', 'protocol_switching']:
                    mtd_factor *= 0.9  # 10% 감소
        
        return base_range * battery_factor * mtd_factor
    
    def _check_signal_quality(self, node1: DroneNode, node2: DroneNode, distance: float) -> bool:
        """신호 품질 체크 (3D 환경 고려)"""
        # 기본 신호 감쇠 모델
        signal_strength = 1.0 - (distance / self.communication_range) ** 2
        
        # 고도 차이에 따른 신호 품질 영향
        altitude_diff = abs(node1.position.z - node2.position.z)
        if altitude_diff > 50:  # 50m 이상 고도 차이
            signal_strength *= 0.8
        
        # 간섭 요소 (허니팟 노드는 의도적 간섭 생성 가능)
        interference_factor = 1.0
        if (node1.capabilities and node1.capabilities.honeypot_enabled) or \
           (node2.capabilities and node2.capabilities.honeypot_enabled):
            interference_factor *= 0.95  # 약간의 간섭
        
        # 임계값 이상일 때만 통신 가능
        return (signal_strength * interference_factor) > 0.3
    
    def _generate_network_config(self, position: Position3D) -> NetworkConfig:
        """3D 위치 기반 네트워크 설정 생성"""
        # 3D 좌표를 네트워크 주소로 매핑
        x_zone = int(abs(position.x) % 256)
        y_zone = int(abs(position.y) % 256) 
        z_zone = int(abs(position.z) % 100)
        
        # IP 주소 생성 (x, y 좌표 기반)
        ip_address = f"10.{x_zone}.{y_zone}.{random.randint(1, 254)}"
        
        # 포트 생성 (z 좌표 + 랜덤)
        port = 8000 + (z_zone * 10) + random.randint(0, 9)
        
        # 서브넷 및 게이트웨이
        subnet = f"10.{x_zone}.{y_zone}.0/24"
        gateway = f"10.{x_zone}.{y_zone}.254"
        
        # 인터페이스 이름 (고도 구간별)
        if position.z < 30:
            interface = "fanet_low"
        elif position.z < 70:
            interface = "fanet_mid"
        else:
            interface = "fanet_high"
        
        return NetworkConfig(
            ip_address=ip_address,
            port=port,
            subnet=subnet,
            gateway=gateway,
            interface=interface,
            encryption_key=self._generate_encryption_key(),
            protocol_version="fanet_v2.1"
        )
    
    def _generate_encryption_key(self) -> str:
        """암호화 키 생성"""
        import secrets
        return secrets.token_hex(16)
    
    async def _initialize_network_topology(self):
        """초기 네트워크 토폴로지 생성"""
        node_count = self.config.get('initial_node_count', 6)
        
        # 다양한 타입의 노드 배치
        node_types = ['regular', 'scout', 'high_value', 'honeypot']
        
        for i in range(node_count):
            # 3D 공간에 전략적 배치
            if i < 2:
                # 정찰 노드: 높은 고도
                position = Position3D(
                    x=random.uniform(-150, 150),
                    y=random.uniform(-150, 150),
                    z=random.uniform(80, 120)
                )
                node_type = 'scout'
            elif i < 4:
                # 일반 노드: 중간 고도
                position = Position3D(
                    x=random.uniform(-100, 100),
                    y=random.uniform(-100, 100),
                    z=random.uniform(30, 70)
                )
                node_type = 'regular'
            elif i < 5:
                # 고부가가치 노드: 보호된 위치
                position = Position3D(
                    x=random.uniform(-50, 50),
                    y=random.uniform(-50, 50),
                    z=random.uniform(40, 60)
                )
                node_type = 'high_value'
            else:
                # 허니팟 노드: 노출된 위치
                position = Position3D(
                    x=random.uniform(-200, 200),
                    y=random.uniform(-200, 200),
                    z=random.uniform(10, 50)
                )
                node_type = 'honeypot'
            
            await self.add_node(f"drone_{i}", position, node_type)
    
    async def _deploy_honeypot_nodes(self):
        """허니팟 노드 전략적 배치"""
        honeypot_nodes = [n for n in self.nodes.values() 
                         if n.capabilities and n.capabilities.honeypot_enabled]
        
        for node in honeypot_nodes:
            # 허니팟 특화 설정
            await self._configure_honeypot_behavior(node)
        
        self.logger.info(f"허니팟 노드 {len(honeypot_nodes)}개 배치 완료")
    
    async def _configure_honeypot_behavior(self, node: DroneNode):
        """허니팟 행동 설정"""
        # 가짜 취약점 노출
        node.security_state.vulnerability_score = 0.8
        
        # 허니팟 특화 네트워크 서비스 시뮬레이션
        honeypot_services = {
            'fake_military_protocol': {'port': 8443, 'vulnerability': 'buffer_overflow'},
            'decoy_telemetry': {'port': 14550, 'vulnerability': 'authentication_bypass'},
            'fake_camera_stream': {'port': 5000, 'vulnerability': 'default_credentials'}
        }
        
        # 이벤트 발행
        await self.event_bus.publish('honeypot_deployed', {
            'node_id': node.id,
            'services': honeypot_services,
            'vulnerability_score': node.security_state.vulnerability_score
        })
    
    async def _update_topology(self):
        """네트워크 토폴로지 업데이트"""
        self.topology_matrix = {}
        
        for node_id in self.nodes:
            self.topology_matrix[node_id] = {}
            for other_id in self.nodes:
                if node_id != other_id:
                    distance = self.nodes[node_id].position.distance_to(
                        self.nodes[other_id].position
                    )
                    self.topology_matrix[node_id][other_id] = distance
        
        # 토폴로지 안정성 계산
        self.network_performance['topology_stability'] = self._calculate_topology_stability()
    
    def _calculate_topology_stability(self) -> float:
        """토폴로지 안정성 계산"""
        if len(self.nodes) < 2:
            return 1.0
        
        active_nodes = [n for n in self.nodes.values() if n.state == DroneState.ACTIVE]
        if len(active_nodes) < 2:
            return 0.0
        
        connected_pairs = 0
        total_pairs = 0
        
        for node in active_nodes:
            for other_node in active_nodes:
                if node.id != other_node.id:
                    total_pairs += 1
                    distance = node.position.distance_to(other_node.position)
                    if distance <= self._get_effective_communication_range(node):
                        connected_pairs += 1
        
        connectivity = connected_pairs / total_pairs if total_pairs > 0 else 0.0
        
        # 배터리 안정성 요소
        avg_battery = sum(n.battery_level for n in active_nodes) / len(active_nodes)
        battery_stability = min(1.0, avg_battery / 50.0)  # 50% 배터리를 기준
        
        return (connectivity + battery_stability) / 2.0
    
    def _get_communication_graph_stats(self) -> Dict[str, Any]:
        """통신 그래프 통계"""
        if not self.nodes:
            return {}
        
        # 각 노드의 연결 수 계산
        connection_counts = {}
        total_connections = 0
        
        for node_id in self.nodes:
            if self.nodes[node_id].state == DroneState.ACTIVE:
                connected = len(asyncio.create_task(self.get_connected_nodes(node_id)).result() or set())
                connection_counts[node_id] = connected
                total_connections += connected
        
        # 네트워크 지름 (최대 홉 수)
        network_diameter = self._calculate_network_diameter()
        
        # 클러스터링 계수
        clustering_coefficient = self._calculate_clustering_coefficient()
        
        return {
            'total_connections': total_connections // 2,  # 양방향 연결이므로 2로 나눔
            'average_degree': total_connections / len(connection_counts) if connection_counts else 0,
            'network_diameter': network_diameter,
            'clustering_coefficient': clustering_coefficient,
            'connected_components': self._count_connected_components()
        }
    
    def _calculate_network_diameter(self) -> int:
        """네트워크 지름 계산 (최단 경로의 최대값)"""
        # 간단한 BFS 기반 구현
        active_nodes = [n.id for n in self.nodes.values() if n.state == DroneState.ACTIVE]
        if len(active_nodes) < 2:
            return 0
        
        max_distance = 0
        
        for start_node in active_nodes:
            distances = self._bfs_distances(start_node, active_nodes)
            if distances:
                max_distance = max(max_distance, max(distances.values()))
        
        return max_distance
    
    def _bfs_distances(self, start_node: str, active_nodes: List[str]) -> Dict[str, int]:
        """BFS로 최단 거리 계산"""
        distances = {start_node: 0}
        queue = [start_node]
        
        while queue:
            current = queue.pop(0)
            current_dist = distances[current]
            
            # 인접 노드 찾기
            for other_node in active_nodes:
                if (other_node not in distances and 
                    other_node != current and
                    self._are_nodes_connected(current, other_node)):
                    distances[other_node] = current_dist + 1
                    queue.append(other_node)
        
        return distances
    
    def _are_nodes_connected(self, node1_id: str, node2_id: str) -> bool:
        """두 노드가 직접 연결되었는지 확인"""
        if node1_id not in self.nodes or node2_id not in self.nodes:
            return False
        
        node1 = self.nodes[node1_id]
        node2 = self.nodes[node2_id]
        
        distance = node1.position.distance_to(node2.position)
        return (distance <= self._get_effective_communication_range(node1) and
                self._check_signal_quality(node1, node2, distance))
    
    def _calculate_clustering_coefficient(self) -> float:
        """클러스터링 계수 계산"""
        active_nodes = [n.id for n in self.nodes.values() if n.state == DroneState.ACTIVE]
        if len(active_nodes) < 3:
            return 0.0
        
        total_coefficient = 0.0
        
        for node_id in active_nodes:
            neighbors = []
            for other_id in active_nodes:
                if other_id != node_id and self._are_nodes_connected(node_id, other_id):
                    neighbors.append(other_id)
            
            if len(neighbors) < 2:
                continue
            
            # 이웃 노드들 간의 연결 수 계산
            connected_pairs = 0
            total_pairs = len(neighbors) * (len(neighbors) - 1) // 2
            
            for i, neighbor1 in enumerate(neighbors):
                for neighbor2 in neighbors[i+1:]:
                    if self._are_nodes_connected(neighbor1, neighbor2):
                        connected_pairs += 1
            
            if total_pairs > 0:
                total_coefficient += connected_pairs / total_pairs
        
        return total_coefficient / len(active_nodes) if active_nodes else 0.0
    
    def _count_connected_components(self) -> int:
        """연결된 컴포넌트 수 계산"""
        active_nodes = [n.id for n in self.nodes.values() if n.state == DroneState.ACTIVE]
        visited = set()
        components = 0
        
        for node_id in active_nodes:
            if node_id not in visited:
                self._dfs_component(node_id, active_nodes, visited)
                components += 1
        
        return components
    
    def _dfs_component(self, node_id: str, active_nodes: List[str], visited: set):
        """DFS로 연결된 컴포넌트 탐색"""
        visited.add(node_id)
        
        for other_id in active_nodes:
            if other_id not in visited and self._are_nodes_connected(node_id, other_id):
                self._dfs_component(other_id, active_nodes, visited)
    
    async def _periodic_network_update(self):
        """주기적 네트워크 상태 업데이트"""
        while self._running:
            try:
                # 배터리 자연 소모
                for node in self.nodes.values():
                    if node.state == DroneState.ACTIVE:
                        # 기본 소모 + 서비스별 추가 소모
                        base_consumption = 0.1  # 기본 0.1%/주기
                        
                        # 허니팟 노드는 추가 소모
                        if node.capabilities and node.capabilities.honeypot_enabled:
                            base_consumption += 0.05
                        
                        # MTD 활성화 시 추가 소모
                        if node.mtd_status.active_strategies:
                            base_consumption += len(node.mtd_status.active_strategies) * 0.02
                        
                        node.battery_level = max(0, node.battery_level - base_consumption)
                        
                        # 배터리 부족 시 상태 변경
                        if node.battery_level <= 0:
                            node.state = DroneState.INACTIVE
                
                # 토폴로지 업데이트
                await self._update_topology()
                
                # 네트워크 성능 메트릭 업데이트
                await self._update_network_performance()
                
                # 이벤트 발행
                await self.event_bus.publish('network_updated', await self.status())
                
                await asyncio.sleep(5)  # 5초마다 업데이트
                
            except Exception as e:
                self.logger.error(f"네트워크 업데이트 오류: {e}")
                await asyncio.sleep(10)
    
    async def _update_network_performance(self):
        """네트워크 성능 메트릭 업데이트"""
        active_nodes = [n for n in self.nodes.values() if n.state == DroneState.ACTIVE]
        
        if len(active_nodes) < 2:
            return
        
        # 패킷 전달률 시뮬레이션
        total_attempts = 0
        successful_transmissions = 0
        total_latency = 0.0
        
        for node in active_nodes:
            connected_nodes = await self.get_connected_nodes(node.id)
            
            for target_id in connected_nodes:
                total_attempts += 1
                target_node = self.nodes[target_id]
                distance = node.position.distance_to(target_node.position)
                
                # 전송 성공 확률 (거리 기반)
                success_prob = max(0.3, 1.0 - (distance / self.communication_range) ** 1.5)
                
                if random.random() < success_prob:
                    successful_transmissions += 1
                    
                    # 지연 시간 계산 (거리 + 처리 지연)
                    propagation_delay = distance / 299792458 * 1000  # 광속 기반 (ms)
                    processing_delay = random.uniform(1, 5)  # 1-5ms
                    total_latency += propagation_delay + processing_delay
        
        # 성능 메트릭 업데이트
        if total_attempts > 0:
            self.network_performance['packet_delivery_ratio'] = successful_transmissions / total_attempts
            self.network_performance['average_latency'] = total_latency / successful_transmissions if successful_transmissions > 0 else 0
        
        # 처리량 시뮬레이션 (Mbps)
        total_bandwidth = sum(10.0 for _ in active_nodes)  # 각 노드 10Mbps 가정
        utilization = min(1.0, len(active_nodes) / 10.0)  # 10개 노드에서 포화
        self.network_performance['throughput'] = total_bandwidth * utilization * self.network_performance['packet_delivery_ratio']
        
        # 메트릭 기록
        self.metrics_collector.record_metric('packet_delivery_ratio', self.network_performance['packet_delivery_ratio'])
        self.metrics_collector.record_metric('average_latency', self.network_performance['average_latency'])
        self.metrics_collector.record_metric('throughput', self.network_performance['throughput'])
    
    async def _periodic_data_collection(self):
        """주기적 연구 데이터 수집"""
        while self._running:
            try:
                if self.experiment_active:
                    # 네트워크 상태 수집
                    network_data = {
                        'timestamp': datetime.now(),
                        'active_nodes': len([n for n in self.nodes.values() if n.state == DroneState.ACTIVE]),
                        'honeypot_nodes': len([n for n in self.nodes.values() if n.capabilities and n.capabilities.honeypot_enabled]),
                        'packet_delivery_ratio': self.network_performance['packet_delivery_ratio'],
                        'average_latency': self.network_performance['average_latency'],
                        'throughput': self.network_performance['throughput'],
                        'topology_stability': self.network_performance['topology_stability'],
                        'average_battery_level': sum(n.battery_level for n in self.nodes.values()) / len(self.nodes) if self.nodes else 0
                    }
                    
                    research_collector.record_network_state(network_data)
                
                await asyncio.sleep(self.data_collection_interval)
                
            except Exception as e:
                self.logger.error(f"데이터 수집 오류: {e}")
                await asyncio.sleep(60)
    
    async def start_experiment(self, experiment_config: Dict[str, Any]):
        """실험 시작"""
        self.experiment_active = True
        self.logger.info(f"네트워크 실험 시작: {experiment_config.get('name', 'Unknown')}")
        
        await self.event_bus.publish('experiment_started', {
            'network_manager': 'honeydrone',
            'config': experiment_config
        })
    
    async def stop_experiment(self):
        """실험 중지"""
        self.experiment_active = False
        await self._collect_final_experiment_data()
        
        self.logger.info("네트워크 실험 완료")
        
        await self.event_bus.publish('experiment_stopped', {
            'network_manager': 'honeydrone'
        })
    
    async def _collect_final_experiment_data(self):
        """최종 실험 데이터 수집"""
        final_data = {
            'experiment_end': datetime.now(),
            'final_network_status': await self.status(),
            'total_metrics': self.metrics_collector.export_metrics(),
            'node_summary': {
                node_id: {
                    'final_battery': node.battery_level,
                    'final_position': node.position.__dict__,
                    'state': node.state.value,
                    'is_honeypot': node.capabilities.honeypot_enabled if node.capabilities else False
                }
                for node_id, node in self.nodes.items()
            }
        }
        
        research_collector.record_performance(final_data)
    
    # 허니팟 특화 메서드들
    async def trigger_honeypot_alert(self, node_id: str, attack_details: Dict[str, Any]):
        """허니팟 알림 트리거"""
        if node_id not in self.nodes:
            return
        
        node = self.nodes[node_id]
        if not (node.capabilities and node.capabilities.honeypot_enabled):
            return
        
        # 보안 상태 업데이트
        node.security_state.attack_detected = True
        node.security_state.last_attack = datetime.now()
        node.security_state.threat_level = min(5, node.security_state.threat_level + 1)
        
        # 허니팟 이벤트 발행
        await self.event_bus.publish('honeypot_triggered', {
            'node_id': node_id,
            'attack_details': attack_details,
            'node_position': node.position.__dict__,
            'timestamp': datetime.now()
        })
        
        self.logger.info(f"허니팟 {node_id}에서 공격 탐지: {attack_details.get('attack_type', 'unknown')}")
    
    async def get_honeypot_stats(self) -> Dict[str, Any]:
        """허니팟 통계"""
        honeypot_nodes = [n for n in self.nodes.values() 
                         if n.capabilities and n.capabilities.honeypot_enabled]
        
        if not honeypot_nodes:
            return {'honeypot_count': 0}
        
        total_attacks = sum(1 for n in honeypot_nodes if n.security_state.attack_detected)
        avg_threat_level = sum(n.security_state.threat_level for n in honeypot_nodes) / len(honeypot_nodes)
        
        return {
            'honeypot_count': len(honeypot_nodes),
            'attacks_detected': total_attacks,
            'average_threat_level': avg_threat_level,
            'active_honeypots': len([n for n in honeypot_nodes if n.state == DroneState.ACTIVE]),
            'compromised_honeypots': len([n for n in honeypot_nodes if n.state == DroneState.COMPROMISED])
        }