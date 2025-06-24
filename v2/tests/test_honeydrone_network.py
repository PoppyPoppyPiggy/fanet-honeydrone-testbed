# tests/test_honeydrone_network.py
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from datetime import datetime

from core.base import EventBus, Position3D, NetworkConfig, MTDStatus, SecurityState, DroneState
from core.honeydrone.network_manager import HoneydroneNetworkManager

class TestHoneydroneNetworkManager:
    @pytest.fixture
    async def network_manager(self):
        """네트워크 매니저 테스트 픽스처"""
        config = {
            'network_range': '10.0.0.0/16',
            'communication_range': 100.0,
            'initial_node_count': 3
        }
        event_bus = EventBus()
        manager = HoneydroneNetworkManager(config, event_bus)
        await manager.start()
        yield manager
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_add_node(self, network_manager):
        """노드 추가 테스트"""
        position = Position3D(x=10.0, y=20.0, z=30.0)
        node = await network_manager.add_node("test_drone", position)
        
        assert node.id == "test_drone"
        assert node.position.x == 10.0
        assert node.position.y == 20.0
        assert node.position.z == 30.0
        assert node.state == DroneState.ACTIVE
        assert "test_drone" in network_manager.nodes
    
    @pytest.mark.asyncio
    async def test_update_position(self, network_manager):
        """위치 업데이트 테스트"""
        position = Position3D(x=0.0, y=0.0, z=10.0)
        node = await network_manager.add_node("test_drone", position)
        
        new_position = Position3D(x=50.0, y=50.0, z=20.0)
        await network_manager.update_node_position("test_drone", new_position)
        
        updated_node = network_manager.nodes["test_drone"]
        assert updated_node.position.x == 50.0
        assert updated_node.position.y == 50.0
        assert updated_node.position.z == 20.0
        assert updated_node.battery_level < 100.0  # 에너지 소모 확인
    
    @pytest.mark.asyncio
    async def test_connected_nodes(self, network_manager):
        """연결된 노드 테스트"""
        # 가까운 두 노드 생성
        pos1 = Position3D(x=0.0, y=0.0, z=10.0)
        pos2 = Position3D(x=50.0, y=0.0, z=10.0)  # 50m 거리
        
        await network_manager.add_node("drone1", pos1)
        await network_manager.add_node("drone2", pos2)
        
        connected = await network_manager.get_connected_nodes("drone1")
        assert "drone2" in connected
    
    @pytest.mark.asyncio
    async def test_network_config_generation(self, network_manager):
        """네트워크 설정 생성 테스트"""
        position = Position3D(x=10.5, y=20.3, z=30.7)
        config = network_manager._generate_network_config(position)
        
        assert config.ip_address.startswith("10.")
        assert config.port >= 8000
        assert config.subnet.endswith("/24")
        assert config.gateway.endswith(".254")
