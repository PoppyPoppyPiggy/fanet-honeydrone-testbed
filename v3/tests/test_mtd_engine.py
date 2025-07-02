# tests/test_mtd_engine.py
import pytest
from unittest.mock import Mock, AsyncMock

from core.base import EventBus, MTDStrategyType
from core.mtd.policy_engine import MTDPolicyEngine, MTDAction

class TestMTDPolicyEngine:
    @pytest.fixture
    async def mtd_engine(self):
        """MTD 엔진 테스트 픽스처"""
        config = {}
        event_bus = EventBus()
        network_manager = Mock()
        network_manager.nodes = {"drone1": Mock(), "drone2": Mock()}
        
        engine = MTDPolicyEngine(config, event_bus, network_manager)
        await engine.start()
        yield engine
        await engine.stop()
    
    @pytest.mark.asyncio
    async def test_execute_ip_hopping(self, mtd_engine):
        """IP 호핑 실행 테스트"""
        action = MTDAction(
            strategy=MTDStrategyType.IP_HOPPING,
            target_node="drone1",
            parameters={},
            cost=0.3,
            expected_effectiveness=0.8
        )
        
        success = await mtd_engine.execute_mtd_action(action)
        assert success == True
        assert len(mtd_engine.action_history) == 1
    
    @pytest.mark.asyncio
    async def test_port_randomization(self, mtd_engine):
        """포트 랜덤화 테스트"""
        action = MTDAction(
            strategy=MTDStrategyType.PORT_RANDOMIZATION,
            target_node="drone1",
            parameters={},
            cost=0.2,
            expected_effectiveness=0.6
        )
        
        success = await mtd_engine.execute_mtd_action(action)
        assert success == True
