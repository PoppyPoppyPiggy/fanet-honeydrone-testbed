# tests/test_cti_engine.py
import pytest
from datetime import datetime

from core.base import EventBus, AttackType
from core.cti.analysis_engine import CTIAnalysisEngine

class TestCTIAnalysisEngine:
    @pytest.fixture
    async def cti_engine(self):
        """CTI 엔진 테스트 픽스처"""
        config = {}
        event_bus = EventBus()
        
        engine = CTIAnalysisEngine(config, event_bus)
        await engine.start()
        yield engine
        await engine.stop()
    
    @pytest.mark.asyncio
    async def test_analyze_gps_spoofing(self, cti_engine):
        """GPS 스푸핑 로그 분석 테스트"""
        log_entry = {
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
        
        threat_intel = await cti_engine.analyze_dvds_log(log_entry)
        
        assert threat_intel is not None
        assert threat_intel.attack_type == AttackType.GPS_SPOOFING
        assert len(threat_intel.iocs) > 0
        assert len(threat_intel.mitre_mappings) > 0
        assert threat_intel.severity >= 4
    
    @pytest.mark.asyncio
    async def test_stix_generation(self, cti_engine):
        """STIX 보고서 생성 테스트"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "mavlink_injection",
            "source_ip": "10.0.0.1",
            "target_component": "autopilot",
            "attack_vector": "command_injection",
            "payload": {"command": "MAVLINK_MSG_ID_SET_MODE"},
            "severity": "high",
            "detection_status": "detected"
        }
        
        threat_intel = await cti_engine.analyze_dvds_log(log_entry)
        stix_report = await cti_engine.generate_stix_report(threat_intel.id)
        
        assert stix_report["type"] == "bundle"
        assert len(stix_report["objects"]) > 0
