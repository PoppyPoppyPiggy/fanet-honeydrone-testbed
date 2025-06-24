# core/base.py - 기본 클래스 및 데이터 모델
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import asyncio
import logging
import json

# 기본 열거형 정의
class AttackType(Enum):
    GPS_SPOOFING = "gps_spoofing"
    MAVLINK_INJECTION = "mavlink_injection"
    WIFI_DEAUTH = "wifi_deauth"
    BATTERY_SPOOFING = "battery_spoofing"
    CAMERA_HIJACK = "camera_hijack"

class MTDStrategyType(Enum):
    IP_HOPPING = "ip_hopping"
    PORT_RANDOMIZATION = "port_randomization"
    FREQUENCY_HOPPING = "frequency_hopping"
    TOPOLOGY_MUTATION = "topology_mutation"
    SERVICE_MIGRATION = "service_migration"

class DroneState(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    DEFENDING = "defending"

# 기본 데이터 모델
@dataclass
class Position3D:
    x: float
    y: float
    z: float
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class NetworkConfig:
    ip_address: str
    port: int
    subnet: str
    gateway: str
    interface: str

@dataclass
class MTDStatus:
    active_strategies: List[MTDStrategyType]
    last_change: datetime
    change_frequency: float
    cost_factor: float

@dataclass
class SecurityState:
    threat_level: int  # 0-5
    attack_detected: bool
    attack_type: Optional[AttackType]
    last_attack: Optional[datetime]
    compromised: bool

@dataclass
class DroneNode:
    id: str
    position: Position3D
    battery_level: float
    network_config: NetworkConfig
    mtd_status: MTDStatus
    security_state: SecurityState
    state: DroneState = DroneState.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)

# 기본 매니저 클래스
class BaseManager(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._running = False
    
    @abstractmethod
    async def start(self):
        """매니저 시작"""
        pass
    
    @abstractmethod
    async def stop(self):
        """매니저 중지"""
        pass
    
    @abstractmethod
    async def status(self) -> Dict[str, Any]:
        """현재 상태 반환"""
        pass

# 이벤트 시스템
class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, List[callable]] = {}
    
    def subscribe(self, event_type: str, callback: callable):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
    
    async def publish(self, event_type: str, data: Any):
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    logging.error(f"Error in event callback: {e}")