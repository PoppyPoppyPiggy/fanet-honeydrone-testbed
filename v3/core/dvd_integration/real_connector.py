# DVD 실시간 연동 모듈
# core/dvd_integration/real_connector.py

import asyncio
import json
import socket
import struct
from datetime import datetime
from typing import Dict, Any, Optional, Callable
import logging

try:
    from pymavlink import mavutil
    MAVLINK_AVAILABLE = True
except ImportError:
    MAVLINK_AVAILABLE = False
    print("Warning: pymavlink not available. Install with: pip install pymavlink")

class DVDRealConnector:
    """실제 DVD 시스템과의 연동 커넥터"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 연결 설정
        self.dvd_host = config.get('host', 'localhost')
        self.dvd_port = config.get('port', 14550)
        self.protocol = config.get('protocol', 'udp')
        
        # MAVLink 연결
        self.mavlink_connection = None
        self.connected = False
        
        # 콜백 함수들
        self.message_callbacks: Dict[str, Callable] = {}
        
    async def connect(self) -> bool:
        """DVD 시스템에 연결"""
        try:
            if not MAVLINK_AVAILABLE:
                self.logger.error("pymavlink이 설치되지 않음")
                return False
            
            connection_string = f"{self.protocol}:{self.dvd_host}:{self.dvd_port}"
            self.logger.info(f"DVD 연결 시도: {connection_string}")
            
            # MAVLink 연결 생성
            self.mavlink_connection = mavutil.mavlink_connection(
                connection_string,
                source_system=255,  # GCS로 식별
                source_component=0
            )
            
            # 연결 확인 (하트비트 대기)
            self.logger.info("하트비트 메시지 대기 중...")
            heartbeat = self.mavlink_connection.recv_match(
                type='HEARTBEAT', 
                blocking=True, 
                timeout=10
            )
            
            if heartbeat:
                self.connected = True
                self.logger.info(f"DVD 연결 성공! 시스템 ID: {heartbeat.get_srcSystem()}")
                
                # 메시지 수신 태스크 시작
                asyncio.create_task(self._message_receiver_task())
                return True
            else:
                self.logger.error("하트비트 메시지 수신 실패")
                return False
                
        except Exception as e:
            self.logger.error(f"DVD 연결 실패: {e}")
            return False
    
    async def disconnect(self):
        """DVD 연결 해제"""
        if self.mavlink_connection:
            self.mavlink_connection.close()
            self.connected = False
            self.logger.info("DVD 연결 해제됨")
    
    def register_message_callback(self, message_type: str, callback: Callable):
        """메시지 타입별 콜백 등록"""
        self.message_callbacks[message_type] = callback
    
    async def send_gps_spoof(self, latitude: float, longitude: float, altitude: float) -> bool:
        """GPS 스푸핑 메시지 전송"""
        if not self.connected:
            return False
        
        try:
            # GPS_RAW_INT 메시지 전송
            self.mavlink_connection.mav.gps_raw_int_send(
                time_usec=int(datetime.now().timestamp() * 1000000),
                fix_type=3,  # 3D Fix
                lat=int(latitude * 1e7),
                lon=int(longitude * 1e7),
                alt=int(altitude * 1000),
                eph=100,
                epv=100,
                vel=0,
                cog=0,
                satellites_visible=12
            )
            
            self.logger.info(f"GPS 스푸핑 메시지 전송: {latitude}, {longitude}, {altitude}")
            return True
            
        except Exception as e:
            self.logger.error(f"GPS 스푸핑 실패: {e}")
            return False
    
    async def send_mavlink_command(self, command: int, params: list) -> bool:
        """MAVLink 명령 전송"""
        if not self.connected:
            return False
        
        try:
            self.mavlink_connection.mav.command_long_send(
                target_system=1,
                target_component=1,
                command=command,
                confirmation=0,
                param1=params[0] if len(params) > 0 else 0,
                param2=params[1] if len(params) > 1 else 0,
                param3=params[2] if len(params) > 2 else 0,
                param4=params[3] if len(params) > 3 else 0,
                param5=params[4] if len(params) > 4 else 0,
                param6=params[5] if len(params) > 5 else 0,
                param7=params[6] if len(params) > 6 else 0
            )
            
            self.logger.info(f"MAVLink 명령 전송: {command}, 매개변수: {params}")
            return True
            
        except Exception as e:
            self.logger.error(f"MAVLink 명령 전송 실패: {e}")
            return False
    
    async def send_battery_spoof(self, battery_percentage: float) -> bool:
        """배터리 상태 스푸핑"""
        if not self.connected:
            return False
        
        try:
            # 전압 계산 (리포 배터리 기준)
            cell_voltage = 3.3 + (battery_percentage / 100.0) * 0.9  # 3.3V - 4.2V
            total_voltage = int(cell_voltage * 4 * 1000)  # 4셀, mV 단위
            
            self.mavlink_connection.mav.battery_status_send(
                id=0,
                battery_function=mavutil.mavlink.MAV_BATTERY_FUNCTION_ALL,
                type=mavutil.mavlink.MAV_BATTERY_TYPE_LIPO,
                temperature=250,  # 25.0°C
                voltages=[total_voltage] + [65535]*9,  # 첫 번째 셀만 설정
                current_battery=-1,
                current_consumed=-1,
                energy_consumed=-1,
                battery_remaining=int(battery_percentage),
                time_remaining=0,
                charge_state=mavutil.mavlink.MAV_BATTERY_CHARGE_STATE_OK
            )
            
            self.logger.info(f"배터리 스푸핑 메시지 전송: {battery_percentage}%")
            return True
            
        except Exception as e:
            self.logger.error(f"배터리 스푸핑 실패: {e}")
            return False
    
    async def get_current_status(self) -> Dict[str, Any]:
        """현재 드론 상태 조회"""
        if not self.connected:
            return {}
        
        try:
            # 최근 메시지들 수집
            messages = {}
            
            # GPS 위치
            gps_msg = self.mavlink_connection.recv_match(type='GPS_RAW_INT', blocking=False)
            if gps_msg:
                messages['gps'] = {
                    'latitude': gps_msg.lat / 1e7,
                    'longitude': gps_msg.lon / 1e7,
                    'altitude': gps_msg.alt / 1000.0,
                    'satellites': gps_msg.satellites_visible
                }
            
            # 배터리 상태
            battery_msg = self.mavlink_connection.recv_match(type='BATTERY_STATUS', blocking=False)
            if battery_msg:
                messages['battery'] = {
                    'percentage': battery_msg.battery_remaining,
                    'voltage': battery_msg.voltages[0] / 1000.0 if battery_msg.voltages[0] != 65535 else 0,
                    'current': battery_msg.current_battery / 100.0 if battery_msg.current_battery != -1 else 0
                }
            
            # 자세 정보
            attitude_msg = self.mavlink_connection.recv_match(type='ATTITUDE', blocking=False)
            if attitude_msg:
                messages['attitude'] = {
                    'roll': attitude_msg.roll,
                    'pitch': attitude_msg.pitch,
                    'yaw': attitude_msg.yaw
                }
            
            return messages
            
        except Exception as e:
            self.logger.error(f"상태 조회 실패: {e}")
            return {}
    
    async def _message_receiver_task(self):
        """백그라운드 메시지 수신 태스크"""
        while self.connected:
            try:
                # 모든 메시지 수신
                msg = self.mavlink_connection.recv_match(blocking=False, timeout=0.1)
                
                if msg:
                    msg_type = msg.get_type()
                    
                    # 등록된 콜백 호출
                    if msg_type in self.message_callbacks:
                        try:
                            await self.message_callbacks[msg_type](msg)
                        except Exception as e:
                            self.logger.error(f"콜백 실행 오류 ({msg_type}): {e}")
                    
                    # 중요 메시지 로깅
                    if msg_type in ['GPS_RAW_INT', 'BATTERY_STATUS', 'HEARTBEAT']:
                        self.logger.debug(f"수신: {msg_type}")
                
                await asyncio.sleep(0.01)  # CPU 사용률 조절
                
            except Exception as e:
                self.logger.error(f"메시지 수신 오류: {e}")
                await asyncio.sleep(1)