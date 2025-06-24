# src/honeydrone_network_manager_ns3.py
"""
허니드론 네트워크 매니저 - NS-3 FANET 시뮬레이션 통합 버전

이 모듈은 기존 허니드론 네트워크 매니저에 NS-3 시뮬레이션과 DVDS 연동 기능을 추가합니다.
실시간 패킷 분석, 공격 시나리오 매핑, 애니메이션 시각화 등의 고급 기능을 제공합니다.
"""

import asyncio
import json
import logging
import time
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

# 기존 허니드론 네트워크 매니저 임포트
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))

from honeydrone_network_manager import (
    HoneydroneNetworkManager, 
    DroneType, 
    DroneState, 
    DroneInstance,
    Position3D
)
from ns3_fanet_bridge import NS3FANETBridge, PacketInfo, PacketType
from dvds_bridge import DVDSBridge

logger = logging.getLogger(__name__)

class EnhancedHoneydroneNetworkManager(HoneydroneNetworkManager):
    """NS-3 및 DVDS 통합 허니드론 네트워크 매니저"""
    
    def __init__(self, config_path: str):
        super().__init__(config_path)
        
        # NS-3 및 DVDS 컴포넌트
        self.ns3_bridge: Optional[NS3FANETBridge] = None
        self.dvds_bridge: Optional[DVDSBridge] = None
        
        # 통합 설정
        self.integration_config = self.config.get('integration', {})
        self.ns3_enabled = self.integration_config.get('ns3_enabled', True)
        self.dvds_enabled = self.integration_config.get('dvds_enabled', True)
        self.packet_analysis_enabled = self.integration_config.get('packet_analysis', True)
        
        # 실시간 데이터
        self.packet_buffer: List[PacketInfo] = []
        self.attack_correlations: List[Dict[str, Any]] = []
        self.animation_data: Dict[str, Any] = {}
        
        # 연동 태스크
        self.integration_task: Optional[asyncio.Task] = None
        self.packet_analysis_task: Optional[asyncio.Task] = None
        
        # 확장 콜백
        self.on_packet_analyzed: Optional[callable] = None
        self.on_attack_correlated: Optional[callable] = None
        self.on_ns3_event: Optional[callable] = None
    
    async def start(self):
        """네트워크 매니저 시작 (NS-3 통합)"""
        # 기본 매니저 시작
        await super().start()
        
        # NS-3 브리지 초기화
        if self.ns3_enabled:
            await self._initialize_ns3_bridge()
        
        # DVDS 브리지 초기화
        if self.dvds_enabled:
            await self._initialize_dvds_bridge()
        
        # 통합 모니터링 시작
        if self.ns3_bridge or self.dvds_bridge:
            self.integration_task = asyncio.create_task(self._integration_loop())
        
        # 패킷 분석 시작
        if self.packet_analysis_enabled and self.ns3_bridge:
            self.packet_analysis_task = asyncio.create_task(self._packet_analysis_loop())
        
        logger.info("허니드론 네트워크 매니저 (NS-3 통합) 시작됨")
    
    async def stop(self):
        """네트워크 매니저 중지"""
        # 통합 태스크 중지
        if self.integration_task:
            self.integration_task.cancel()
            try:
                await self.integration_task
            except asyncio.CancelledError:
                pass
        
        if self.packet_analysis_task:
            self.packet_analysis_task.cancel()
            try:
                await self.packet_analysis_task
            except asyncio.CancelledError:
                pass
        
        # 브리지 중지
        if self.ns3_bridge:
            await self.ns3_bridge.stop()
        
        # 기본 매니저 중지
        await super().stop()
        
        logger.info("허니드론 네트워크 매니저 (NS-3 통합) 중지됨")
    
    async def _initialize_ns3_bridge(self):
        """NS-3 브리지 초기화"""
        try:
            ns3_config_path = self.config_dir / 'ns3_config.json'
            if not ns3_config_path.exists():
                # 기본 NS-3 설정 생성
                await self._create_default_ns3_config(ns3_config_path)
            
            self.ns3_bridge = NS3FANETBridge(str(ns3_config_path))
            
            # 콜백 설정
            self.ns3_bridge.on_packet_analyzed = self._on_packet_analyzed
            self.ns3_bridge.on_attack_detected = self._on_ns3_attack_detected
            self.ns3_bridge.on_anomaly_found = self._on_ns3_anomaly_found
            
            # 드론 노드 정보로 NS-3 시뮬레이션 시작
            drone_nodes = self._convert_drones_to_ns3_format()
            await self.ns3_bridge.start(drone_nodes)
            
            logger.info("NS-3 브리지 초기화 완료")
            
        except Exception as e:
            logger.error(f"NS-3 브리지 초기화 실패: {e}")
            self.ns3_bridge = None
    
    async def _initialize_dvds_bridge(self):
        """DVDS 브리지 초기화"""
        try:
            dvds_config = self.config.get('dvds', {
                'dvds_host': 'localhost',
                'dvds_port': 8888
            })
            
            self.dvds_bridge = DVDSBridge(dvds_config)
            
            # DVDS 연결 확인
            connected = await self.dvds_bridge.connect_to_dvds()
            if connected:
                logger.info("DVDS 브리지 초기화 완료")
            else:
                logger.warning("DVDS 연결 실패 - 시뮬레이션 모드로 계속 진행")
                
        except Exception as e:
            logger.error(f"DVDS 브리지 초기화 실패: {e}")
            self.dvds_bridge = None
    
    async def _create_default_ns3_config(self, config_path: Path):
        """기본 NS-3 설정 생성"""
        ns3_config = {
            'ns3': {
                'ns3_path': '/usr/local/ns-3',
                'simulation_script': 'fanet_simulation.cc',
                'output_dir': str(project_root / 'ns3_output'),
                'socket_port': 9999,
                'simulation_duration': 300,
                'routing_protocol': 'AODV',
                'transmission_range': 100,
                'mobility_speed': 5.0,
                'wifi_standard': '802.11n',
                'data_rate': '54Mbps'
            },
            'dvds': {
                'dvds_host': 'localhost',
                'dvds_port': 8888
            },
            'analysis': {
                'realtime_analysis': True,
                'analysis_interval': 1.0,
                'packet_buffer_size': 1000,
                'anomaly_threshold': 0.5
            }
        }
        
        config_path.parent.mkdir(exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(ns3_config, f, indent=2)
        
        logger.info(f"기본 NS-3 설정 생성: {config_path}")
    
    def _convert_drones_to_ns3_format(self) -> Dict[str, Any]:
        """드론 정보를 NS-3 형식으로 변환"""
        ns3_nodes = {}
        
        for drone_id, drone in self.drones.items():
            ns3_nodes[drone_id] = {
                'drone_type': drone.drone_type.value,
                'position': {
                    'x': drone.position.x,
                    'y': drone.position.y,
                    'z': drone.position.z
                },
                'vulnerability_level': drone.config.vulnerability_level,
                'state': drone.state.value,
                'config': {
                    'cpu_cores': drone.config.cpu_cores,
                    'memory_mb': drone.config.memory_mb,
                    'network_bandwidth': drone.config.network_bandwidth
                }
            }
        
        return ns3_nodes
    
    async def _integration_loop(self):
        """통합 모니터링 루프"""
        try:
            while self.is_running:
                # NS-3 시뮬레이션과 허니드론 네트워크 동기화
                if self.ns3_bridge:
                    await self._sync_with_ns3()
                
                # DVDS 공격과 허니드론 상태 동기화
                if self.dvds_bridge:
                    await self._sync_with_dvds()
                
                # 공격 상관관계 분석
                await self._analyze_attack_correlations()
                
                await asyncio.sleep(5)  # 5초마다 동기화
                
        except asyncio.CancelledError:
            logger.info("통합 모니터링 루프가 취소되었습니다")
        except Exception as e:
            logger.error(f"통합 모니터링 오류: {e}")
    
    async def _packet_analysis_loop(self):
        """실시간 패킷 분석 루프"""
        try:
            while self.is_running:
                if self.ns3_bridge:
                    # 새로운 패킷 데이터 수집
                    new_packets = self.ns3_bridge.get_realtime_packets(50)
                    
                    for packet in new_packets:
                        # 패킷을 버퍼에 추가
                        self.packet_buffer.append(packet)
                        
                        # 버퍼 크기 제한
                        if len(self.packet_buffer) > 1000:
                            self.packet_buffer = self.packet_buffer[-1000:]
                        
                        # 허니드론 네트워크와 패킷 매핑
                        await self._map_packet_to_drones(packet)
                
                await asyncio.sleep(1)  # 1초마다 분석
                
        except asyncio.CancelledError:
            logger.info("패킷 분석 루프가 취소되었습니다")
        except Exception as e:
            logger.error(f"패킷 분석 오류: {e}")
    
    async def _sync_with_ns3(self):
        """NS-3 시뮬레이션과 동기화"""
        try:
            # 드론 위치 업데이트를 NS-3에 반영
            for drone_id, drone in self.drones.items():
                if hasattr(self.ns3_bridge.ns3_simulator, 'update_node_position'):
                    await self.ns3_bridge.ns3_simulator.update_node_position(
                        drone_id, drone.position
                    )
            
            # 애니메이션 데이터 수집
            self.animation_data = self.ns3_bridge.get_animation_data()
            
        except Exception as e:
            logger.error(f"NS-3 동기화 오류: {e}")
    
    async def _sync_with_dvds(self):
        """DVDS와 동기화"""
        try:
            if not self.dvds_bridge:
                return
            
            # 타협된 드론에 대한 DVDS 공격 성공률 증가
            for drone_id, drone in self.drones.items():
                if drone.state == DroneState.COMPROMISED:
                    # DVDS에 성공적인 공격 알림
                    logger.debug(f"드론 {drone_id} 타협 상태를 DVDS에 알림")
            
            # DVDS 공격 시나리오와 허니드론 상태 매핑
            if self.packet_buffer and self.ns3_bridge:
                attack_mappings = self.dvds_bridge.get_attack_mapping(self.packet_buffer[-50:])
                
                for mapping in attack_mappings:
                    target_drone = mapping['attack_record']['target']
                    if target_drone in self.drones:
                        # 공격받은 드론의 상태 업데이트
                        drone = self.drones[target_drone]
                        drone.compromise_attempts += 1
                        
                        # 높은 신뢰도의 공격이면 타협 상태로 변경
                        if mapping['confidence'] > 0.8:
                            await self._handle_drone_compromise(target_drone, 
                                f"DVDS 공격: {mapping['attack_record']['scenario']}")
            
        except Exception as e:
            logger.error(f"DVDS 동기화 오류: {e}")
    
    async def _analyze_attack_correlations(self):
        """공격 상관관계 분석"""
        try:
            if not self.ns3_bridge or not self.packet_buffer:
                return
            
            # 최근 패킷들에서 공격 패턴 분석
            recent_packets = self.packet_buffer[-100:]
            attack_packets = [p for p in recent_packets if p.is_malicious or p.packet_type == PacketType.ATTACK]
            
            if len(attack_packets) >= 2:
                # 시간별로 그룹화
                time_groups = self._group_packets_by_time(attack_packets, window_seconds=30)
                
                for time_window, packets in time_groups.items():
                    if len(packets) >= 2:
                        correlation = {
                            'correlation_id': f"corr_{int(time.time())}_{len(self.attack_correlations)}",
                            'time_window': time_window,
                            'packet_count': len(packets),
                            'involved_drones': list(set([p.source_id for p in packets] + [p.destination_id for p in packets])),
                            'attack_types': list(set([p.attack_signature for p in packets if p.attack_signature])),
                            'confidence': min(1.0, len(packets) / 5.0),
                            'timestamp': datetime.now()
                        }
                        
                        self.attack_correlations.append(correlation)
                        
                        # 콜백 호출
                        if self.on_attack_correlated:
                            self.on_attack_correlated(correlation)
                        
                        logger.info(f"공격 상관관계 탐지: {len(packets)}개 패킷, 드론 {len(correlation['involved_drones'])}개 관련")
            
        except Exception as e:
            logger.error(f"공격 상관관계 분석 오류: {e}")
    
    def _group_packets_by_time(self, packets: List[PacketInfo], window_seconds: int = 30) -> Dict[datetime, List[PacketInfo]]:
        """패킷을 시간 윈도우로 그룹화"""
        groups = {}
        
        for packet in packets:
            # 시간 윈도우 시작점 계산
            window_start = packet.timestamp.replace(second=0, microsecond=0)
            window_start = window_start.replace(minute=(window_start.minute // (window_seconds // 60)) * (window_seconds // 60))
            
            if window_start not in groups:
                groups[window_start] = []
            
            groups[window_start].append(packet)
        
        return groups
    
    async def _map_packet_to_drones(self, packet: PacketInfo):
        """패킷을 허니드론 네트워크에 매핑"""
        try:
            # 소스 드론 식별
            source_drone = None
            dest_drone = None
            
            for drone_id, drone in self.drones.items():
                if drone_id == packet.source_id:
                    source_drone = drone
                if drone_id == packet.destination_id:
                    dest_drone = drone
            
            # 공격 패킷인 경우 드론 상태 업데이트
            if packet.is_malicious and dest_drone:
                dest_drone.honeypot_interactions += 1
                dest_drone.network_activity += packet.size / 1024.0  # KB
                
                # 공격 패킷 로깅
                attack_record = {
                    'packet_id': packet.packet_id,
                    'source_drone': packet.source_id,
                    'target_drone': packet.destination_id,
                    'attack_type': packet.attack_signature or 'unknown',
                    'packet_size': packet.size,
                    'timestamp': packet.timestamp,
                    'detected_by_ns3': True
                }
                
                # 기존 공격 로그에 추가
                self.attack_log.append(attack_record)
                
                logger.debug(f"NS-3 공격 패킷 매핑: {packet.source_id} -> {packet.destination_id}")
            
        except Exception as e:
            logger.error(f"패킷 매핑 오류: {e}")
    
    # 콜백 핸들러들
    
    def _on_packet_analyzed(self, packet: PacketInfo, analysis_result: Dict[str, Any]):
        """NS-3 패킷 분석 콜백"""
        if self.on_packet_analyzed:
            self.on_packet_analyzed(packet, analysis_result)
        
        # 높은 위험도 패킷 처리
        if analysis_result.get('risk_score', 0) > 0.7:
            logger.warning(f"높은 위험도 패킷 탐지: {packet.packet_id} (위험도: {analysis_result['risk_score']:.2f})")
    
    def _on_ns3_attack_detected(self, attack_event: Dict[str, Any]):
        """NS-3 공격 탐지 콜백"""
        # 허니드론 네트워크의 해당 드론 상태 업데이트
        target_drone = attack_event.get('target_node') or attack_event.get('target_drone')
        
        if target_drone and target_drone in self.drones:
            asyncio.create_task(self._handle_drone_compromise(
                target_drone, 
                f"NS-3 탐지: {attack_event.get('attack_type', 'unknown')}"
            ))
        
        # 기존 공격 탐지 콜백 호출
        if self.on_attack_detected:
            self.on_attack_detected(attack_event)
    
    def _on_ns3_anomaly_found(self, anomaly_event: Dict[str, Any]):
        """NS-3 이상 탐지 콜백"""
        logger.info(f"NS-3 이상 탐지: {anomaly_event.get('anomaly_type')} (심각도: {anomaly_event.get('severity')})")
    
    # 확장 인터페이스 메서드들
    
    async def launch_coordinated_attack(self, scenario: str, target_drones: List[str]) -> Dict[str, Any]:
        """조정된 공격 시나리오 실행"""
        results = {}
        
        # DVDS를 통한 공격 실행
        if self.dvds_bridge:
            for target_drone in target_drones:
                if target_drone in self.drones:
                    attack_result = await self.dvds_bridge.launch_attack_scenario(scenario, target_drone)
                    results[target_drone] = attack_result
                    
                    # NS-3에도 공격 패킷 주입
                    if self.ns3_bridge and attack_result.get('success'):
                        self.ns3_bridge.inject_attack_packet(
                            source_id="attacker",
                            dest_id=target_drone,
                            attack_type=scenario
                        )
        
        logger.info(f"조정된 공격 시나리오 실행: {scenario} -> {len(target_drones)}개 타겟")
        return results
    
    def get_ns3_animation_data(self) -> Dict[str, Any]:
        """NS-3 애니메이션 데이터 가져오기"""
        if self.ns3_bridge:
            return self.ns3_bridge.get_animation_data()
        return {}
    
    def get_packet_analysis_summary(self, time_window: int = 300) -> Dict[str, Any]:
        """패킷 분석 요약"""
        base_summary = {}
        
        if self.ns3_bridge:
            base_summary = self.ns3_bridge.get_packet_analysis_summary(time_window)
        
        # 허니드론 네트워크 특화 정보 추가
        recent_correlations = [
            corr for corr in self.attack_correlations
            if (datetime.now() - corr['timestamp']).total_seconds() <= time_window
        ]
        
        honeydrone_summary = {
            'honeydrone_interactions': sum(d.honeypot_interactions for d in self.drones.values()),
            'network_activity_mb': sum(d.network_activity for d in self.drones.values()),
            'attack_correlations': len(recent_correlations),
            'compromised_drones': len([d for d in self.drones.values() if d.state == DroneState.COMPROMISED]),
            'ns3_integration_active': self.ns3_bridge is not None and self.ns3_bridge.is_running,
            'dvds_integration_active': self.dvds_bridge is not None
        }
        
        base_summary.update(honeydrone_summary)
        return base_summary
    
    def get_integration_status(self) -> Dict[str, Any]:
        """통합 상태 정보"""
        status = {
            'integration_enabled': True,
            'ns3_bridge_status': 'disabled',
            'dvds_bridge_status': 'disabled',
            'packet_analysis_active': False,
            'animation_available': False,
            'total_packets_analyzed': 0,
            'attack_correlations_found': len(self.attack_correlations)
        }
        
        if self.ns3_bridge:
            status['ns3_bridge_status'] = 'active' if self.ns3_bridge.is_running else 'stopped'
            status['packet_analysis_active'] = self.packet_analysis_enabled
            status['animation_available'] = bool(self.animation_data)
            status['total_packets_analyzed'] = len(self.packet_buffer)
        
        if self.dvds_bridge:
            status['dvds_bridge_status'] = 'active'
            status['dvds_scenarios'] = list(self.dvds_bridge.attack_scenarios.keys()) if hasattr(self.dvds_bridge, 'attack_scenarios') else []
        
        return status
    
    def export_integrated_analysis(self) -> Dict[str, Any]:
        """통합 분석 데이터 내보내기"""
        base_data = self.export_network_data(include_logs=True)
        
        # NS-3 및 DVDS 데이터 추가
        integrated_data = {
            'integration_timestamp': datetime.now().isoformat(),
            'honeydrone_network': base_data,
            'packet_analysis': {
                'total_packets': len(self.packet_buffer),
                'recent_packets': [
                    {
                        'packet_id': p.packet_id,
                        'source_id': p.source_id,
                        'destination_id': p.destination_id,
                        'packet_type': p.packet_type.value,
                        'size': p.size,
                        'timestamp': p.timestamp.isoformat(),
                        'is_malicious': p.is_malicious
                    }
                    for p in self.packet_buffer[-100:]  # 최근 100개
                ]
            },
            'attack_correlations': [
                {
                    **corr,
                    'timestamp': corr['timestamp'].isoformat()
                }
                for corr in self.attack_correlations
            ],
            'integration_status': self.get_integration_status()
        }
        
        # NS-3 애니메이션 데이터
        if self.animation_data:
            integrated_data['ns3_animation'] = self.animation_data
        
        # DVDS 분석 데이터
        if self.dvds_bridge:
            integrated_data['dvds_analysis'] = self.dvds_bridge.get_attack_statistics()
        
        return integrated_data
    
    async def simulate_realistic_attack_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """현실적인 공격 시나리오 시뮬레이션"""
        scenario_results = {
            'scenario_name': scenario_name,
            'start_time': datetime.now(),
            'phases': [],
            'total_packets_generated': 0,
            'drones_affected': [],
            'detection_events': []
        }
        
        if scenario_name == "advanced_persistent_threat":
            # APT 시나리오: 정찰 -> 침투 -> 확산 -> 목표 달성
            phases = [
                ("reconnaissance", 30, ["network_reconnaissance"]),
                ("initial_compromise", 60, ["command_injection"]),
                ("lateral_movement", 90, ["man_in_the_middle", "data_exfiltration"]),
                ("mission_completion", 45, ["data_exfiltration", "denial_of_service"])
            ]
            
            for phase_name, duration, attack_types in phases:
                phase_start = datetime.now()
                phase_result = {
                    'phase_name': phase_name,
                    'duration': duration,
                    'start_time': phase_start,
                    'attacks_launched': [],
                    'success_rate': 0.0
                }
                
                # 각 페이즈에서 여러 공격 실행
                for attack_type in attack_types:
                    # 타겟 드론 선택 (더미 드론 우선)
                    target_drones = [
                        drone_id for drone_id, drone in self.drones.items()
                        if drone.drone_type == DroneType.DUMMY and drone.state == DroneState.ACTIVE
                    ]
                    
                    if not target_drones and attack_type != "reconnaissance":
                        # 더미 드론이 없으면 가상 드론 타겟
                        target_drones = [
                            drone_id for drone_id, drone in self.drones.items()
                            if drone.drone_type == DroneType.VIRTUAL and drone.state == DroneState.ACTIVE
                        ][:2]  # 최대 2개
                    
                    for target_drone in target_drones[:3]:  # 최대 3개 타겟
                        if self.dvds_bridge:
                            attack_result = await self.dvds_bridge.launch_attack_scenario(attack_type, target_drone)
                            phase_result['attacks_launched'].append({
                                'attack_type': attack_type,
                                'target_drone': target_drone,
                                'success': attack_result.get('success', False),
                                'timestamp': datetime.now()
                            })
                        
                        # 페이즈 간 지연
                        await asyncio.sleep(duration / len(target_drones))
                
                phase_result['end_time'] = datetime.now()
                phase_result['actual_duration'] = (phase_result['end_time'] - phase_start).total_seconds()
                phase_result['success_rate'] = sum(1 for a in phase_result['attacks_launched'] if a['success']) / max(1, len(phase_result['attacks_launched']))
                
                scenario_results['phases'].append(phase_result)
                
                logger.info(f"APT 페이즈 완료: {phase_name} (성공률: {phase_result['success_rate']:.2f})")
        
        scenario_results['end_time'] = datetime.now()
        scenario_results['total_duration'] = (scenario_results['end_time'] - scenario_results['start_time']).total_seconds()
        scenario_results['overall_success_rate'] = sum(p['success_rate'] for p in scenario_results['phases']) / len(scenario_results['phases'])
        
        # 영향받은 드론 목록
        affected_drones = set()
        for phase in scenario_results['phases']:
            for attack in phase['attacks_launched']:
                affected_drones.add(attack['target_drone'])
        
        scenario_results['drones_affected'] = list(affected_drones)
        scenario_results['total_drones_affected'] = len(affected_drones)
        
        logger.info(f"현실적인 공격 시나리오 완료: {scenario_name} (전체 성공률: {scenario_results['overall_success_rate']:.2f})")
        
        return scenario_results


# 사용 예시 및 테스트
if __name__ == "__main__":
    import asyncio
    
    async def test_enhanced_manager():
        """향상된 허니드론 네트워크 매니저 테스트"""
        # 테스트 설정
        test_config = {
            'max_drones': 8,
            'default_virtual_drones': 3,
            'default_dummy_drones': 2,
            'integration': {
                'ns3_enabled': True,
                'dvds_enabled': True,
                'packet_analysis': True
            },
            'fanet': {
                'topology': 'mesh',
                'communication_range': 150.0
            },
            'docker': {
                'base_image': 'alpine:latest',
                'network_name': 'test_enhanced_honeydrone'
            }
        }
        
        with open('test_enhanced_config.json', 'w') as f:
            json.dump(test_config, f)
        
        # 향상된 매니저 생성
        manager = EnhancedHoneydroneNetworkManager('test_enhanced_config.json')
        
        # 콜백 설정
        def on_packet_analyzed(packet, analysis):
            if analysis.get('risk_score', 0) > 0.5:
                print(f"📊 위험 패킷: {packet.packet_id} (위험도: {analysis['risk_score']:.2f})")
        
        def on_attack_correlated(correlation):
            print(f"🔗 공격 상관관계: {len(correlation['involved_drones'])}개 드론, "
                  f"신뢰도: {correlation['confidence']:.2f}")
        
        def on_ns3_event(event):
            print(f"🌐 NS-3 이벤트: {event}")
        
        manager.on_packet_analyzed = on_packet_analyzed
        manager.on_attack_correlated = on_attack_correlated
        manager.on_ns3_event = on_ns3_event
        
        print("🚀 향상된 허니드론 네트워크 매니저 테스트 시작...")
        
        try:
            # 매니저 시작
            await manager.start()
            
            # 통합 상태 확인
            print("\n--- 통합 상태 ---")
            integration_status = manager.get_integration_status()
            print(f"NS-3 브리지: {integration_status['ns3_bridge_status']}")
            print(f"DVDS 브리지: {integration_status['dvds_bridge_status']}")
            print(f"패킷 분석: {integration_status['packet_analysis_active']}")
            
            # 현실적인 공격 시나리오 실행
            print("\n--- APT 공격 시나리오 실행 ---")
            apt_result = await manager.simulate_realistic_attack_scenario("advanced_persistent_threat")
            print(f"APT 시나리오 결과: {apt_result['total_drones_affected']}개 드론 영향, "
                  f"성공률: {apt_result['overall_success_rate']:.2f}")
            
            # 30초간 모니터링
            print("\n--- 30초간 통합 모니터링 ---")
            for i in range(6):
                await asyncio.sleep(5)
                
                summary = manager.get_packet_analysis_summary(30)
                integration_status = manager.get_integration_status()
                
                print(f"[{(i+1)*5}초] 패킷: {summary.get('total_packets', 0)}, "
                      f"상관관계: {integration_status['attack_correlations_found']}, "
                      f"애니메이션: {'가능' if integration_status['animation_available'] else '불가능'}")
            
            # 최종 분석 결과
            print("\n--- 최종 통합 분석 ---")
            final_analysis = manager.export_integrated_analysis()
            print(f"총 패킷 분석: {final_analysis['packet_analysis']['total_packets']}")
            print(f"공격 상관관계: {len(final_analysis['attack_correlations'])}")
            print(f"허니드론 상호작용: {final_analysis['honeydrone_network']['attack_statistics']['total_attacks']}")
            
        except Exception as e:
            print(f"❌ 테스트 중 오류: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            # 정리
            print("\n🛑 향상된 매니저 중지 중...")
            await manager.stop()
            print("✅ 테스트 완료!")
    
    # 테스트 실행
    # asyncio.run(test_enhanced_manager())