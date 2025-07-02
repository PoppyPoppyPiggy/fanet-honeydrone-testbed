# core/phase_management/phase_controller.py

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum
import logging

class BattlefieldEnvironment(Enum):
    FAVOURABLE = "favourable"      # 호의적: 아군 우세, 낮은 위협
    NEUTRAL = "neutral"            # 중립적: 균형, 중간 위협
    UNFAVOURABLE = "unfavourable"  # 불호의적: 적군 우세, 높은 위협

class PhaseType(Enum):
    HONEY_INFILTRATION = "phase_1_honey_infiltration"
    ENEMY_DETECTION = "phase_2_enemy_detection"
    INFORMATION_REVERSING = "phase_3_information_reversing"
    MTD_HONEY_DEPLOYMENT = "phase_4_mtd_honey_deployment"
    COORDINATED_FLIGHT = "phase_5_coordinated_flight"
    SECOND_DETECTION = "phase_6_second_detection"
    REGULAR_MISSION = "phase_7_regular_mission"
    MERGE_COMPLETION = "phase_8_merge_completion"

class PhaseTransitionController:
    """8단계 Phase 전환 컨트롤러"""
    
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus
        self.logger = logging.getLogger(__name__)
        
        # 현재 상태
        self.current_phase = PhaseType.HONEY_INFILTRATION
        self.battlefield_env = BattlefieldEnvironment.NEUTRAL
        self.phase_start_time = datetime.now()
        
        # Phase별 데이터 수집
        self.phase_data = {}
        self.attack_logs = []
        self.mtd_actions = []
        self.cti_intelligence = []
        
        # 드론 분류
        self.real_drones = set()      # 실제 임무 드론
        self.virtual_drones = set()   # 가상 미끼 드론
        self.dummy_drones = set()     # 취약 미끼 드론
        
    async def start_mission_cycle(self, battlefield_env: BattlefieldEnvironment):
        """전체 미션 사이클 시작"""
        self.battlefield_env = battlefield_env
        self.logger.info(f"🎯 미션 시작 - 전장 환경: {battlefield_env.value}")
        
        # Phase별 순차 실행
        for phase in PhaseType:
            await self._execute_phase(phase)
            
            # 환경별 적응형 대기 시간
            wait_time = self._calculate_phase_duration(phase, battlefield_env)
            await asyncio.sleep(wait_time)
        
        # 최종 결과 수집 및 분석
        mission_result = await self._generate_mission_report()
        return mission_result
    
    async def _execute_phase(self, phase: PhaseType):
        """개별 Phase 실행"""
        self.current_phase = phase
        self.phase_start_time = datetime.now()
        
        self.logger.info(f"🚀 {phase.value} 시작")
        
        if phase == PhaseType.HONEY_INFILTRATION:
            await self._phase_1_honey_infiltration()
        elif phase == PhaseType.ENEMY_DETECTION:
            await self._phase_2_enemy_detection()
        elif phase == PhaseType.INFORMATION_REVERSING:
            await self._phase_3_information_reversing()
        elif phase == PhaseType.MTD_HONEY_DEPLOYMENT:
            await self._phase_4_mtd_honey_deployment()
        elif phase == PhaseType.COORDINATED_FLIGHT:
            await self._phase_5_coordinated_flight()
        elif phase == PhaseType.SECOND_DETECTION:
            await self._phase_6_second_detection()
        elif phase == PhaseType.REGULAR_MISSION:
            await self._phase_7_regular_mission()
        elif phase == PhaseType.MERGE_COMPLETION:
            await self._phase_8_merge_completion()
        
        await self.event_bus.publish('phase_completed', {
            'phase': phase.value,
            'duration': (datetime.now() - self.phase_start_time).total_seconds(),
            'battlefield_env': self.battlefield_env.value
        })

    async def _phase_1_honey_infiltration(self):
        """Phase 1: 허니드론 침투 유도"""
        self.logger.info("📡 Phase 1: 허니드론 네트워크 배치 및 침투 유도")
        
        # 1. 가상 드론 배치 (적 군집 오인 유도)
        virtual_drone_count = self._get_env_adaptive_count('virtual_drones')
        for i in range(virtual_drone_count):
            drone_id = f"virtual_drone_{i}"
            self.virtual_drones.add(drone_id)
            
            # 3D 공간에 전략적 배치
            position = self._generate_strategic_position('virtual', i)
            await self._deploy_virtual_drone(drone_id, position)
        
        # 2. 더미 드론 배치 (취약점 노출로 공격 유도)
        dummy_drone_count = self._get_env_adaptive_count('dummy_drones')
        for i in range(dummy_drone_count):
            drone_id = f"dummy_drone_{i}"
            self.dummy_drones.add(drone_id)
            
            position = self._generate_strategic_position('dummy', i)
            vulnerability_profile = self._create_vulnerability_profile()
            await self._deploy_dummy_drone(drone_id, position, vulnerability_profile)
        
        # 3. 네트워크 신호 방출 (탐지 유도)
        await self._emit_honeypot_signals()
        
        phase_1_data = {
            'virtual_drones_deployed': len(self.virtual_drones),
            'dummy_drones_deployed': len(self.dummy_drones),
            'battlefield_adaptations': self._get_battlefield_adaptations(),
            'infiltration_success_rate': 0.0  # 다음 Phase에서 측정
        }
        
        self.phase_data['phase_1'] = phase_1_data

    async def _phase_2_enemy_detection(self):
        """Phase 2: 적 탐지 및 공격 유도"""
        self.logger.info("🎯 Phase 2: 적 공격 탐지 및 행동 분석")
        
        # 1. 공격 탐지 시스템 활성화
        detection_systems = [
            'network_intrusion_detection',
            'behavioral_analysis',
            'protocol_anomaly_detection',
            'signal_intelligence'
        ]
        
        detected_attacks = []
        
        for system in detection_systems:
            attacks = await self._activate_detection_system(system)
            detected_attacks.extend(attacks)
        
        # 2. DVD 공격 시뮬레이션 (적 행동 유도)
        dvd_scenarios = self._select_adaptive_dvd_scenarios()
        for scenario in dvd_scenarios:
            attack_result = await self._execute_dvd_scenario(scenario)
            if attack_result['detected']:
                detected_attacks.append(attack_result)
        
        # 3. 공격 로그 상세 분석
        for attack in detected_attacks:
            detailed_log = await self._analyze_attack_behavior(attack)
            self.attack_logs.append(detailed_log)
        
        # 4. 적 패턴 학습
        enemy_patterns = await self._extract_enemy_patterns(detected_attacks)
        
        phase_2_data = {
            'total_attacks_detected': len(detected_attacks),
            'attack_types_identified': list(set(a['type'] for a in detected_attacks)),
            'enemy_behavioral_patterns': enemy_patterns,
            'honeypot_effectiveness': self._calculate_honeypot_effectiveness(),
            'phase_duration': (datetime.now() - self.phase_start_time).total_seconds()
        }
        
        self.phase_data['phase_2'] = phase_2_data

    async def _phase_3_information_reversing(self):
        """Phase 3: 위협 정보 역분석 및 CTI 생성"""
        self.logger.info("🔍 Phase 3: 공격 로그 → MITRE CTI 변환")
        
        # 1. 공격 로그 전처리
        processed_logs = []
        for attack_log in self.attack_logs:
            processed = await self._preprocess_attack_log(attack_log)
            processed_logs.append(processed)
        
        # 2. MITRE ATT&CK 매핑
        mitre_mappings = []
        for log in processed_logs:
            mapping = await self._map_to_mitre_attack(log)
            mitre_mappings.append(mapping)
        
        # 3. CTI 구조화
        structured_cti = []
        for mapping in mitre_mappings:
            cti_data = await self._generate_structured_cti(mapping)
            structured_cti.append(cti_data)
            self.cti_intelligence.append(cti_data)
        
        # 4. 위협 우선순위 평가
        threat_priorities = await self._assess_threat_priorities(structured_cti)
        
        # 5. STIX 2.1 형식 변환
        stix_bundles = []
        for cti in structured_cti:
            stix_bundle = await self._convert_to_stix(cti)
            stix_bundles.append(stix_bundle)
        
        phase_3_data = {
            'logs_processed': len(processed_logs),
            'mitre_techniques_identified': len(set(m['technique_id'] for m in mitre_mappings)),
            'cti_intelligence_generated': len(structured_cti),
            'threat_priorities': threat_priorities,
            'stix_bundles_created': len(stix_bundles)
        }
        
        self.phase_data['phase_3'] = phase_3_data

    async def _phase_4_mtd_honey_deployment(self):
        """Phase 4: MTD 전략 적용 및 허니드론 재배치"""
        self.logger.info("🔄 Phase 4: MTD 기반 허니드론 재배치")
        
        # 1. CTI 기반 MTD 전략 생성
        mtd_strategies = await self._generate_mtd_strategies_from_cti()
        
        # 2. 강화학습 모델을 통한 최적 전략 선택
        optimal_strategies = await self._optimize_mtd_with_rl(mtd_strategies)
        
        # 3. 허니드론 재배치 실행
        redeployment_results = []
        
        # 가상 드론 재배치
        for virtual_drone in self.virtual_drones:
            new_position = await self._calculate_optimal_position(virtual_drone, 'virtual')
            new_config = await self._generate_adaptive_config(virtual_drone, optimal_strategies)
            
            redeploy_result = await self._redeploy_virtual_drone(
                virtual_drone, new_position, new_config
            )
            redeployment_results.append(redeploy_result)
        
        # 더미 드론 취약점 상태 전이
        for dummy_drone in self.dummy_drones:
            new_vulnerability_state = await self._transition_vulnerability_state(
                dummy_drone, optimal_strategies
            )
            
            transition_result = await self._apply_vulnerability_transition(
                dummy_drone, new_vulnerability_state
            )
            redeployment_results.append(transition_result)
        
        # 4. MTD 액션 기록
        for strategy in optimal_strategies:
            mtd_action = {
                'strategy_type': strategy['type'],
                'target_nodes': strategy['targets'],
                'parameters': strategy['params'],
                'expected_effectiveness': strategy['effectiveness'],
                'execution_time': datetime.now().isoformat()
            }
            self.mtd_actions.append(mtd_action)
        
        phase_4_data = {
            'mtd_strategies_generated': len(mtd_strategies),
            'optimal_strategies_selected': len(optimal_strategies),
            'nodes_redeployed': len(redeployment_results),
            'redeployment_success_rate': sum(1 for r in redeployment_results if r['success']) / len(redeployment_results),
            'mtd_effectiveness_prediction': sum(s['effectiveness'] for s in optimal_strategies) / len(optimal_strategies)
        }
        
        self.phase_data['phase_4'] = phase_4_data

    async def _phase_5_coordinated_flight(self):
        """Phase 5: 실드론-허니드론 협력 비행"""
        self.logger.info("✈️ Phase 5: 협력 비행 준비 및 편대 구성")
        
        # 1. 실드론 식별 및 상태 확인
        real_drone_status = await self._assess_real_drone_status()
        
        # 2. 허니드론과 실드론 간 역할 분배
        role_assignments = await self._assign_coordinated_roles()
        
        # 3. 편대 비행 패턴 생성
        formation_patterns = await self._generate_formation_patterns()
        
        # 4. 통신 보안 설정
        secure_comm_channels = await self._establish_secure_communications()
        
        # 5. 협력 비행 시뮬레이션
        coordination_results = []
        
        for pattern in formation_patterns:
            simulation_result = await self._simulate_coordinated_flight(pattern)
            coordination_results.append(simulation_result)
        
        # 6. 적응형 편대 조정 (전장 환경별)
        adaptive_formations = await self._adapt_formation_to_battlefield()
        
        phase_5_data = {
            'real_drones_coordinated': len(self.real_drones),
            'honey_drones_integrated': len(self.virtual_drones) + len(self.dummy_drones),
            'formation_patterns_tested': len(formation_patterns),
            'coordination_success_rate': sum(1 for r in coordination_results if r['success']) / len(coordination_results),
            'adaptive_formations_generated': len(adaptive_formations),
            'communication_security_level': secure_comm_channels['security_level']
        }
        
        self.phase_data['phase_5'] = phase_5_data

    async def _phase_6_second_detection(self):
        """Phase 6: 2차 공격 감지 및 반응"""
        self.logger.info("🛡️ Phase 6: 재배치 후 2차 공격 탐지")
        
        # 1. 향상된 탐지 시스템 활성화
        enhanced_detection_results = await self._activate_enhanced_detection()
        
        # 2. MTD 효과성 실시간 측정
        mtd_effectiveness = await self._measure_mtd_effectiveness()
        
        # 3. 적 적응 행동 분석
        enemy_adaptation_patterns = await self._analyze_enemy_adaptation()
        
        # 4. 동적 대응 전략 실행
        dynamic_responses = await self._execute_dynamic_responses()
        
        # 5. 허니드론 상태 모니터링
        honeydrone_status = await self._monitor_honeydrone_status()
        
        phase_6_data = {
            'second_wave_attacks_detected': len(enhanced_detection_results),
            'mtd_effectiveness_measured': mtd_effectiveness,
            'enemy_adaptation_level': enemy_adaptation_patterns['adaptation_score'],
            'dynamic_responses_triggered': len(dynamic_responses),
            'honeydrone_survival_rate': honeydrone_status['survival_rate']
        }
        
        self.phase_data['phase_6'] = phase_6_data

    async def _phase_7_regular_mission(self):
        """Phase 7: 실제 임무 수행"""
        self.logger.info("🎯 Phase 7: 실제 드론 임무 실행")
        
        # 1. 임무 유형 결정 (전장 환경별)
        mission_type = self._determine_mission_type()
        
        # 2. 실드론 임무 할당
        mission_assignments = await self._assign_real_drone_missions(mission_type)
        
        # 3. 허니드론 보호막 운용
        protection_coverage = await self._operate_honeydrone_shield()
        
        # 4. 임무 진행 모니터링
        mission_progress = await self._monitor_mission_progress()
        
        # 5. 위협 대응 중 임무 지속성 평가
        mission_continuity = await self._assess_mission_continuity()
        
        phase_7_data = {
            'mission_type': mission_type,
            'missions_assigned': len(mission_assignments),
            'mission_completion_rate': mission_progress['completion_rate'],
            'protection_effectiveness': protection_coverage['effectiveness'],
            'mission_continuity_score': mission_continuity['score']
        }
        
        self.phase_data['phase_7'] = phase_7_data

    async def _phase_8_merge_completion(self):
        """Phase 8: 시스템 병합 및 완료"""
        self.logger.info("📊 Phase 8: 최종 병합 및 결과 분석")
        
        # 1. 전체 Phase 데이터 통합
        integrated_data = await self._integrate_all_phase_data()
        
        # 2. 전장 환경별 성능 평가
        battlefield_performance = await self._evaluate_battlefield_performance()
        
        # 3. MTD-허니드론 시너지 효과 분석
        synergy_analysis = await self._analyze_mtd_honeydrone_synergy()
        
        # 4. 적응형 모델 업데이트
        model_updates = await self._update_adaptive_models()
        
        # 5. 최종 보고서 생성
        final_report = await self._generate_final_mission_report()
        
        phase_8_data = {
            'total_mission_duration': (datetime.now() - self.phase_start_time).total_seconds(),
            'overall_success_rate': battlefield_performance['success_rate'],
            'mtd_honeydrone_synergy_score': synergy_analysis['synergy_score'],
            'adaptive_improvements': len(model_updates),
            'final_report_generated': final_report is not None
        }
        
        self.phase_data['phase_8'] = phase_8_data

    def _get_env_adaptive_count(self, drone_type: str) -> int:
        """전장 환경별 적응형 드론 수량 결정"""
        base_counts = {
            'virtual_drones': {'favourable': 3, 'neutral': 5, 'unfavourable': 8},
            'dummy_drones': {'favourable': 2, 'neutral': 3, 'unfavourable': 5}
        }
        
        return base_counts[drone_type][self.battlefield_env.value]

    def _generate_strategic_position(self, drone_type: str, index: int) -> Dict[str, float]:
        """전략적 3D 위치 생성"""
        import random
        
        # 전장 환경별 배치 전략
        if self.battlefield_env == BattlefieldEnvironment.FAVOURABLE:
            # 넓은 범위 배치 (적 탐지 최대화)
            x_range, y_range, z_range = 200, 200, 80
        elif self.battlefield_env == BattlefieldEnvironment.NEUTRAL:
            # 중간 범위 배치 (균형)
            x_range, y_range, z_range = 150, 150, 60
        else:  # UNFAVOURABLE
            # 집중 배치 (생존성 우선)
            x_range, y_range, z_range = 100, 100, 40
        
        # 드론 타입별 배치 패턴
        if drone_type == 'virtual':
            # 가상 드론: 적 주의 분산용 넓은 배치
            return {
                'x': random.uniform(-x_range, x_range),
                'y': random.uniform(-y_range, y_range),
                'z': random.uniform(20, z_range)
            }
        else:  # dummy
            # 더미 드론: 공격 유도용 전방 배치
            return {
                'x': random.uniform(-x_range/2, x_range/2),
                'y': random.uniform(0, y_range),  # 전방 배치
                'z': random.uniform(10, z_range/2)  # 낮은 고도
            }

    async def _deploy_virtual_drone(self, drone_id: str, position: Dict[str, float]):
        """가상 드론 배치"""
        virtual_drone_config = {
            'id': drone_id,
            'type': 'virtual',
            'position': position,
            'capabilities': {
                'stealth_mode': True,
                'signal_emission': True,
                'decoy_behavior': True
            },
            'mission_profile': 'enemy_deception'
        }
        
        # 네트워크 매니저에 가상 노드 추가
        await self.event_bus.publish('deploy_virtual_drone', virtual_drone_config)

    async def _deploy_dummy_drone(self, drone_id: str, position: Dict[str, float], vulnerability_profile: Dict[str, Any]):
        """더미 드론 배치"""
        dummy_drone_config = {
            'id': drone_id,
            'type': 'dummy',
            'position': position,
            'vulnerability_profile': vulnerability_profile,
            'attack_attraction': {
                'gps_spoofing_susceptible': True,
                'mavlink_injection_vulnerable': True,
                'weak_encryption': True
            },
            'mission_profile': 'attack_honeypot'
        }
        
        await self.event_bus.publish('deploy_dummy_drone', dummy_drone_config)

    def _create_vulnerability_profile(self) -> Dict[str, Any]:
        """취약점 프로필 생성"""
        return {
            'firmware_version': 'vulnerable_v1.2.3',
            'security_features': {
                'encryption_enabled': False,
                'authentication_required': False,
                'access_control': 'minimal'
            },
            'exposed_services': [
                'mavlink_unsecured',
                'telemetry_plain',
                'camera_stream_unauth'
            ],
            'intentional_weaknesses': [
                'buffer_overflow_potential',
                'privilege_escalation_path',
                'credential_exposure'
            ]
        }