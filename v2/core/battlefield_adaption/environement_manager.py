# 전장 환경별 적응형 MTD 전략 매니저
# core/battlefield_adaptation/environment_manager.py

class BattlefieldEnvironmentManager:
    """전장 환경별 적응형 관리자"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 환경별 전략 매핑
        self.environment_strategies = {
            BattlefieldEnvironment.FAVOURABLE: {
                'mtd_aggressiveness': 0.3,  # 낮은 공격성
                'honeydrone_visibility': 0.8,  # 높은 가시성
                'decoy_authenticity': 0.6,  # 중간 수준 리얼리즘
                'mission_priority': 'intelligence_gathering'
            },
            BattlefieldEnvironment.NEUTRAL: {
                'mtd_aggressiveness': 0.6,  # 중간 공격성
                'honeydrone_visibility': 0.6,  # 중간 가시성
                'decoy_authenticity': 0.8,  # 높은 리얼리즘
                'mission_priority': 'balanced_operations'
            },
            BattlefieldEnvironment.UNFAVOURABLE: {
                'mtd_aggressiveness': 0.9,  # 높은 공격성
                'honeydrone_visibility': 0.4,  # 낮은 가시성 (스텔스)
                'decoy_authenticity': 0.9,  # 최고 수준 리얼리즘
                'mission_priority': 'survival_protection'
            }
        }
    
    def get_adaptive_strategy(self, environment: BattlefieldEnvironment, 
                            current_threat_level: float) -> Dict[str, Any]:
        """환경 및 위협 수준별 적응형 전략"""
        base_strategy = self.environment_strategies[environment]
        
        # 위협 수준에 따른 동적 조정
        threat_modifier = {
            'mtd_aggressiveness': min(1.0, base_strategy['mtd_aggressiveness'] + threat_level * 0.3),
            'honeydrone_visibility': max(0.1, base_strategy['honeydrone_visibility'] - threat_level * 0.2),
            'response_speed': threat_level * 0.8 + 0.2
        }
        
        return {**base_strategy, **threat_modifier}