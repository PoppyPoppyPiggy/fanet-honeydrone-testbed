# 강화학습 기반 MTD 정책 통합 시스템
# rl_mtd_integration.py

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import deque
import random
import json

@dataclass
class MTDState:
    """MTD 시스템 상태"""
    attack_detected: bool
    attack_type: str
    attack_success_rate: float
    system_load: float
    network_latency: float
    previous_mtd_actions: List[str]
    time_since_last_attack: float
    threat_level: int
    active_connections: int
    resource_usage: float

@dataclass
class MTDAction:
    """MTD 액션"""
    action_id: int
    action_name: str
    target_component: str
    parameters: Dict[str, Any]
    expected_cost: float
    expected_effectiveness: float

@dataclass
class Experience:
    """강화학습 경험"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool

class MTDQNetwork(nn.Module):
    """MTD 정책을 위한 Deep Q-Network"""
    
    def __init__(self, state_size: int, action_size: int, hidden_size: int = 256):
        super(MTDQNetwork, self).__init__()
        
        self.feature_extractor = nn.Sequential(
            nn.Linear(state_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2)
        )
        
        # 듀얼링 아키텍처
        self.value_stream = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, 1)
        )
        
        self.advantage_stream = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, action_size)
        )
        
    def forward(self, x):
        features = self.feature_extractor(x)
        
        value = self.value_stream(features)
        advantage = self.advantage_stream(features)
        
        # 듀얼링 Q-value 계산
        q_value = value + (advantage - advantage.mean(dim=1, keepdim=True))
        
        return q_value

class MTDRLAgent:
    """강화학습 기반 MTD 에이전트"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 환경 설정
        self.state_size = config.get('state_size', 10)
        self.action_size = config.get('action_size', 8)
        self.hidden_size = config.get('hidden_size', 256)
        
        # 하이퍼파라미터
        self.learning_rate = config.get('learning_rate', 0.001)
        self.batch_size = config.get('batch_size', 32)
        self.gamma = config.get('gamma', 0.95)
        self.epsilon = config.get('epsilon', 1.0)
        self.epsilon_min = config.get('epsilon_min', 0.01)
        self.epsilon_decay = config.get('epsilon_decay', 0.995)
        self.target_update = config.get('target_update', 100)
        
        # 네트워크 초기화
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.q_network = MTDQNetwork(self.state_size, self.action_size, self.hidden_size).to(self.device)
        self.target_network = MTDQNetwork(self.state_size, self.action_size, self.hidden_size).to(self.device)
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
        
        # 경험 재플레이 버퍼
        self.memory = deque(maxlen=config.get('memory_size', 10000))
        
        # MTD 액션 정의
        self.mtd_actions = self._define_mtd_actions()
        
        # 학습 통계
        self.training_stats = {
            'episodes': 0,
            'total_reward': 0,
            'loss_history': [],
            'epsilon_history': [],
            'action_counts': {i: 0 for i in range(self.action_size)}
        }
        
        # 성능 메트릭
        self.performance_metrics = {
            'attack_prevention_rate': 0.0,
            'false_positive_rate': 0.0,
            'average_response_time': 0.0,
            'system_overhead': 0.0,
            'mtd_effectiveness_score': 0.0
        }
    
    def _define_mtd_actions(self) -> List[MTDAction]:
        """MTD 액션 정의"""
        actions = [
            MTDAction(0, "no_action", "none", {}, 0.0, 0.0),
            MTDAction(1, "ip_hopping", "network", {"hop_frequency": 30}, 0.1, 0.7),
            MTDAction(2, "port_randomization", "network", {"port_range": "8000-9000"}, 0.15, 0.6),
            MTDAction(3, "frequency_hopping", "radio", {"hop_interval": 10}, 0.3, 0.8),
            MTDAction(4, "mavlink_encryption", "protocol", {"key_rotation": 60}, 0.2, 0.9),
            MTDAction(5, "topology_mutation", "network", {"mutation_rate": 0.3}, 0.5, 0.8),
            MTDAction(6, "service_migration", "application", {"migration_time": 5}, 0.4, 0.7),
            MTDAction(7, "decoy_deployment", "deception", {"decoy_count": 3}, 0.3, 0.6)
        ]
        return actions
    
    def state_to_vector(self, state: MTDState) -> np.ndarray:
        """MTD 상태를 벡터로 변환"""
        vector = np.array([
            float(state.attack_detected),
            self._encode_attack_type(state.attack_type),
            state.attack_success_rate,
            state.system_load,
            state.network_latency / 1000.0,  # 정규화
            len(state.previous_mtd_actions) / 10.0,  # 정규화
            min(state.time_since_last_attack / 3600.0, 1.0),  # 시간 정규화
            state.threat_level / 5.0,  # 0-5 스케일
            state.active_connections / 100.0,  # 정규화
            state.resource_usage
        ])
        return vector
    
    def _encode_attack_type(self, attack_type: str) -> float:
        """공격 유형 인코딩"""
        encoding = {
            'none': 0.0,
            'gps_spoofing': 0.2,
            'mavlink_injection': 0.4,
            'wifi_deauth': 0.6,
            'companion_compromise': 0.8,
            'battery_spoofing': 1.0
        }
        return encoding.get(attack_type, 0.0)
    
    def select_action(self, state: MTDState, training: bool = True) -> int:
        """액션 선택 (epsilon-greedy)"""
        state_vector = self.state_to_vector(state)
        
        # 탐험 vs 활용
        if training and random.random() < self.epsilon:
            action = random.randint(0, self.action_size - 1)
        else:
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state_vector).unsqueeze(0).to(self.device)
                q_values = self.q_network(state_tensor)
                action = q_values.argmax().item()
        
        # 액션 통계 업데이트
        self.training_stats['action_counts'][action] += 1
        
        return action
    
    def calculate_reward(self, prev_state: MTDState, action: int, current_state: MTDState, 
                        attack_prevented: bool, mtd_success: bool) -> float:
        """보상 함수"""
        reward = 0.0
        
        # 기본 보상: 공격 차단 성공
        if attack_prevented:
            reward += 100.0
            
            # 보너스: 높은 위협 수준에서의 차단
            reward += current_state.threat_level * 20.0
        
        # 페널티: 공격 성공
        if current_state.attack_detected and current_state.attack_success_rate > 0.7:
            reward -= 50.0
        
        # MTD 액션 관련 보상/페널티
        action_obj = self.mtd_actions[action]
        
        if mtd_success:
            # MTD 성공 보상 (효과성 기반)
            reward += action_obj.expected_effectiveness * 30.0
        
        # 비용 페널티
        reward -= action_obj.expected_cost * 10.0
        
        # 시스템 성능 페널티
        if current_state.system_load > 0.8:
            reward -= 20.0
        
        if current_state.network_latency > 100:  # 100ms 이상
            reward -= 15.0
        
        # 연속적인 같은 액션 페널티 (다양성 장려)
        if len(prev_state.previous_mtd_actions) > 0:
            if prev_state.previous_mtd_actions[-1] == action_obj.action_name:
                reward -= 5.0
        
        # 적응성 보너스: 공격 유형에 맞는 액션
        if self._is_appropriate_action(current_state.attack_type, action):
            reward += 25.0
        
        return reward
    
    def _is_appropriate_action(self, attack_type: str, action: int) -> bool:
        """공격 유형에 적합한 액션인지 판단"""
        appropriate_actions = {
            'gps_spoofing': [3, 6],  # frequency_hopping, service_migration
            'mavlink_injection': [4, 1, 2],  # mavlink_encryption, ip_hopping, port_randomization
            'wifi_deauth': [3, 5],  # frequency_hopping, topology_mutation
            'companion_compromise': [1, 2, 6],  # ip_hopping, port_randomization, service_migration
            'battery_spoofing': [4, 7]  # mavlink_encryption, decoy_deployment
        }
        
        return action in appropriate_actions.get(attack_type, [])
    
    def remember(self, state: MTDState, action: int, reward: float, 
                next_state: MTDState, done: bool):
        """경험 저장"""
        state_vector = self.state_to_vector(state)
        next_state_vector = self.state_to_vector(next_state)
        
        experience = Experience(state_vector, action, reward, next_state_vector, done)
        self.memory.append(experience)
    
    def replay(self) -> Optional[float]:
        """경험 재플레이 학습"""
        if len(self.memory) < self.batch_size:
            return None
        
        # 배치 샘플링
        batch = random.sample(self.memory, self.batch_size)
        
        states = torch.FloatTensor([e.state for e in batch]).to(self.device)
        actions = torch.LongTensor([e.action for e in batch]).to(self.device)
        rewards = torch.FloatTensor([e.reward for e in batch]).to(self.device)
        next_states = torch.FloatTensor([e.next_state for e in batch]).to(self.device)
        dones = torch.BoolTensor([e.done for e in batch]).to(self.device)
        
        # 현재 Q-values
        current_q_values = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # 다음 Q-values (Double DQN)
        next_actions = self.q_network(next_states).argmax(1, keepdim=True)
        next_q_values = self.target_network(next_states).gather(1, next_actions).squeeze(1)
        
        # 타겟 Q-values
        target_q_values = rewards + (self.gamma * next_q_values * ~dones)
        
        # 손실 계산
        loss = nn.MSELoss()(current_q_values.squeeze(1), target_q_values.detach())
        
        # 역전파
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        self.optimizer.step()
        
        # Epsilon 감소
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # 통계 업데이트
        self.training_stats['loss_history'].append(loss.item())
        self.training_stats['epsilon_history'].append(self.epsilon)
        
        return loss.item()
    
    def update_target_network(self):
        """타겟 네트워크 업데이트"""
        self.target_network.load_state_dict(self.q_network.state_dict())
    
    def save_model(self, filepath: str):
        """모델 저장"""
        torch.save({
            'q_network': self.q_network.state_dict(),
            'target_network': self.target_network.state_dict(),
            'optimizer': self.optimizer.state_dict(),
            'training_stats': self.training_stats,
            'performance_metrics': self.performance_metrics,
            'epsilon': self.epsilon
        }, filepath)
        
        self.logger.info(f"모델 저장됨: {filepath}")
    
    def load_model(self, filepath: str):
        """모델 로드"""
        checkpoint = torch.load(filepath, map_location=self.device)
        
        self.q_network.load_state_dict(checkpoint['q_network'])
        self.target_network.load_state_dict(checkpoint['target_network'])
        self.optimizer.load_state_dict(checkpoint['optimizer'])
        self.training_stats = checkpoint['training_stats']
        self.performance_metrics = checkpoint['performance_metrics']
        self.epsilon = checkpoint['epsilon']
        
        self.logger.info(f"모델 로드됨: {filepath}")

class MTDIntegratedSystem:
    """MTD 통합 시스템 - 실제 공격 환경과 강화학습 연동"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 강화학습 에이전트
        self.rl_agent = MTDRLAgent(config.get('rl_config', {}))
        
        # 실제 공격 평가기 (이전에 만든 것)
        from real_attack_mtd_evaluator import RealAttackMTDEvaluator
        self.attack_evaluator = RealAttackMTDEvaluator(config.get('attack_config', {}))
        
        # 현재 상태
        self.current_state = None
        self.episode_count = 0
        self.training_active = False
        
        # 성과 추적
        self.episode_rewards = []
        self.attack_prevention_history = []
        self.mtd_action_history = []
    
    async def start_training(self, num_episodes: int = 1000):
        """강화학습 훈련 시작"""
        self.logger.info(f"MTD 강화학습 훈련 시작: {num_episodes} 에피소드")
        self.training_active = True
        
        try:
            # 환경 설정
            await self.attack_evaluator.setup_environment()
            
            for episode in range(num_episodes):
                if not self.training_active:
                    break
                
                self.episode_count = episode
                episode_reward = await self._run_training_episode()
                self.episode_rewards.append(episode_reward)
                
                # 주기적 평가 및 모델 저장
                if episode % 50 == 0:
                    await self._evaluate_performance()
                    self._save_training_checkpoint(episode)
                
                # 타겟 네트워크 업데이트
                if episode % self.rl_agent.target_update == 0:
                    self.rl_agent.update_target_network()
                
                self.logger.info(f"에피소드 {episode}: 보상 {episode_reward:.2f}, "
                               f"Epsilon {self.rl_agent.epsilon:.3f}")
        
        except Exception as e:
            self.logger.error(f"훈련 오류: {e}")
        
        finally:
            self.training_active = False
            await self._save_final_model()
    
    async def _run_training_episode(self) -> float:
        """훈련 에피소드 실행"""
        
        # 초기 상태 생성
        current_state = await self._generate_initial_state()
        episode_reward = 0.0
        step_count = 0
        max_steps = 20  # 에피소드당 최대 스텝
        
        while step_count < max_steps:
            # 액션 선택
            action = self.rl_agent.select_action(current_state, training=True)
            
            # 환경에서 액션 실행
            next_state, reward, done, mtd_success = await self._execute_mtd_action(
                current_state, action
            )
            
            # 경험 저장
            self.rl_agent.remember(current_state, action, reward, next_state, done)
            
            # 학습
            if len(self.rl_agent.memory) >= self.rl_agent.batch_size:
                loss = self.rl_agent.replay()
            
            episode_reward += reward
            current_state = next_state
            step_count += 1
            
            if done:
                break
        
        return episode_reward
    
    async def _generate_initial_state(self) -> MTDState:
        """초기 상태 생성"""
        
        # 랜덤한 공격 시나리오 선택
        attack_scenarios = ['gps_spoofing_real', 'mavlink_injection_real', 'wifi_deauth_real']
        attack_type = random.choice(['none', 'gps_spoofing', 'mavlink_injection', 'wifi_deauth'])
        
        return MTDState(
            attack_detected=random.random() < 0.3,  # 30% 확률로 공격 탐지
            attack_type=attack_type,
            attack_success_rate=random.uniform(0.0, 1.0),
            system_load=random.uniform(0.1, 0.9),
            network_latency=random.uniform(10, 200),
            previous_mtd_actions=[],
            time_since_last_attack=random.uniform(0, 3600),
            threat_level=random.randint(1, 5),
            active_connections=random.randint(1, 50),
            resource_usage=random.uniform(0.1, 0.8)
        )
    
    async def _execute_mtd_action(self, state: MTDState, action: int) -> Tuple[MTDState, float, bool, bool]:
        """MTD 액션 실행 및 결과 반환"""
        
        mtd_action = self.rl_agent.mtd_actions[action]
        
        # MTD 액션 실행 시뮬레이션
        mtd_success = await self._simulate_mtd_execution(mtd_action, state)
        
        # 실제 공격 시나리오 실행 (일부 에피소드에서만)
        attack_prevented = False
        if random.random() < 0.3:  # 30% 확률로 실제 공격 실행
            attack_result = await self._run_real_attack_scenario(state.attack_type)
            attack_prevented = attack_result.get('mtd_triggered', False)
        
        # 다음 상태 생성
        next_state = await self._generate_next_state(state, action, mtd_success)
        
        # 보상 계산
        reward = self.rl_agent.calculate_reward(state, action, next_state, attack_prevented, mtd_success)
        
        # 에피소드 종료 조건
        done = (next_state.attack_success_rate > 0.9 or  # 공격 대부분 성공
                next_state.system_load > 0.95 or        # 시스템 과부하
                len(next_state.previous_mtd_actions) > 10)  # 너무 많은 액션
        
        return next_state, reward, done, mtd_success
    
    async def _simulate_mtd_execution(self, mtd_action: MTDAction, state: MTDState) -> bool:
        """MTD 액션 실행 시뮬레이션"""
        
        # 실행 성공 확률 (액션 복잡도와 시스템 상태 기반)
        base_success_rate = mtd_action.expected_effectiveness
        
        # 시스템 로드가 높으면 성공률 감소
        if state.system_load > 0.8:
            base_success_rate *= 0.7
        
        # 이전 같은 액션이 있으면 성공률 감소 (내성)
        if mtd_action.action_name in state.previous_mtd_actions[-3:]:
            base_success_rate *= 0.8
        
        success = random.random() < base_success_rate
        
        # 실행 지연 시뮬레이션
        execution_delay = mtd_action.expected_cost * 2  # 비용에 비례한 지연
        await asyncio.sleep(min(execution_delay, 2.0))  # 최대 2초
        
        return success
    
    async def _run_real_attack_scenario(self, attack_type: str) -> Dict[str, Any]:
        """실제 공격 시나리오 실행"""
        
        if attack_type == 'none':
            return {'mtd_triggered': False, 'success_rate': 0}
        
        # 공격 유형에 따른 시나리오 매핑
        scenario_mapping = {
            'gps_spoofing': 'gps_spoofing_real',
            'mavlink_injection': 'mavlink_injection_real',
            'wifi_deauth': 'wifi_deauth_real'
        }
        
        scenario = scenario_mapping.get(attack_type)
        if scenario:
            try:
                result = await self.attack_evaluator.execute_real_attack_scenario(scenario)
                return result
            except Exception as e:
                self.logger.debug(f"실제 공격 실행 오류: {e}")
        
        # 시뮬레이션된 결과 반환
        return {
            'mtd_triggered': random.random() < 0.6,
            'success_rate': random.uniform(0.2, 0.8)
        }
    
    async def _generate_next_state(self, current_state: MTDState, action: int, mtd_success: bool) -> MTDState:
        """다음 상태 생성"""
        
        mtd_action = self.rl_agent.mtd_actions[action]
        
        # 새로운 상태 계산
        new_previous_actions = current_state.previous_mtd_actions[-9:] + [mtd_action.action_name]
        
        # 시스템 로드 변화 (MTD 액션에 따라)
        load_change = mtd_action.expected_cost * random.uniform(0.5, 1.5)
        new_system_load = min(1.0, current_state.system_load + load_change)
        
        # 네트워크 지연 변화
        latency_change = mtd_action.expected_cost * random.uniform(-10, 30)
        new_network_latency = max(5, current_state.network_latency + latency_change)
        
        # 공격 성공률 변화 (MTD 효과 반영)
        if mtd_success and current_state.attack_detected:
            success_rate_reduction = mtd_action.expected_effectiveness * random.uniform(0.3, 0.7)
            new_attack_success_rate = max(0, current_state.attack_success_rate - success_rate_reduction)
        else:
            new_attack_success_rate = current_state.attack_success_rate
        
        # 새로운 공격 발생 가능성
        new_attack_detected = random.random() < 0.2  # 20% 확률
        new_attack_type = random.choice(['none', 'gps_spoofing', 'mavlink_injection']) if new_attack_detected else 'none'
        
        return MTDState(
            attack_detected=new_attack_detected,
            attack_type=new_attack_type,
            attack_success_rate=new_attack_success_rate,
            system_load=new_system_load,
            network_latency=new_network_latency,
            previous_mtd_actions=new_previous_actions,
            time_since_last_attack=0 if new_attack_detected else current_state.time_since_last_attack + 60,
            threat_level=random.randint(1, 5),
            active_connections=max(1, current_state.active_connections + random.randint(-5, 5)),
            resource_usage=min(1.0, new_system_load + random.uniform(-0.1, 0.1))
        )
    
    async def _evaluate_performance(self):
        """성능 평가"""
        
        # 최근 50 에피소드 성능 분석
        recent_rewards = self.episode_rewards[-50:] if len(self.episode_rewards) >= 50 else self.episode_rewards
        
        if recent_rewards:
            avg_reward = sum(recent_rewards) / len(recent_rewards)
            
            self.rl_agent.performance_metrics.update({
                'average_reward': avg_reward,
                'episodes_completed': len(self.episode_rewards),
                'current_epsilon': self.rl_agent.epsilon
            })
            
            self.logger.info(f"성능 평가 - 평균 보상: {avg_reward:.2f}, "
                           f"완료 에피소드: {len(self.episode_rewards)}")
    
    def _save_training_checkpoint(self, episode: int):
        """훈련 체크포인트 저장"""
        
        checkpoint_path = f"mtd_checkpoint_episode_{episode}.pth"
        self.rl_agent.save_model(checkpoint_path)
        
        # 성능 메트릭 저장
        metrics_path = f"training_metrics_episode_{episode}.json"
        with open(metrics_path, 'w') as f:
            json.dump({
                'episode': episode,
                'episode_rewards': self.episode_rewards,
                'training_stats': self.rl_agent.training_stats,
                'performance_metrics': self.rl_agent.performance_metrics
            }, f, indent=2)
    
    async def _save_final_model(self):
        """최종 모델 저장"""
        
        final_model_path = f"mtd_final_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pth"
        self.rl_agent.save_model(final_model_path)
        
        # 최종 성과 리포트 생성
        final_report = {
            'training_completed': datetime.now().isoformat(),
            'total_episodes': len(self.episode_rewards),
            'final_performance': self.rl_agent.performance_metrics,
            'training_summary': {
                'average_reward': sum(self.episode_rewards) / len(self.episode_rewards) if self.episode_rewards else 0,
                'best_episode_reward': max(self.episode_rewards) if self.episode_rewards else 0,
                'final_epsilon': self.rl_agent.epsilon
            }
        }
        
        with open('mtd_training_final_report.json', 'w') as f:
            json.dump(final_report, f, indent=2)
        
        self.logger.info(f"최종 모델 저장됨: {final_model_path}")
    
    async def run_evaluation_mode(self, num_episodes: int = 10):
        """평가 모드 실행 (훈련 없이)"""
        
        self.logger.info(f"MTD 평가 모드 시작: {num_episodes} 에피소드")
        
        evaluation_results = []
        
        try:
            await self.attack_evaluator.setup_environment()
            
            for episode in range(num_episodes):
                current_state = await self._generate_initial_state()
                episode_reward = 0.0
                step_count = 0
                max_steps = 20
                
                episode_log = {
                    'episode': episode,
                    'steps': [],
                    'total_reward': 0,
                    'attacks_prevented': 0,
                    'mtd_actions_taken': []
                }
                
                while step_count < max_steps:
                    # 액션 선택 (훈련 모드 OFF)
                    action = self.rl_agent.select_action(current_state, training=False)
                    
                    # 액션 실행
                    next_state, reward, done, mtd_success = await self._execute_mtd_action(
                        current_state, action
                    )
                    
                    # 로그 기록
                    episode_log['steps'].append({
                        'step': step_count,
                        'action': self.rl_agent.mtd_actions[action].action_name,
                        'reward': reward,
                        'mtd_success': mtd_success
                    })
                    
                    if mtd_success:
                        episode_log['attacks_prevented'] += 1
                    
                    episode_log['mtd_actions_taken'].append(action)
                    
                    episode_reward += reward
                    current_state = next_state
                    step_count += 1
                    
                    if done:
                        break
                
                episode_log['total_reward'] = episode_reward
                evaluation_results.append(episode_log)
                
                self.logger.info(f"평가 에피소드 {episode}: 보상 {episode_reward:.2f}, "
                               f"공격 차단 {episode_log['attacks_prevented']}회")
        
        except Exception as e:
            self.logger.error(f"평가 모드 오류: {e}")
        
        # 평가 결과 저장
        evaluation_report_path = f"mtd_evaluation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(evaluation_report_path, 'w') as f:
            json.dump(evaluation_results, f, indent=2)
        
        self.logger.info(f"평가 결과 저장됨: {evaluation_report_path}")
        
        return evaluation_results

# 실행 예제
async def main():
    """강화학습 기반 MTD 시스템 실행"""
    
    config = {
        'rl_config': {
            'state_size': 10,
            'action_size': 8,
            'learning_rate': 0.001,
            'batch_size': 32,
            'gamma': 0.95,
            'epsilon': 1.0,
            'epsilon_min': 0.01,
            'epsilon_decay': 0.995,
            'target_update': 100,
            'memory_size': 10000
        },
        'attack_config': {
            'kali_container': 'kali-attacker',
            'dvd_container': 'damn-vulnerable-drone',
            'dvd_ip': '192.168.100.10',
            'kali_ip': '192.168.100.20'
        }
    }
    
    mtd_system = MTDIntegratedSystem(config)
    
    try:
        print("🤖 강화학습 기반 MTD 시스템 시작")
        print("🎯 훈련 모드로 시작...")
        
        # 훈련 실행
        await mtd_system.start_training(num_episodes=200)
        
        print("📊 평가 모드로 전환...")
        
        # 평가 실행
        evaluation_results = await mtd_system.run_evaluation_mode(num_episodes=10)
        
        print("✅ MTD 강화학습 시스템 완료")
        
    except KeyboardInterrupt:
        print("\n🛑 사용자에 의해 중단됨")
    except Exception as e:
        print(f"❌ 실행 오류: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())