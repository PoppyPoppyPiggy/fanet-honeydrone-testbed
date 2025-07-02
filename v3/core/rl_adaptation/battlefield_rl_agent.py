
# 강화학습 기반 MTD 최적화 (환경별 적응)
# core/rl_adaptation/battlefield_rl_agent.py

import numpy as np
import torch
import torch.nn as nn
from typing import Tuple

class BattlefieldAdaptiveQNetwork(nn.Module):
    """전장 환경 적응형 Q-Network"""
    
    def __init__(self, state_size: int, action_size: int, environment_embedding_size: int = 16):
        super().__init__()
        
        # 환경 임베딩 레이어
        self.environment_embedding = nn.Embedding(3, environment_embedding_size)  # 3개 환경
        
        # 상태 처리 레이어
        self.state_processing = nn.Sequential(
            nn.Linear(state_size, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU()
        )