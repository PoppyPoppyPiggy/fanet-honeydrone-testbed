#!/usr/bin/env python3
"""간단한 MTD 엔진 데모"""

import asyncio
import json
import random
import time
from datetime import datetime

class SimpleMTDEngine:
    def __init__(self):
        self.is_running = False
        self.threat_level = 0
        self.actions_taken = []
        
    async def start(self):
        self.is_running = True
        print("🚁 MTD Engine Started")
        
        while self.is_running:
            await self.check_threats()
            await self.make_decision()
            await asyncio.sleep(5)  # 5초마다 체크
    
    async def check_threats(self):
        # 랜덤 위협 시뮬레이션
        if random.random() < 0.1:  # 10% 확률로 위협 발생
            self.threat_level += random.randint(1, 3)
            print(f"⚠️  위협 감지! 레벨: {self.threat_level}")
    
    async def make_decision(self):
        if self.threat_level > 5:
            action = random.choice([
                "IP_SHUFFLE", "PORT_SHUFFLE", "TOPOLOGY_CHANGE"
            ])
            self.actions_taken.append({
                'time': datetime.now().isoformat(),
                'action': action,
                'threat_level': self.threat_level
            })
            print(f"🛡️  MTD 액션 실행: {action}")
            self.threat_level = max(0, self.threat_level - 3)
    
    def stop(self):
        self.is_running = False
        print("MTD Engine Stopped")

if __name__ == "__main__":
    engine = SimpleMTDEngine()
    try:
        asyncio.run(engine.start())
    except KeyboardInterrupt:
        engine.stop()
