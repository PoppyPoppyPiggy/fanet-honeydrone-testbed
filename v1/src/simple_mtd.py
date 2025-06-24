#!/usr/bin/env python3
import asyncio
import random
import time
from datetime import datetime

class SimpleMTD:
    def __init__(self):
        self.threat_level = 0
        self.running = True
        
    async def run(self):
        print("🚁 MTD Engine Started")
        
        while self.running:
            # 위협 감지 시뮬레이션
            if random.random() < 0.2:  # 20% 확률
                threat_increase = random.randint(1, 3)
                self.threat_level += threat_increase
                print(f"⚠️  위협 감지! 레벨: {self.threat_level}")
                
                # MTD 액션 실행
                if self.threat_level > 5:
                    actions = ["TOPOLOGY_CHANGE", "PORT_SHUFFLE", "IP_SHUFFLE", "DECOY_DEPLOYMENT"]
                    action = random.choice(actions)
                    print(f"🛡️  MTD 액션 실행: {action}")
                    self.threat_level = max(0, self.threat_level - random.randint(2, 4))
            
            await asyncio.sleep(3)
    
    def stop(self):
        self.running = False

if __name__ == "__main__":
    mtd = SimpleMTD()
    try:
        asyncio.run(mtd.run())
    except KeyboardInterrupt:
        mtd.stop()
        print("\n🛑 MTD Engine Stopped")
