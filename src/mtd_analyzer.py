#!/usr/bin/env python3
"""MTD 효과성 실시간 분석 도구"""

import time
import json
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import numpy as np

class MTDAnalyzer:
    def __init__(self):
        self.threat_history = deque(maxlen=100)
        self.action_history = deque(maxlen=100)
        self.action_counts = defaultdict(int)
        self.threat_levels = deque(maxlen=50)
        self.timestamps = deque(maxlen=50)
        
    def parse_mtd_output(self, line):
        """MTD 엔진 출력 파싱"""
        timestamp = datetime.now()
        
        # 위협 감지 패턴
        threat_match = re.search(r'위협 감지! 레벨: (\d+)', line)
        if threat_match:
            level = int(threat_match.group(1))
            self.threat_history.append({
                'timestamp': timestamp,
                'level': level,
                'type': 'threat_detected'
            })
            self.threat_levels.append(level)
            self.timestamps.append(timestamp)
            return 'threat', level
        
        # MTD 액션 패턴
        action_match = re.search(r'MTD 액션 실행: (\w+)', line)
        if action_match:
            action = action_match.group(1)
            self.action_history.append({
                'timestamp': timestamp,
                'action': action,
                'type': 'mtd_action'
            })
            self.action_counts[action] += 1
            return 'action', action
        
        return None, None
    
    def calculate_metrics(self):
        """MTD 효과성 메트릭 계산"""
        if len(self.threat_history) < 2:
            return {}
        
        recent_threats = [t for t in self.threat_history 
                         if t['timestamp'] > datetime.now() - timedelta(minutes=5)]
        recent_actions = [a for a in self.action_history 
                         if a['timestamp'] > datetime.now() - timedelta(minutes=5)]
        
        metrics = {
            'total_threats': len(self.threat_history),
            'total_actions': len(self.action_history),
            'recent_threats_5min': len(recent_threats),
            'recent_actions_5min': len(recent_actions),
            'avg_threat_level': np.mean([t['level'] for t in recent_threats]) if recent_threats else 0,
            'max_threat_level': max([t['level'] for t in recent_threats]) if recent_threats else 0,
            'action_frequency': len(recent_actions) / 5.0,  # 분당 액션 수
            'threat_response_ratio': len(recent_actions) / max(len(recent_threats), 1)
        }
        
        return metrics
    
    def get_action_distribution(self):
        """액션 분포 반환"""
        total = sum(self.action_counts.values())
        if total == 0:
            return {}
        
        return {action: count/total for action, count in self.action_counts.items()}
    
    def print_dashboard(self):
        """실시간 대시보드 출력"""
        metrics = self.calculate_metrics()
        action_dist = self.get_action_distribution()
        
        print("\n" + "="*60)
        print("🛡️  MTD 시스템 실시간 분석 대시보드")
        print("="*60)
        
        print(f"📊 전체 통계:")
        print(f"  - 총 위협 감지: {metrics.get('total_threats', 0)}회")
        print(f"  - 총 MTD 액션: {metrics.get('total_actions', 0)}회")
        
        print(f"\n⏱️  최근 5분간:")
        print(f"  - 위협 감지: {metrics.get('recent_threats_5min', 0)}회")
        print(f"  - MTD 액션: {metrics.get('recent_actions_5min', 0)}회")
        print(f"  - 평균 위협 레벨: {metrics.get('avg_threat_level', 0):.1f}")
        print(f"  - 최대 위협 레벨: {metrics.get('max_threat_level', 0)}")
        print(f"  - 액션 빈도: {metrics.get('action_frequency', 0):.2f}/분")
        print(f"  - 대응 비율: {metrics.get('threat_response_ratio', 0):.2f}")
        
        if action_dist:
            print(f"\n🎯 MTD 액션 분포:")
            for action, ratio in sorted(action_dist.items(), key=lambda x: x[1], reverse=True):
                bar = "█" * int(ratio * 20)
                print(f"  - {action:15}: {ratio:5.1%} {bar}")
        
        # 최근 활동
        print(f"\n📈 최근 활동:")
        recent_events = sorted(
            list(self.threat_history)[-5:] + list(self.action_history)[-5:],
            key=lambda x: x['timestamp']
        )[-8:]
        
        for event in recent_events:
            time_str = event['timestamp'].strftime("%H:%M:%S")
            if event['type'] == 'threat_detected':
                print(f"  {time_str} ⚠️  위협 레벨 {event['level']}")
            else:
                print(f"  {time_str} 🛡️  {event['action']}")
    
    def save_report(self, filename="mtd_analysis_report.json"):
        """분석 결과를 JSON 파일로 저장"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'metrics': self.calculate_metrics(),
            'action_distribution': self.get_action_distribution(),
            'threat_history': [
                {
                    'timestamp': t['timestamp'].isoformat(),
                    'level': t['level']
                } for t in list(self.threat_history)
            ],
            'action_history': [
                {
                    'timestamp': a['timestamp'].isoformat(),
                    'action': a['action']
                } for a in list(self.action_history)
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 분석 보고서 저장됨: {filename}")

def monitor_mtd_engine():
    """MTD 엔진 실시간 모니터링"""
    analyzer = MTDAnalyzer()
    
    print("🔍 MTD 엔진 실시간 모니터링 시작...")
    print("Ctrl+C로 중지하고 보고서 생성")
    
    try:
        # MTD 엔진 프로세스 찾기
        result = subprocess.run(['pgrep', '-f', 'rl_mtd_engine.py'], 
                               capture_output=True, text=True)
        
        if result.returncode != 0:
            print("❌ MTD 엔진 프로세스를 찾을 수 없습니다.")
            return
        
        pid = result.stdout.strip().split('\n')[0]
        print(f"✅ MTD 엔진 PID: {pid}")
        
        # 실시간 로그 모니터링 (journalctl 또는 프로세스 출력)
        # 실제 구현에서는 MTD 엔진의 로그 출력을 캡처해야 함
        
        last_dashboard_update = time.time()
        simulation_counter = 0
        
        while True:
            # 시뮬레이션된 데이터 (실제로는 MTD 엔진에서 읽어옴)
            simulation_counter += 1
            
            if simulation_counter % 3 == 0:  # 위협 시뮬레이션
                threat_level = np.random.randint(4, 9)
                analyzer.parse_mtd_output(f"⚠️  위협 감지! 레벨: {threat_level}")
                
                if threat_level > 5:  # MTD 액션 트리거
                    actions = ["TOPOLOGY_CHANGE", "PORT_SHUFFLE", "IP_SHUFFLE", 
                             "DECOY_DEPLOYMENT", "FREQUENCY_CHANGE"]
                    action = np.random.choice(actions)
                    analyzer.parse_mtd_output(f"🛡️  MTD 액션 실행: {action}")
            
            # 30초마다 대시보드 업데이트
            if time.time() - last_dashboard_update > 30:
                analyzer.print_dashboard()
                last_dashboard_update = time.time()
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\n🛑 모니터링 중지")
        analyzer.print_dashboard()
        analyzer.save_report()

def analyze_saved_logs(log_file):
    """저장된 로그 파일 분석"""
    analyzer = MTDAnalyzer()
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                analyzer.parse_mtd_output(line.strip())
        
        analyzer.print_dashboard()
        analyzer.save_report(f"analysis_{int(time.time())}.json")
        
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {log_file}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # 로그 파일 분석 모드
        analyze_saved_logs(sys.argv[1])
    else:
        # 실시간 모니터링 모드
        monitor_mtd_engine()