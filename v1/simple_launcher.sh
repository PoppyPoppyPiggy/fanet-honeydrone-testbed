#!/bin/bash
# simple_launcher.sh
# 간단한 DVDS + MTD 통합 런처

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DVDS_DIR="${PROJECT_DIR}/external/dvds"

setup_environment() {
    log_info "환경 설정 중..."
    
    # 디렉토리 생성
    mkdir -p logs data external src config
    
    # Python 가상환경 설정
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_info "Python 가상환경 생성됨"
    fi
    
    # 의존성 설치
    source venv/bin/activate
    pip install --upgrade pip
    pip install requests asyncio numpy networkx flask
    
    log_info "환경 설정 완료"
}

clone_dvds() {
    log_info "DVDS 설정 중..."
    
    if [[ ! -d "$DVDS_DIR" ]]; then
        log_info "DVDS 클론 중..."
        mkdir -p external
        cd external
        git clone https://github.com/nicholasaleks/Damn-Vulnerable-Drone.git dvds
        cd "$PROJECT_DIR"
        log_info "DVDS 클론 완료"
    else
        log_info "DVDS 이미 존재함"
    fi
}

start_dvds() {
    log_info "DVDS 시작 중..."
    
    if [[ ! -d "$DVDS_DIR" ]]; then
        log_error "DVDS가 설치되지 않았습니다. 먼저 setup을 실행하세요."
        return 1
    fi
    
    cd "$DVDS_DIR"
    
    # DVDS 시작
    if [[ -f "start.sh" ]]; then
        sudo ./start.sh
        sleep 10
        
        # 상태 확인
        if sudo ./status.sh | grep -q "is running"; then
            log_info "DVDS가 성공적으로 시작됨"
            return 0
        else
            log_warn "DVDS 시작에 문제가 있을 수 있습니다"
            sudo ./status.sh
            return 1
        fi
    else
        log_error "DVDS start.sh 파일이 없습니다"
        return 1
    fi
}

start_mtd() {
    log_info "MTD 엔진 시작 중..."
    
    cd "$PROJECT_DIR"
    source venv/bin/activate
    
    # 간단한 MTD 엔진 생성
    cat > src/simple_mtd.py << 'EOF'
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
EOF

    # MTD 엔진 백그라운드 실행
    python3 src/simple_mtd.py &
    MTD_PID=$!
    echo $MTD_PID > data/mtd.pid
    
    log_info "MTD 엔진이 백그라운드에서 시작됨 (PID: $MTD_PID)"
}

stop_services() {
    log_info "서비스 중지 중..."
    
    # MTD 엔진 중지
    if [[ -f "data/mtd.pid" ]]; then
        PID=$(cat data/mtd.pid)
        if kill -0 $PID 2>/dev/null; then
            kill $PID
            log_info "MTD 엔진 중지됨"
        fi
        rm -f data/mtd.pid
    fi
    
    # DVDS 중지
    if [[ -d "$DVDS_DIR" ]]; then
        cd "$DVDS_DIR"
        sudo ./stop.sh 2>/dev/null || true
        log_info "DVDS 중지됨"
    fi
}

check_status() {
    log_info "서비스 상태 확인 중..."
    
    echo "=== MTD 엔진 ===="
    if [[ -f "data/mtd.pid" ]] && kill -0 $(cat data/mtd.pid) 2>/dev/null; then
        echo "MTD 엔진: 실행 중"
    else
        echo "MTD 엔진: 중지됨"
    fi
    
    echo -e "\n=== DVDS 상태 ==="
    if [[ -d "$DVDS_DIR" ]]; then
        cd "$DVDS_DIR"
        sudo ./status.sh 2>/dev/null || echo "DVDS 상태 확인 실패"
        cd "$PROJECT_DIR"
    else
        echo "DVDS: 설치되지 않음"
    fi
    
    echo -e "\n=== 네트워크 포트 ==="
    netstat -tulpn 2>/dev/null | grep -E ":808[0-9]|:500[0-9]" | grep LISTEN || echo "관련 포트 없음"
}

show_help() {
    cat << EOF
간단한 DVDS + MTD 통합 런처

사용법: $0 <명령>

명령어:
  setup     - 환경 설정 및 DVDS 클론
  start     - 모든 서비스 시작
  stop      - 모든 서비스 중지
  status    - 서비스 상태 확인
  help      - 도움말 표시

예시:
  $0 setup
  $0 start
  $0 status
EOF
}

case "${1:-help}" in
    "setup")
        setup_environment
        clone_dvds
        log_info "설정 완료"
        ;;
    "start")
        if start_dvds; then
            start_mtd
            log_info "모든 서비스가 시작되었습니다!"
        else
            log_warn "DVDS 시작 실패, MTD만 시작합니다"
            start_mtd
        fi
        ;;
    "stop")
        stop_services
        ;;
    "status")
        check_status
        ;;
    "help"|*)
        show_help
        ;;
esac