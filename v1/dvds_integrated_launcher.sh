#!/bin/bash
# dvds_integrated_launcher.sh
# DVDS 통합 FANET 허니드론 테스트베드 실행 스크립트

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="${PROJECT_DIR}/logs"
DATA_DIR="${PROJECT_DIR}/data" 
EXTERNAL_DIR="${PROJECT_DIR}/external"
DVDS_DIR="${EXTERNAL_DIR}/dvds"

setup_dvds() {
    log_info "DVDS 설정 중..."
    
    mkdir -p "$EXTERNAL_DIR"
    
    if [[ ! -d "$DVDS_DIR" ]]; then
        log_info "DVDS GitHub 저장소 클론 중..."
        cd "$EXTERNAL_DIR"
        git clone https://github.com/nicholasaleks/Damn-Vulnerable-Drone.git dvds
        cd "$PROJECT_DIR"
    else
        log_info "DVDS 이미 존재함"
    fi
    
    # DVDS 의존성 설치
    if [[ -f "$DVDS_DIR/requirements.txt" ]]; then
        log_info "DVDS Python 의존성 설치 중..."
        cd "$DVDS_DIR"
        
        # Python 가상환경 생성 (DVDS용)
        if [[ ! -d "venv" ]]; then
            python3 -m venv venv
        fi
        
        source venv/bin/activate
        pip install -r requirements.txt
        cd "$PROJECT_DIR"
    fi
}

setup_directories() {
    log_info "프로젝트 디렉토리 구조 생성 중..."
    
    mkdir -p "$LOGS_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$EXTERNAL_DIR"
    mkdir -p "${PROJECT_DIR}/config"
    mkdir -p "${PROJECT_DIR}/src"
    mkdir -p "${PROJECT_DIR}/models"
    
    log_info "디렉토리 구조 생성 완료"
}

setup_python_env() {
    log_info "Python 환경 설정 중..."
    
    cd "$PROJECT_DIR"
    
    # 메인 프로젝트 가상환경 생성
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_info "Python 가상환경 생성됨"
    fi
    
    source venv/bin/activate
    
    # 기본 패키지 설치
    pip install --upgrade pip
    pip install asyncio numpy networkx flask yara-python requests websockets
    
    log_info "Python 환경 설정 완료"
}

create_mtd_engine() {
    log_info "MTD 엔진 생성 중..."
    
    cat > "${PROJECT_DIR}/src/rl_mtd_engine.py" << 'EOF'
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
EOF

    chmod +x "${PROJECT_DIR}/src/rl_mtd_engine.py"
    log_info "MTD 엔진 생성 완료"
}

create_dvds_connector() {
    log_info "DVDS 연결기 생성 중..."
    
    cat > "${PROJECT_DIR}/src/dvds_connector.py" << 'EOF'
#!/usr/bin/env python3
"""DVDS 연결 및 제어"""

import subprocess
import time
import requests
import json

class DVDSConnector:
    def __init__(self, dvds_path):
        self.dvds_path = dvds_path
        self.process = None
        self.port = 8080
    
    def start_dvds(self):
        try:
            print(f"🎯 DVDS 시작 중... (경로: {self.dvds_path})")
            
            # DVDS 실행 (백그라운드)
            self.process = subprocess.Popen(
                ['python3', 'app.py'],
                cwd=self.dvds_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # DVDS 시작 대기
            time.sleep(5)
            
            # 연결 테스트
            if self.test_connection():
                print(f"✅ DVDS 성공적으로 시작됨 (포트: {self.port})")
                return True
            else:
                print("❌ DVDS 연결 실패")
                return False
                
        except Exception as e:
            print(f"❌ DVDS 시작 실패: {e}")
            return False
    
    def test_connection(self):
        try:
            response = requests.get(f'http://localhost:{self.port}', timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def stop_dvds(self):
        if self.process:
            self.process.terminate()
            print("🛑 DVDS 중지됨")

if __name__ == "__main__":
    import sys
    dvds_path = sys.argv[1] if len(sys.argv) > 1 else "../external/dvds"
    
    connector = DVDSConnector(dvds_path)
    try:
        if connector.start_dvds():
            print("DVDS가 실행 중입니다. Ctrl+C로 중지하세요.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        connector.stop_dvds()
EOF

    chmod +x "${PROJECT_DIR}/src/dvds_connector.py"
    log_info "DVDS 연결기 생성 완료"
}

start_services() {
    log_info "서비스 시작 중..."
    
    cd "$PROJECT_DIR"
    source venv/bin/activate
    
    # DVDS 시작
    if [[ -d "$DVDS_DIR" ]]; then
        log_info "DVDS 시작 중..."
        python3 src/dvds_connector.py "$DVDS_DIR" &
        DVDS_PID=$!
        echo $DVDS_PID > "$DATA_DIR/dvds.pid"
        sleep 3
    fi
    
    # MTD 엔진 시작
    log_info "MTD 엔진 시작 중..."
    python3 src/rl_mtd_engine.py &
    MTD_PID=$!
    echo $MTD_PID > "$DATA_DIR/mtd.pid"
    
    log_info "모든 서비스가 시작되었습니다!"
    log_info "DVDS: http://localhost:8080"
    log_info "MTD 엔진이 백그라운드에서 실행 중"
}

stop_services() {
    log_info "서비스 중지 중..."
    
    # PID 파일에서 프로세스 종료
    for service in dvds mtd; do
        if [[ -f "$DATA_DIR/$service.pid" ]]; then
            PID=$(cat "$DATA_DIR/$service.pid")
            if kill -0 $PID 2>/dev/null; then
                kill $PID
                log_info "$service 프로세스 종료됨"
            fi
            rm -f "$DATA_DIR/$service.pid"
        fi
    done
    
    log_info "모든 서비스가 중지되었습니다."
}

get_status() {
    log_info "서비스 상태 확인 중..."
    
    echo -e "\n${BLUE}=== 시스템 상태 ===${NC}"
    
    # MTD 엔진
    if [[ -f "$DATA_DIR/mtd.pid" ]] && kill -0 $(cat "$DATA_DIR/mtd.pid") 2>/dev/null; then
        echo -e "MTD 엔진: ${GREEN}실행 중${NC}"
    else
        echo -e "MTD 엔진: ${RED}중지됨${NC}"
    fi
    
    # DVDS
    if [[ -f "$DATA_DIR/dvds.pid" ]] && kill -0 $(cat "$DATA_DIR/dvds.pid") 2>/dev/null; then
        echo -e "DVDS: ${GREEN}실행 중${NC} (http://localhost:8080)"
    else
        echo -e "DVDS: ${RED}중지됨${NC}"
    fi
    
    # 디렉토리 정보
    echo -e "\n${BLUE}=== 디렉토리 정보 ===${NC}"
    echo "프로젝트 경로: $PROJECT_DIR"
    echo "DVDS 경로: $DVDS_DIR"
    if [[ -d "$DVDS_DIR" ]]; then
        echo -e "DVDS: ${GREEN}설치됨${NC}"
    else
        echo -e "DVDS: ${RED}설치 필요${NC}"
    fi
}

show_help() {
    cat << EOF
${BLUE}DVDS 통합 FANET 허니드론 테스트베드${NC}

사용법: $0 <명령>

${YELLOW}설정 명령:${NC}
  setup              전체 시스템 설정
  setup-dvds         DVDS만 설정
  setup-python       Python 환경만 설정

${YELLOW}운영 명령:${NC}
  start              모든 서비스 시작
  stop               모든 서비스 중지
  restart            서비스 재시작
  status             시스템 상태 확인

${YELLOW}예시:${NC}
  $0 setup           # 전체 설정
  $0 start           # 서비스 시작
  $0 status          # 상태 확인

${YELLOW}서비스:${NC}
  DVDS:      http://localhost:8080
  MTD 엔진:   백그라운드 실행

EOF
}

# 메인 로직
case "${1:-help}" in
    "setup")
        setup_directories
        setup_dvds
        setup_python_env
        create_mtd_engine
        create_dvds_connector
        log_info "전체 설정 완료"
        ;;
    "setup-dvds")
        setup_dvds
        ;;
    "setup-python")
        setup_python_env
        ;;
    "start")
        start_services
        ;;
    "stop")
        stop_services
        ;;
    "restart")
        stop_services
        sleep 2
        start_services
        ;;
    "status")
        get_status
        ;;
    "help"|*)
        show_help
        ;;
esac