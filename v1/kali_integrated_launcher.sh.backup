#!/bin/bash
# kali_integrated_launcher.sh
# FANET 허니드론 네트워크 테스트베드 통합 실행 스크립트

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 로그 함수
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# 프로젝트 디렉토리
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="${PROJECT_DIR}/logs"
DATA_DIR="${PROJECT_DIR}/data"
EXTERNAL_DIR="${PROJECT_DIR}/external"

# Docker 설정
DOCKER_NETWORK="honeydrone_network"
BASE_IMAGE="honeydrone-base:latest"
DASHBOARD_CONTAINER="honeydrone-dashboard"
DVDS_CONTAINER="dvds-simulator"

# 함수들

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "이 스크립트는 root 권한이 필요합니다."
        log_info "sudo $0 $@"
        exit 1
    fi
}

check_kali() {
    if ! grep -q "kali" /etc/os-release 2>/dev/null; then
        log_warn "Kali Linux가 아닌 환경에서 실행 중입니다."
        log_info "Ubuntu/Debian 환경에서도 작동하지만 일부 기능이 제한될 수 있습니다."
    else
        log_info "Kali Linux 환경 확인됨"
    fi
}

check_dependencies() {
    log_info "시스템 의존성 확인 중..."
    
    local deps=("docker" "docker-compose" "python3" "python3-pip" "git")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "다음 의존성이 설치되지 않았습니다: ${missing_deps[*]}"
        log_info "설치하려면: sudo apt update && sudo apt install -y ${missing_deps[*]}"
        return 1
    fi
    
    # Docker 서비스 확인
    if ! systemctl is-active --quiet docker; then
        log_info "Docker 서비스 시작 중..."
        systemctl start docker
        systemctl enable docker
    fi
    
    # Docker 그룹 확인
    if ! groups $SUDO_USER | grep -q docker; then
        log_info "사용자를 docker 그룹에 추가 중..."
        usermod -aG docker $SUDO_USER
        log_warn "로그아웃 후 다시 로그인하여 docker 그룹 권한을 적용하세요."
    fi
    
    log_info "모든 의존성이 확인되었습니다."
}

install_python_deps() {
    log_info "Python 의존성 설치 중..."
    
    cd "$PROJECT_DIR"
    
    # 가상환경 생성 (존재하지 않는 경우)
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log_info "Python 가상환경 생성됨"
    fi
    
    # 가상환경 활성화
    source venv/bin/activate
    
    # 의존성 설치
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        log_info "Python 패키지 설치 완료"
    else
        # 기본 패키지 설치
        pip install asyncio numpy networkx docker flask yara-python
        log_info "기본 Python 패키지 설치 완료"
    fi
}

setup_directories() {
    log_info "프로젝트 디렉토리 구조 생성 중..."
    
    mkdir -p "$LOGS_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$EXTERNAL_DIR"
    mkdir -p "${PROJECT_DIR}/config/yara_rules"
    mkdir -p "${PROJECT_DIR}/models"
    
    # 권한 설정
    chown -R $SUDO_USER:$SUDO_USER "$PROJECT_DIR"
    chmod 755 "$PROJECT_DIR"
    
    log_info "디렉토리 구조 생성 완료"
}

create_docker_network() {
    log_info "Docker 네트워크 설정 중..."
    
    if ! docker network ls | grep -q "$DOCKER_NETWORK"; then
        docker network create --driver bridge \
            --subnet=172.20.0.0/16 \
            --gateway=172.20.0.1 \
            "$DOCKER_NETWORK"
        log_info "Docker 네트워크 '$DOCKER_NETWORK' 생성됨"
    else
        log_info "Docker 네트워크 '$DOCKER_NETWORK' 이미 존재함"
    fi
}

build_docker_images() {
    log_info "Docker 이미지 빌드 중..."
    
    cd "$PROJECT_DIR"
    
    # 허니드론 기본 이미지 빌드
    if [[ -d "docker/honeydrone-base" ]]; then
        cd docker/honeydrone-base
        docker build -t "$BASE_IMAGE" .
        log_info "허니드론 기본 이미지 빌드 완료"
        cd "$PROJECT_DIR"
    else
        log_warn "docker/honeydrone-base 디렉토리가 없습니다. 기본 이미지를 생성합니다."
        create_default_docker_image
    fi
    
    # DVDS 이미지 확인/빌드
    if ! docker images | grep -q "dvds"; then
        build_dvds_image
    fi
}

create_default_docker_image() {
    log_info "기본 Docker 이미지 생성 중..."
    
    mkdir -p docker/honeydrone-base/scripts
    
    cat > docker/honeydrone-base/Dockerfile << 'EOF'
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# 기본 패키지 설치
RUN apt-get update && apt-get install -y \
    openssh-server \
    telnetd \
    apache2 \
    python3 \
    python3-pip \
    curl \
    wget \
    net-tools \
    tcpdump \
    netcat \
    nmap \
    vim \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# SSH 설정
RUN mkdir /var/run/sshd
RUN echo 'root:honeydrone123' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 취약한 웹 서비스 설정
COPY scripts/web_service.py /opt/
RUN echo '<h1>Drone Control Panel</h1><p>Admin: admin/admin123</p>' > /var/www/html/index.html

# Supervisor 설정
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 포트 노출
EXPOSE 22 23 80 8080 9000

# 시작 스크립트
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

CMD ["/entrypoint.sh"]
EOF

    cat > docker/honeydrone-base/entrypoint.sh << 'EOF'
#!/bin/bash

echo "🚁 Honeydrone starting..."
echo "Drone ID: ${DRONE_ID:-unknown}"
echo "Drone Type: ${DRONE_TYPE:-unknown}"
echo "Vulnerability Level: ${VULNERABILITY_LEVEL:-0.5}"

# SSH 키 생성
ssh-keygen -A

# 로그 디렉토리 생성
mkdir -p /var/log/drone

# 드론 정보 로깅
echo "$(date): Drone ${DRONE_ID} started (${DRONE_TYPE})" >> /var/log/drone/startup.log

# 취약점 설정 (DUMMY 드론인 경우)
if [[ "$DRONE_TYPE" == "dummy" ]]; then
    echo "🎯 Configuring dummy drone vulnerabilities..."
    
    # 약한 패스워드 설정
    echo 'admin:admin123' | chpasswd
    useradd -m -s /bin/bash dummy
    echo 'dummy:password' | chpasswd
    
    # 텔넷 활성화
    systemctl enable telnetd || service telnetd start
    
    # 취약한 웹 서비스 시작
    python3 /opt/web_service.py &
fi

# Supervisor로 서비스 관리
exec /usr/bin/supervisord -n
EOF

    cat > docker/honeydrone-base/supervisord.conf << 'EOF'
[supervisord]
nodaemon=true
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:sshd]
command=/usr/sbin/sshd -D
autostart=true
autorestart=true

[program:apache2]
command=/usr/sbin/apache2ctl -D FOREGROUND
autostart=true
autorestart=true

[program:telnetd]
command=/usr/sbin/in.telnetd -debug
autostart=%(ENV_DRONE_TYPE)s=="dummy"
autorestart=true
EOF

    cat > docker/honeydrone-base/scripts/web_service.py << 'EOF'
#!/usr/bin/env python3
"""취약한 웹 서비스 (데모용)"""

import socket
import threading
import os
from datetime import datetime

def handle_client(client_socket, addr):
    try:
        request = client_socket.recv(1024).decode()
        
        # 로깅
        with open('/var/log/drone/web_access.log', 'a') as f:
            f.write(f"{datetime.now()}: Access from {addr[0]}: {request.split()[0:2]}\n")
        
        # 간단한 HTTP 응답
        response = """HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Drone Control Panel</title></head>
<body>
<h1>🚁 Drone Control Panel</h1>
<p>Drone ID: {}</p>
<p>Status: Online</p>
<form method="POST">
<input type="text" name="command" placeholder="Enter command">
<button type="submit">Execute</button>
</form>
</body>
</html>
""".format(os.environ.get('DRONE_ID', 'unknown'))
        
        client_socket.send(response.encode())
        
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_web_service():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 8080))
    server.listen(5)
    
    print("Web service listening on port 8080")
    
    while True:
        client_socket, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()

if __name__ == "__main__":
    start_web_service()
EOF

    chmod +x docker/honeydrone-base/entrypoint.sh
    chmod +x docker/honeydrone-base/scripts/web_service.py
    
    cd docker/honeydrone-base
    docker build -t "$BASE_IMAGE" .
    cd "$PROJECT_DIR"
    
    log_info "기본 Docker 이미지 생성 완료"
}

build_dvds_image() {
    log_info "DVDS (Damn Vulnerable Drone Simulator) 이미지 빌드 중..."
    
    # DVDS가 없다면 시뮬레이션된 버전 생성
    cat > Dockerfile.dvds << 'EOF'
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    netcat \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# DVDS 시뮬레이터 스크립트
COPY dvds_simulator.py /app/
COPY dvds_config.json /app/

EXPOSE 8888

CMD ["python", "dvds_simulator.py"]
EOF

    cat > dvds_simulator.py << 'EOF'
#!/usr/bin/env python3
"""DVDS (Damn Vulnerable Drone Simulator) 시뮬레이터"""

import json
import time
import socket
import threading
import random
from datetime import datetime

class DVDSSimulator:
    def __init__(self):
        self.drones = {}
        self.attacks = []
        self.running = True
        
    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 8888))
        server.listen(5)
        
        print("🎯 DVDS Simulator started on port 8888")
        
        while self.running:
            try:
                client, addr = server.accept()
                threading.Thread(target=self.handle_client, args=(client, addr)).start()
            except:
                break
    
    def handle_client(self, client, addr):
        try:
            data = client.recv(1024).decode()
            print(f"DVDS: Received from {addr}: {data}")
            
            response = self.process_command(data.strip())
            client.send(response.encode())
            
        except Exception as e:
            print(f"DVDS Error: {e}")
        finally:
            client.close()
    
    def process_command(self, command):
        if command.startswith("SCAN"):
            return self.simulate_scan()
        elif command.startswith("ATTACK"):
            return self.simulate_attack(command)
        elif command.startswith("STATUS"):
            return self.get_status()
        else:
            return "DVDS: Unknown command"
    
    def simulate_scan(self):
        scan_results = []
        for i in range(random.randint(2, 8)):
            drone_id = f"target_drone_{i+1}"
            vulnerability = random.choice(["high", "medium", "low"])
            scan_results.append(f"{drone_id}:{vulnerability}")
        
        return f"SCAN_RESULT:{','.join(scan_results)}"
    
    def simulate_attack(self, command):
        parts = command.split(":")
        if len(parts) < 2:
            return "ATTACK_ERROR:Invalid format"
        
        target = parts[1]
        attack_type = parts[2] if len(parts) > 2 else "generic"
        
        success = random.random() > 0.3  # 70% 성공률
        
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'attack_type': attack_type,
            'success': success,
            'source_ip': '172.20.0.100'
        }
        
        self.attacks.append(attack_record)
        
        if success:
            return f"ATTACK_SUCCESS:{target}:Compromised"
        else:
            return f"ATTACK_FAILED:{target}:Defense active"
    
    def get_status(self):
        return f"STATUS:Active attacks: {len(self.attacks)}, Targets: {len(self.drones)}"

if __name__ == "__main__":
    simulator = DVDSSimulator()
    simulator.start_server()
EOF

    cat > dvds_config.json << 'EOF'
{
    "simulator_name": "DVDS",
    "version": "1.0.0",
    "attack_scenarios": [
        "network_scan",
        "brute_force",
        "command_injection",
        "data_exfiltration"
    ],
    "default_targets": 5,
    "success_rate": 0.7
}
EOF

    docker build -f Dockerfile.dvds -t dvds:latest .
    rm -f Dockerfile.dvds dvds_simulator.py dvds_config.json
    
    log_info "DVDS 이미지 빌드 완료"
}

start_services() {
    log_info "서비스 시작 중..."
    
    cd "$PROJECT_DIR"
    
    # Python 가상환경 활성화
    source venv/bin/activate
    
    # DVDS 시뮬레이터 시작
    if ! docker ps | grep -q "$DVDS_CONTAINER"; then
        docker run -d --name "$DVDS_CONTAINER" \
            --network "$DOCKER_NETWORK" \
            --ip 172.20.0.100 \
            -p 8888:8888 \
            dvds:latest
        log_info "DVDS 시뮬레이터 시작됨"
    fi
    
    # 메인 테스트베드 시작
    python3 scripts/start_testbed.py &
    TESTBED_PID=$!
    echo $TESTBED_PID > "$DATA_DIR/testbed.pid"
    
    # 웹 대시보드 시작
    cd dashboard
    python3 app.py &
    DASHBOARD_PID=$!
    echo $DASHBOARD_PID > "$DATA_DIR/dashboard.pid"
    cd "$PROJECT_DIR"
    
    log_info "모든 서비스가 시작되었습니다."
    log_info "웹 대시보드: http://localhost:8080"
    log_info "DVDS 시뮬레이터: http://localhost:8888"
}

stop_services() {
    log_info "서비스 중지 중..."
    
    # PID 파일에서 프로세스 종료
    if [[ -f "$DATA_DIR/testbed.pid" ]]; then
        PID=$(cat "$DATA_DIR/testbed.pid")
        if kill -0 $PID 2>/dev/null; then
            kill $PID
            log_info "테스트베드 프로세스 종료됨"
        fi
        rm -f "$DATA_DIR/testbed.pid"
    fi
    
    if [[ -f "$DATA_DIR/dashboard.pid" ]]; then
        PID=$(cat "$DATA_DIR/dashboard.pid")
        if kill -0 $PID 2>/dev/null; then
            kill $PID
            log_info "대시보드 프로세스 종료됨"
        fi
        rm -f "$DATA_DIR/dashboard.pid"
    fi
    
    # Docker 컨테이너 정리
    docker ps -a --filter "name=honeydrone_" --format "{{.Names}}" | xargs -r docker rm -f
    docker ps -a --filter "name=$DVDS_CONTAINER" --format "{{.Names}}" | xargs -r docker rm -f
    
    log_info "모든 서비스가 중지되었습니다."
}

get_status() {
    log_info "서비스 상태 확인 중..."
    
    echo -e "\n${CYAN}=== 시스템 상태 ===${NC}"
    
    # 테스트베드 프로세스
    if [[ -f "$DATA_DIR/testbed.pid" ]] && kill -0 $(cat "$DATA_DIR/testbed.pid") 2>/dev/null; then
        echo -e "테스트베드: ${GREEN}실행 중${NC}"
    else
        echo -e "테스트베드: ${RED}중지됨${NC}"
    fi
    
    # 대시보드 프로세스
    if [[ -f "$DATA_DIR/dashboard.pid" ]] && kill -0 $(cat "$DATA_DIR/dashboard.pid") 2>/dev/null; then
        echo -e "웹 대시보드: ${GREEN}실행 중${NC} (http://localhost:8080)"
    else
        echo -e "웹 대시보드: ${RED}중지됨${NC}"
    fi
    
    # Docker 컨테이너
    echo -e "\n${CYAN}=== Docker 컨테이너 ===${NC}"
    HONEYDRONE_COUNT=$(docker ps --filter "name=honeydrone_" --format "{{.Names}}" | wc -l)
    echo -e "허니드론 컨테이너: ${GREEN}${HONEYDRONE_COUNT}개 실행 중${NC}"
    
    if docker ps | grep -q "$DVDS_CONTAINER"; then
        echo -e "DVDS 시뮬레이터: ${GREEN}실행 중${NC} (http://localhost:8888)"
    else
        echo -e "DVDS 시뮬레이터: ${RED}중지됨${NC}"
    fi
    
    # 네트워크
    if docker network ls | grep -q "$DOCKER_NETWORK"; then
        echo -e "Docker 네트워크: ${GREEN}활성${NC}"
    else
        echo -e "Docker 네트워크: ${RED}비활성${NC}"
    fi
    
    # 디스크 사용량
    echo -e "\n${CYAN}=== 리소스 사용량 ===${NC}"
    echo "디스크 사용량 (프로젝트):"
    du -sh "$PROJECT_DIR" 2>/dev/null || echo "측정 불가"
    
    echo "로그 크기:"
    du -sh "$LOGS_DIR" 2>/dev/null || echo "로그 없음"
}

show_logs() {
    local service="$1"
    
    case "$service" in
        "testbed"|"main")
            if [[ -f "$LOGS_DIR/testbed.log" ]]; then
                tail -f "$LOGS_DIR/testbed.log"
            else
                log_error "테스트베드 로그 파일을 찾을 수 없습니다."
            fi
            ;;
        "dashboard"|"web")
            if [[ -f "$LOGS_DIR/dashboard.log" ]]; then
                tail -f "$LOGS_DIR/dashboard.log"
            else
                log_error "대시보드 로그 파일을 찾을 수 없습니다."
            fi
            ;;
        "phase")
            if [[ -f "$LOGS_DIR/phase_transitions.log" ]]; then
                tail -f "$LOGS_DIR/phase_transitions.log"
            else
                log_error "Phase 로그 파일을 찾을 수 없습니다."
            fi
            ;;
        "mtd")
            if [[ -f "$LOGS_DIR/mtd_engine.log" ]]; then
                tail -f "$LOGS_DIR/mtd_engine.log"
            else
                log_error "MTD 로그 파일을 찾을 수 없습니다."
            fi
            ;;
        "cti")
            if [[ -f "$LOGS_DIR/cti_analysis.log" ]]; then
                tail -f "$LOGS_DIR/cti_analysis.log"
            else
                log_error "CTI 로그 파일을 찾을 수 없습니다."
            fi
            ;;
        "all")
            if [[ -d "$LOGS_DIR" ]]; then
                tail -f "$LOGS_DIR"/*.log 2>/dev/null || log_error "로그 파일을 찾을 수 없습니다."
            else
                log_error "로그 디렉토리를 찾을 수 없습니다."
            fi
            ;;
        *)
            log_error "알 수 없는 서비스: $service"
            log_info "사용 가능한 서비스: testbed, dashboard, phase, mtd, cti, all"
            ;;
    esac
}

run_experiment() {
    local experiment="$1"
    
    log_info "실험 시작: $experiment"
    
    cd "$PROJECT_DIR"
    source venv/bin/activate
    
    case "$experiment" in
        "basic_mtd")
            python3 scripts/experiments/basic_mtd_experiment.py
            ;;
        "energy_constraint")
            python3 scripts/experiments/energy_experiment.py
            ;;
        "honeypot_effectiveness")
            python3 scripts/experiments/honeypot_experiment.py
            ;;
        "phase_transition")
            python3 scripts/experiments/phase_experiment.py
            ;;
        *)
            log_error "알 수 없는 실험: $experiment"
            log_info "사용 가능한 실험: basic_mtd, energy_constraint, honeypot_effectiveness, phase_transition"
            return 1
            ;;
    esac
    
    log_info "실험 완료: $experiment"
}

cleanup() {
    log_info "시스템 정리 중..."
    
    # 서비스 중지
    stop_services
    
    # Docker 정리
    docker container prune -f
    docker image prune -f
    
    # 임시 파일 정리
    rm -f /tmp/honeydrone_*
    
    # 로그 압축 (7일 이상 된 것)
    find "$LOGS_DIR" -name "*.log" -mtime +7 -exec gzip {} \;
    
    log_info "시스템 정리 완료"
}

backup_data() {
    local backup_name="honeydrone_backup_$(date +%Y%m%d_%H%M%S)"
    local backup_dir="/tmp/$backup_name"
    
    log_info "데이터 백업 중: $backup_name"
    
    mkdir -p "$backup_dir"
    
    # 설정 파일 백업
    cp -r "$PROJECT_DIR/config" "$backup_dir/"
    
    # 로그 백업 (최근 7일)
    mkdir -p "$backup_dir/logs"
    find "$LOGS_DIR" -name "*.log" -mtime -7 -exec cp {} "$backup_dir/logs/" \;
    
    # 데이터 백업
    cp -r "$DATA_DIR" "$backup_dir/"
    
    # 압축
    tar -czf "$backup_name.tar.gz" -C /tmp "$backup_name"
    rm -rf "$backup_dir"
    
    log_info "백업 완료: $backup_name.tar.gz"
}

show_help() {
    cat << EOF
${CYAN}FANET 허니드론 네트워크 테스트베드 실행 스크립트${NC}

사용법: $0 <명령> [옵션]

${YELLOW}설정 명령:${NC}
  setup              시스템 초기 설정 (의존성 설치)
  init               프로젝트 초기화 (디렉토리, 네트워크 설정)
  build              Docker 이미지 빌드

${YELLOW}운영 명령:${NC}
  start              모든 서비스 시작
  stop               모든 서비스 중지
  restart            서비스 재시작
  status             시스템 상태 확인

${YELLOW}로그 명령:${NC}
  logs <service>     로그 보기 (testbed|dashboard|phase|mtd|cti|all)

${YELLOW}실험 명령:${NC}
  experiment <type>  실험 실행
    - basic_mtd: 기본 MTD 효과 측정
    - energy_constraint: 에너지 제약 조건 연구
    - honeypot_effectiveness: 허니팟 효과성 분석
    - phase_transition: 8-Phase 전이 시스템 검증

${YELLOW}유지보수 명령:${NC}
  cleanup            시스템 정리
  backup             데이터 백업
  reset              전체 시스템 재설정

${YELLOW}예시:${NC}
  sudo $0 setup                    # 최초 설정
  sudo $0 init                     # 프로젝트 초기화
  sudo $0 build                    # Docker 이미지 빌드
  sudo $0 start                    # 서비스 시작
  $0 status                        # 상태 확인
  $0 logs all                      # 모든 로그 보기
  $0 experiment basic_mtd          # MTD 실험 실행

${YELLOW}웹 인터페이스:${NC}
  대시보드: http://localhost:8080
  DVDS:     http://localhost:8888

EOF
}

# 메인 로직
case "${1:-help}" in
    "setup")
        check_root
        check_kali
        check_dependencies
        install_python_deps
        log_info "시스템 설정 완료"
        ;;
    "init")
        check_root
        setup_directories
        create_docker_network
        log_info "프로젝트 초기화 완료"
        ;;
    "build")
        check_root
        build_docker_images
        log_info "Docker 이미지 빌드 완료"
        ;;
    "start")
        check_root
        start_services
        ;;
    "stop")
        check_root
        stop_services
        ;;
    "restart")
        check_root
        stop_services
        sleep 3
        start_services
        ;;
    "status")
        get_status
        ;;
    "logs")
        show_logs "${2:-all}"
        ;;
    "experiment")
        if [[ -z "$2" ]]; then
            log_error "실험 타입을 지정해주세요."
            log_info "사용법: $0 experiment <type>"
            exit 1
        fi
        run_experiment "$2"
        ;;
    "cleanup")
        check_root
        cleanup
        ;;
    "backup")
        backup_data
        ;;
    "reset")
        check_root
        log_warn "전체 시스템을 재설정합니다. 계속하시겠습니까? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            stop_services
            docker system prune -af
            docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
            rm -rf "$LOGS_DIR" "$DATA_DIR" "$EXTERNAL_DIR"
            log_info "시스템 재설정 완료"
        else
            log_info "재설정이 취소되었습니다."
        fi
        ;;
    "help"|*)
        show_help
        ;;
esac