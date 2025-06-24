# integrated_launcher.sh - FANET 허니드론 테스트베드 통합 시작 스크립트

set -e

# 색상 코드 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로고 출력
print_logo() {
    echo -e "${BLUE}"
    echo "  ███████╗ █████╗ ███╗   ██╗███████╗████████╗"
    echo "  ██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝"
    echo "  █████╗  ███████║██╔██╗ ██║█████╗     ██║   "
    echo "  ██╔══╝  ██╔══██║██║╚██╗██║██╔══╝     ██║   "
    echo "  ██║     ██║  ██║██║ ╚████║███████╗   ██║   "
    echo "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   "
    echo ""
    echo "  허니드론 네트워크 테스트베드 v1.0.0"
    echo "  Flying Ad-hoc Network Honeypot Testbed"
    echo -e "${NC}"
}

# 메뉴 출력
print_menu() {
    echo -e "${YELLOW}=== FANET 허니드론 테스트베드 시작 메뉴 ===${NC}"
    echo ""
    echo "1) 🚀 개발 환경 시작 (Development Mode)"
    echo "2) 🐳 Docker 환경 시작 (Production Mode)"  
    echo "3) 🔧 시스템 설정 및 초기화"
    echo "4) 🧪 실험 실행"
    echo "5) 📊 성능 벤치마크"
    echo "6) 📈 로그 분석 및 보고서 생성"
    echo "7) ✅ 설정 파일 검증"
    echo "8) 🛑 시스템 종료"
    echo ""
    echo -e "${BLUE}선택하세요 [1-8]:${NC} "
}

# 환경 검사
check_environment() {
    echo -e "${YELLOW}환경 검사 중...${NC}"
    
    # Python 검사
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        echo -e "${GREEN}✓ Python ${PYTHON_VERSION} 발견${NC}"
    else
        echo -e "${RED}✗ Python3이 설치되지 않음${NC}"
        exit 1
    fi
    
    # Docker 검사
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✓ Docker 사용 가능${NC}"
        DOCKER_AVAILABLE=true
    else
        echo -e "${YELLOW}⚠ Docker가 설치되지 않음 (선택사항)${NC}"
        DOCKER_AVAILABLE=false
    fi
    
    # 가상환경 검사
    if [ -d "venv" ]; then
        echo -e "${GREEN}✓ Python 가상환경 발견${NC}"
        VENV_EXISTS=true
    else
        echo -e "${YELLOW}⚠ Python 가상환경이 없음${NC}"
        VENV_EXISTS=false
    fi
    
    # 설정 파일 검사
    if [ -d "config" ] && [ "$(ls -A config)" ]; then
        echo -e "${GREEN}✓ 설정 파일 발견${NC}"
    else
        echo -e "${YELLOW}⚠ 설정 파일이 없거나 비어있음${NC}"
    fi
    
    echo ""
}

# 개발 환경 시작
start_development() {
    echo -e "${GREEN}개발 환경 시작 중...${NC}"
    
    # 가상환경 확인 및 생성
    if [ "$VENV_EXISTS" = false ]; then
        echo "Python 가상환경 생성 중..."
        python3 -m venv venv
    fi
    
    # 가상환경 활성화
    source venv/bin/activate
    
    # 의존성 설치
    echo "의존성 설치 중..."
    pip install -r requirements.txt
    
    # 환경 변수 설정
    export PYTHONPATH="${PWD}"
    export CONFIG_DIR="${PWD}/config"
    export DATA_DIR="${PWD}/data"
    export LOG_LEVEL="DEBUG"
    
    # 백그라운드에서 서비스 시작
    echo "API 서버 시작 중..."
    python interfaces/api/main.py &
    API_PID=$!
    echo $API_PID > data/api.pid
    
    # 대시보드 시작 (있는 경우)
    if [ -d "dashboard" ] && [ -f "dashboard/package.json" ]; then
        echo "대시보드 시작 중..."
        cd dashboard
        if [ ! -d "node_modules" ]; then
            npm install
        fi
        npm start &
        DASHBOARD_PID=$!
        echo $DASHBOARD_PID > ../data/dashboard.pid
        cd ..
    fi
    
    echo -e "${GREEN}✓ 개발 환경이 시작되었습니다!${NC}"
    echo ""
    echo "🌐 API 서버: http://localhost:8000"
    echo "📊 API 문서: http://localhost:8000/docs"
    if [ ! -z "$DASHBOARD_PID" ]; then
        echo "🎨 대시보드: http://localhost:3000"
    fi
    echo ""
    echo "시스템을 중지하려면 메뉴에서 '8) 시스템 종료'를 선택하세요."
}

# Docker 환경 시작
start_docker() {
    echo -e "${GREEN}Docker 환경 시작 중...${NC}"
    
    if [ "$DOCKER_AVAILABLE" = false ]; then
        echo -e "${RED}✗ Docker가 설치되지 않았습니다.${NC}"
        return
    fi
    
    # Docker Compose 파일 확인
    if [ ! -f "deployment/docker-compose.yml" ]; then
        echo -e "${RED}✗ Docker Compose 파일이 없습니다.${NC}"
        return
    fi
    
    # Docker 이미지 빌드 및 실행
    echo "Docker 이미지 빌드 중..."
    docker-compose -f deployment/docker-compose.yml build
    
    echo "Docker 컨테이너 시작 중..."
    docker-compose -f deployment/docker-compose.yml up -d
    
    echo -e "${GREEN}✓ Docker 환경이 시작되었습니다!${NC}"
    echo ""
    echo "🌐 API 서버: http://localhost:8000"
    echo "🎨 대시보드: http://localhost:3000"
    echo "📊 모니터링: http://localhost:9090"
    echo ""
    echo "로그 확인: docker-compose -f deployment/docker-compose.yml logs -f"
    echo "시스템 중지: docker-compose -f deployment/docker-compose.yml down"
}

# 시스템 설정
setup_system() {
    echo -e "${GREEN}시스템 설정 및 초기화 중...${NC}"
    
    python3 scripts/setup_environment.py
    
    echo -e "${GREEN}✓ 시스템 설정 완료${NC}"
}

# 실험 실행
run_experiment() {
    echo -e "${GREEN}실험 실행${NC}"
    echo ""
    echo "사용 가능한 실험:"
    echo "1) MTD 효과성 테스트"
    echo "2) 공격 대응 시나리오"
    echo "3) 에너지 효율성 분석"
    echo "4) 사용자 정의 실험"
    echo ""
    read -p "실험을 선택하세요 [1-4]: " exp_choice
    
    case $exp_choice in
        1)
            echo "MTD 효과성 테스트 실행 중..."
            python3 scripts/experiment_runner.py experiment --config config/experiments.json --experiment mtd_effectiveness
            ;;
        2)
            echo "공격 대응 시나리오 실행 중..."
            python3 scripts/experiment_runner.py experiment --config config/experiments.json --experiment attack_response
            ;;
        3)
            echo "에너지 효율성 분석 실행 중..."
            python3 scripts/experiment_runner.py experiment --config config/experiments.json --experiment energy_efficiency
            ;;
        4)
            read -p "실험 설정 파일 경로: " config_path
            read -p "실험 이름: " exp_name
            python3 scripts/experiment_runner.py experiment --config "$config_path" --experiment "$exp_name"
            ;;
        *)
            echo "잘못된 선택입니다."
            ;;
    esac
}

# 성능 벤치마크
run_benchmark() {
    echo -e "${GREEN}성능 벤치마크 실행 중...${NC}"
    
    python3 scripts/benchmark.py
    
    echo -e "${GREEN}✓ 벤치마크 완료${NC}"
}

# 로그 분석
analyze_logs() {
    echo -e "${GREEN}로그 분석 및 보고서 생성 중...${NC}"
    
    python3 scripts/log_analyzer.py analyze
    
    echo -e "${GREEN}✓ 분석 완료. reports/ 디렉토리를 확인하세요.${NC}"
}

# 설정 검증
validate_config() {
    echo -e "${GREEN}설정 파일 검증 중...${NC}"
    
    python3 scripts/config_validator.py validate
    
    echo -e "${GREEN}✓ 설정 검증 완료${NC}"
}

# 시스템 종료
shutdown_system() {
    echo -e "${YELLOW}시스템 종료 중...${NC}"
    
    # PID 파일로부터 프로세스 종료
    if [ -f "data/api.pid" ]; then
        API_PID=$(cat data/api.pid)
        if kill -0 $API_PID 2>/dev/null; then
            echo "API 서버 종료 중..."
            kill $API_PID
            rm data/api.pid
        fi
    fi
    
    if [ -f "data/dashboard.pid" ]; then
        DASHBOARD_PID=$(cat data/dashboard.pid)
        if kill -0 $DASHBOARD_PID 2>/dev/null; then
            echo "대시보드 종료 중..."
            kill $DASHBOARD_PID
            rm data/dashboard.pid
        fi
    fi
    
    # Docker 컨테이너 종료
    if [ "$DOCKER_AVAILABLE" = true ] && [ -f "deployment/docker-compose.yml" ]; then
        if docker-compose -f deployment/docker-compose.yml ps | grep -q "Up"; then
            echo "Docker 컨테이너 종료 중..."
            docker-compose -f deployment/docker-compose.yml down
        fi
    fi
    
    echo -e "${GREEN}✓ 시스템이 안전하게 종료되었습니다.${NC}"
}

# 종료 시그널 핸들러
cleanup() {
    echo ""
    echo -e "${YELLOW}종료 신호를 받았습니다. 시스템을 안전하게 종료합니다...${NC}"
    shutdown_system
    exit 0
}

# 메인 실행 로직
main() {
    # 시그널 핸들러 등록
    trap cleanup SIGINT SIGTERM
    
    # 로고 출력
    print_logo
    
    # 환경 검사
    check_environment
    
    # 메인 루프
    while true; do
        print_menu
        read -r choice
        
        case $choice in
            1)
                start_development
                ;;
            2)
                start_docker
                ;;
            3)
                setup_system
                ;;
            4)
                run_experiment
                ;;
            5)
                run_benchmark
                ;;
            6)
                analyze_logs
                ;;
            7)
                validate_config
                ;;
            8)
                shutdown_system
                exit 0
                ;;
            *)
                echo -e "${RED}잘못된 선택입니다. 1-8 사이의 숫자를 입력해주세요.${NC}"
                ;;
        esac
        
        echo ""
        read -p "계속하려면 Enter를 누르세요..."
        clear
        print_logo
    done
}

# 스크립트 실행
main "$@"

---
