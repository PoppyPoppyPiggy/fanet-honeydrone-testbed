# scripts/setup_environment.py
#!/usr/bin/env python3
"""
FANET 허니드론 테스트베드 환경 설정 스크립트
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestbedSetup:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.venv_path = self.project_root / 'venv'
        
    def check_system_requirements(self):
        """시스템 요구사항 확인"""
        logger.info("시스템 요구사항 확인 중...")
        
        # Python 버전 확인
        python_version = sys.version_info
        if python_version.major != 3 or python_version.minor < 8:
            raise RuntimeError("Python 3.8 이상이 필요합니다.")
        
        # Docker 설치 확인
        try:
            subprocess.run(['docker', '--version'], check=True, capture_output=True)
            logger.info("✓ Docker 설치됨")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("⚠ Docker가 설치되지 않음. 설치를 권장합니다.")
        
        # Git 확인
        try:
            subprocess.run(['git', '--version'], check=True, capture_output=True)
            logger.info("✓ Git 설치됨")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Git이 필요합니다.")
    
    def setup_virtual_environment(self):
        """Python 가상환경 설정"""
        logger.info("Python 가상환경 설정 중...")
        
        if self.venv_path.exists():
            logger.info("기존 가상환경 발견됨")
        else:
            subprocess.run([sys.executable, '-m', 'venv', str(self.venv_path)], check=True)
            logger.info("✓ 가상환경 생성됨")
        
        # 의존성 설치
        pip_path = self.venv_path / 'bin' / 'pip'
        if sys.platform == 'win32':
            pip_path = self.venv_path / 'Scripts' / 'pip.exe'
        
        requirements_file = self.project_root / 'requirements.txt'
        if requirements_file.exists():
            subprocess.run([str(pip_path), 'install', '-r', str(requirements_file)], check=True)
            logger.info("✓ Python 의존성 설치됨")
    
    def setup_directories(self):
        """프로젝트 디렉토리 구조 생성"""
        logger.info("디렉토리 구조 생성 중...")
        
        directories = [
            'data',
            'logs',
            'config',
            'models',
            'external/dvds',
            'deployment',
            'tests/fixtures'
        ]
        
        for dir_path in directories:
            full_path = self.project_root / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("✓ 디렉토리 구조 생성됨")
    
    def download_ns3(self):
        """NS-3 다운로드 및 설치"""
        logger.info("NS-3 다운로드 중...")
        
        ns3_dir = self.project_root / 'ns-allinone-3.40'
        if ns3_dir.exists():
            logger.info("NS-3가 이미 존재함")
            return
        
        try:
            # NS-3 다운로드
            subprocess.run([
                'wget', 
                'https://www.nsnam.org/releases/ns-allinone-3.40.tar.bz2'
            ], cwd=self.project_root, check=True)
            
            # 압축 해제
            subprocess.run([
                'tar', '-xf', 'ns-allinone-3.40.tar.bz2'
            ], cwd=self.project_root, check=True)
            
            # 압축 파일 삭제
            (self.project_root / 'ns-allinone-3.40.tar.bz2').unlink()
            
            logger.info("✓ NS-3 다운로드 완료")
            
        except subprocess.CalledProcessError:
            logger.warning("⚠ NS-3 자동 다운로드 실패. 수동으로 설치해 주세요.")
    
    def setup_configuration_files(self):
        """설정 파일 생성"""
        logger.info("설정 파일 생성 중...")
        
        # 기본 네트워크 설정
        network_config = """
# Network Configuration
network:
  range: "10.0.0.0/16"
  communication_range: 100.0
  initial_node_count: 6
  
honeydrone:
  enable_battery_simulation: true
  energy_model: "linear"
  max_battery_life: 3600  # seconds
  
fanet:
  mobility_model: "random_walk_3d"
  speed_range: [5, 25]  # m/s
  altitude_range: [10, 100]  # meters
"""
        
        # MTD 설정
        mtd_config = """
# MTD Configuration  
mtd:
  default_strategy: "adaptive"
  strategies:
    - ip_hopping
    - port_randomization
    - frequency_hopping
    - topology_mutation
    - service_migration
  
  timing:
    periodic_interval: 30  # seconds
    attack_response_delay: 5  # seconds
  
  costs:
    ip_hopping: 0.1
    port_randomization: 0.15
    frequency_hopping: 0.3
    topology_mutation: 0.7
    service_migration: 0.6
"""
        
        # CTI 설정
        cti_config = """
# CTI Configuration
cti:
  log_sources:
    - dvds_logs
    - network_packets
    - system_events
  
  analysis:
    confidence_threshold: 0.7
    correlation_window: 300  # seconds
    
  mitre_attack:
    framework_version: "v12.1"
    tactics_filter: []  # empty = all tactics
    
  output_formats:
    - stix2.1
    - json
    - csv
"""
        
        config_files = {
            'network_config.yaml': network_config,
            'mtd_config.yaml': mtd_config,
            'cti_config.yaml': cti_config
        }
        
        config_dir = self.project_root / 'config'
        for filename, content in config_files.items():
            config_file = config_dir / filename
            if not config_file.exists():
                with open(config_file, 'w') as f:
                    f.write(content)
        
        logger.info("✓ 설정 파일 생성됨")
    
    def create_launcher_scripts(self):
        """시작 스크립트 생성"""
        logger.info("시작 스크립트 생성 중...")
        
        # 개발 환경 시작 스크립트
        dev_launcher = """#!/bin/bash
# FANET 허니드론 테스트베드 개발 환경 시작

set -e

echo "FANET 허니드론 테스트베드 시작..."

# 가상환경 활성화
source venv/bin/activate

# 환경 변수 설정
export PYTHONPATH="${PWD}"
export CONFIG_DIR="${PWD}/config"
export DATA_DIR="${PWD}/data"
export LOG_LEVEL="DEBUG"

# API 서버 시작
echo "API 서버 시작 중..."
python interfaces/api/main.py &
API_PID=$!

# 대시보드 시작 (백그라운드)
if [ -d "dashboard" ]; then
    echo "대시보드 시작 중..."
    cd dashboard && npm start &
    DASHBOARD_PID=$!
    cd ..
fi

# 종료 핸들러
cleanup() {
    echo "시스템 종료 중..."
    kill $API_PID 2>/dev/null || true
    if [ ! -z "$DASHBOARD_PID" ]; then
        kill $DASHBOARD_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "✓ 시스템이 시작되었습니다."
echo "API: http://localhost:8000"
echo "대시보드: http://localhost:3000"
echo "종료하려면 Ctrl+C를 누르세요."

wait
"""
        
        # 프로덕션 Docker 시작 스크립트
        docker_launcher = """#!/bin/bash
# FANET 허니드론 테스트베드 Docker 환경 시작

set -e

echo "Docker 환경에서 FANET 허니드론 테스트베드 시작..."

# Docker Compose로 전체 시스템 시작
docker-compose -f deployment/docker-compose.yml up -d

echo "✓ 시스템이 Docker에서 시작되었습니다."
echo "API: http://localhost:8000"
echo "대시보드: http://localhost:3000"
echo "모니터링: http://localhost:9090"

echo "로그 확인: docker-compose -f deployment/docker-compose.yml logs -f"
echo "시스템 중지: docker-compose -f deployment/docker-compose.yml down"
"""
        
        # 스크립트 파일 생성
        scripts = {
            'start_dev.sh': dev_launcher,
            'start_docker.sh': docker_launcher
        }
        
        for filename, content in scripts.items():
            script_path = self.project_root / filename
            with open(script_path, 'w') as f:
                f.write(content)
            script_path.chmod(0o755)  # 실행 권한 부여
        
        logger.info("✓ 시작 스크립트 생성됨")
    
    def run_tests(self):
        """테스트 실행"""
        logger.info("테스트 실행 중...")
        
        try:
            # 가상환경의 pytest 사용
            pytest_path = self.venv_path / 'bin' / 'pytest'
            if sys.platform == 'win32':
                pytest_path = self.venv_path / 'Scripts' / 'pytest.exe'
            
            subprocess.run([
                str(pytest_path), 
                'tests/', 
                '-v', 
                '--tb=short'
            ], cwd=self.project_root, check=True)
            
            logger.info("✓ 모든 테스트 통과")
            
        except subprocess.CalledProcessError:
            logger.warning("⚠ 일부 테스트 실패")
    
    def setup(self):
        """전체 설정 실행"""
        try: