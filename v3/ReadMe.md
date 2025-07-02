# README.md

# FANET 허니드론 네트워크 테스트베드

VD 기반 공격 시나리오와 NS-3 연동을 통한 CTI 수집 및 강화학습 기반 MTD Policy 최적화 연구를 위한 통합 테스트베드입니다.

## 📋 목차

- [프로젝트 개요](#프로젝트-개요)
- [주요 특징](#주요-특징)
- [시스템 요구사항](#시스템-요구사항)
- [설치 및 설정](#설치-및-설정)
- [사용법](#사용법)
- [아키텍처](#아키텍처)
- [API 문서](#api-문서)
- [실험 가이드](#실험-가이드)
- [기여 방법](#기여-방법)

## 🎯 프로젝트 개요

본 프로젝트는 FANET(Flying Ad-hoc Network) 환경에서 허니드론 네트워크를 구축하고, DVD(Damn Vulnerable Drone) 시뮬레이터를 활용한 공격 시나리오 재현, CTI(Cyber Threat Intelligence) 분석, 그리고 강화학습 기반 MTD(Moving Target Defense) 정책 최적화를 수행하는 통합 테스트베드입니다.

### 🔬 연구 목적

1. **DVD 시뮬레이터를 활용한 실제적 드론 공격 시나리오 재현**
2. **사이버 위협 인텔리전스(CTI) 자동 수집 및 구조화 체계 구축**
3. **NS-3 네트워크 시뮬레이터 연동을 통한 공격 영향도 정량화**
4. **강화학습 기반 MTD 정책 자동 최적화 시스템 개발**

## ✨ 주요 특징

### 🛡️ 보안 및 기만
- **허니드론 네트워크**: MAVLink, SSH, HTTP 허니팟 서비스
- **FANET 특성 기반 3차원 MTD**: 입체적 방어 전략
- **실시간 적응형 방어**: 공격 패턴 기반 자동 대응

### 🔍 위협 인텔리전스
- **MITRE ATT&CK 프레임워크 매핑**: 드론 특화 TTP 분류
- **STIX 2.1 형식 지원**: 표준화된 위협 정보 교환
- **실시간 CTI 분석**: DVDs 로그 자동 분석 및 지표 추출

### 🌐 네트워크 시뮬레이션
- **NS-3 연동**: 패킷 레벨 정밀 시뮬레이션
- **3차원 토폴로지**: 고도 동적 FANET 환경 모델링
- **에너지 기반 제약**: 실제 드론 배터리 특성 반영

### 🧠 강화학습 최적화
- **DQN/PPO 알고리즘**: 다중 목적 보상 함수 기반 학습
- **적응형 정책**: 실시간 위협 환경 변화 대응
- **비용-효과 최적화**: 방어 비용과 보안 효과 균형

## 🔧 시스템 요구사항

### 필수 요구사항
- **운영체제**: Ubuntu 20.04+ / macOS 10.15+ / Windows 10+
- **Python**: 3.8 이상
- **메모리**: 8GB RAM 이상
- **저장공간**: 20GB 이상

### 선택사항
- **Docker**: 컨테이너 기반 배포용
- **NVIDIA GPU**: 강화학습 가속 (CUDA 지원)
- **NS-3**: 네트워크 시뮬레이션 (자동 설치됨)

## 🚀 설치 및 설정

### 빠른 시작

1. **저장소 클론**
```bash
git clone https://github.com/PoppyPoppyPiggy/fanet-honeydrone-testbed.git
cd fanet-honeydrone-testbed
```

2. **통합 설치 스크립트 실행**
```bash
chmod +x integrated_launcher.sh
./integrated_launcher.sh
```

3. **메뉴에서 "3) 시스템 설정 및 초기화" 선택**

### 수동 설치

1. **Python 가상환경 생성**
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. **의존성 설치**
```bash
pip install -r requirements.txt
```

3. **환경 설정**
```bash
python3 scripts/setup_environment.py
```

## 🎮 사용법

### 1. 통합 런처 사용 (권장)

```bash
./integrated_launcher.sh
```

메뉴에서 원하는 작업을 선택하세요:
- 개발 환경 시작
- Docker 환경 시작
- 실험 실행
- 성능 분석 등

### 2. 개별 컴포넌트 실행

#### API 서버 시작
```bash
python interfaces/api/main.py
```

#### 실험 실행
```bash
python scripts/experiment_runner.py experiment --config config/experiments.json --experiment mtd_effectiveness
```

#### 로그 분석
```bash
python scripts/log_analyzer.py analyze
```

### 3. Docker 사용

```bash
docker-compose -f deployment/docker-compose.yml up -d
```

## 🏗️ 아키텍처

### 시스템 구성도

```
┌─────────────────────────────────────────────────────────────────────┐
│                        통합 테스트베드 아키텍처                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Honeydrone   │◄──►│ MTD          │◄──►│ DVDs Simulator       │   │
│  │ Network      │    │ Simulator    │    │ (Gazebo/ArduPilot)   │   │
│  │              │    │              │    │                      │   │
│  │ - SDN Ctrl   │    │ - Manager    │    │ - QGroundControl     │   │
│  │ - NS-3 FANET │    │ - Policies   │    │ - MAVLink Protocol   |   │
│  │ - 6 Nodes    │    │ - RL Engine  │    │ - Physics Simulation │   │
│  └──────────────┘    └──────────────┘    └──────────────────────┘   │
│           │                    │                         │          │
│           └────────────────────┼─────────────────────────┘          │
│                                │                                    │
│  ┌─────────────────────────────┴─────────────────────────────────┐  │
│  │                    NS-3 Network Simulator                     │  │
│  │  - Packet Level Simulation                                    │  │
│  │  - FANET Mobility Models                                      |  │
│  │  - TAP Bridge Interface                                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 핵심 모듈

1. **Honeydrone Network Manager** (`core/honeydrone/`)
   - FANET 토폴로지 관리
   - 3D 좌표계 기반 네트워크 매핑
   - 에너지 기반 제약 조건

2. **MTD Policy Engine** (`core/mtd/`)
   - 강화학습 기반 정책 최적화
   - 다중 MTD 전략 지원
   - 실시간 적응형 방어

3. **CTI Analysis Engine** (`core/cti/`)
   - DVDs 로그 분석
   - MITRE ATT&CK 매핑
   - STIX 2.1 형식 변환

4. **NS-3 Simulation Bridge** (`core/ns3/`)
   - 네트워크 시뮬레이션 연동
   - 성능 메트릭 수집
   - TAP 인터페이스 관리

## 📚 API 문서

### RESTful API

테스트베드가 실행 중일 때 다음에서 API 문서를 확인할 수 있습니다:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 주요 엔드포인트

#### 드론 관리
```http
GET    /api/v1/drones              # 드론 목록
POST   /api/v1/drones              # 드론 생성
PUT    /api/v1/drones/{id}/position # 위치 업데이트
```

#### 공격 시뮬레이션
```http
POST   /api/v1/attacks             # 공격 실행
GET    /api/v1/attacks             # 공격 이력
```

#### MTD 관리
```http
POST   /api/v1/mtd/execute         # MTD 실행
GET    /api/v1/mtd/history         # MTD 이력
```

#### CTI 분석
```http
GET    /api/v1/cti/indicators      # 위협 지표
GET    /api/v1/cti/stix/{id}       # STIX 보고서
```

### WebSocket 이벤트

```javascript
// WebSocket 연결
const ws = new WebSocket('ws://localhost:8000/ws');

// 실시간 이벤트 수신
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    // node_added, attack_detected, mtd_action_executed 등
};
```

## 🧪 실험 가이드

### 실험 설정 파일

실험은 JSON 설정 파일로 정의됩니다:

```json
{
  "experiments": {
    "mtd_effectiveness": {
      "description": "MTD 전략별 효과성 비교",
      "duration": 60,
      "scenario": {
        "type": "mtd_effectiveness",
        "mtd_strategies": ["ip_hopping", "port_randomization", "frequency_hopping"],
        "attack_types": ["gps_spoofing", "mavlink_injection"]
      }
    }
  }
}
```

### 실험 실행

1. **통합 런처 사용**
```bash
./integrated_launcher.sh
# 메뉴에서 "4) 실험 실행" 선택
```

2. **직접 실행**
```bash
python scripts/experiment_runner.py experiment \
  --config config/experiments.json \
  --experiment mtd_effectiveness
```

### 결과 분석

실험 완료 후 `data/experiments/` 디렉토리에 결과가 저장됩니다:
- `network_metrics.csv`: 네트워크 성능 데이터
- `mtd_actions.csv`: MTD 실행 이력
- `attack_events.csv`: 공격 이벤트 로그
- `analysis_report.md`: 종합 분석 보고서

## 📊 성능 벤치마크

시스템 성능을 측정하려면:

```bash
python scripts/benchmark.py
```

또는 통합 런처에서 "5) 성능 벤치마크" 선택

## 🔍 로그 분석

로그를 분석하고 시각화하려면:

```bash
python scripts/log_analyzer.py analyze
```

생성되는 결과물:
- `reports/attack_patterns.png`: 공격 패턴 시각화
- `reports/mtd_effectiveness.png`: MTD 효과성 차트
- `reports/analysis_report.md`: 상세 분석 보고서

## ⚙️ 설정

### 주요 설정 파일

- `config/network_config.yaml`: 네트워크 설정
- `config/mtd_config.yaml`: MTD 정책 설정
- `config/cti_config.yaml`: CTI 분석 설정
- `config/experiments.json`: 실험 시나리오 정의

### 환경 변수

```bash
export PYTHONPATH="${PWD}"
export CONFIG_DIR="${PWD}/config"
export DATA_DIR="${PWD}/data"
export LOG_LEVEL="INFO"
```

## 🐛 문제 해결

### 일반적인 문제

1. **NS-3 컴파일 오류**
```bash
# 의존성 재설치
sudo apt-get install build-essential cmake python3-dev
```

2. **Docker 권한 오류**
```bash
sudo usermod -aG docker $USER
# 로그아웃 후 다시 로그인
```

3. **포트 충돌**
```bash
# 사용 중인 포트 확인
netstat -tulpn | grep :8000
```

### 로그 확인

- 애플리케이션 로그: `logs/application/`
- 시뮬레이션 로그: `logs/simulation/`
- 보안 이벤트 로그: `logs/security/`

## 🤝 기여 방법

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 개발 환경 설정

```bash
# 개발 의존성 설치
pip install -r requirements.txt -e ".[dev]"

# 코드 포맷팅
black src/ tests/
flake8 src/ tests/

# 테스트 실행
pytest tests/ -v --cov=src
```

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 🙏 감사의 말

- [ArduPilot](https://ardupilot.org/) 오픈소스 자동조종장치
- [NS-3](https://www.nsnam.org/) 네트워크 시뮬레이터
- [Gazebo](http://gazebosim.org/) 로봇 시뮬레이터
- [MITRE ATT&CK](https://attack.mitre.org/) 프레임워크
