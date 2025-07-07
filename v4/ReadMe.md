MTD 기반 드론 생존성 시뮬레이터 프로젝트 구조
📁 전체 디렉토리 구조
mtd-drone-testbed/
├── 📁 core/                                    # 핵심 시스템 모듈
│   ├── 📁 honeydrone/                          # 허니드론 네트워크 관리
│   │   ├── __init__.py                         # 모듈 초기화
│   │   ├── network_manager.py                  # FANET 토폴로지 관리
│   │   ├── virtual_drone.py                    # 가상 드론 (적 주의 분산)
│   │   ├── dummy_drone.py                      # 더미 드론 (허니팟)
│   │   └── honeypot_services.py               # MAVLink, SSH, HTTP 허니팟
│   │
│   ├── 📁 mtd/                                 # MTD 정책 엔진
│   │   ├── __init__.py
│   │   ├── mtd_controller.py                   # MTD 정책 실행기
│   │   ├── strategies.py                       # MTD 전략 구현
│   │   └── decoy_controller.py                 # Decoy 정책기
│   │
│   ├── 📁 rl_adaptation/                       # 강화학습 최적화
│   │   ├── __init__.py
│   │   ├── environment.py                      # RL 환경 정의
│   │   ├── agents.py                           # DQN/PPO 에이전트
│   │   ├── reward_functions.py                 # 보상 함수
│   │   └── rl_mtd_integration.py              # RL-MTD 통합
│   │
│   ├── 📁 dvd_integration/                     # DVD 시뮬레이터 연동
│   │   ├── __init__.py
│   │   ├── dvd_controller.py                   # DVD 컨테이너 관리
│   │   ├── attack_executor.py                  # 공격 시나리오 실행
│   │   ├── cti_collector.py                    # CTI 수집기
│   │   └── mitre_mapper.py                     # MITRE ATT&CK 매핑
│   │
│   ├── 📁 ns3_integration/                     # NS-3 연동
│   │   ├── __init__.py
│   │   ├── ns3_controller.py                   # NS-3 시뮬레이션 제어
│   │   ├── network_topology.py                 # 3D 네트워크 토폴로지
│   │   ├── tap_interface.py                    # TAP 인터페이스 관리
│   │   └── performance_collector.py            # 성능 메트릭 수집
│   │
│   ├── 📁 phase_management/                    # 4단계 실험 관리
│   │   ├── __init__.py
│   │   ├── phase_controller.py                 # 단계별 실험 제어
│   │   ├── phase_1_deployment.py              # Phase 1: 허니드론 배치
│   │   ├── phase_2_attack.py                   # Phase 2: 공격 실행
│   │   ├── phase_3_cti.py                      # Phase 3: CTI 분석
│   │   └── phase_4_mtd.py                      # Phase 4: MTD 재배치
│   │
│   └── 📁 common/                              # 공통 유틸리티
│       ├── __init__.py
│       ├── data_models.py                      # 데이터 클래스
│       ├── event_bus.py                        # 이벤트 버스
│       ├── logging_config.py                   # 로깅 설정
│       └── utils.py                            # 유틸리티 함수
│
├── 📁 config/                                  # 설정 파일
│   ├── network_config.yaml                     # 네트워크 설정
│   ├── mtd_config.yaml                         # MTD 정책 설정
│   ├── cti_config.yaml                         # CTI 분석 설정
│   ├── attack_scenarios.json                   # 공격 시나리오 정의
│   └── experiments.json                        # 실험 설정
│
├── 📁 scripts/                                 # 스크립트
│   ├── setup_environment.py                    # 환경 설정
│   ├── run_experiment.py                       # 실험 실행기
│   ├── analyze_results.py                      # 결과 분석
│   └── docker_manager.py                       # Docker 관리
│
├── 📁 interfaces/                              # 인터페이스
│   ├── 📁 api/                                 # REST API
│   │   ├── main.py                             # FastAPI 서버
│   │   ├── routers/                            # API 라우터
│   │   └── schemas/                            # 데이터 스키마
│   │
│   └── 📁 cli/                                 # CLI 인터페이스
│       ├── main.py                             # CLI 메인
│       └── commands/                           # CLI 명령어
│
├── 📁 data/                                    # 데이터 저장소
│   ├── 📁 models/                              # 학습된 모델
│   ├── 📁 logs/                                # 실험 로그
│   ├── 📁 cti/                                 # CTI 데이터
│   └── 📁 experiments/                         # 실험 결과
│
├── 📁 external/                                # 외부 도구
│   ├── 📁 dvds/                                # DVD 시뮬레이터
│   ├── 📁 ns3/                                 # NS-3 설치
│   └── 📁 docker/                              # Docker 설정
│
├── 📁 tests/                                   # 테스트
│   ├── unit/                                   # 단위 테스트
│   ├── integration/                            # 통합 테스트
│   └── fixtures/                               # 테스트 데이터
│
├── 📁 docs/                                    # 문서
│   ├── api.md                                  # API 문서
│   ├── setup.md                                # 설치 가이드
│   └── experiments.md                          # 실험 가이드
│
├── 📁 deployment/                              # 배포 설정
│   ├── docker-compose.yml                      # Docker Compose
│   ├── Dockerfile                              # Docker 이미지
│   └── kubernetes/                             # Kubernetes 설정
│
├── requirements.txt                            # Python 의존성
├── main.py                                     # 메인 런처
├── README.md                                   # 프로젝트 문서
└── .env                                        # 환경 변수
🔧 주요 컴포넌트 매핑
1. 허니드론 네트워크 (core/honeydrone/)

Virtual Drone: 적의 주의를 분산시키는 가상 드론
Dummy Drone: 공격을 유도하는 취약한 허니팟 드론
Network Manager: FANET 3D 토폴로지 관리

2. MTD 정책 엔진 (core/mtd/)

MTD Controller: IP 호핑, 포트 랜더마이제이션 등 실행
Decoy Controller: 허니드론 네트워크 동적 재배치
Strategies: 다양한 MTD 전략 구현

3. 강화학습 최적화 (core/rl_adaptation/)

Environment: MTD 환경을 RL 환경으로 모델링
Agents: DQN/PPO 기반 정책 학습
Integration: RL-MTD 실시간 통합

4. DVD 연동 (core/dvd_integration/)

DVD Controller: Docker 기반 DVD 시뮬레이터 관리
Attack Executor: 10가지 공격 시나리오 실행
CTI Collector: 실시간 위협 정보 수집

5. NS-3 연동 (core/ns3_integration/)

NS3 Controller: 네트워크 시뮬레이션 실행
Topology: 3D FANET 토폴로지 구현
Performance Collector: 패킷 레벨 메트릭 수집

6. 실험 관리 (core/phase_management/)

Phase 1: 허니드론 네트워크 초기 배치
Phase 2: DVD 기반 공격 시나리오 실행
Phase 3: CTI 수집 및 MITRE 매핑
Phase 4: RL 기반 MTD/Decoy 재최적화

🚀 실행 흐름

환경 설정: scripts/setup_environment.py
Docker 컨테이너 시작: DVD, NS-3 환경 구축
허니드론 네트워크 배치: Virtual/Dummy 드론 초기화
공격 시나리오 실행: 10가지 MITRE 기반 공격
CTI 수집 및 분석: 실시간 위협 정보 추출
RL 기반 최적화: MTD/Decoy 정책 자동 조정
성능 평가: NS-3 기반 정량적 분석