# interfaces/api/main.py
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
import logging
from datetime import datetime

from core.base import EventBus, DroneNode, Position3D, AttackType, MTDStrategyType
from core.honeydrone.network_manager import HoneydroneNetworkManager
from core.mtd.policy_engine import MTDPolicyEngine, MTDAction
from core.cti.analysis_engine import CTIAnalysisEngine
from core.ns3.simulation_bridge import NS3SimulationBridge

# Pydantic 모델들
class Position3DModel(BaseModel):
    x: float
    y: float
    z: float

class DroneNodeResponse(BaseModel):
    id: str
    position: Position3DModel
    battery_level: float
    network_config: Dict[str, Any]
    mtd_status: Dict[str, Any]
    security_state: Dict[str, Any]
    state: str
    created_at: datetime

class AttackScenarioRequest(BaseModel):
    attack_type: AttackType
    target_node: str
    parameters: Dict[str, Any]

class MTDActionRequest(BaseModel):
    strategy: MTDStrategyType
    target_node: str
    parameters: Dict[str, Any]

class SimulationRequest(BaseModel):
    duration: int = 300
    scenario: Optional[str] = None

# FastAPI 앱 초기화
app = FastAPI(
    title="FANET Honeydrone Testbed API",
    description="API for FANET-based Honeydrone Network Testbed",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 전역 매니저 인스턴스들
event_bus = EventBus()
network_manager: Optional[HoneydroneNetworkManager] = None
mtd_engine: Optional[MTDPolicyEngine] = None
cti_engine: Optional[CTIAnalysisEngine] = None
ns3_bridge: Optional[NS3SimulationBridge] = None

# WebSocket 연결 관리
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# 시스템 이벤트 핸들러
async def broadcast_event(event_data):
    """시스템 이벤트를 WebSocket으로 브로드캐스트"""
    await manager.broadcast(json.dumps(event_data))

@app.on_event("startup")
async def startup_event():
    """애플리케이션 시작시 초기화"""
    global network_manager, mtd_engine, cti_engine, ns3_bridge
    
    # 설정 로드 (실제로는 config 파일에서)
    config = {
        'network_range': '10.0.0.0/16',
        'communication_range': 100.0,
        'initial_node_count': 6,
        'ns3_path': '/opt/ns-allinone-3.40/ns-3.40'
    }
    
    # 매니저들 초기화
    network_manager = HoneydroneNetworkManager(config, event_bus)
    mtd_engine = MTDPolicyEngine(config, event_bus, network_manager)
    cti_engine = CTIAnalysisEngine(config, event_bus)
    ns3_bridge = NS3SimulationBridge(config, event_bus, network_manager)
    
    # 이벤트 구독
    event_bus.subscribe('node_added', lambda data: broadcast_event({'type': 'node_added', 'data': data}))
    event_bus.subscribe('node_moved', lambda data: broadcast_event({'type': 'node_moved', 'data': data}))
    event_bus.subscribe('attack_detected', lambda data: broadcast_event({'type': 'attack_detected', 'data': data}))
    event_bus.subscribe('mtd_action_executed', lambda data: broadcast_event({'type': 'mtd_action_executed', 'data': data}))
    
    # 매니저들 시작
    await network_manager.start()
    await mtd_engine.start()
    await cti_engine.start()
    await ns3_bridge.start()
    
    logging.info("FANET Honeydrone Testbed API started")

@app.on_event("shutdown")
async def shutdown_event():
    """애플리케이션 종료시 정리"""
    if network_manager:
        await network_manager.stop()
    if mtd_engine:
        await mtd_engine.stop()
    if cti_engine:
        await cti_engine.stop()
    if ns3_bridge:
        await ns3_bridge.stop()
    
    logging.info("FANET Honeydrone Testbed API stopped")

# WebSocket 엔드포인트
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # 클라이언트로부터의 메시지 처리
            await manager.send_personal_message(f"Message received: {data}", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# API 엔드포인트들

# 시스템 상태
@app.get("/api/v1/status")
async def get_system_status():
    """전체 시스템 상태 조회"""
    status = {}
    
    if network_manager:
        status['network'] = await network_manager.status()
    if mtd_engine:
        status['mtd'] = await mtd_engine.status()
    if cti_engine:
        status['cti'] = await cti_engine.status()
    if ns3_bridge:
        status['simulation'] = await ns3_bridge.status()
    
    return status

# 드론 노드 관리
@app.get("/api/v1/drones", response_model=List[DroneNodeResponse])
async def get_drones():
    """모든 드론 노드 조회"""
    if not network_manager:
        raise HTTPException(status_code=503, detail="Network manager not available")
    
    nodes = []
    for node in network_manager.nodes.values():
        nodes.append(DroneNodeResponse(
            id=node.id,
            position=Position3DModel(x=node.position.x, y=node.position.y, z=node.position.z),
            battery_level=node.battery_level,
            network_config=node.network_config.__dict__,
            mtd_status=node.mtd_status.__dict__,
            security_state=node.security_state.__dict__,
            state=node.state.value,
            created_at=node.created_at
        ))
    
    return nodes

@app.post("/api/v1/drones")
async def create_drone(position: Position3DModel):
    """새 드론 노드 생성"""
    if not network_manager:
        raise HTTPException(status_code=503, detail="Network manager not available")
    
    pos3d = Position3D(x=position.x, y=position.y, z=position.z)
    node_id = f"drone_{len(network_manager.nodes)}"
    
    node = await network_manager.add_node(node_id, pos3d)
    
    return {"message": f"Drone {node_id} created successfully", "node_id": node_id}

@app.get("/api/v1/drones/{node_id}")
async def get_drone(node_id: str):
    """특정 드론 노드 조회"""
    if not network_manager:
        raise HTTPException(status_code=503, detail="Network manager not available")
    
    if node_id not in network_manager.nodes:
        raise HTTPException(status_code=404, detail="Drone not found")
    
    node = network_manager.nodes[node_id]
    return DroneNodeResponse(
        id=node.id,
        position=Position3DModel(x=node.position.x, y=node.position.y, z=node.position.z),
        battery_level=node.battery_level,
        network_config=node.network_config.__dict__,
        mtd_status=node.mtd_status.__dict__,
        security_state=node.security_state.__dict__,
        state=node.state.value,
        created_at=node.created_at
    )

@app.put("/api/v1/drones/{node_id}/position")
async def update_drone_position(node_id: str, position: Position3DModel):
    """드론 위치 업데이트"""
    if not network_manager:
        raise HTTPException(status_code=503, detail="Network manager not available")
    
    if node_id not in network_manager.nodes:
        raise HTTPException(status_code=404, detail="Drone not found")
    
    pos3d = Position3D(x=position.x, y=position.y, z=position.z)
    await network_manager.update_node_position(node_id, pos3d)
    
    return {"message": f"Position updated for drone {node_id}"}

@app.get("/api/v1/drones/{node_id}/connections")
async def get_drone_connections(node_id: str):
    """드론의 연결 정보 조회"""
    if not network_manager:
        raise HTTPException(status_code=503, detail="Network manager not available")
    
    if node_id not in network_manager.nodes:
        raise HTTPException(status_code=404, detail="Drone not found")
    
    connected_nodes = await network_manager.get_connected_nodes(node_id)
    return {"node_id": node_id, "connected_nodes": list(connected_nodes)}

# 공격 시나리오 관리
@app.post("/api/v1/attacks")
async def execute_attack_scenario(attack_request: AttackScenarioRequest):
    """공격 시나리오 실행"""
    if not cti_engine:
        raise HTTPException(status_code=503, detail="CTI engine not available")
    
    # DVDs 로그 시뮬레이션
    fake_log = {
        "timestamp": datetime.now().isoformat(),
        "event_type": attack_request.attack_type.value,
        "source_ip": attack_request.parameters.get("source_ip", "192.168.1.100"),
        "target_component": attack_request.target_node,
        "attack_vector": f"{attack_request.attack_type.value}_injection",
        "payload": attack_request.parameters,
        "severity": "high",
        "detection_status": "undetected"
    }
    
    threat_intel = await cti_engine.analyze_dvds_log(fake_log)
    
    return {
        "message": "Attack scenario executed",
        "threat_intel_id": threat_intel.id if threat_intel else None,
        "log_entry": fake_log
    }

@app.get("/api/v1/attacks")
async def get_attacks(
    attack_type: Optional[AttackType] = None,
    severity_min: int = 1,
    time_range_hours: int = 24
):
    """공격 이벤트 조회"""
    if not cti_engine:
        raise HTTPException(status_code=503, detail="CTI engine not available")
    
    threats = await cti_engine.search_threats(attack_type, severity_min, time_range_hours)
    
    return {
        "threats": [
            {
                "id": t.id,
                "attack_type": t.attack_type.value,
                "severity": t.severity,
                "description": t.description,
                "created_at": t.created_at.isoformat(),
                "mitre_mappings": [m.__dict__ for m in t.mitre_mappings]
            }
            for t in threats
        ]
    }

# MTD 정책 관리
@app.post("/api/v1/mtd/execute")
async def execute_mtd_action(mtd_request: MTDActionRequest):
    """MTD 액션 실행"""
    if not mtd_engine:
        raise HTTPException(status_code=503, detail="MTD engine not available")
    
    action = MTDAction(
        strategy=mtd_request.strategy,
        target_node=mtd_request.target_node,
        parameters=mtd_request.parameters,
        cost=0.5,  # 기본값
        expected_effectiveness=0.7  # 기본값
    )
    
    success = await mtd_engine.execute_mtd_action(action)
    
    return {
        "success": success,
        "message": f"MTD action {'executed' if success else 'failed'}",
        "action": {
            "strategy": action.strategy.value,
            "target_node": action.target_node,
            "parameters": action.parameters
        }
    }

@app.get("/api/v1/mtd/history")
async def get_mtd_history():
    """MTD 실행 이력 조회"""
    if not mtd_engine:
        raise HTTPException(status_code=503, detail="MTD engine not available")
    
    return {
        "total_actions": len(mtd_engine.action_history),
        "recent_actions": [
            {
                "strategy": action.strategy.value,
                "target_node": action.target_node,
                "cost": action.cost,
                "effectiveness": action.expected_effectiveness,
                "parameters": action.parameters
            }
            for action in mtd_engine.action_history[-10:]  # 최근 10개
        ]
    }

# CTI 분석
@app.get("/api/v1/cti/indicators")
async def get_cti_indicators():
    """CTI 지표 조회"""
    if not cti_engine:
        raise HTTPException(status_code=503, detail="CTI engine not available")
    
    all_indicators = []
    for threat in cti_engine.threat_intelligence_db.values():
        for ioc in threat.iocs:
            all_indicators.append({
                "type": ioc.type,
                "value": ioc.value,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen.isoformat(),
                "last_seen": ioc.last_seen.isoformat(),
                "context": ioc.context,
                "threat_id": threat.id
            })
    
    return {"indicators": all_indicators}

@app.get("/api/v1/cti/mappings")
async def get_mitre_mappings():
    """MITRE ATT&CK 매핑 조회"""
    if not cti_engine:
        raise HTTPException(status_code=503, detail="CTI engine not available")
    
    mappings = []
    for threat in cti_engine.threat_intelligence_db.values():
        for mapping in threat.mitre_mappings:
            mappings.append({
                "threat_id": threat.id,
                "attack_type": threat.attack_type.value,
                "tactic": mapping.tactic,
                "technique": mapping.technique,
                "technique_id": mapping.technique_id,
                "confidence": mapping.confidence
            })
    
    return {"mappings": mappings}

@app.get("/api/v1/cti/stix/{threat_id}")
async def get_stix_report(threat_id: str):
    """STIX 형식 위협 정보 조회"""
    if not cti_engine:
        raise HTTPException(status_code=503, detail="CTI engine not available")
    
    stix_report = await cti_engine.generate_stix_report(threat_id)
    
    if not stix_report:
        raise HTTPException(status_code=404, detail="Threat intelligence not found")
    
    return stix_report

# NS-3 시뮬레이션 관리
@app.post("/api/v1/simulation/start")
async def start_simulation(sim_request: SimulationRequest):
    """시뮬레이션 시작"""
    if not ns3_bridge:
        raise HTTPException(status_code=503, detail="NS-3 bridge not available")
    
    success = await ns3_bridge.start_simulation(sim_request.duration)
    
    return {
        "success": success,
        "message": f"Simulation {'started' if success else 'failed to start'}",
        "duration": sim_request.duration
    }

@app.post("/api/v1/simulation/stop")
async def stop_simulation():
    """시뮬레이션 중지"""
    if not ns3_bridge:
        raise HTTPException(status_code=503, detail="NS-3 bridge not available")
    
    success = await ns3_bridge.stop_simulation()
    
    return {
        "success": success,
        "message": f"Simulation {'stopped' if success else 'was not running'}"
    }

@app.get("/api/v1/simulation/metrics")
async def get_simulation_metrics():
    """시뮬레이션 메트릭 조회"""
    if not ns3_bridge:
        raise HTTPException(status_code=503, detail="NS-3 bridge not available")
    
    metrics = await ns3_bridge.get_simulation_metrics()
    
    return {"metrics": metrics}

@app.get("/api/v1/simulation/status")
async def get_simulation_status():
    """시뮬레이션 상태 조회"""
    if not ns3_bridge:
        raise HTTPException(status_code=503, detail="NS-3 bridge not available")
    
    status = await ns3_bridge.status()
    
    return status

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)