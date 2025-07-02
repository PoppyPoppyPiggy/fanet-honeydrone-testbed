# core/ns3/simulation_bridge.py
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

class NS3SimulationBridge(BaseManager):
    def __init__(self, config: Dict[str, Any], event_bus: EventBus, network_manager):
        super().__init__(config)
        self.event_bus = event_bus
        self.network_manager = network_manager
        self.ns3_path = config.get('ns3_path', '/opt/ns-allinone-3.40/ns-3.40')
        self.simulation_script = 'fanet-simulation.cc'
        self.current_simulation = None
        self.metrics_data = {}
        
    async def start(self):
        """NS-3 브리지 시작"""
        self._running = True
        self.logger.info("NS-3 Simulation Bridge started")
        
        # NS-3 환경 검증
        if not await self._verify_ns3_installation():
            raise RuntimeError("NS-3 installation not found or invalid")
        
        # 시뮬레이션 스크립트 생성
        await self._generate_simulation_script()
        
    async def stop(self):
        """NS-3 브리지 중지"""
        self._running = False
        if self.current_simulation:
            self.current_simulation.terminate()
        self.logger.info("NS-3 Simulation Bridge stopped")
    
    async def status(self) -> Dict[str, Any]:
        """시뮬레이션 상태"""
        return {
            'simulation_running': self.current_simulation is not None,
            'node_count': len(self.network_manager.nodes),
            'last_metrics': self.metrics_data
        }
    
    async def start_simulation(self, duration: int = 300) -> bool:
        """NS-3 시뮬레이션 시작"""
        try:
            # 현재 네트워크 토폴로지 기반 시뮬레이션 설정 생성
            config_file = await self._generate_simulation_config()
            
            # NS-3 시뮬레이션 실행
            cmd = [
                f'{self.ns3_path}/ns3',
                'run',
                f'{self.simulation_script}',
                '--',
                f'--config={config_file}',
                f'--duration={duration}'
            ]
            
            self.current_simulation = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.ns3_path
            )
            
            self.logger.info(f"NS-3 simulation started with duration {duration}s")
            
            # 시뮬레이션 모니터링 시작
            asyncio.create_task(self._monitor_simulation())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start NS-3 simulation: {e}")
            return False
    
    async def stop_simulation(self) -> bool:
        """NS-3 시뮬레이션 중지"""
        if self.current_simulation:
            self.current_simulation.terminate()
            self.current_simulation = None
            self.logger.info("NS-3 simulation stopped")
            return True
        return False
    
    async def get_simulation_metrics(self) -> Dict[str, Any]:
        """시뮬레이션 메트릭 조회"""
        return self.metrics_data
    
    async def _verify_ns3_installation(self) -> bool:
        """NS-3 설치 확인"""
        try:
            ns3_executable = Path(self.ns3_path) / 'ns3'
            if not ns3_executable.exists():
                return False
            
            result = subprocess.run([str(ns3_executable), '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
            
        except Exception:
            return False
    
    async def _generate_simulation_config(self) -> str:
        """현재 네트워크 상태 기반 시뮬레이션 설정 생성"""
        config = {
            'nodes': [],
            'links': [],
            'applications': []
        }
        
        # 노드 정보 추가
        for node_id, node in self.network_manager.nodes.items():
            config['nodes'].append({
                'id': node_id,
                'position': [node.position.x, node.position.y, node.position.z],
                'battery_level': node.battery_level,
                'ip_address': node.network_config.ip_address
            })
        
        # 연결 정보 추가
        for node_id in self.network_manager.nodes:
            connected_nodes = await self.network_manager.get_connected_nodes(node_id)
            for connected_id in connected_nodes:
                if node_id < connected_id:  # 중복 방지
                    config['links'].append({
                        'source': node_id,
                        'target': connected_id,
                        'distance': self.network_manager.topology_matrix.get(node_id, {}).get(connected_id, 0)
                    })
        
        # 설정 파일 저장
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f, indent=2)
            return f.name
    
    async def _generate_simulation_script(self):
        """NS-3 시뮬레이션 스크립트 생성"""
        script_content = """
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include <fstream>
#include <nlohmann/json.hpp>

using namespace ns3;
using json = nlohmann::json;

NS_LOG_COMPONENT_DEFINE("FANETSimulation");

int main(int argc, char *argv[]) {
    std::string configFile = "";
    uint32_t duration = 300;
    
    CommandLine cmd;
    cmd.AddValue("config", "Configuration file path", configFile);
    cmd.AddValue("duration", "Simulation duration", duration);
    cmd.Parse(argc, argv);
    
    // JSON 설정 파일 읽기
    std::ifstream file(configFile);
    json config;
    file >> config;
    
    // 노드 생성
    NodeContainer nodes;
    nodes.Create(config["nodes"].size());
    
    // Wi-Fi 설정
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211n);
    
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    
    YansWifiPhyHelper phy = YansWifiPhyHelper::Default();
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());
    
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);
    
    // 이동성 모델 설정
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
    
    // JSON에서 위치 정보 설정
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<MobilityModel> mobilityModel = nodes.Get(i)->GetObject<MobilityModel>();
        auto pos = config["nodes"][i]["position"];
        mobilityModel->SetPosition(Vector(pos[0], pos[1], pos[2]));
    }
    
    // 인터넷 스택 설치
    InternetStackHelper internet;
    internet.Install(nodes);
    
    // IP 주소 할당
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);
    
    // 플로우 모니터 설정
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    
    // 시뮬레이션 실행
    Simulator::Stop(Seconds(duration));
    Simulator::Run();
    
    // 결과 수집
    monitor->SerializeToXmlFile("fanet-flowmon.xml", true, true);
    
    Simulator::Destroy();
    return 0;
}
"""
        
        script_path = Path(self.ns3_path) / 'scratch' / self.simulation_script
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        self.logger.info(f"NS-3 simulation script generated: {script_path}")
    
    async def _monitor_simulation(self):
        """시뮬레이션 모니터링"""
        while self.current_simulation and self.current_simulation.poll() is None:
            await asyncio.sleep(5)
            
            # 중간 결과 파일 체크
            flowmon_file = Path(self.ns3_path) / 'fanet-flowmon.xml'
            if flowmon_file.exists():
                await self._parse_flowmon_results(str(flowmon_file))
        
        # 시뮬레이션 완료 처리
        if self.current_simulation:
            stdout, stderr = self.current_simulation.communicate()
            self.current_simulation = None
            
            await self.event_bus.publish('simulation_completed', {
                'metrics': self.metrics_data,
                'stdout': stdout.decode() if stdout else '',
                'stderr': stderr.decode() if stderr else ''
            })
    
    async def _parse_flowmon_results(self, xml_file: str):
        """FlowMonitor XML 결과 파싱"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            flows = {}
            for flow in root.findall('.//Flow'):
                flow_id = flow.get('flowId')
                flows[flow_id] = {
                    'tx_packets': int(flow.get('txPackets', 0)),
                    'rx_packets': int(flow.get('rxPackets', 0)),
                    'lost_packets': int(flow.get('lostPackets', 0)),
                    'tx_bytes': int(flow.get('txBytes', 0)),
                    'rx_bytes': int(flow.get('rxBytes', 0)),
                    'delay_sum': float(flow.get('delaySum', 0)),
                    'jitter_sum': float(flow.get('jitterSum', 0))
                }
            
            # 전체 네트워크 메트릭 계산
            total_tx = sum(f['tx_packets'] for f in flows.values())
            total_rx = sum(f['rx_packets'] for f in flows.values())
            total_lost = sum(f['lost_packets'] for f in flows.values())
            
            self.metrics_data = {
                'packet_delivery_ratio': total_rx / total_tx if total_tx > 0 else 0,
                'packet_loss_ratio': total_lost / total_tx if total_tx > 0 else 0,
                'average_delay': sum(f['delay_sum'] for f in flows.values()) / total_rx if total_rx > 0 else 0,
                'throughput': sum(f['rx_bytes'] for f in flows.values()) * 8 / 1000000,  # Mbps
                'flows': flows
            }
            
            await self.event_bus.publish('metrics_updated', self.metrics_data)
            
        except Exception as e:
            self.logger.error(f"Error parsing FlowMonitor results: {e}")