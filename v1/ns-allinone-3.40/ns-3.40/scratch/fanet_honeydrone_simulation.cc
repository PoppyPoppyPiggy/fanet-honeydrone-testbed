/*
 * FANET Honeydrone Simulation for NS-3
 * Enhanced version with MTD and threat modeling
 */

 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/wifi-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/applications-module.h"
 #include "ns3/flow-monitor-module.h"
 #include "ns3/netanim-module.h"
 #include "ns3/energy-module.h"
 #include "ns3/spectrum-module.h"
 
 #include <iostream>
 #include <fstream>
 #include <vector>
 #include <map>
 #include <random>
 #include <chrono>
 #include <thread>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
 using namespace ns3;
 
 NS_LOG_COMPONENT_DEFINE("FANETHoneydroneSimulation");
 
 // Enums for node types and threat types
 enum NodeType {
     REAL_DRONE = 0,
     HONEYPOT = 1,
     GCS = 2,
     RELAY = 3,
     ATTACKER = 4
 };
 
 enum ThreatType {
     JAMMING = 0,
     SPOOFING = 1,
     EAVESDROPPING = 2,
     DOS = 3,
     MITM = 4,
     PHYSICAL_CAPTURE = 5,
     ROUTING_ATTACK = 6,
     SYBIL_ATTACK = 7
 };
 
 enum MTDActionType {
     FREQUENCY_HOPPING = 0,
     ROUTE_MUTATION = 1,
     IDENTITY_ROTATION = 2,
     POWER_ADJUSTMENT = 3,
     TOPOLOGY_SHUFFLE = 4,
     CHANNEL_SWITCHING = 5
 };
 
 // Global variables
 uint32_t nDrones = 10;
 uint32_t nHoneypots = 5;
 uint32_t nGCS = 1;
 uint32_t nRelays = 2;
 uint32_t nAttackers = 2;
 double simTime = 300.0;
 std::string attackScenario = "mixed";
 bool enableMTD = true;
 std::string resultsFile = "simulation_results.json";
 std::string traceFile = "simulation_trace.db";
 std::string animationFile = "fanet_animation.xml";
 
 // Network containers
 NodeContainer droneNodes;
 NodeContainer honeypotNodes;
 NodeContainer gcsNodes;
 NodeContainer relayNodes;
 NodeContainer attackerNodes;
 NodeContainer allNodes;
 
 // Network devices and interfaces
 NetDeviceContainer devices;
 Ipv4InterfaceContainer interfaces;
 
 // Applications
 ApplicationContainer serverApps;
 ApplicationContainer clientApps;
 
 // Monitoring and analysis
 std::map<uint32_t, NodeType> nodeTypes;
 std::map<uint32_t, bool> compromisedNodes;
 std::map<uint32_t, double> nodeEnergyLevels;
 std::vector<std::pair<uint32_t, ThreatType>> detectedThreats;
 std::vector<std::pair<uint32_t, MTDActionType>> executedMTDActions;
 
 // Communication with Python bridge
 int bridgeSocket = -1;
 struct sockaddr_in bridgeAddr;
 
 // Random number generators
 std::random_device rd;
 std::mt19937 gen(rd());
 
 // Function declarations
 void SetupTopology();
 void SetupMobility();
 void SetupWireless();
 void SetupApplications();
 void SetupEnergyModel();
 void SetupFlowMonitor();
 void StartAttackScenario();
 void HandleThreatDetection(uint32_t sourceNode, uint32_t targetNode, ThreatType threat);
 void ExecuteMTDAction(uint32_t targetNode, MTDActionType action);
 void MonitorNetwork();
 void ExportResults();
 void SendToPythonBridge(const std::string& message);
 bool InitializeBridgeCommunication();
 void ProcessMTDCommand(const std::string& command);
 
 // Custom application for FANET communication
 class FANETApplication : public Application
 {
 public:
     FANETApplication();
     virtual ~FANETApplication();
     void Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, 
                uint32_t nPackets, DataRate dataRate, NodeType nodeType);
 
 private:
     virtual void StartApplication(void);
     virtual void StopApplication(void);
 
     void ScheduleTx(void);
     void SendPacket(void);
     void HandleRead(Ptr<Socket> socket);
 
     Ptr<Socket> m_socket;
     Address m_peer;
     uint32_t m_packetSize;
     uint32_t m_nPackets;
     DataRate m_dataRate;
     EventId m_sendEvent;
     bool m_running;
     uint32_t m_packetsSent;
     NodeType m_nodeType;
     uint32_t m_nodeId;
 };
 
 FANETApplication::FANETApplication()
     : m_socket(0),
       m_peer(),
       m_packetSize(0),
       m_nPackets(0),
       m_dataRate(0),
       m_running(false),
       m_packetsSent(0),
       m_nodeType(REAL_DRONE),
       m_nodeId(0)
 {
 }
 
 FANETApplication::~FANETApplication()
 {
     m_socket = 0;
 }
 
 void
 FANETApplication::Setup(Ptr<Socket> socket, Address address, uint32_t packetSize,
                        uint32_t nPackets, DataRate dataRate, NodeType nodeType)
 {
     m_socket = socket;
     m_peer = address;
     m_packetSize = packetSize;
     m_nPackets = nPackets;
     m_dataRate = dataRate;
     m_nodeType = nodeType;
     m_nodeId = GetNode()->GetId();
 }
 
 void
 FANETApplication::StartApplication(void)
 {
     m_running = true;
     m_packetsSent = 0;
     m_socket->Bind();
     m_socket->Connect(m_peer);
     m_socket->SetRecvCallback(MakeCallback(&FANETApplication::HandleRead, this));
     SendPacket();
 }
 
 void
 FANETApplication::StopApplication(void)
 {
     m_running = false;
     if (m_sendEvent.IsRunning())
     {
         Simulator::Cancel(m_sendEvent);
     }
     if (m_socket)
     {
         m_socket->Close();
     }
 }
 
 void
 FANETApplication::SendPacket(void)
 {
     // Create packet with node type and status information
     std::string nodeTypeStr;
     switch (m_nodeType) {
         case REAL_DRONE: nodeTypeStr = "real_drone"; break;
         case HONEYPOT: nodeTypeStr = "honeypot"; break;
         case GCS: nodeTypeStr = "gcs"; break;
         case RELAY: nodeTypeStr = "relay"; break;
         case ATTACKER: nodeTypeStr = "attacker"; break;
     }
 
     std::string packetData = "NODE_ID:" + std::to_string(m_nodeId) + 
                            ",TYPE:" + nodeTypeStr + 
                            ",STATUS:active" +
                            ",ENERGY:" + std::to_string(nodeEnergyLevels[m_nodeId]);
 
     Ptr<Packet> packet = Create<Packet>((uint8_t*)packetData.c_str(), packetData.length());
     m_socket->Send(packet);
 
     // Log packet transmission
     Vector pos = GetNode()->GetObject<MobilityModel>()->GetPosition();
     std::cout << "NODE_UPDATE:" << m_nodeId << ":" << pos.x << ":" << pos.y << ":" << pos.z 
               << ":" << nodeEnergyLevels[m_nodeId] << ":" << (compromisedNodes[m_nodeId] ? "true" : "false") << std::endl;
 
     if (++m_packetsSent < m_nPackets)
     {
         ScheduleTx();
     }
 }
 
 void
 FANETApplication::ScheduleTx(void)
 {
     if (m_running)
     {
         Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));
         
         // Add random jitter for realistic behavior
         std::uniform_real_distribution<double> jitter(0.8, 1.2);
         tNext = Seconds(tNext.GetSeconds() * jitter(gen));
         
         m_sendEvent = Simulator::Schedule(tNext, &FANETApplication::SendPacket, this);
     }
 }
 
 void
 FANETApplication::HandleRead(Ptr<Socket> socket)
 {
     Ptr<Packet> packet;
     while ((packet = socket->Recv()))
     {
         // Process received packet
         uint8_t buffer[1024];
         packet->CopyData(buffer, packet->GetSize());
         buffer[packet->GetSize()] = '\0';
         
         std::string receivedData((char*)buffer);
         
         // Check for potential threats based on packet content and sender
         if (m_nodeType == HONEYPOT && receivedData.find("ATTACK") != std::string::npos)
         {
             // Honeypot detected malicious activity
             HandleThreatDetection(GetNode()->GetId(), m_nodeId, SPOOFING);
         }
         
         // Simulate energy consumption
         nodeEnergyLevels[m_nodeId] -= 0.001;
         if (nodeEnergyLevels[m_nodeId] < 0) nodeEnergyLevels[m_nodeId] = 0;
     }
 }
 
 // Threat simulation and detection
 class ThreatSimulator
 {
 public:
     ThreatSimulator();
     void StartThreatGeneration();
     void GenerateJammingAttack();
     void GenerateSpoofingAttack();
     void GenerateDoSAttack();
     void GenerateEavesdroppingAttack();
     void GenerateMITMAttack();
     void GenerateRoutingAttack();
 
 private:
     std::uniform_int_distribution<> m_nodeDist;
     std::uniform_int_distribution<> m_threatDist;
     std::uniform_real_distribution<> m_probDist;
     EventId m_nextThreatEvent;
 };
 
 ThreatSimulator::ThreatSimulator()
     : m_nodeDist(0, allNodes.GetN() - 1),
       m_threatDist(0, 7),
       m_probDist(0.0, 1.0)
 {
 }
 
 void
 ThreatSimulator::StartThreatGeneration()
 {
     if (attackScenario == "none") return;
     
     // Schedule first threat
     std::uniform_real_distribution<> timeDist(10.0, 30.0);
     Time nextTime = Seconds(timeDist(gen));
     
     if (attackScenario == "jamming")
     {
         Simulator::Schedule(nextTime, &ThreatSimulator::GenerateJammingAttack, this);
     }
     else if (attackScenario == "spoofing")
     {
         Simulator::Schedule(nextTime, &ThreatSimulator::GenerateSpoofingAttack, this);
     }
     else if (attackScenario == "mixed")
     {
         // Random threat type
         ThreatType threatType = static_cast<ThreatType>(m_threatDist(gen));
         switch (threatType)
         {
             case JAMMING:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateJammingAttack, this);
                 break;
             case SPOOFING:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateSpoofingAttack, this);
                 break;
             case DOS:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateDoSAttack, this);
                 break;
             case EAVESDROPPING:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateEavesdroppingAttack, this);
                 break;
             case MITM:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateMITMAttack, this);
                 break;
             case ROUTING_ATTACK:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateRoutingAttack, this);
                 break;
             default:
                 Simulator::Schedule(nextTime, &ThreatSimulator::GenerateJammingAttack, this);
                 break;
         }
     }
 }
 
 void
 ThreatSimulator::GenerateJammingAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     // Ensure different nodes
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // Simulate jamming detection based on signal strength changes
     if (m_probDist(gen) > 0.3) // 70% detection rate
     {
         HandleThreatDetection(attackerNode, targetNode, JAMMING);
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 void
 ThreatSimulator::GenerateSpoofingAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // Higher detection rate for honeypots
     double detectionProb = (nodeTypes[targetNode] == HONEYPOT) ? 0.9 : 0.5;
     
     if (m_probDist(gen) < detectionProb)
     {
         HandleThreatDetection(attackerNode, targetNode, SPOOFING);
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 void
 ThreatSimulator::GenerateDoSAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // DoS attacks are easier to detect due to traffic patterns
     if (m_probDist(gen) > 0.2) // 80% detection rate
     {
         HandleThreatDetection(attackerNode, targetNode, DOS);
         
         // DoS can compromise the target node
         if (m_probDist(gen) > 0.6)
         {
             compromisedNodes[targetNode] = true;
         }
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 void
 ThreatSimulator::GenerateEavesdroppingAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // Eavesdropping is harder to detect
     if (m_probDist(gen) > 0.7) // 30% detection rate
     {
         HandleThreatDetection(attackerNode, targetNode, EAVESDROPPING);
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 void
 ThreatSimulator::GenerateMITMAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // MITM detection varies based on node type
     double detectionProb = 0.4;
     if (nodeTypes[targetNode] == HONEYPOT) detectionProb = 0.8;
     if (nodeTypes[targetNode] == GCS) detectionProb = 0.7;
     
     if (m_probDist(gen) < detectionProb)
     {
         HandleThreatDetection(attackerNode, targetNode, MITM);
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 void
 ThreatSimulator::GenerateRoutingAttack()
 {
     uint32_t attackerNode = m_nodeDist(gen);
     uint32_t targetNode = m_nodeDist(gen);
     
     while (targetNode == attackerNode)
     {
         targetNode = m_nodeDist(gen);
     }
     
     // Routing attacks affect network topology
     if (m_probDist(gen) > 0.4) // 60% detection rate
     {
         HandleThreatDetection(attackerNode, targetNode, ROUTING_ATTACK);
     }
     
     // Schedule next threat
     std::uniform_real_distribution<> timeDist(5.0, 20.0);
     Time nextTime = Seconds(timeDist(gen));
     Simulator::Schedule(nextTime, &ThreatSimulator::StartThreatGeneration, this);
 }
 
 // MTD Engine
 class MTDEngine
 {
 public:
     MTDEngine();
     void ProcessThreat(uint32_t sourceNode, uint32_t targetNode, ThreatType threat);
     void ExecuteFrequencyHopping(uint32_t nodeId);
     void ExecuteRouteMutation(uint32_t nodeId);
     void ExecuteIdentityRotation(uint32_t nodeId);
     void ExecutePowerAdjustment(uint32_t nodeId);
     void ExecuteTopologyShuffle();
     void ExecuteChannelSwitching(uint32_t nodeId);
 
 private:
     std::map<ThreatType, std::vector<MTDActionType>> m_threatToMTDMap;
     std::uniform_real_distribution<> m_probDist;
     std::uniform_int_distribution<> m_actionDist;
 };
 
 MTDEngine::MTDEngine()
     : m_probDist(0.0, 1.0),
       m_actionDist(0, 5)
 {
     // Map threats to appropriate MTD actions
     m_threatToMTDMap[JAMMING] = {FREQUENCY_HOPPING, CHANNEL_SWITCHING, POWER_ADJUSTMENT};
     m_threatToMTDMap[SPOOFING] = {IDENTITY_ROTATION, ROUTE_MUTATION};
     m_threatToMTDMap[DOS] = {ROUTE_MUTATION, TOPOLOGY_SHUFFLE, POWER_ADJUSTMENT};
     m_threatToMTDMap[EAVESDROPPING] = {FREQUENCY_HOPPING, CHANNEL_SWITCHING, IDENTITY_ROTATION};
     m_threatToMTDMap[MITM] = {ROUTE_MUTATION, IDENTITY_ROTATION, TOPOLOGY_SHUFFLE};
     m_threatToMTDMap[ROUTING_ATTACK] = {ROUTE_MUTATION, TOPOLOGY_SHUFFLE};
 }
 
 void
 MTDEngine::ProcessThreat(uint32_t sourceNode, uint32_t targetNode, ThreatType threat)
 {
     if (!enableMTD) return;
     
     // Select appropriate MTD action based on threat type
     std::vector<MTDActionType> possibleActions = m_threatToMTDMap[threat];
     if (possibleActions.empty()) return;
     
     std::uniform_int_distribution<> actionSelect(0, possibleActions.size() - 1);
     MTDActionType selectedAction = possibleActions[actionSelect(gen)];
     
     // Execute MTD action with some probability
     if (m_probDist(gen) < 0.8) // 80% MTD activation rate
     {
         ExecuteMTDAction(targetNode, selectedAction);
     }
 }
 
 void
 MTDEngine::ExecuteFrequencyHopping(uint32_t nodeId)
 {
     // Simulate frequency hopping
     std::uniform_real_distribution<> freqDist(2.4, 2.5);
     double newFreq = freqDist(gen);
     
     std::cout << "MTD_ACTION:frequency_hopping:" << nodeId << ":0.8:0.1" << std::endl;
     
     // Log to Python bridge
     SendToPythonBridge("MTD_ACTION:frequency_hopping:" + std::to_string(nodeId) + ":0.8:0.1");
 }
 
 void
 MTDEngine::ExecuteRouteMutation(uint32_t nodeId)
 {
     // Simulate route mutation
     std::cout << "MTD_ACTION:route_mutation:" << nodeId << ":0.7:0.15" << std::endl;
     
     SendToPythonBridge("MTD_ACTION:route_mutation:" + std::to_string(nodeId) + ":0.7:0.15");
 }
 
 void
 MTDEngine::ExecuteIdentityRotation(uint32_t nodeId)
 {
     // Simulate identity rotation
     std::cout << "MTD_ACTION:identity_rotation:" << nodeId << ":0.9:0.05" << std::endl;
     
     SendToPythonBridge("MTD_ACTION:identity_rotation:" + std::to_string(nodeId) + ":0.9:0.05");
 }
 
 void
 MTDEngine::ExecutePowerAdjustment(uint32_t nodeId)
 {
     // Simulate power adjustment
     std::uniform_real_distribution<> powerDist(0.5, 1.5);
     double powerFactor = powerDist(gen);
     
     std::cout << "MTD_ACTION:power_adjustment:" << nodeId << ":0.6:0.2" << std::endl;
     
     SendToPythonBridge("MTD_ACTION:power_adjustment:" + std::to_string(nodeId) + ":0.6:0.2");
 }
 
 void
 MTDEngine::ExecuteTopologyShuffle()
 {
     // Simulate topology shuffle affecting multiple nodes
     std::string nodeList = "";
     for (uint32_t i = 0; i < std::min(5u, static_cast<uint32_t>(allNodes.GetN())); ++i)
     {
         if (i > 0) nodeList += ",";
         nodeList += std::to_string(i);
     }
     
     std::cout << "MTD_ACTION:topology_shuffle:" << nodeList << ":0.75:0.3" << std::endl;
     
     SendToPythonBridge("MTD_ACTION:topology_shuffle:" + nodeList + ":0.75:0.3");
 }
 
 void
 MTDEngine::ExecuteChannelSwitching(uint32_t nodeId)
 {
     // Simulate channel switching
     std::cout << "MTD_ACTION:channel_switching:" << nodeId << ":0.8:0.1" << std::endl;
     
     SendToPythonBridge("MTD_ACTION:channel_switching:" + std::to_string(nodeId) + ":0.8:0.1");
 }
 
 // Global instances
 ThreatSimulator* g_threatSimulator = nullptr;
 MTDEngine* g_mtdEngine = nullptr;
 
 void
 HandleThreatDetection(uint32_t sourceNode, uint32_t targetNode, ThreatType threat)
 {
     // Log threat detection
     std::string threatTypeStr;
     switch (threat) {
         case JAMMING: threatTypeStr = "jamming"; break;
         case SPOOFING: threatTypeStr = "spoofing"; break;
         case DOS: threatTypeStr = "dos"; break;
         case EAVESDROPPING: threatTypeStr = "eavesdropping"; break;
         case MITM: threatTypeStr = "mitm"; break;
         case ROUTING_ATTACK: threatTypeStr = "routing_attack"; break;
         default: threatTypeStr = "unknown"; break;
     }
     
     std::cout << "THREAT_DETECTED:" << threatTypeStr << ":" << sourceNode << ":" 
               << targetNode << ":0.7" << std::endl;
     
     // Store threat
     detectedThreats.push_back({sourceNode, threat});
     
     // Send to Python bridge
     SendToPythonBridge("THREAT_DETECTED:" + threatTypeStr + ":" + 
                       std::to_string(sourceNode) + ":" + std::to_string(targetNode) + ":0.7");
     
     // Trigger MTD response
     if (g_mtdEngine != nullptr)
     {
         g_mtdEngine->ProcessThreat(sourceNode, targetNode, threat);
     }
 }
 
 void
 ExecuteMTDAction(uint32_t targetNode, MTDActionType action)
 {
     if (g_mtdEngine == nullptr) return;
     
     switch (action)
     {
         case FREQUENCY_HOPPING:
             g_mtdEngine->ExecuteFrequencyHopping(targetNode);
             break;
         case ROUTE_MUTATION:
             g_mtdEngine->ExecuteRouteMutation(targetNode);
             break;
         case IDENTITY_ROTATION:
             g_mtdEngine->ExecuteIdentityRotation(targetNode);
             break;
         case POWER_ADJUSTMENT:
             g_mtdEngine->ExecutePowerAdjustment(targetNode);
             break;
         case TOPOLOGY_SHUFFLE:
             g_mtdEngine->ExecuteTopologyShuffle();
             break;
         case CHANNEL_SWITCHING:
             g_mtdEngine->ExecuteChannelSwitching(targetNode);
             break;
     }
     
     executedMTDActions.push_back({targetNode, action});
 }
 
 bool
 InitializeBridgeCommunication()
 {
     bridgeSocket = socket(AF_INET, SOCK_STREAM, 0);
     if (bridgeSocket < 0)
     {
         NS_LOG_ERROR("Failed to create bridge socket");
         return false;
     }
     
     bridgeAddr.sin_family = AF_INET;
     bridgeAddr.sin_port = htons(9999);
     bridgeAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
     
     // Try to connect to Python bridge
     if (connect(bridgeSocket, (struct sockaddr*)&bridgeAddr, sizeof(bridgeAddr)) < 0)
     {
         NS_LOG_WARN("Could not connect to Python bridge - running standalone");
         close(bridgeSocket);
         bridgeSocket = -1;
         return false;
     }
     
     NS_LOG_INFO("Connected to Python bridge");
     return true;
 }
 
 void
 SendToPythonBridge(const std::string& message)
 {
     if (bridgeSocket < 0) return;
     
     send(bridgeSocket, message.c_str(), message.length(), 0);
 }
 
 void
 SetupTopology()
 {
     // Create nodes
     droneNodes.Create(nDrones);
     honeypotNodes.Create(nHoneypots);
     gcsNodes.Create(nGCS);
     relayNodes.Create(nRelays);
     attackerNodes.Create(nAttackers);
     
     // Combine all nodes
     allNodes.Add(droneNodes);
     allNodes.Add(honeypotNodes);
     allNodes.Add(gcsNodes);
     allNodes.Add(relayNodes);
     allNodes.Add(attackerNodes);
     
     // Initialize node types and states
     for (uint32_t i = 0; i < nDrones; ++i)
     {
         nodeTypes[i] = REAL_DRONE;
         compromisedNodes[i] = false;
         nodeEnergyLevels[i] = 1.0;
     }
     
     for (uint32_t i = 0; i < nHoneypots; ++i)
     {
         uint32_t nodeId = nDrones + i;
         nodeTypes[nodeId] = HONEYPOT;
         compromisedNodes[nodeId] = false;
         nodeEnergyLevels[nodeId] = 1.0;
     }
     
     for (uint32_t i = 0; i < nGCS; ++i)
     {
         uint32_t nodeId = nDrones + nHoneypots + i;
         nodeTypes[nodeId] = GCS;
         compromisedNodes[nodeId] = false;
         nodeEnergyLevels[nodeId] = 1.0;
     }
     
     for (uint32_t i = 0; i < nRelays; ++i)
     {
         uint32_t nodeId = nDrones + nHoneypots + nGCS + i;
         nodeTypes[nodeId] = RELAY;
         compromisedNodes[nodeId] = false;
         nodeEnergyLevels[nodeId] = 1.0;
     }
     
     for (uint32_t i = 0; i < nAttackers; ++i)
     {
         uint32_t nodeId = nDrones + nHoneypots + nGCS + nRelays + i;
         nodeTypes[nodeId] = ATTACKER;
         compromisedNodes[nodeId] = false;
         nodeEnergyLevels[nodeId] = 1.0;
     }
 }
 
 void
 SetupMobility()
 {
     MobilityHelper mobility;
     
     // Setup mobility for drones (3D random walk)
     mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds", RectangleValue(Rectangle(-500, 500, -500, 500)),
                              "Speed", StringValue("ns3::UniformRandomVariable[Min=5.0|Max=15.0]"),
                              "Direction", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=6.28]"));
     
     // Set initial positions for drones
     mobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Z", StringValue("ns3::UniformRandomVariable[Min=50.0|Max=150.0]"));
     mobility.Install(droneNodes);
     
     // Honeypots - similar mobility to drones but different patterns
     mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds", RectangleValue(Rectangle(-500, 500, -500, 500)),
                              "Speed", StringValue("ns3::UniformRandomVariable[Min=3.0|Max=12.0]"),
                              "Direction", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=6.28]"));
     mobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Z", StringValue("ns3::UniformRandomVariable[Min=40.0|Max=160.0]"));
     mobility.Install(honeypotNodes);
     
     // GCS - stationary ground stations
     mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
     mobility.SetPositionAllocator("ns3::ListPositionAllocator");
     Ptr<ListPositionAllocator> gcsPositionAlloc = DynamicCast<ListPositionAllocator>(mobility.GetPositionAllocator());
     gcsPositionAlloc->Add(Vector(500.0, 500.0, 10.0)); // Central GCS
     mobility.Install(gcsNodes);
     
     // Relay nodes - semi-stationary at strategic positions
     mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
     mobility.SetPositionAllocator("ns3::ListPositionAllocator");
     Ptr<ListPositionAllocator> relayPositionAlloc = DynamicCast<ListPositionAllocator>(mobility.GetPositionAllocator());
     relayPositionAlloc->Add(Vector(200.0, 200.0, 100.0));
     relayPositionAlloc->Add(Vector(800.0, 800.0, 100.0));
     mobility.Install(relayNodes);
     
     // Attackers - aggressive mobility patterns
     mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds", RectangleValue(Rectangle(-500, 500, -500, 500)),
                              "Speed", StringValue("ns3::UniformRandomVariable[Min=10.0|Max=20.0]"),
                              "Direction", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=6.28]"));
     mobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Z", StringValue("ns3::UniformRandomVariable[Min=30.0|Max=180.0]"));
     mobility.Install(attackerNodes);
 }
 
 void
 SetupWireless()
 {
     // WiFi setup for FANET communication
     WifiHelper wifi;
     wifi.SetStandard(WIFI_STANDARD_80211n);
     wifi.SetRemoteStationManager("ns3::AarfWifiManager");
     
     // WiFi PHY setup
     YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
     channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
     channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
     channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
     
     YansWifiPhyHelper phy;
     phy.SetChannel(channel.Create());
     phy.Set("TxPowerStart", DoubleValue(20.0));
     phy.Set("TxPowerEnd", DoubleValue(20.0));
     phy.Set("TxGain", DoubleValue(3.0));
     phy.Set("RxGain", DoubleValue(3.0));
     phy.Set("RxSensitivity", DoubleValue(-85.0));
     
     // WiFi MAC setup
     WifiMacHelper mac;
     Ssid ssid = Ssid("FANET-Network");
     mac.SetType("ns3::AdhocWifiMac",
                 "Ssid", SsidValue(ssid));
     
     // Install WiFi on all nodes
     devices = wifi.Install(phy, mac, allNodes);
     
     // Internet stack
     InternetStackHelper stack;
     stack.Install(allNodes);
     
     // IP addresses
     Ipv4AddressHelper address;
     address.SetBase("10.1.1.0", "255.255.255.0");
     interfaces = address.Assign(devices);
 }
 
 void
 SetupApplications()
 {
     // Setup FANET communication applications
     uint16_t port = 9;
     
     // Install applications on all nodes
     for (uint32_t i = 0; i < allNodes.GetN(); ++i)
     {
         Ptr<Node> node = allNodes.Get(i);
         NodeType nodeType = nodeTypes[i];
         
         // Create socket
         TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
         Ptr<Socket> socket = Socket::CreateSocket(node, tid);
         
         // Setup application
         Ptr<FANETApplication> app = CreateObject<FANETApplication>();
         
         // Different communication patterns for different node types
         uint32_t packetSize = 1024;
         uint32_t maxPackets = 1000000;
         DataRate dataRate("500kb/s");
         
         if (nodeType == GCS)
         {
             // GCS communicates with higher frequency
             dataRate = DataRate("1Mb/s");
             packetSize = 2048;
         }
         else if (nodeType == HONEYPOT)
         {
             // Honeypots have distinctive communication patterns
             dataRate = DataRate("250kb/s");
             packetSize = 512;
         }
         else if (nodeType == ATTACKER)
         {
             // Attackers may have aggressive communication
             dataRate = DataRate("2Mb/s");
             packetSize = 4096;
         }
         
         // Set destination (broadcast for simplicity)
         InetSocketAddress remote = InetSocketAddress(Ipv4Address("255.255.255.255"), port);
         
         app->Setup(socket, remote, packetSize, maxPackets, dataRate, nodeType);
         node->AddApplication(app);
         
         // Stagger start times
         double startTime = 1.0 + i * 0.1;
         app->SetStartTime(Seconds(startTime));
         app->SetStopTime(Seconds(simTime));
     }
 }
 
 void
 SetupEnergyModel()
 {
     // Basic energy source for all nodes
     BasicEnergySourceHelper basicSourceHelper;
     basicSourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(1000.0));
     basicSourceHelper.Set("BasicEnergySupplyVoltageV", DoubleValue(3.3));
     
     EnergySourceContainer sources = basicSourceHelper.Install(allNodes);
     
     // WiFi radio energy model
     WifiRadioEnergyModelHelper radioEnergyHelper;
     radioEnergyHelper.Set("TxCurrentA", DoubleValue(0.0174));
     radioEnergyHelper.Set("RxCurrentA", DoubleValue(0.0197));
     radioEnergyHelper.Set("IdleCurrentA", DoubleValue(0.0));
     radioEnergyHelper.Set("SleepCurrentA", DoubleValue(0.0));
     
     DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install(devices, sources);
     
     // Energy depletion callback
     for (uint32_t i = 0; i < sources.GetN(); ++i)
     {
         Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource>(sources.Get(i));
         basicSourcePtr->TraceConnectWithoutContext("RemainingEnergy", 
             MakeBoundCallback(&MonitorEnergyDepletion, i));
     }
 }
 
 void
 MonitorEnergyDepletion(uint32_t nodeId, double oldValue, double newValue)
 {
     nodeEnergyLevels[nodeId] = newValue / 1000.0; // Normalize to 0-1 range
     
     // Check for low energy
     if (newValue < 100.0) // Less than 10% energy
     {
         std::cout << "LOW_ENERGY:" << nodeId << ":" << newValue << std::endl;
         SendToPythonBridge("LOW_ENERGY:" + std::to_string(nodeId) + ":" + std::to_string(newValue));
     }
     
     // Node is depleted
     if (newValue <= 0.0)
     {
         std::cout << "NODE_DEPLETED:" << nodeId << std::endl;
         SendToPythonBridge("NODE_DEPLETED:" + std::to_string(nodeId));
         
         // Stop applications on depleted node
         Ptr<Node> node = allNodes.Get(nodeId);
         for (uint32_t i = 0; i < node->GetNApplications(); ++i)
         {
             Ptr<Application> app = node->GetApplication(i);
             app->SetStopTime(Simulator::Now());
         }
     }
 }
 
 void
 SetupFlowMonitor()
 {
     FlowMonitorHelper flowmon;
     Ptr<FlowMonitor> monitor = flowmon.InstallAll();
     
     // Schedule periodic flow monitoring
     Simulator::Schedule(Seconds(10.0), &PrintFlowStatistics, monitor);
 }
 
 void
 PrintFlowStatistics(Ptr<FlowMonitor> monitor)
 {
     monitor->CheckForLostPackets();
     
     Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(
         flowmon.GetClassifier());
     
     FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
     
     uint32_t totalPacketsSent = 0;
     uint32_t totalPacketsReceived = 0;
     double totalThroughput = 0.0;
     
     for (auto i = stats.begin(); i != stats.end(); ++i)
     {
         totalPacketsSent += i->second.txPackets;
         totalPacketsReceived += i->second.rxPackets;
         totalThroughput += (i->second.rxBytes * 8.0) / (simTime * 1000); // kbps
     }
     
     double packetDeliveryRatio = 0.0;
     if (totalPacketsSent > 0)
     {
         packetDeliveryRatio = (double)totalPacketsReceived / totalPacketsSent * 100.0;
     }
     
     std::cout << "FLOW_STATS:" << totalPacketsSent << ":" << totalPacketsReceived 
               << ":" << packetDeliveryRatio << ":" << totalThroughput << std::endl;
     
     SendToPythonBridge("FLOW_STATS:" + std::to_string(totalPacketsSent) + ":" +
                       std::to_string(totalPacketsReceived) + ":" +
                       std::to_string(packetDeliveryRatio) + ":" +
                       std::to_string(totalThroughput));
     
     // Schedule next monitoring
     if (Simulator::Now().GetSeconds() < simTime - 10.0)
     {
         Simulator::Schedule(Seconds(10.0), &PrintFlowStatistics, monitor);
     }
 }
 
 void
 MonitorNetwork()
 {
     // Periodic network monitoring
     std::uniform_real_distribution<> probDist(0.0, 1.0);
     
     // Check for network anomalies
     for (uint32_t i = 0; i < allNodes.GetN(); ++i)
     {
         // Simulate random node compromise
         if (!compromisedNodes[i] && probDist(gen) < 0.001) // 0.1% chance per monitoring cycle
         {
             compromisedNodes[i] = true;
             std::cout << "NODE_COMPROMISED:" << i << std::endl;
             SendToPythonBridge("NODE_COMPROMISED:" + std::to_string(i));
         }
         
         // Energy depletion simulation
         if (nodeEnergyLevels[i] > 0)
         {
             nodeEnergyLevels[i] -= 0.0001; // Small energy drain
             if (nodeEnergyLevels[i] < 0) nodeEnergyLevels[i] = 0;
         }
     }
     
     // Schedule next monitoring
     if (Simulator::Now().GetSeconds() < simTime - 5.0)
     {
         Simulator::Schedule(Seconds(5.0), &MonitorNetwork, this);
     }
 }
 
 void
 ExportResults()
 {
     std::ofstream resultsStream(resultsFile);
     if (!resultsStream.is_open())
     {
         NS_LOG_ERROR("Cannot open results file: " << resultsFile);
         return;
     }
     
     // Create JSON results
     resultsStream << "{\n";
     resultsStream << "  \"metadata\": {\n";
     resultsStream << "    \"simulation_time\": " << simTime << ",\n";
     resultsStream << "    \"total_nodes\": " << allNodes.GetN() << ",\n";
     resultsStream << "    \"drones\": " << nDrones << ",\n";
     resultsStream << "    \"honeypots\": " << nHoneypots << ",\n";
     resultsStream << "    \"gcs\": " << nGCS << ",\n";
     resultsStream << "    \"relays\": " << nRelays << ",\n";
     resultsStream << "    \"attackers\": " << nAttackers << ",\n";
     resultsStream << "    \"attack_scenario\": \"" << attackScenario << "\",\n";
     resultsStream << "    \"mtd_enabled\": " << (enableMTD ? "true" : "false") << "\n";
     resultsStream << "  },\n";
     
     // Export node information
     resultsStream << "  \"nodes\": [\n";
     for (uint32_t i = 0; i < allNodes.GetN(); ++i)
     {
         Ptr<Node> node = allNodes.Get(i);
         Vector pos = node->GetObject<MobilityModel>()->GetPosition();
         
         if (i > 0) resultsStream << ",\n";
         
         resultsStream << "    {\n";
         resultsStream << "      \"id\": " << i << ",\n";
         resultsStream << "      \"type\": \"";
         
         switch (nodeTypes[i])
         {
             case REAL_DRONE: resultsStream << "real_drone"; break;
             case HONEYPOT: resultsStream << "honeypot"; break;
             case GCS: resultsStream << "gcs"; break;
             case RELAY: resultsStream << "relay"; break;
             case ATTACKER: resultsStream << "attacker"; break;
         }
         
         resultsStream << "\",\n";
         resultsStream << "      \"position\": [" << pos.x << ", " << pos.y << ", " << pos.z << "],\n";
         resultsStream << "      \"energy_level\": " << nodeEnergyLevels[i] << ",\n";
         resultsStream << "      \"is_compromised\": " << (compromisedNodes[i] ? "true" : "false") << "\n";
         resultsStream << "    }";
     }
     resultsStream << "\n  ],\n";
     
     // Export detected threats
     resultsStream << "  \"threats\": [\n";
     for (size_t i = 0; i < detectedThreats.size(); ++i)
     {
         if (i > 0) resultsStream << ",\n";
         
         resultsStream << "    {\n";
         resultsStream << "      \"id\": \"threat_" << i << "\",\n";
         resultsStream << "      \"source_node\": " << detectedThreats[i].first << ",\n";
         resultsStream << "      \"type\": \"";
         
         switch (detectedThreats[i].second)
         {
             case JAMMING: resultsStream << "jamming"; break;
             case SPOOFING: resultsStream << "spoofing"; break;
             case DOS: resultsStream << "dos"; break;
             case EAVESDROPPING: resultsStream << "eavesdropping"; break;
             case MITM: resultsStream << "mitm"; break;
             case ROUTING_ATTACK: resultsStream << "routing_attack"; break;
             default: resultsStream << "unknown"; break;
         }
         
         resultsStream << "\",\n";
         resultsStream << "      \"severity\": 0.7,\n";
         resultsStream << "      \"detected\": true\n";
         resultsStream << "    }";
     }
     resultsStream << "\n  ],\n";
     
     // Export MTD actions
     resultsStream << "  \"mtd_actions\": [\n";
     for (size_t i = 0; i < executedMTDActions.size(); ++i)
     {
         if (i > 0) resultsStream << ",\n";
         
         resultsStream << "    {\n";
         resultsStream << "      \"id\": \"mtd_" << i << "\",\n";
         resultsStream << "      \"target_node\": " << executedMTDActions[i].first << ",\n";
         resultsStream << "      \"action\": \"";
         
         switch (executedMTDActions[i].second)
         {
             case FREQUENCY_HOPPING: resultsStream << "frequency_hopping"; break;
             case ROUTE_MUTATION: resultsStream << "route_mutation"; break;
             case IDENTITY_ROTATION: resultsStream << "identity_rotation"; break;
             case POWER_ADJUSTMENT: resultsStream << "power_adjustment"; break;
             case TOPOLOGY_SHUFFLE: resultsStream << "topology_shuffle"; break;
             case CHANNEL_SWITCHING: resultsStream << "channel_switching"; break;
         }
         
         resultsStream << "\",\n";
         resultsStream << "      \"effectiveness\": 0.8,\n";
         resultsStream << "      \"cost\": 0.1,\n";
         resultsStream << "      \"success\": true\n";
         resultsStream << "    }";
     }
     resultsStream << "\n  ]\n";
     
     resultsStream << "}\n";
     resultsStream.close();
     
     std::cout << "RESULTS_EXPORTED:" << resultsFile << std::endl;
     SendToPythonBridge("RESULTS_EXPORTED:" + resultsFile);
 }
 
 int
 main(int argc, char *argv[])
 {
     // Enable logging
     LogComponentEnable("FANETHoneydroneSimulation", LOG_LEVEL_INFO);
     
     // Command line arguments
     CommandLine cmd;
     cmd.AddValue("nDrones", "Number of drone nodes", nDrones);
     cmd.AddValue("nHoneypots", "Number of honeypot nodes", nHoneypots);
     cmd.AddValue("nGCS", "Number of GCS nodes", nGCS);
     cmd.AddValue("nRelays", "Number of relay nodes", nRelays);
     cmd.AddValue("nAttackers", "Number of attacker nodes", nAttackers);
     cmd.AddValue("simTime", "Simulation time in seconds", simTime);
     cmd.AddValue("attackScenario", "Attack scenario type", attackScenario);
     cmd.AddValue("enableMTD", "Enable MTD responses", enableMTD);
     cmd.AddValue("resultsFile", "Results output file", resultsFile);
     cmd.AddValue("traceFile", "Trace database file", traceFile);
     cmd.AddValue("animationFile", "Animation XML file", animationFile);
     
     cmd.Parse(argc, argv);
     
     // Initialize communication with Python bridge
     InitializeBridgeCommunication();
     
     NS_LOG_INFO("Starting FANET Honeydrone Simulation");
     NS_LOG_INFO("Drones: " << nDrones << ", Honeypots: " << nHoneypots);
     NS_LOG_INFO("Attack Scenario: " << attackScenario << ", MTD: " << (enableMTD ? "Enabled" : "Disabled"));
     
     // Setup simulation
     SetupTopology();
     SetupMobility();
     SetupWireless();
     SetupApplications();
     SetupEnergyModel();
     SetupFlowMonitor();
     
     // Initialize threat simulator and MTD engine
     g_threatSimulator = new ThreatSimulator();
     g_mtdEngine = new MTDEngine();
     
     // Start threat generation
     Simulator::Schedule(Seconds(30.0), &ThreatSimulator::StartThreatGeneration, g_threatSimulator);
     
     // Start network monitoring
     Simulator::Schedule(Seconds(5.0), &MonitorNetwork);
     
     // Setup animation
     AnimationInterface anim(animationFile);
     anim.SetMaxPktsPerTraceFile(500000);
     
     // Set node descriptions for animation
     for (uint32_t i = 0; i < allNodes.GetN(); ++i)
     {
         std::string nodeDesc;
         switch (nodeTypes[i])
         {
             case REAL_DRONE: nodeDesc = "Drone"; break;
             case HONEYPOT: nodeDesc = "Honeypot"; break;
             case GCS: nodeDesc = "GCS"; break;
             case RELAY: nodeDesc = "Relay"; break;
             case ATTACKER: nodeDesc = "Attacker"; break;
         }
         anim.UpdateNodeDescription(allNodes.Get(i), nodeDesc);
     }
     
     // Schedule result export before simulation ends
     Simulator::Schedule(Seconds(simTime - 1.0), &ExportResults);
     
     // Phase change notifications
     Simulator::Schedule(Seconds(1.0), []() {
         std::cout << "PHASE_CHANGE:normal_operation" << std::endl;
         SendToPythonBridge("PHASE_CHANGE:normal_operation");
     });
     
     Simulator::Schedule(Seconds(30.0), []() {
         std::cout << "PHASE_CHANGE:under_attack" << std::endl;
         SendToPythonBridge("PHASE_CHANGE:under_attack");
     });
     
     if (enableMTD)
     {
         Simulator::Schedule(Seconds(60.0), []() {
             std::cout << "PHASE_CHANGE:mtd_active" << std::endl;
             SendToPythonBridge("PHASE_CHANGE:mtd_active");
         });
     }
     
     // Run simulation
     Simulator::Stop(Seconds(simTime));
     
     std::cout << "SIMULATION_STARTING" << std::endl;
     SendToPythonBridge("SIMULATION_STARTING");
     
     Simulator::Run();
     
     std::cout << "SIMULATION_COMPLETED" << std::endl;
     SendToPythonBridge("SIMULATION_COMPLETED");
     
     // Cleanup
     if (bridgeSocket >= 0)
     {
         close(bridgeSocket);
     }
     
     delete g_threatSimulator;
     delete g_mtdEngine;
     
     Simulator::Destroy();
     
     NS_LOG_INFO("Simulation completed successfully");
     return 0;
 }