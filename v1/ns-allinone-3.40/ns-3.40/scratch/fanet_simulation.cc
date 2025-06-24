/*
 * FANET Drone Network Simulation for NS-3
 * 
 * This script simulates a Flying Ad-hoc Network (FANET) with multiple drone nodes,
 * implementing various routing protocols and attack scenarios for honeydrone research.
 * 
 * Features:
 * - Multiple drone types (Virtual, Dummy, Real)
 * - AODV/OLSR routing protocols
 * - Mobility models for realistic drone movement
 * - Attack packet injection capabilities
 * - Real-time packet analysis and logging
 * - Animation output for visualization
 * - Socket communication with Python bridge
 */

 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/wifi-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/aodv-module.h"
 #include "ns3/olsr-module.h"
 #include "ns3/applications-module.h"
 #include "ns3/flow-monitor-module.h"
 #include "ns3/netanim-module.h"
 #include "ns3/config-store-module.h"
 #include "ns3/point-to-point-module.h"
 
 #include <iostream>
 #include <fstream>
 #include <vector>
 #include <string>
 #include <map>
 #include <thread>
 #include <mutex>
 #include <queue>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <unistd.h>
 #include <ctime>
 #include <random>
 
 using namespace ns3;
 using namespace std;
 
 NS_LOG_COMPONENT_DEFINE ("FANETDroneSimulation");
 
 // Global variables for simulation configuration
 uint32_t nNodes = 10;           // Number of drone nodes
 double simTime = 300.0;         // Simulation time in seconds
 string routingProtocol = "AODV"; // Routing protocol
 string outputDir = "ns3_output"; // Output directory
 uint32_t socketPort = 9999;     // Socket port for Python communication
 bool enableAnimation = true;     // Enable NetAnim output
 bool enablePcap = true;          // Enable PCAP output
 
 // Drone types
 enum DroneType {
     VIRTUAL_DRONE = 0,
     DUMMY_DRONE = 1,
     REAL_DRONE = 2
 };
 
 // Drone node information
 struct DroneNode {
     uint32_t nodeId;
     DroneType type;
     Vector3D position;
     Vector3D velocity;
     string droneId;
     double vulnerabilityLevel;
     bool isCompromised;
     uint32_t attackCount;
 };
 
 // Attack packet information
 struct AttackPacket {
     uint32_t packetId;
     uint32_t sourceNode;
     uint32_t destNode;
     string attackType;
     uint32_t size;
     double timestamp;
     bool isDetected;
 };
 
 // Global containers
 vector<DroneNode> droneNodes;
 map<uint32_t, Ptr<Node>> nodeMap;
 queue<AttackPacket> attackQueue;
 mutex attackQueueMutex;
 
 // Socket communication variables
 int serverSocket = -1;
 vector<int> clientSockets;
 mutex socketMutex;
 
 // Statistics
 uint32_t totalPackets = 0;
 uint32_t attackPackets = 0;
 uint32_t droppedPackets = 0;
 double totalLatency = 0.0;
 
 // Function declarations
 void SetupSimulation(int argc, char *argv[]);
 void CreateNodes();
 void SetupMobility();
 void SetupWifi();
 void SetupRouting();
 void SetupApplications();
 void SetupMonitoring();
 void StartSocketServer();
 void HandleSocketCommunication();
 void SendPacketToClients(const string& data);
 void InjectAttackPacket(uint32_t source, uint32_t dest, const string& attackType);
 void PacketSentTrace(Ptr<const Packet> packet, const Address& from, const Address& to);
 void PacketReceivedTrace(Ptr<const Packet> packet, const Address& from);
 void PhyTxTrace(Ptr<const Packet> packet);
 void PhyRxTrace(Ptr<const Packet> packet);
 void GenerateStatistics();
 void CleanupAndExit();
 
 /**
  * Parse command line arguments and configure simulation
  */
 void SetupSimulation(int argc, char *argv[]) {
     CommandLine cmd;
     cmd.AddValue("nNodes", "Number of drone nodes", nNodes);
     cmd.AddValue("simTime", "Simulation time in seconds", simTime);
     cmd.AddValue("protocol", "Routing protocol (AODV/OLSR)", routingProtocol);
     cmd.AddValue("outputDir", "Output directory", outputDir);
     cmd.AddValue("socketPort", "Socket port for communication", socketPort);
     cmd.AddValue("animation", "Enable animation output", enableAnimation);
     cmd.AddValue("pcap", "Enable PCAP output", enablePcap);
     
     cmd.Parse(argc, argv);
     
     NS_LOG_INFO("FANET Simulation Configuration:");
     NS_LOG_INFO("  Nodes: " << nNodes);
     NS_LOG_INFO("  Simulation Time: " << simTime << "s");
     NS_LOG_INFO("  Routing Protocol: " << routingProtocol);
     NS_LOG_INFO("  Output Directory: " << outputDir);
     NS_LOG_INFO("  Socket Port: " << socketPort);
     
     // Create output directory
     system(("mkdir -p " + outputDir).c_str());
 }
 
 /**
  * Create drone nodes with different types and characteristics
  */
 void CreateNodes() {
     NS_LOG_INFO("Creating " << nNodes << " drone nodes...");
     
     NodeContainer nodes;
     nodes.Create(nNodes);
     
     // Initialize drone nodes with different characteristics
     random_device rd;
     mt19937 gen(rd());
     uniform_real_distribution<> typeDist(0.0, 1.0);
     uniform_real_distribution<> vulnDist(0.1, 0.9);
     
     for (uint32_t i = 0; i < nNodes; ++i) {
         DroneNode drone;
         drone.nodeId = i;
         drone.droneId = "drone_" + to_string(i);
         drone.isCompromised = false;
         drone.attackCount = 0;
         
         // Assign drone type based on probability
         double typeProb = typeDist(gen);
         if (typeProb < 0.5) {
             drone.type = VIRTUAL_DRONE;
             drone.vulnerabilityLevel = vulnDist(gen) * 0.5; // Lower vulnerability
         } else if (typeProb < 0.8) {
             drone.type = DUMMY_DRONE;
             drone.vulnerabilityLevel = vulnDist(gen) * 0.8 + 0.2; // Higher vulnerability
         } else {
             drone.type = REAL_DRONE;
             drone.vulnerabilityLevel = vulnDist(gen) * 0.3; // Very low vulnerability
         }
         
         // Set initial position (distributed in 3D space)
         uniform_real_distribution<> posDist(0.0, 1000.0);
         uniform_real_distribution<> altDist(50.0, 200.0);
         
         drone.position.x = posDist(gen);
         drone.position.y = posDist(gen);
         drone.position.z = altDist(gen);
         
         droneNodes.push_back(drone);
         nodeMap[i] = nodes.Get(i);
         
         NS_LOG_DEBUG("Created drone " << i << " type=" << drone.type 
                     << " vuln=" << drone.vulnerabilityLevel 
                     << " pos=(" << drone.position.x << "," << drone.position.y << "," << drone.position.z << ")");
     }
 }
 
 /**
  * Setup mobility models for realistic drone movement
  */
 void SetupMobility() {
     NS_LOG_INFO("Setting up mobility models...");
     
     MobilityHelper mobility;
     
     // Position allocator for initial positions
     Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
     
     for (const auto& drone : droneNodes) {
         positionAlloc->Add(Vector(drone.position.x, drone.position.y, drone.position.z));
     }
     
     mobility.SetPositionAllocator(positionAlloc);
     
     // Different mobility models for different drone types
     for (uint32_t i = 0; i < nNodes; ++i) {
         Ptr<Node> node = nodeMap[i];
         
         switch (droneNodes[i].type) {
             case VIRTUAL_DRONE:
                 // Random waypoint mobility for virtual drones
                 mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                                         "Bounds", RectangleValue(Rectangle(0, 1000, 0, 1000)),
                                         "Speed", StringValue("ns3::ConstantRandomVariable[Constant=5.0]"),
                                         "Distance", DoubleValue(50.0));
                 break;
                 
             case DUMMY_DRONE:
                 // More predictable movement for dummy drones (easier targets)
                 mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
                 break;
                 
             case REAL_DRONE:
                 // Mission-oriented movement for real drones
                 mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
                                         "Bounds", BoxValue(Box(0, 1000, 0, 1000, 50, 200)),
                                         "TimeStep", TimeValue(Seconds(2.0)),
                                         "Alpha", DoubleValue(0.85),
                                         "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=2|Max=8]"));
                 break;
         }
         
         NodeContainer singleNode(node);
         mobility.Install(singleNode);
     }
 }
 
 /**
  * Setup WiFi network with appropriate parameters for drone communication
  */
 void SetupWifi() {
     NS_LOG_INFO("Setting up WiFi network...");
     
     // WiFi helper
     WifiHelper wifi;
     wifi.SetStandard(WIFI_PHY_STANDARD_80211n_2_4GHZ);
     
     // WiFi MAC and PHY configuration
     WifiMacHelper mac;
     mac.SetType("ns3::AdhocWifiMac");
     
     YansWifiPhyHelper phy = YansWifiPhyHelper::Default();
     phy.Set("TxPowerStart", DoubleValue(20.0)); // 20 dBm
     phy.Set("TxPowerEnd", DoubleValue(20.0));
     phy.Set("TxGain", DoubleValue(0.0));
     phy.Set("RxGain", DoubleValue(0.0));
     phy.Set("RxNoiseFigure", DoubleValue(7.0));
     
     // Channel configuration
     YansWifiChannelHelper channel;
     channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
     channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
     channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel",
                               "m0", DoubleValue(1.0),
                               "m1", DoubleValue(1.0),
                               "m2", DoubleValue(1.0));
     
     phy.SetChannel(channel.Create());
     
     // Remote station manager
     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("HtMcs7"),
                                 "ControlMode", StringValue("HtMcs0"));
     
     // Install WiFi on all nodes
     NodeContainer allNodes;
     for (const auto& pair : nodeMap) {
         allNodes.Add(pair.second);
     }
     
     NetDeviceContainer devices = wifi.Install(phy, mac, allNodes);
     
     // Enable tracing
     if (enablePcap) {
         phy.EnablePcapAll(outputDir + "/fanet-drone");
     }
 }
 
 /**
  * Setup routing protocol (AODV or OLSR)
  */
 void SetupRouting() {
     NS_LOG_INFO("Setting up " << routingProtocol << " routing...");
     
     InternetStackHelper internet;
     
     if (routingProtocol == "AODV") {
         AodvHelper aodv;
         aodv.Set("EnableHello", BooleanValue(true));
         aodv.Set("HelloInterval", TimeValue(Seconds(3.0)));
         aodv.Set("ActiveRouteTimeout", TimeValue(Seconds(100.0)));
         internet.SetRoutingHelper(aodv);
     } else if (routingProtocol == "OLSR") {
         OlsrHelper olsr;
         olsr.Set("HelloInterval", TimeValue(Seconds(2.0)));
         olsr.Set("TcInterval", TimeValue(Seconds(5.0)));
         internet.SetRoutingHelper(olsr);
     }
     
     // Install internet stack on all nodes
     NodeContainer allNodes;
     for (const auto& pair : nodeMap) {
         allNodes.Add(pair.second);
     }
     internet.Install(allNodes);
     
     // Assign IP addresses
     Ipv4AddressHelper address;
     address.SetBase("192.168.1.0", "255.255.255.0");
     
     NetDeviceContainer allDevices;
     for (uint32_t i = 0; i < nNodes; ++i) {
         Ptr<Node> node = nodeMap[i];
         NetDeviceContainer nodeDevices = node->GetDevice(0);
         allDevices.Add(nodeDevices);
     }
     
     Ipv4InterfaceContainer interfaces = address.Assign(allDevices);
     
     NS_LOG_INFO("IP addresses assigned to " << interfaces.GetN() << " interfaces");
 }
 
 /**
  * Setup applications for traffic generation
  */
 void SetupApplications() {
     NS_LOG_INFO("Setting up applications...");
     
     // UDP Echo Server on dummy drones (vulnerable targets)
     for (uint32_t i = 0; i < nNodes; ++i) {
         if (droneNodes[i].type == DUMMY_DRONE) {
             UdpEchoServerHelper echoServer(9);
             ApplicationContainer serverApps = echoServer.Install(nodeMap[i]);
             serverApps.Start(Seconds(1.0));
             serverApps.Stop(Seconds(simTime - 1.0));
             
             NS_LOG_DEBUG("Installed UDP Echo Server on dummy drone " << i);
         }
     }
     
     // UDP Echo Clients on other drones
     for (uint32_t i = 0; i < nNodes; ++i) {
         if (droneNodes[i].type != DUMMY_DRONE) {
             // Find a dummy drone to communicate with
             for (uint32_t j = 0; j < nNodes; ++j) {
                 if (droneNodes[j].type == DUMMY_DRONE) {
                     Ptr<Ipv4> ipv4 = nodeMap[j]->GetObject<Ipv4>();
                     Ipv4Address serverAddr = ipv4->GetAddress(1, 0).GetLocal();
                     
                     UdpEchoClientHelper echoClient(serverAddr, 9);
                     echoClient.SetAttribute("MaxPackets", UintegerValue(100));
                     echoClient.SetAttribute("Interval", TimeValue(Seconds(2.0)));
                     echoClient.SetAttribute("PacketSize", UintegerValue(512));
                     
                     ApplicationContainer clientApps = echoClient.Install(nodeMap[i]);
                     clientApps.Start(Seconds(2.0 + i * 0.1)); // Stagger start times
                     clientApps.Stop(Seconds(simTime - 1.0));
                     
                     break; // Only connect to one dummy drone
                 }
             }
         }
     }
     
     // OnOff applications for background traffic
     for (uint32_t i = 0; i < nNodes / 2; ++i) {
         for (uint32_t j = nNodes / 2; j < nNodes; ++j) {
             Ptr<Ipv4> ipv4 = nodeMap[j]->GetObject<Ipv4>();
             Ipv4Address destAddr = ipv4->GetAddress(1, 0).GetLocal();
             
             OnOffHelper onoff("ns3::UdpSocketFactory",
                             InetSocketAddress(destAddr, 8080));
             onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
             onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
             onoff.SetAttribute("DataRate", DataRateValue(DataRate("256Kbps")));
             onoff.SetAttribute("PacketSize", UintegerValue(256));
             
             ApplicationContainer onoffApps = onoff.Install(nodeMap[i]);
             onoffApps.Start(Seconds(10.0 + i * 1.0));
             onoffApps.Stop(Seconds(simTime - 10.0));
         }
     }
 }
 
 /**
  * Setup monitoring and tracing
  */
 void SetupMonitoring() {
     NS_LOG_INFO("Setting up monitoring and tracing...");
     
     // Connect packet tracing callbacks
     Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::UdpEchoClient/Tx", 
                                  MakeCallback(&PacketSentTrace));
     Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::UdpEchoServer/Rx", 
                                  MakeCallback(&PacketReceivedTrace));
     
     // PHY layer tracing
     Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin", 
                                  MakeCallback(&PhyTxTrace));
     Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxEnd", 
                                  MakeCallback(&PhyRxTrace));
     
     // Flow Monitor for detailed statistics
     FlowMonitorHelper flowmon;
     Ptr<FlowMonitor> monitor = flowmon.InstallAll();
     
     // Schedule periodic statistics generation
     Simulator::Schedule(Seconds(30.0), &GenerateStatistics);
     
     // Animation output
     if (enableAnimation) {
         AnimationInterface anim(outputDir + "/fanet-animation.xml");
         anim.SetMaxPktsPerTraceFile(500000);
         
         // Set node descriptions
         for (uint32_t i = 0; i < nNodes; ++i) {
             string nodeDesc = droneNodes[i].droneId + " (";
             switch (droneNodes[i].type) {
                 case VIRTUAL_DRONE: nodeDesc += "Virtual)"; break;
                 case DUMMY_DRONE: nodeDesc += "Dummy)"; break;
                 case REAL_DRONE: nodeDesc += "Real)"; break;
             }
             anim.UpdateNodeDescription(nodeMap[i], nodeDesc);
             
             // Set node colors based on type
             switch (droneNodes[i].type) {
                 case VIRTUAL_DRONE:
                     anim.UpdateNodeColor(nodeMap[i], 0, 255, 0); // Green
                     break;
                 case DUMMY_DRONE:
                     anim.UpdateNodeColor(nodeMap[i], 255, 0, 0); // Red
                     break;
                 case REAL_DRONE:
                     anim.UpdateNodeColor(nodeMap[i], 0, 0, 255); // Blue
                     break;
             }
             
             // Set node size based on vulnerability
             double size = 1.0 + droneNodes[i].vulnerabilityLevel * 2.0;
             anim.UpdateNodeSize(nodeMap[i], size, size);
         }
     }
 }
 
 /**
  * Start socket server for communication with Python bridge
  */
 void StartSocketServer() {
     thread socketThread([]() {
         struct sockaddr_in address;
         int opt = 1;
         int addrlen = sizeof(address);
         
         // Create socket
         if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
             NS_LOG_ERROR("Socket creation failed");
             return;
         }
         
         // Set socket options
         if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
             NS_LOG_ERROR("Setsockopt failed");
             return;
         }
         
         address.sin_family = AF_INET;
         address.sin_addr.s_addr = INADDR_ANY;
         address.sin_port = htons(socketPort);
         
         // Bind socket
         if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address)) < 0) {
             NS_LOG_ERROR("Bind failed on port " << socketPort);
             return;
         }
         
         // Listen for connections
         if (listen(serverSocket, 3) < 0) {
             NS_LOG_ERROR("Listen failed");
             return;
         }
         
         NS_LOG_INFO("Socket server listening on port " << socketPort);
         
         // Accept connections
         while (true) {
             int clientSocket;
             if ((clientSocket = accept(serverSocket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                 if (serverSocket != -1) { // Only log if server is still running
                     NS_LOG_ERROR("Accept failed");
                 }
                 break;
             }
             
             lock_guard<mutex> lock(socketMutex);
             clientSockets.push_back(clientSocket);
             
             NS_LOG_INFO("Client connected, total clients: " << clientSockets.size());
             
             // Start thread to handle this client
             thread clientThread(HandleSocketCommunication);
             clientThread.detach();
         }
     });
     
     socketThread.detach();
 }
 
 /**
  * Handle socket communication with connected clients
  */
 void HandleSocketCommunication() {
     // Process attack queue and send real-time packet information
     while (serverSocket != -1) {
         {
             lock_guard<mutex> lock(attackQueueMutex);
             while (!attackQueue.empty()) {
                 AttackPacket attack = attackQueue.front();
                 attackQueue.pop();
                 
                 // Create packet info string
                 string packetInfo = to_string(attack.packetId) + "," +
                                   to_string(attack.sourceNode) + "," +
                                   to_string(attack.destNode) + "," +
                                   attack.attackType + "," +
                                   to_string(attack.size) + "," +
                                   to_string(attack.timestamp) + "," +
                                   (attack.isDetected ? "1" : "0") + "\n";
                 
                 SendPacketToClients(packetInfo);
             }
         }
         
         this_thread::sleep_for(chrono::milliseconds(100));
     }
 }
 
 /**
  * Send packet information to all connected clients
  */
 void SendPacketToClients(const string& data) {
     lock_guard<mutex> lock(socketMutex);
     
     auto it = clientSockets.begin();
     while (it != clientSockets.end()) {
         if (send(*it, data.c_str(), data.length(), MSG_NOSIGNAL) < 0) {
             // Client disconnected, remove from list
             close(*it);
             it = clientSockets.erase(it);
         } else {
             ++it;
         }
     }
 }
 
 /**
  * Inject attack packet into the simulation
  */
 void InjectAttackPacket(uint32_t source, uint32_t dest, const string& attackType) {
     if (source >= nNodes || dest >= nNodes) {
         NS_LOG_ERROR("Invalid node indices for attack packet injection");
         return;
     }
     
     // Create attack packet
     AttackPacket attack;
     attack.packetId = ++attackPackets;
     attack.sourceNode = source;
     attack.destNode = dest;
     attack.attackType = attackType;
     attack.size = 1024; // Default attack packet size
     attack.timestamp = Simulator::Now().GetSeconds();
     attack.isDetected = false;
     
     // Mark source drone as potentially compromised
     droneNodes[source].attackCount++;
     if (droneNodes[source].attackCount > 3 && !droneNodes[source].isCompromised) {
         droneNodes[source].isCompromised = true;
         NS_LOG_WARN("Drone " << source << " marked as compromised after " << droneNodes[source].attackCount << " attacks");
     }
     
     // Detection probability based on target vulnerability
     double detectionProb = 1.0 - droneNodes[dest].vulnerabilityLevel;
     random_device rd;
     mt19937 gen(rd());
     uniform_real_distribution<> dist(0.0, 1.0);
     
     if (dist(gen) < detectionProb) {
         attack.isDetected = true;
         NS_LOG_INFO("Attack packet detected: " << attackType << " from " << source << " to " << dest);
     }
     
     // Add to queue for transmission to Python bridge
     {
         lock_guard<mutex> lock(attackQueueMutex);
         attackQueue.push(attack);
     }
     
     // Actually send the packet in the simulation
     Ptr<Node> sourceNode = nodeMap[source];
     Ptr<Node> destNode = nodeMap[dest];
     
     if (sourceNode && destNode) {
         Ptr<Ipv4> destIpv4 = destNode->GetObject<Ipv4>();
         Ipv4Address destAddr = destIpv4->GetAddress(1, 0).GetLocal();
         
         // Create a malicious UDP packet
         UdpClientHelper udpClient(destAddr, 9999);
         udpClient.SetAttribute("MaxPackets", UintegerValue(1));
         udpClient.SetAttribute("Interval", TimeValue(Seconds(0.1)));
         udpClient.SetAttribute("PacketSize", UintegerValue(attack.size));
         
         ApplicationContainer clientApp = udpClient.Install(sourceNode);
         clientApp.Start(Seconds(0.1));
         clientApp.Stop(Seconds(0.2));
         
         NS_LOG_INFO("Injected " << attackType << " attack packet from node " << source << " to node " << dest);
     }
 }
 
 /**
  * Trace packet transmission
  */
 void PacketSentTrace(Ptr<const Packet> packet, const Address& from, const Address& to) {
     totalPackets++;
     
     // Extract source and destination from addresses
     InetSocketAddress fromAddr = InetSocketAddress::ConvertFrom(from);
     InetSocketAddress toAddr = InetSocketAddress::ConvertFrom(to);
     
     // Create real-time packet info for bridge
     uint32_t packetId = packet->GetUid();
     uint32_t size = packet->GetSize();
     double timestamp = Simulator::Now().GetSeconds();
     
     // Find source and destination node IDs
     uint32_t sourceNodeId = 0, destNodeId = 0;
     for (uint32_t i = 0; i < nNodes; ++i) {
         Ptr<Ipv4> ipv4 = nodeMap[i]->GetObject<Ipv4>();
         Ipv4Address nodeAddr = ipv4->GetAddress(1, 0).GetLocal();
         
         if (nodeAddr == fromAddr.GetIpv4()) sourceNodeId = i;
         if (nodeAddr == toAddr.GetIpv4()) destNodeId = i;
     }
     
     // Send packet info to Python bridge via socket
     string packetInfo = to_string(packetId) + "," +
                        to_string(sourceNodeId) + "," +
                        to_string(destNodeId) + "," +
                        "DATA," +
                        to_string(size) + "," +
                        to_string(timestamp) + ",0\n";
     
     SendPacketToClients(packetInfo);
 }
 
 /**
  * Trace packet reception
  */
 void PacketReceivedTrace(Ptr<const Packet> packet, const Address& from) {
     // Update latency statistics
     double currentTime = Simulator::Now().GetSeconds();
     // Note: Simplified latency calculation - in real implementation, 
     // we would track send time and calculate actual latency
     totalLatency += 0.001; // Placeholder latency
 }
 
 /**
  * Trace PHY layer transmission
  */
 void PhyTxTrace(Ptr<const Packet> packet) {
     // PHY layer statistics
     uint32_t size = packet->GetSize();
     double timestamp = Simulator::Now().GetSeconds();
     
     // Log PHY transmission for analysis
     NS_LOG_DEBUG("PHY TX: packet size=" << size << " time=" << timestamp);
 }
 
 /**
  * Trace PHY layer reception
  */
 void PhyRxTrace(Ptr<const Packet> packet) {
     // PHY layer statistics
     uint32_t size = packet->GetSize();
     double timestamp = Simulator::Now().GetSeconds();
     
     // Log PHY reception for analysis
     NS_LOG_DEBUG("PHY RX: packet size=" << size << " time=" << timestamp);
 }
 
 /**
  * Generate and output statistics
  */
 void GenerateStatistics() {
     double currentTime = Simulator::Now().GetSeconds();
     
     // Calculate statistics
     double packetLossRate = static_cast<double>(droppedPackets) / totalPackets;
     double averageLatency = totalLatency / totalPackets;
     double attackRate = static_cast<double>(attackPackets) / totalPackets;
     
     // Count compromised drones
     uint32_t compromisedDrones = 0;
     for (const auto& drone : droneNodes) {
         if (drone.isCompromised) compromisedDrones++;
     }
     
     // Output statistics to file
     ofstream statsFile(outputDir + "/simulation_stats.txt", ios::app);
     if (statsFile.is_open()) {
         statsFile << "Time: " << currentTime << "s" << endl;
         statsFile << "Total Packets: " << totalPackets << endl;
         statsFile << "Attack Packets: " << attackPackets << endl;
         statsFile << "Dropped Packets: " << droppedPackets << endl;
         statsFile << "Packet Loss Rate: " << packetLossRate << endl;
         statsFile << "Average Latency: " << averageLatency << "s" << endl;
         statsFile << "Attack Rate: " << attackRate << endl;
         statsFile << "Compromised Drones: " << compromisedDrones << "/" << nNodes << endl;
         statsFile << "----------------------------------------" << endl;
         statsFile.close();
     }
     
     // Send statistics to Python bridge
     string statsInfo = "STATS," + to_string(currentTime) + "," +
                       to_string(totalPackets) + "," +
                       to_string(attackPackets) + "," +
                       to_string(packetLossRate) + "," +
                       to_string(averageLatency) + "," +
                       to_string(compromisedDrones) + "\n";
     
     SendPacketToClients(statsInfo);
     
     NS_LOG_INFO("Statistics at " << currentTime << "s: "
                << "Packets=" << totalPackets 
                << " Attacks=" << attackPackets
                << " Compromised=" << compromisedDrones);
     
     // Schedule next statistics generation
     if (currentTime < simTime - 30.0) {
         Simulator::Schedule(Seconds(30.0), &GenerateStatistics);
     }
 }
 
 /**
  * Cleanup and exit simulation
  */
 void CleanupAndExit() {
     NS_LOG_INFO("Cleaning up simulation...");
     
     // Close socket connections
     {
         lock_guard<mutex> lock(socketMutex);
         for (int clientSocket : clientSockets) {
             close(clientSocket);
         }
         clientSockets.clear();
     }
     
     if (serverSocket != -1) {
         close(serverSocket);
         serverSocket = -1;
     }
     
     // Generate final statistics
     GenerateStatistics();
     
     // Output final drone states
     ofstream droneStatesFile(outputDir + "/final_drone_states.txt");
     if (droneStatesFile.is_open()) {
         droneStatesFile << "Final Drone States:" << endl;
         droneStatesFile << "===================" << endl;
         
         for (const auto& drone : droneNodes) {
             droneStatesFile << "Drone " << drone.nodeId << " (" << drone.droneId << "):" << endl;
             droneStatesFile << "  Type: ";
             switch (drone.type) {
                 case VIRTUAL_DRONE: droneStatesFile << "Virtual"; break;
                 case DUMMY_DRONE: droneStatesFile << "Dummy"; break;
                 case REAL_DRONE: droneStatesFile << "Real"; break;
             }
             droneStatesFile << endl;
             droneStatesFile << "  Vulnerability Level: " << drone.vulnerabilityLevel << endl;
             droneStatesFile << "  Compromised: " << (drone.isCompromised ? "Yes" : "No") << endl;
             droneStatesFile << "  Attack Count: " << drone.attackCount << endl;
             droneStatesFile << "  Final Position: (" << drone.position.x << ", " 
                            << drone.position.y << ", " << drone.position.z << ")" << endl;
             droneStatesFile << endl;
         }
         
         droneStatesFile.close();
     }
     
     NS_LOG_INFO("Simulation cleanup completed");
 }
 
 /**
  * Main simulation function
  */
 int main(int argc, char *argv[]) {
     // Setup logging
     LogComponentEnable("FANETDroneSimulation", LOG_LEVEL_INFO);
     LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
     LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
     
     // Parse command line and setup simulation
     SetupSimulation(argc, argv);
     
     NS_LOG_INFO("Starting FANET Drone Network Simulation");
     NS_LOG_INFO("=========================================");
     
     // Create simulation components
     CreateNodes();
     SetupMobility();
     SetupWifi();
     SetupRouting();
     SetupApplications();
     SetupMonitoring();
     
     // Start socket server for Python communication
     StartSocketServer();
     
     // Schedule some attack scenarios for demonstration
     random_device rd;
     mt19937 gen(rd());
     uniform_int_distribution<> nodeDist(0, nNodes - 1);
     uniform_real_distribution<> timeDist(30.0, simTime - 30.0);
     
     // Schedule random attacks
     for (int i = 0; i < 5; ++i) {
         uint32_t attackSource = nodeDist(gen);
         uint32_t attackTarget = nodeDist(gen);
         while (attackTarget == attackSource) {
             attackTarget = nodeDist(gen);
         }
         
         double attackTime = timeDist(gen);
         string attackType = (i % 2 == 0) ? "DOS_ATTACK" : "DATA_EXFILTRATION";
         
         Simulator::Schedule(Seconds(attackTime), &InjectAttackPacket, 
                           attackSource, attackTarget, attackType);
         
         NS_LOG_INFO("Scheduled " << attackType << " attack from node " << attackSource 
                    << " to node " << attackTarget << " at time " << attackTime << "s");
     }
     
     // Schedule cleanup
     Simulator::Schedule(Seconds(simTime), &CleanupAndExit);
     
     // Run simulation
     NS_LOG_INFO("Starting simulation for " << simTime << " seconds...");
     Simulator::Stop(Seconds(simTime));
     Simulator::Run();
     
     NS_LOG_INFO("Simulation completed successfully");
     Simulator::Destroy();
     
     return 0;
 }