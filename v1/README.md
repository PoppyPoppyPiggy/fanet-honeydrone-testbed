FANET HoneyDrone Network Testbed
Flying Ad-hoc Network-based HoneyDrone Network Testbed with Moving Target Defense

🎯 Key Features
8-Phase State Transition System: Structured CTI collection process

Reinforcement Learning-based MTD: Adaptive defense using DQN/Q-Learning

CTI Analysis Engine: Based on the MITRE ATT&CK Framework

HoneyDrone Network: Docker-based Virtual/Dummy drones

DVDs Integration: Integrated with Damn Vulnerable Drone Simulator

Optimized for Kali Linux: Specialized for cybersecurity research environments

🚀 Quick Start
bash
복사
편집
# 1. Initial Setup (Run once)
sudo ./kali_integrated_launcher.sh setup

# 2. Project Initialization
sudo ./kali_integrated_launcher.sh init

# 3. Build Docker Images
sudo ./kali_integrated_launcher.sh build

# 4. Start the Testbed
sudo ./kali_integrated_launcher.sh start

# 5. Check Status
./kali_integrated_launcher.sh status
📊 Monitoring

Web Dashboard: http://localhost:8080

Log Monitoring: ./kali_integrated_launcher.sh logs all

Phase Status: ./kali_integrated_launcher.sh logs phase

🧪 Experiment Scenarios

bash
복사
편집
# Measure Basic MTD Effectiveness
./kali_integrated_launcher.sh experiment basic_mtd

# Research under Energy Constraints
./kali_integrated_launcher.sh experiment energy_constraint

# Analyze Honeypot Effectiveness
./kali_integrated_launcher.sh experiment honeypot_effectiveness

# Verify 8-Phase Transition System
./kali_integrated_launcher.sh experiment phase_transition
🔧 System Requirements

OS: Kali Linux (Recommended) or Ubuntu 20.04+

Memory: Minimum 8GB RAM

Storage: Minimum 20GB of free space

Software: Docker, Docker Compose, Python 3.8+

📚 Documentation

Installation Guide

Usage Instructions

Architecture Overview

API Reference

📝 License

MIT License

