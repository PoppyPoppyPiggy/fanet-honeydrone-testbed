"""
FANET HoneyDrone Network Testbed Main Launcher
"""

import sys
import os
import asyncio
import signal
import threading
import time
import json
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import modules
from src.phase_transition_manager import PhaseTransitionManager
from src.rl_mtd_engine import ReinforcementLearningMTDEngine
from src.cti_analysis_engine import CTIAnalysisEngine
from src.honeydrone_network_manager import HoneydroneNetworkManager

class TestbedLauncher:
    def __init__(self):
        self.phase_manager = None
        self.mtd_engine = None
        self.cti_analyzer = None
        self.network_manager = None
        self.running = False

        # Logging configuration
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("TestbedLauncher")

    async def start_all_components(self):
        """Start all components"""
        print("🚀 Starting FANET HoneyDrone Network Testbed...")

        try:
            # 1. Start network manager
            print("📡 Initializing Network Manager...")
            self.network_manager = HoneydroneNetworkManager()
            await self.network_manager.initialize_network()

            # 2. Start CTI analysis engine
            print("🔍 Starting CTI Analysis Engine...")
            self.cti_analyzer = CTIAnalysisEngine()
            self.cti_analyzer.start_analysis_worker()

            # 3. Start MTD engine
            print("🛡️ Initializing MTD Engine...")
            self.mtd_engine = ReinforcementLearningMTDEngine()

            # 4. Start Phase Manager
            print("⚡ Starting Phase Manager...")
            self.phase_manager = PhaseTransitionManager()

            # Connect components
            self.phase_manager.mtd_engine = self.mtd_engine
            self.phase_manager.cti_analyzer = self.cti_analyzer
            self.phase_manager.honeydrone_manager = self.network_manager

            self.mtd_engine.phase_manager = self.phase_manager

            print("✅ All components initialized successfully")
            print("🎯 Starting Phase Management System...")

            # Start phase management
            self.running = True
            await self.phase_manager.start_phase_management()

        except Exception as e:
            print(f"❌ Failed to start testbed: {e}")
            await self.stop_all_components()
            raise

    async def stop_all_components(self):
        """Stop all components"""
        print("🛑 Shutting down testbed...")

        self.running = False

        if self.phase_manager:
            self.phase_manager.stop()
            print("  ✓ Phase Manager stopped")

        if self.mtd_engine:
            self.mtd_engine.stop()
            print("  ✓ MTD Engine stopped")

        if self.cti_analyzer:
            self.cti_analyzer.stop()
            print("  ✓ CTI Analyzer stopped")

        if self.network_manager:
            await self.network_manager.shutdown()
            print("  ✓ Network Manager stopped")

        print("✅ Testbed shutdown complete")

def main():
    launcher = TestbedLauncher()

    # Signal handler
    def signal_handler(signum, frame):
        print("\n⚠️ Termination signal received...")
        launcher.running = False
        asyncio.create_task(launcher.stop_all_components())
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        print("🎯 FANET HoneyDrone Network Testbed")
        print("=" * 50)
        asyncio.run(launcher.start_all_components())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user...")
    except Exception as e:
        print(f"❌ Execution error: {e}")
    finally:
        asyncio.run(launcher.stop_all_components())

if __name__ == '__main__':
    main()
