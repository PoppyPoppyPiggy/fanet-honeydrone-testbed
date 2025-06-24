#!/usr/bin/env python3
"""
Phase Transition Manager Test
"""

import unittest
import asyncio
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.phase_transition_manager import PhaseTransitionManager, PhaseType

class TestPhaseTransitionManager(unittest.TestCase):
    """Unit tests for Phase Transition Manager"""
    
    def setUp(self):
        """Test setup"""
        self.manager = PhaseTransitionManager()
    
    def test_initialization(self):
        """Test initial state"""
        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager.current_phase, PhaseType.HONEY_INFILTRATION)
        self.assertFalse(self.manager.is_running)
    
    def test_phase_transition(self):
        """Test phase transition logic"""
        async def test_transition():
            await self.manager.transition_to_phase(
                PhaseType.ENEMY_DETECTION, 
                "Test transition"
            )
            self.assertEqual(self.manager.current_phase, PhaseType.ENEMY_DETECTION)
        
        asyncio.run(test_transition())
    
    def test_cti_data_processing(self):
        """Test CTI data queuing"""
        test_data = {
            'timestamp': '2024-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'attack_type': 'port_scan',
            'payload': 'nmap -sS target',
            'success_level': 0.5
        }
        
        self.manager.add_cti_data(test_data)
        self.assertGreater(self.manager.event_queue.qsize(), 0)

if __name__ == '__main__':
    unittest.main()
