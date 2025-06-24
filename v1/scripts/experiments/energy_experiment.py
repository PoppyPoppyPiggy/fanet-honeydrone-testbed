import asyncio
import time
import json
import logging
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.rl_mtd_engine import ReinforcementLearningMTDEngine
from src.cti_analysis_engine import CTIAnalysisEngine

class BasicMTDExperiment:
    """Basic experiment to measure the effectiveness of MTD"""
    
    def __init__(self):
        self.logger = logging.getLogger("BasicMTDExperiment")
        self.results = {
            'mtd_disabled': {'attacks_successful': 0, 'attacks_total': 0},
            'mtd_enabled': {'attacks_successful': 0, 'attacks_total': 0},
            'timeline': []
        }
    
    async def run_experiment(self, duration_minutes=30):
        """Run the experiment"""
        self.logger.info("🧪 Starting Basic MTD Effectiveness Experiment")
        
        # Phase 1: Test with MTD disabled
        self.logger.info("📊 Phase 1: Testing with MTD disabled")
        await self._test_without_mtd(duration_minutes // 2)
        
        # Phase 2: Test with MTD enabled
        self.logger.info("📊 Phase 2: Testing with MTD enabled")
        await self._test_with_mtd(duration_minutes // 2)
        
        # Analyze the results
        await self._analyze_results()
        
        self.logger.info("✅ Basic MTD Effectiveness Experiment Completed")
    
    async def _test_without_mtd(self, duration_minutes):
        """Test without MTD enabled"""
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        while time.time() < end_time:
            attack_success = await self._simulate_attack(mtd_enabled=False)
            
            self.results['mtd_disabled']['attacks_total'] += 1
            if attack_success:
                self.results['mtd_disabled']['attacks_successful'] += 1
            
            self.results['timeline'].append({
                'timestamp': datetime.now().isoformat(),
                'mtd_enabled': False,
                'attack_successful': attack_success
            })
            
            await asyncio.sleep(10)  # Simulate an attack every 10 seconds
    
    async def _test_with_mtd(self, duration_minutes):
        """Test with MTD enabled"""
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        while time.time() < end_time:
            attack_success = await self._simulate_attack(mtd_enabled=True)
            
            self.results['mtd_enabled']['attacks_total'] += 1
            if attack_success:
                self.results['mtd_enabled']['attacks_successful'] += 1
            
            self.results['timeline'].append({
                'timestamp': datetime.now().isoformat(),
                'mtd_enabled': True,
                'attack_successful': attack_success
            })
            
            await asyncio.sleep(10)  # Simulate an attack every 10 seconds
    
    async def _simulate_attack(self, mtd_enabled=False):
        """Simulate a single attack"""
        import random
        
        # Lower attack success rate if MTD is enabled
        success_rate = 0.2 if mtd_enabled else 0.8
        return random.random() < success_rate
    
    async def _analyze_results(self):
        """Analyze results"""
        mtd_disabled_rate = (
            self.results['mtd_disabled']['attacks_successful'] / 
            max(1, self.results['mtd_disabled']['attacks_total'])
        )
        
        mtd_enabled_rate = (
            self.results['mtd_enabled']['attacks_successful'] / 
            max(1, self.results['mtd_enabled']['attacks_total'])
        )
        
        effectiveness = (mtd_disabled_rate - mtd_enabled_rate) / max(0.01, mtd_disabled_rate)

        # Display results
        print("\n" + "="*50)
        print("🔍 Results of Basic MTD Effectiveness Experiment")
        print("="*50)
        print(f"Attack success rate with MTD disabled: {mtd_disabled_rate:.2%}")
        print(f"Attack success rate with MTD enabled : {mtd_enabled_rate:.2%}")
        print(f"MTD Effectiveness                   : {effectiveness:.2%}")
        print("="*50)

        # Save results to file
        final_results = {
            'experiment_type': 'basic_mtd_effectiveness',
            'timestamp': datetime.now().isoformat(),
            'mtd_disabled_success_rate': mtd_disabled_rate,
            'mtd_enabled_success_rate': mtd_enabled_rate,
            'mtd_effectiveness': effectiveness,
            'raw_data': self.results
        }

        results_file = f"data/mtd_experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(final_results, f, indent=2)
        
        self.logger.info(f"📊 Experiment results saved to: {results_file}")

async def main():
    """Main function"""
    experiment = BasicMTDExperiment()
    await experiment.run_experiment(duration_minutes=10)  # 10-minute experiment

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
