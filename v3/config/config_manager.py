# 설정 관리 시스템
# config/config_manager.py
import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.configs: Dict[str, Dict[str, Any]] = {}
        self._load_all_configs()
    
    def _load_all_configs(self):
        """모든 설정 파일 로드"""
        config_files = [
            'network_config.yaml',
            'mtd_config.yaml',
            'cti_config.yaml',
            'phase_config.yaml'
        ]
        
        for config_file in config_files:
            config_path = self.config_dir / config_file
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_name = config_file.replace('.yaml', '').replace('_config', '')
                    self.configs[config_name] = yaml.safe_load(f)
    
    def get_config(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """설정값 조회"""
        if section not in self.configs:
            return default
        
        if key is None:
            return self.configs[section]
        
        return self.configs[section].get(key, default)
    
    def update_config(self, section: str, key: str, value: Any):
        """설정값 업데이트"""
        if section not in self.configs:
            self.configs[section] = {}
        
        self.configs[section][key] = value
        
        # 파일에 저장
        config_file = self.config_dir / f"{section}_config.yaml"
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self.configs[section], f, default_flow_style=False, allow_unicode=True)
