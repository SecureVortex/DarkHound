"""
Secure configuration management for DarkHound.
Implements secure loading of configuration with environment variable support.
"""
import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('darkhound.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecureConfig:
    """Secure configuration management class."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self._config = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file with security validation."""
        try:
            if not self.config_path.exists():
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                self._config = self._get_default_config()
                return
            
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self._config = yaml.safe_load(file) or {}
            
            self._validate_config()
            self._load_environment_overrides()
            logger.info("Configuration loaded successfully")
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML configuration: {e}")
        except Exception as e:
            logger.error(f"Configuration loading error: {e}")
            raise ValueError(f"Failed to load configuration: {e}")
    
    def _validate_config(self) -> None:
        """Validate configuration structure and values."""
        required_sections = ['dark_web_sources', 'alerting', 'database']
        
        for section in required_sections:
            if section not in self._config:
                logger.warning(f"Missing required section: {section}")
                self._config[section] = {}
        
        # Validate email format if provided
        if 'email_to' in self._config.get('alerting', {}):
            email = self._config['alerting']['email_to']
            if email and '@' not in email:
                raise ValueError("Invalid email format in alerting.email_to")
        
        # Validate security settings
        security_config = self._config.get('security', {})
        if 'max_scan_timeout' in security_config:
            timeout = security_config['max_scan_timeout']
            if not isinstance(timeout, int) or timeout <= 0 or timeout > 300:
                logger.warning("Invalid max_scan_timeout, using default 30 seconds")
                self._config['security']['max_scan_timeout'] = 30
        
        if 'max_concurrent_scans' in security_config:
            concurrent = security_config['max_concurrent_scans']
            if not isinstance(concurrent, int) or concurrent <= 0 or concurrent > 20:
                logger.warning("Invalid max_concurrent_scans, using default 5")
                self._config['security']['max_concurrent_scans'] = 5
    
    def _load_environment_overrides(self) -> None:
        """Load sensitive values from environment variables."""
        env_mappings = {
            'DARKHOUND_EMAIL_TO': ('alerting', 'email_to'),
            'DARKHOUND_SLACK_WEBHOOK': ('alerting', 'slack_webhook'),
            'DARKHOUND_TEAMS_WEBHOOK': ('alerting', 'teams_webhook'),
            'DARKHOUND_HAVEIBEENPWNED_API_KEY': ('threat_intel', 'haveibeenpwned_api_key'),
            'DARKHOUND_DEHASHED_API_KEY': ('threat_intel', 'dehashed_api_key'),
            'DARKHOUND_DARKOWL_API_KEY': ('threat_intel', 'darkowl_api_key'),
            'DARKHOUND_FLARE_API_KEY': ('threat_intel', 'flare_api_key'),
            'DARKHOUND_CYBERSIXGILL_API_KEY': ('threat_intel', 'cybersixgill_api_key'),
            'DARKHOUND_DB_PATH': ('database', 'path'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                if section not in self._config:
                    self._config[section] = {}
                self._config[section][key] = value
                logger.info(f"Loaded {section}.{key} from environment")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return secure default configuration."""
        return {
            'dark_web_sources': [],
            'alerting': {
                'email_to': '',
                'slack_webhook': '',
                'teams_webhook': ''
            },
            'threat_intel': {
                'haveibeenpwned_api_key': '',
                'dehashed_api_key': '',
                'darkowl_api_key': '',
                'flare_api_key': '',
                'cybersixgill_api_key': ''
            },
            'database': {
                'type': 'sqlite',
                'path': 'darkhound.db'
            },
            'security': {
                'max_scan_timeout': 30,
                'max_concurrent_scans': 5,
                'enable_request_logging': False
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key."""
        try:
            keys = key.split('.')
            value = self._config
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section."""
        return self._config.get(section, {})
    
    def validate_required_settings(self) -> bool:
        """Validate that required settings are configured."""
        warnings = []
        
        if not self.get('dark_web_sources'):
            warnings.append("No dark web sources configured")
        
        if not self.get('alerting.email_to'):
            warnings.append("No alerting email configured")
        
        if warnings:
            for warning in warnings:
                logger.warning(f"Configuration warning: {warning}")
            return False
        
        return True