"""
BRIM Network - Enterprise Configuration Management
Secure configuration loader with encryption, validation, and dynamic reloading
"""

import logging
import os
import sys
from typing import Dict, Any, Optional, Type
from pathlib import Path
import yaml
import json
import dotenv
from pydantic import BaseModel, ValidationError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
from prometheus_client import Counter, Gauge

# Prometheus Metrics
CONFIG_RELOADS = Counter('config_reload_total', 'Configuration reload events')
CONFIG_ERRORS = Counter('config_errors_total', 'Configuration validation errors')
CONFIG_VERSION = Gauge('config_version', 'Active configuration version')

logger = logging.getLogger(__name__)

class ConfigUpdateHandler(FileSystemEventHandler):
    """Filesystem watcher for config hot-reloading"""
    
    def __init__(self, loader: ConfigLoader):
        super().__init__()
        self.loader = loader
        
    def on_modified(self, event):
        if Path(event.src_path) == self.loader.config_path:
            logger.info("Detected config file modification")
            self.loader.safe_reload()

class SecureFernet:
    """Wrapper for Fernet encryption with key rotation"""
    
    def __init__(self):
        self.active_key = os.getenv('CONFIG_ENCRYPTION_KEY')
        self.fernet = Fernet(self.active_key)
        self._previous_keys = [
            os.getenv(f'CONFIG_ENCRYPTION_KEY_{i}') 
            for i in range(5, 0, -1)
        ]
        
    def decrypt(self, encrypted_data: str) -> str:
        """Multi-key decryption support"""
        for key in [self.active_key] + self._previous_keys:
            try:
                return Fernet(key).decrypt(encrypted_data.encode()).decode()
            except:
                continue
        raise ValueError("Failed to decrypt with available keys")

class ConfigModel(BaseModel):
    """Base configuration schema model"""
    
    class Config:
        extra = 'forbid'
        validate_all = True
        anystr_strip_whitespace = True

class AppConfig(ConfigModel):
    """Default application configuration schema"""
    environment: str = 'production'
    log_level: str = 'info'
    api_endpoint: str
    database_url: Optional[str]
    encrypted_secret: Optional[str]
    
    @validator('log_level')
    def validate_log_level(cls, v):
        if v.upper() not in logging._nameToLevel:
            raise ValueError(f"Invalid log level: {v}")
        return v.upper()

class ConfigLoader:
    """Enterprise-grade configuration manager"""
    
    def __init__(
        self,
        config_path: Path,
        schema_model: Type[ConfigModel] = AppConfig,
        watch_for_changes: bool = True
    ):
        self.config_path = config_path
        self.schema_model = schema_model
        self.cipher = SecureFernet()
        self.current_config: Optional[AppConfig] = None
        self.config_version = 0
        
        # Initialize with first load
        self.reload()
        
        # Start file watcher
        if watch_for_changes:
            self.observer = Observer()
            self.observer.schedule(
                ConfigUpdateHandler(self),
                path=str(config_path.parent),
                recursive=False
            )
            self.observer.start()
            
    def _decrypt_values(self, raw_config: Dict[str, Any]) -> Dict[str, Any]:
        """Process encrypted configuration values"""
        decrypted = raw_config.copy()
        if 'encrypted_secret' in decrypted:
            decrypted['secret'] = self.cipher.decrypt(
                decrypted.pop('encrypted_secret')
            )
        return decrypted
    
    def _load_raw_config(self) -> Dict[str, Any]:
        """Load configuration from multiple format sources"""
        # Try YAML first
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError:
            pass
            
        # Fallback to JSON
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
            
        # Fallback to environment variables
        try:
            return dict(os.environ)
        except Exception:
            raise RuntimeError(f"Failed to parse config: {self.config_path}")
            
    def reload(self) -> None:
        """Force configuration reload with validation"""
        try:
            raw_config = self._load_raw_config()
            processed_config = self._decrypt_values(raw_config)
            self.current_config = self.schema_model(**processed_config)
            self.config_version += 1
            CONFIG_VERSION.set(self.config_version)
            CONFIG_RELOADS.inc()
            logger.info(f"Loaded config version {self.config_version}")
        except ValidationError as ve:
            CONFIG_ERRORS.inc()
            logger.critical(f"Config validation failed: {ve.errors()}")
            sys.exit(1)
        except Exception as e:
            CONFIG_ERRORS.inc()
            logger.critical(f"Config load failed: {str(e)}")
            sys.exit(1)
            
    def safe_reload(self) -> bool:
        """Reload configuration with fallback to previous state"""
        try:
            previous_config = self.current_config
            self.reload()
            return True
        except:
            self.current_config = previous_config
            logger.error("Config reload failed - using previous version")
            return False
            
    def get_config(self) -> AppConfig:
        """Get validated configuration instance"""
        if not self.current_config:
            raise RuntimeError("Configuration not loaded")
        return self.current_config
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'observer'):
            self.observer.stop()
            self.observer.join()

# Example Usage
if __name__ == "__main__":
    loader = ConfigLoader(Path('/etc/brim/config.yaml'))
    config = loader.get_config()
    print(f"Current environment: {config.environment}")
