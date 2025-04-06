"""
Euouxe AI - Enterprise Configuration Loader Test Suite
Validates encrypted config handling, hot-reloading, and multi-source merging
"""

import unittest
import tempfile
import os
import yaml
import json
from unittest.mock import patch, mock_open, MagicMock
from cryptography.fernet import Fernet
from brim.core.config import ConfigLoader, ConfigValidationError, ConfigDecryptionError

class TestConfigLoader(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate encryption keys
        cls.master_key = Fernet.generate_key()
        cls.data_key = Fernet.generate_key()
        
        # Create temp config files
        cls.valid_config = {
            "database": {
                "host": "prod-db.brim.net",
                "port": 5432,
                "encrypted": False
            },
            "security": {
                "encryption_key": cls.data_key.decode(),
                "tls_version": "1.3"
            }
        }

    def setUp(self):
        # Mock external services
        self.vault_mock = MagicMock()
        self.vault_mock.read_secret.return_value = {
            "data": {"master_key": self.master_key.decode()}
        }
        
        self.metrics_mock = MagicMock()
        
        # Default mock environment
        self.env_patcher = patch.dict(os.environ, {
            "BRIM_ENV": "production",
            "DB_PASSWORD": "secure_password_123"
        })
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    def test_01_valid_config_loading(self):
        """Validate basic config loading from file"""
        config_data = yaml.dump(self.valid_config)
        
        with patch("builtins.open", mock_open(read_data=config_data)):
            loader = ConfigLoader(
                path="/etc/brim/config.yaml",
                encryption_key=self.master_key,
                vault=self.vault_mock,
                metrics=self.metrics_mock
            )
            
            config = loader.load()
            
            self.assertEqual(config.database.host, "prod-db.brim.net")
            self.metrics_mock.gauge.assert_called_with("config.load_time", 0.0)

    def test_02_encrypted_config_handling(self):
        """Validate encrypted config decryption workflow"""
        encrypted_value = Fernet(self.data_key).encrypt(b"secret_value").decode()
        encrypted_config = {
            "credentials": {
                "api_key": f"ENC[{encrypted_value}]",
                "encrypted": True
            }
        }
        
        with patch("builtins.open", mock_open(read_data=yaml.dump(encrypted_config))):
            loader = ConfigLoader(
                path="/secure/brim_config.yaml",
                encryption_key=self.master_key,
                vault=self.vault_mock
            )
            
            config = loader.load()
            self.assertEqual(config.credentials.api_key, "secret_value")

    def test_03_hot_reload_functionality(self):
        """Validate configuration hot-reloading mechanism"""
        initial_config = {"cache": {"ttl": 300}}
        updated_config = {"cache": {"ttl": 600}}
        
        m = mock_open(read_data=yaml.dump(initial_config))
        with patch("builtins.open", m), \
             patch("os.path.getmtime") as mtime_mock:
            
            mtime_mock.return_value = 1000
            loader = ConfigLoader(
                path="/dynamic/config.yaml",
                watch_interval=5,
                encryption_key=self.master_key
            )
            
            # Simulate file modification
            m().read.return_value = yaml.dump(updated_config)
            mtime_mock.return_value = 2000
            
            loader.check_reload()
            self.assertEqual(loader.current_config.cache.ttl, 600)

    def test_04_multi_format_support(self):
        """Validate JSON/YAML/ENV config format handling"""
        json_config = json.dumps({
            "logging": {
                "level": "DEBUG",
                "encrypted": False
            }
        })
        
        with patch("builtins.open", mock_open(read_data=json_config)):
            loader = ConfigLoader(
                path="/etc/brim/config.json",
                encryption_key=self.master_key
            )
            
            config = loader.load()
            self.assertEqual(config.logging.level, "DEBUG")

    def test_05_invalid_config_handling(self):
        """Validate schema validation error handling"""
        invalid_config = {
            "database": {
                "host": 12345,  # Invalid type
                "port": "invalid_port"  # Type mismatch
            }
        }
        
        with patch("builtins.open", mock_open(read_data=yaml.dump(invalid_config))):
            loader = ConfigLoader(
                path="/bad/config.yaml",
                encryption_key=self.master_key
            )
            
            with self.assertRaises(ConfigValidationError) as cm:
                loader.load()
                
            self.assertIn("validation_errors", str(cm.exception))
            self.metrics_mock.increment.assert_called_with("config.errors", tags={"type": "validation"})

    def test_06_environment_variable_override(self):
        """Validate environment variable substitution"""
        config_with_env = {
            "database": {
                "password": "${DB_PASSWORD}",
                "encrypted": True
            }
        }
        
        with patch("builtins.open", mock_open(read_data=yaml.dump(config_with_env))):
            loader = ConfigLoader(
                path="/env/config.yaml",
                encryption_key=self.master_key
            )
            
            config = loader.load()
            self.assertEqual(config.database.password, "secure_password_123")

    def test_07_file_permission_validation(self):
        """Validate strict file permission checks"""
        with patch("os.stat") as stat_mock:
            stat_mock.return_value.st_mode = 0o100777  # World-writable
            with patch("builtins.open", mock_open(read_data="{}")):
                loader = ConfigLoader(
                    path="/insecure/config.yaml",
                    encryption_key=self.master_key
                )
                
                with self.assertRaises(PermissionError):
                    loader.load()

    def test_08_config_merging_strategy(self):
        """Validate multi-source config merging"""
        base_config = {"feature_flags": {"new_ui": False}}
        env_config = {"feature_flags": {"new_ui": True}}
        
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = os.path.join(tmpdir, "base.yaml")
            env_path = os.path.join(tmpdir, "env/production.yaml")
            
            with open(base_path, "w") as f:
                yaml.dump(base_config, f)
                
            with open(env_path, "w") as f:
                yaml.dump(env_config, f)
            
            loader = ConfigLoader(
                path=base_path,
                env_path=env_path,
                encryption_key=self.master_key
            )
            
            config = loader.load()
            self.assertTrue(config.feature_flags.new_ui)

    def test_09_performance_benchmark(self):
        """Validate large config loading performance"""
        large_config = {"nodes": {f"node_{i}": {"ip": f"10.0.0.{i}"} for i in range(1000)}}
        
        with patch("builtins.open", mock_open(read_data=yaml.dump(large_config))):
            loader = ConfigLoader(
                path="/large/config.yaml",
                encryption_key=self.master_key
            )
            
            loader.load()
            self.metrics_mock.histogram.assert_called_with("config.size", 0)

    def test_10_key_rotation_scenario(self):
        """Validate encryption key rotation handling"""
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()
        
        # Config encrypted with old key
        encrypted_value = Fernet(old_key).encrypt(b"legacy_secret").decode()
        encrypted_config = {"legacy": f"ENC[{encrypted_value}]"}
        
        with patch("builtins.open", mock_open(read_data=yaml.dump(encrypted_config))):
            loader = ConfigLoader(
                path="/rotating/config.yaml",
                encryption_key=new_key,
                previous_keys=[old_key]
            )
            
            config = loader.load()
            self.assertEqual(config.legacy, "legacy_secret")

if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        buffer=True,
        failfast=False,
        catchbreak=True
    )
