"""
BRIM Network - Enterprise JWT Authentication Test Suite
Validates token lifecycle, key rotation, and security hardening controls
"""

import unittest
import time
import jwt
import cryptography
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta
from brim.security.jwt import JWTManager, TokenValidationError, TokenRevokedError

class TestJWTAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure production-grade JWT settings
        cls.security_config = {
            "issuer": "brim.prod",
            "audience": ["api.brim.network", "internal.services"],
            "algorithm": "RS256",
            "key_rotation": {
                "interval": 3600,
                "key_storage": "vault",
                "backup_keys": 2
            },
            "token_ttl": {
                "access": 900,
                "refresh": 86400
            },
            "revocation": {
                "check_interval": 300,
                "redis_url": "redis://prod-redis:6379/0"
            },
            "security_headers": {
                "require_encrypted_claims": True,
                "strict_typ": "at+jwt"
            }
        }

        # Generate test keys
        cls.current_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        cls.old_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

    def setUp(self):
        # Mock Redis client for revocation list
        self.redis_mock = MagicMock()
        self.redis_patcher = patch('redis.StrictRedis', return_value=self.redis_mock)
        self.redis_mock.get.return_value = None  # Default to non-revoked tokens
        self.redis_mock_patcher = self.redis_patcher.start()

        # Initialize metrics collector
        self.metrics_mock = MagicMock()

        # Create JWT manager instance
        self.jwt_manager = JWTManager(
            config=self.security_config,
            current_key=self.current_key,
            previous_keys=[self.old_key],
            metrics=self.metrics_mock
        )

    def tearDown(self):
        self.redis_patcher.stop()

    def test_01_valid_token_flow(self):
        """Validate end-to-end token generation and verification"""
        payload = {
            "sub": "user:123",
            "roles": ["admin", "auditor"],
            "encrypted_claim": self.jwt_manager.encrypt_claim("secret_value")
        }
        
        # Generate token
        token = self.jwt_manager.generate_token(payload, token_type="access")
        
        # Verify token
        decoded = self.jwt_manager.verify_token(token)
        
        self.assertEqual(decoded["sub"], "user:123")
        self.assertEqual(decoded["roles"], ["admin", "auditor"])
        self.metrics_mock.timer.assert_called_with("jwt.verification_time")

    def test_02_expired_token_handling(self):
        """Validate token expiration enforcement"""
        expired_payload = {
            "exp": datetime.utcnow() - timedelta(seconds=300)
        }
        token = jwt.encode(
            expired_payload,
            self.current_key,
            algorithm="RS256",
            headers={"kid": "current"}
        )
        
        with self.assertRaises(TokenValidationError) as cm:
            self.jwt_manager.verify_token(token)
            
        self.assertEqual(cm.exception.error_code, "token_expired")
        self.metrics_mock.increment.assert_called_with("jwt.validation_errors", tags={"reason": "expired"})

    def test_03_signature_validation(self):
        """Detect tampered tokens with invalid signatures"""
        valid_token = self.jwt_manager.generate_token({"sub": "user:456"})
        header, payload, signature = valid_token.split(".")
        
        # Tamper with payload
        malicious_token = f"{header}.{payload[:-2]}XX.{signature}"
        
        with self.assertRaises(TokenValidationError) as cm:
            self.jwt_manager.verify_token(malicious_token)
            
        self.assertEqual(cm.exception.error_code, "signature_verification_failed")

    def test_04_key_rotation_scenario(self):
        """Validate seamless key rotation process"""
        # Generate token with old key
        old_token = jwt.encode(
            {"sub": "legacy_user"},
            self.old_key,
            algorithm="RS256",
            headers={"kid": "old"}
        )
        
        # Verify during key rotation window
        decoded = self.jwt_manager.verify_token(old_token)
        self.assertEqual(decoded["sub"], "legacy_user")

    def test_05_token_revocation(self):
        """Validate revocation list integration"""
        revoked_jti = "revoked-12345"
        self.redis_mock.get.return_value = "1"  # Simulate revoked token
        
        token = self.jwt_manager.generate_token({"jti": revoked_jti})
        
        with self.assertRaises(TokenRevokedError):
            self.jwt_manager.verify_token(token)
            
        self.metrics_mock.increment.assert_called_with("jwt.revoked_tokens")

    def test_06_encrypted_claims(self):
        """Validate JWE encrypted claim handling"""
        sensitive_data = {"ssn": "123-45-6789"}
        encrypted_claim = self.jwt_manager.encrypt_claim(sensitive_data)
        
        token = self.jwt_manager.generate_token({
            "user": "protected",
            "data": encrypted_claim
        })
        
        decoded = self.jwt_manager.verify_token(token)
        self.assertEqual(decoded["data"]["ssn"], "123-45-6789")

    def test_07_injection_attempts(self):
        """Block header injection attacks"""
        malicious_headers = {
            "alg": "none",
            "kid": "../../malicious-key"
        }
        
        token = jwt.encode(
            {"sub": "attacker"},
            key="",
            headers=malicious_headers
        )
        
        with self.assertRaises(TokenValidationError) as cm:
            self.jwt_manager.verify_token(token)
            
        self.assertEqual(cm.exception.error_code, "invalid_header")

    def test_08_audience_validation(self):
        """Validate strict audience verification"""
        token = self.jwt_manager.generate_token({
            "aud": "external.service"
        })
        
        with self.assertRaises(TokenValidationError) as cm:
            self.jwt_manager.verify_token(token)
            
        self.assertEqual(cm.exception.error_code, "invalid_audience")

    def test_09_high_volume_token_generation(self):
        """Validate performance under load"""
        for _ in range(1000):
            self.jwt_manager.generate_token({
                "sub": f"user:{_}",
                "roles": ["operator"]
            })
            
        self.metrics_mock.histogram.assert_called_with("jwt.token_size", 0)

    def test_10_refresh_token_flow(self):
        """Validate refresh token lifecycle"""
        refresh_payload = {
            "sub": "user:789",
            "refresh": True
        }
        refresh_token = self.jwt_manager.generate_token(refresh_payload, token_type="refresh")
        
        # Verify refresh token
        decoded_refresh = self.jwt_manager.verify_token(refresh_token)
        
        # Generate new access token
        new_access_token = self.jwt_manager.generate_token({
            "sub": decoded_refresh["sub"]
        })
        
        self.assertTrue(len(new_access_token) > 100)
        self.metrics_mock.increment.assert_any_call("jwt.refresh_cycles")

if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        buffer=True,
        failfast=False,
        catchbreak=True
    )
