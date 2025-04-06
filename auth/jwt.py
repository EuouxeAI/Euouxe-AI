"""
Euouxe AI - Enterprise JWT Management System
Implements FIPS-compliant token handling with refresh/revocation and claim encryption
"""

import os
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Union

# Core dependencies
from jose import jwt, JWTError
from jose.constants import ALGORITHMS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, BaseSettings, Field, ValidationError
import redis

# Monitoring
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# ======================
# Configuration Models
# ======================

class JWTConfig(BaseSettings):
    # RSA Key configuration
    rsa_key_size: int = Field(4096, env="JWT_RSA_KEY_SIZE")
    key_rotation_interval: int = Field(604800, env="JWT_KEY_ROTATION_SEC")  # 7 days
    
    # Token policies
    access_token_expire: int = Field(900, env="JWT_ACCESS_EXPIRE")  # 15m
    refresh_token_expire: int = Field(2592000, env="JWT_REFRESH_EXPIRE")  # 30d
    allowed_algs: List[str] = Field(["RS256"], env="JWT_ALLOWED_ALGS")
    
    # Encryption
    claim_encryption_key: str = Field(..., env="JWT_CLAIM_ENCRYPT_KEY")
    
    # Revocation store
    redis_url: str = Field("redis://localhost:6379/0", env="JWT_REDIS_URL")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# ======================
# Security Exceptions
# ======================

class JWTManagementError(Exception):
    """Base exception for JWT operations"""

class InvalidTokenError(JWTManagementError):
    """Token validation failed"""

class TokenRevokedError(JWTManagementError):
    """Token found in revocation list"""

# ======================
# Key Management
# ======================

class KeyVault:
    def __init__(self, config: JWTConfig):
        self.config = config
        self._current_key = self._generate_rsa_key()
        self._key_store: Dict[str, rsa.RSAPrivateKey] = {}
        self._last_rotation = time.time()
        
    def _generate_rsa_key(self) -> rsa.RSAPrivateKey:
        """Generate FIPS-compliant RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.rsa_key_size,
            backend=default_backend()
        )
        
    def rotate_keys(self) -> None:
        """Perform scheduled key rotation"""
        if (time.time() - self._last_rotation) > self.config.key_rotation_interval:
            self._key_store[self.key_id] = self._current_key
            self._current_key = self._generate_rsa_key()
            self._last_rotation = time.time()
            logger.info("Performed JWT key rotation")
            
    @property
    def key_id(self) -> str:
        """Current key identifier (SHA-256 thumbprint)"""
        public_bytes = self._current_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jwt.get_unverified_header(public_bytes).get("kid", "default")
    
    def get_signing_key(self) -> rsa.RSAPrivateKey:
        """Get current private key with auto-rotation"""
        self.rotate_keys()
        return self._current_key
    
    def get_verification_keys(self) -> Dict[str, rsa.RSAPublicKey]:
        """Get all active public keys"""
        return {
            kid: key.public_key()
            for kid, key in self._key_store.items()
        } | {self.key_id: self._current_key.public_key()}

# ======================
# Token Manager
# ======================

class JWTManager:
    def __init__(self, config: JWTConfig):
        self.config = config
        self.key_vault = KeyVault(config)
        self.redis = redis.Redis.from_url(config.redis_url)
        
        # Initialize Fernet for claim encryption
        self.fernet = jwt.Fernet(config.claim_encryption_key.encode())
        
        # Prometheus metrics
        self.token_counter = Counter(
            "jwt_tokens_issued", 
            "Total tokens issued", 
            ["token_type"]
        )
        self.validation_errors = Counter(
            "jwt_validation_errors",
            "Token validation failures",
            ["error_type"]
        )
        self.revocation_gauge = Gauge(
            "jwt_revoked_tokens",
            "Number of revoked tokens"
        )
        self.processing_time = Histogram(
            "jwt_processing_seconds",
            "Token processing latency",
            ["operation"]
        )
        
    def _encrypt_claims(self, claims: Dict) -> Dict:
        """Encrypt sensitive claims using Fernet"""
        encrypted = {
            key: self.fernet.encrypt(str(value).encode()).decode()
            if key in ["sub", "roles", "email"] else value
            for key, value in claims.items()
        }
        return encrypted
        
    def _decrypt_claims(self, encrypted_claims: Dict) -> Dict:
        """Decrypt Fernet-encrypted claims"""
        return {
            key: self.fernet.decrypt(value.encode()).decode()
            if key in ["sub", "roles", "email"] else value
            for key, value in encrypted_claims.items()
        }
        
    def create_access_token(
        self,
        subject: Union[str, int],
        roles: List[str],
        additional_claims: Optional[Dict] = None
    ) -> str:
        """Generate JWT access token with encrypted claims"""
        with self.processing_time.labels("generate").time():
            claims = {
                "sub": str(subject),
                "roles": roles,
                "iss": "brim-network",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(seconds=self.config.access_token_expire)
            }
            if additional_claims:
                claims.update(additional_claims)
                
            encrypted_claims = self._encrypt_claims(claims)
            private_key = self.key_vault.get_signing_key()
            
            token = jwt.encode(
                claims=encrypted_claims,
                key=private_key,
                algorithm="RS256",
                headers={"kid": self.key_vault.key_id}
            )
            
            self.token_counter.labels("access").inc()
            return token
            
    def create_refresh_token(self, subject: Union[str, int]) -> str:
        """Generate long-lived refresh token"""
        with self.processing_time.labels("generate").time():
            claims = {
                "sub": str(subject),
                "type": "refresh",
                "exp": datetime.utcnow() + timedelta(seconds=self.config.refresh_token_expire)
            }
            private_key = self.key_vault.get_signing_key()
            
            token = jwt.encode(
                claims=claims,
                key=private_key,
                algorithm="RS256",
                headers={"kid": self.key_vault.key_id}
            )
            
            self.token_counter.labels("refresh").inc()
            return token
            
    def validate_token(self, token: str) -> Dict:
        """Validate and decrypt JWT token"""
        with self.processing_time.labels("validate").time():
            try:
                # Check revocation list first
                if self.redis.sismember("jwt:revoked", token):
                    self.validation_errors.labels("revoked").inc()
                    raise TokenRevokedError("Token revoked")
                    
                # Get public keys for verification
                public_keys = self.key_vault.get_verification_keys()
                
                # Decode without validation to get key ID
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")
                
                if not kid or kid not in public_keys:
                    self.validation_errors.labels("invalid_kid").inc()
                    raise InvalidTokenError("Invalid key ID")
                    
                # Full validation
                decoded = jwt.decode(
                    token=token,
                    key=public_keys[kid],
                    algorithms=self.config.allowed_algs,
                    options={
                        "require_sub": True,
                        "require_exp": True,
                        "verify_aud": False
                    }
                )
                
                # Decrypt sensitive claims
                decrypted_claims = self._decrypt_claims(decoded)
                return decrypted_claims
                
            except JWTError as e:
                self.validation_errors.labels("jwt_error").inc()
                raise InvalidTokenError(f"JWT validation failed: {str(e)}")
            except ValidationError as e:
                self.validation_errors.labels("validation_error").inc()
                raise InvalidTokenError(f"Claim validation failed: {str(e)}")
                
    def revoke_token(self, token: str, expire_in: int = 86400) -> None:
        """Add token to revocation list with TTL"""
        with self.redis.pipeline() as pipe:
            pipe.sadd("jwt:revoked", token)
            pipe.expire("jwt:revoked", expire_in)
            pipe.execute()
        self.revocation_gauge.inc()
        
    def bulk_revoke(self, tokens: List[str]) -> None:
        """Revoke multiple tokens in batch"""
        if tokens:
            self.redis.sadd("jwt:revoked", *tokens)
            self.revocation_gauge.inc(len(tokens))

# ======================
# Usage Example
# ======================

if __name__ == "__main__":
    # Initialize with environment variables
    config = JWTConfig()
    manager = JWTManager(config)
    
    # Generate tokens
    access_token = manager.create_access_token(
        subject="user-123", 
        roles=["admin", "developer"]
    )
    refresh_token = manager.create_refresh_token("user-123")
    
    # Validate token
    try:
        claims = manager.validate_token(access_token)
        print(f"Valid token for {claims['sub']}")
    except (InvalidTokenError, TokenRevokedError) as e:
        print(f"Token invalid: {str(e)}")
    
    # Revoke example
    manager.revoke_token(access_token)
