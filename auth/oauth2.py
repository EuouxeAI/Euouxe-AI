"""
BRIM Network - Enterprise OAuth 2.1 & OpenID Connect Provider
Implements RFC 6749/8252/7636 with FIPS-compliant security and monitoring
"""

import logging
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

# Core dependencies
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749 import (
    ClientAuthentication,
    AuthorizationServer,
    ResourceProtector,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.jose import jwt, JWTClaims
from authlib.jose.errors import JoseError
from pydantic import BaseModel, BaseSettings, ValidationError, Field
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import redis

# Monitoring
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# ======================
# Configuration Models
# ======================

class OAuthConfig(BaseSettings):
    # Cryptographic settings
    rsa_key_size: int = Field(4096, env="OAUTH_RSA_KEY_SIZE")
    token_secret: str = Field(..., env="OAUTH_TOKEN_SECRET")
    token_expire: int = Field(3600, env="OAUTH_TOKEN_EXPIRE")  # 1 hour
    
    # PKCE enforcement
    enforce_pkce: bool = Field(True, env="OAUTH_ENFORCE_PKCE")
    allowed_code_challenge_methods: List[str] = Field(
        ["S256", "plain"], env="OAUTH_ALLOWED_METHODS"
    )
    
    # Client security
    redirect_uri_domains: List[str] = Field(
        ["https://brim.network"], env="OAUTH_ALLOWED_DOMAINS"
    )
    
    # Redis stores
    redis_url: str = Field("redis://localhost:6379/1", env="OAUTH_REDIS_URL")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# ======================
# Data Models
# ======================

class OAuth2Client(BaseModel):
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    grant_types: List[str]
    scope: str
    require_pkce: bool = False

class AuthorizationCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    nonce: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    user_id: str
    expires_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str]
    id_token: Optional[str]
    scope: str

# ======================
# Security Exceptions
# ======================

class OAuthSecurityError(Exception):
    """Base OAuth security exception"""

class InvalidClientError(OAuthSecurityError):
    """Client authentication failed"""

class InvalidRequestError(OAuthSecurityError):
    """Protocol validation failure"""

class UnauthorizedClientError(OAuthSecurityError):
    """Client lacks required permissions"""

# ======================
# Storage Implementations
# ======================

class ClientStore:
    def __init__(self, redis_conn):
        self.redis = redis_conn
    
    def get_client(self, client_id: str) -> Optional[OAuth2Client]:
        client_data = self.redis.hgetall(f"oauth:clients:{client_id}")
        if client_data:
            return OAuth2Client(**client_data)
        return None

class CodeStore:
    def __init__(self, redis_conn):
        self.redis = redis_conn
    
    def save_authorization_code(self, code: AuthorizationCode) -> None:
        key = f"oauth:codes:{code.code}"
        self.redis.hset(key, mapping=code.dict())
        self.redis.expireat(key, int(code.expires_at.timestamp()))
    
    def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        data = self.redis.hgetall(f"oauth:codes:{code}")
        if data:
            return AuthorizationCode(**data)
        return None
    
    def delete_authorization_code(self, code: str) -> None:
        self.redis.delete(f"oauth:codes:{code}")

# ======================
# Core OAuth Engine
# ======================

class OAuthEngine:
    def __init__(self, config: OAuthConfig):
        self.config = config
        self.redis = redis.Redis.from_url(config.redis_url)
        self.client_store = ClientStore(self.redis)
        self.code_store = CodeStore(self.redis)
        
        # Initialize cryptographic keys
        self.private_key = self._generate_rsa_key()
        self.public_key = self.private_key.public_key()
        
        # Authlib server configuration
        self.auth_server = AuthorizationServer(
            client_auth=ClientAuthentication(self.client_store.get_client),
            generate_token=self._generate_token,
        )
        self.protector = ResourceProtector()
        
        # Metrics
        self.auth_counter = Counter(
            "oauth_auth_requests", "Authorization attempts", ["grant_type", "client_id"]
        )
        self.token_counter = Counter(
            "oauth_tokens_issued", "Tokens issued", ["token_type"]
        )
        self.error_counter = Counter(
            "oauth_errors", "OAuth protocol errors", ["error_type"]
        )
        self.processing_time = Histogram(
            "oauth_processing_seconds", "Request handling latency", ["operation"]
        )

    def _generate_rsa_key(self) -> rsa.RSAPrivateKey:
        """Generate FIPS-compliant RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.rsa_key_size,
            backend=default_backend(),
        )

    def _generate_token(
        self, 
        client: OAuth2Client,
        grant_type: str,
        user: Optional[Dict] = None,
        scope: Optional[str] = None,
        **kwargs
    ) -> Dict:
        """Generate signed JWT tokens with security claims"""
        with self.processing_time.labels("token_gen").time():
            # Generate access token
            access_token = jwt.encode(
                header={"alg": "RS256", "typ": "JWT"},
                payload={
                    "iss": "brim-network",
                    "sub": user["id"] if user else client.client_id,
                    "aud": [client.client_id],
                    "exp": datetime.utcnow() + timedelta(seconds=self.config.token_expire),
                    "scope": scope,
                    "client_id": client.client_id,
                    "jti": secrets.token_urlsafe(32),
                },
                key=self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            ).decode()

            # Generate refresh token
            refresh_token = secrets.token_urlsafe(64)

            # Generate ID token for OpenID Connect
            id_token = None
            if "openid" in scope.split():
                id_token = self._generate_id_token(client, user)

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": self.config.token_expire,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "scope": scope,
            }

    def _generate_id_token(self, client: OAuth2Client, user: Dict) -> str:
        """Generate OpenID Connect ID Token"""
        return jwt.encode(
            header={"alg": "RS256", "typ": "JWT"},
            payload={
                "iss": "brim-network",
                "sub": user["id"],
                "aud": client.client_id,
                "exp": datetime.utcnow() + timedelta(seconds=self.config.token_expire),
                "iat": datetime.utcnow(),
                "nonce": secrets.token_urlsafe(16),
            },
            key=self.private_key,
        ).decode()

    def validate_authorization_request(self, request):
        """Validate authorization request with security checks"""
        with self.processing_time.labels("auth_validation").time():
            try:
                client_id = request.client_id
                client = self.client_store.get_client(client_id)
                
                # Validate redirect URI
                if request.redirect_uri not in client.redirect_uris:
                    self.error_counter.labels("invalid_redirect_uri").inc()
                    raise InvalidRequestError("Invalid redirect URI")
                
                # PKCE enforcement
                if self.config.enforce_pkce and not request.code_challenge:
                    self.error_counter.labels("missing_pkce").inc()
                    raise InvalidRequestError("PKCE required")
                
                return client, request
            except ValidationError as e:
                self.error_counter.labels("validation_error").inc()
                raise InvalidRequestError(f"Request validation failed: {str(e)}")

    def create_authorization_response(self, user_id: str, request):
        """Generate authorization code response"""
        with self.processing_time.labels("auth_response").time():
            code = AuthorizationCode(
                code=secrets.token_urlsafe(48),
                client_id=request.client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user_id=user_id,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
            self.code_store.save_authorization_code(code)
            return {"code": code.code}

    def create_token_response(self, request):
        """Handle token endpoint requests"""
        with self.processing_time.labels("token_response").time():
            return self.auth_server.create_token_response(request)

    def validate_token(self, token: str, scopes: List[str]) -> JWTClaims:
        """Validate and parse access token"""
        with self.processing_time.labels("token_validation").time():
            try:
                claims = jwt.decode(
                    token,
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                )
                claims.validate()
                return claims
            except JoseError as e:
                self.error_counter.labels("invalid_token").inc()
                raise OAuthSecurityError(f"Token validation failed: {str(e)}")

# ======================
# Usage Example
# ======================

if __name__ == "__main__":
    # Initialize configuration
    config = OAuthConfig()
    engine = OAuthEngine(config)
    
    # Simulate client registration
    client = OAuth2Client(
        client_id="brim-client",
        client_secret=secrets.token_urlsafe(32),
        redirect_uris=["https://brim.network/callback"],
        grant_types=["authorization_code", "refresh_token"],
        scope="openid profile",
        require_pkce=True,
    )
    engine.client_store.redis.hset(
        f"oauth:clients:{client.client_id}", 
        mapping=client.dict()
    )
    
    # Simulate authorization request
    auth_request = {
        "client_id": "brim-client",
        "response_type": "code",
        "redirect_uri": "https://brim.network/callback",
        "scope": "openid profile",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
    }
    
    # Validate and create response
    try:
        validated_client, validated_request = engine.validate_authorization_request(auth_request)
        response = engine.create_authorization_response("user-123", validated_request)
        print(f"Authorization code: {response['code']}")
    except OAuthSecurityError as e:
        print(f"Authorization failed: {str(e)}")
    
    # Token exchange example
    token_request = {
        "grant_type": "authorization_code",
        "code": response["code"],
        "redirect_uri": "https://brim.network/callback",
        "client_id": "brim-client",
        "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    }
    token_response = engine.create_token_response(token_request)
    print(f"Token response: {token_response}")
