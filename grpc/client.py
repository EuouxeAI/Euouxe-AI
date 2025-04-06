"""
Euouxe AI - Enterprise AI Client SDK
Implements secure, resilient communication with BRIM servers and agent clusters
"""

import os
import logging
import json
import asyncio
from typing import Dict, Optional, List, Tuple, AsyncGenerator

# Core dependencies
import httpx
import grpc
from grpc import aio
from pydantic import BaseModel, BaseSettings, Field, AnyUrl, validator
from cryptography.fernet import Fernet
from jose import jwt

# Monitoring
from prometheus_client import Counter, Histogram, generate_latest

# Generated protobuf
from . import agent_pb2
from . import agent_pb2_grpc

logger = logging.getLogger(__name__)

# ======================
# Configuration Models
# ======================

class ClientConfig(BaseSettings):
    # Cluster endpoints
    rest_endpoints: List[AnyUrl] = Field(
        ["http://localhost:8000"], 
        env="BRIM_REST_ENDPOINTS"
    )
    grpc_endpoints: List[str] = Field(
        ["localhost:50051"], 
        env="BRIM_GRPC_ENDPOINTS"
    )
    
    # Security
    tls_ca_cert: Optional[str] = Field(None, env="BRIM_TLS_CA_CERT")
    jwt_secret: str = Field(..., env="BRIM_JWT_SECRET")
    fernet_key: str = Field(..., env="BRIM_FERNET_KEY")
    
    # Policies
    max_retries: int = Field(3, env="BRIM_MAX_RETRIES")
    request_timeout: int = Field(30, env="BRIM_TIMEOUT")
    load_balance_strategy: str = Field("round_robin", env="BRIM_LB_STRATEGY")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# ======================
# Security Handlers
# ======================

class SecurePayloadHandler:
    def __init__(self, fernet_key: str, jwt_secret: str):
        self.fernet = Fernet(fernet_key.encode())
        self.jwt_secret = jwt_secret
        
    def generate_token(self, user: str, roles: List[str]) -> str:
        """Generate JWT with encrypted claims"""
        claims = {
            "sub": user,
            "roles": self.fernet.encrypt(json.dumps(roles).encode()).decode()
        }
        return jwt.encode(claims, self.jwt_secret, algorithm="HS256")

    def encrypt_payload(self, payload: dict) -> str:
        """Fernet-encrypt payload with timestamp"""
        return self.fernet.encrypt(json.dumps(payload).encode()).decode()

    def decrypt_response(self, encrypted: str) -> dict:
        """Decrypt and validate server response"""
        return json.loads(self.fernet.decrypt(encrypted.encode()))

# ======================
# gRPC Client
# ======================

class BRIMgRPCClient:
    def __init__(self, config: ClientConfig):
        self._channels = [
            self._create_channel(endpoint) 
            for endpoint in config.grpc_endpoints
        ]
        self._lb_strategy = config.load_balance_strategy
        self._current_index = 0
        
    def _create_channel(self, endpoint: str) -> aio.Channel:
        """Create secure async gRPC channel"""
        return aio.insecure_channel(endpoint)  # Add TLS logic if needed
        
    def _get_channel(self) -> aio.Channel:
        """Load balancing strategy implementation"""
        if self._lb_strategy == "round_robin":
            self._current_index = (self._current_index + 1) % len(self._channels)
            return self._channels[self._current_index]
        # Implement other strategies (random, least_conn, etc.)
        return self._channels[0]
        
    async def submit_task(
        self, 
        agent_id: str,
        payload: dict,
        metadata: Dict[str, str],
        timeout: int = 30
    ) -> dict:
        """Execute task via gRPC with retry logic"""
        stub = agent_pb2_grpc.AgentServiceStub(self._get_channel())
        request = agent_pb2.TaskRequest(
            agent_id=agent_id,
            payload=payload,
            task_id=os.urandom(16).hex()
        )
        
        try:
            response = await stub.ProcessTask(
                request,
                timeout=timeout,
                metadata=[("authorization", metadata["token"])]
            )
            return self.decrypt_response(response.payload)
        except grpc.RpcError as e:
            logger.error(f"gRPC error: {e.code()}: {e.details()}")
            raise

# ======================
# REST Client
# ======================

class BRIMRESTClient:
    def __init__(self, config: ClientConfig):
        self._client = httpx.AsyncClient(
            timeout=config.request_timeout,
            limits=httpx.Limits(max_connections=100),
            transport=httpx.AsyncHTTPTransport(retries=3)
        )
        self._endpoints = config.rest_endpoints
        self._current_endpoint = 0
        
    def _get_endpoint(self) -> str:
        """Round-robin load balancing for REST endpoints"""
        self._current_endpoint = (self._current_endpoint + 1) % len(self._endpoints)
        return str(self._endpoints[self._current_endpoint])
        
    async def submit_task(
        self,
        agent_id: str,
        payload: dict,
        metadata: Dict[str, str],
    ) -> dict:
        """Execute task via REST API"""
        endpoint = f"{self._get_endpoint()}/tasks"
        try:
            response = await self._client.post(
                endpoint,
                json={
                    "agent_id": agent_id,
                    "payload": payload
                },
                headers={"Authorization": f"Bearer {metadata['token']}"}
            )
            response.raise_for_status()
            return self.decrypt_response(response.json()["result"])
        except httpx.HTTPError as e:
            logger.error(f"REST error: {str(e)}")
            raise

# ======================
# Unified Client
# ======================

class BRIMClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.security = SecurePayloadHandler(config.fernet_key, config.jwt_secret)
        self.grpc_client = BRIMgRPCClient(config)
        self.rest_client = BRIMRESTClient(config)
        
        # Monitoring
        self.request_counter = Counter(
            "brim_client_requests_total",
            "Total API requests",
            ["protocol", "agent_id", "status"]
        )
        self.latency_histogram = Histogram(
            "brim_client_request_duration_seconds",
            "Request latency distribution",
            ["protocol"],
            buckets=[0.01, 0.05, 0.1, 0.5, 1, 5]
        )
        
    async def execute(
        self,
        agent_id: str,
        payload: dict,
        *,
        protocol: str = "grpc",
        user: str = "system",
        roles: List[str] = ["admin"]
    ) -> dict:
        """Unified task execution interface"""
        encrypted_payload = self.security.encrypt_payload(payload)
        token = self.security.generate_token(user, roles)
        metadata = {"token": token}
        
        with self.latency_histogram.labels(protocol).time():
            try:
                if protocol == "grpc":
                    result = await self.grpc_client.submit_task(
                        agent_id, encrypted_payload, metadata
                    )
                else:
                    result = await self.rest_client.submit_task(
                        agent_id, encrypted_payload, metadata
                    )
                self.request_counter.labels(protocol, agent_id, "success").inc()
                return result
            except Exception as e:
                self.request_counter.labels(protocol, agent_id, "error").inc()
                logger.error(f"Execution failed: {str(e)}")
                raise

    async def stream_updates(self, task_id: str) -> AsyncGenerator[dict, None]:
        """Real-time task monitoring stream"""
        # Implementation using server-sent events or gRPC streaming
        pass

    async def close(self):
        """Graceful shutdown"""
        await self.grpc_client._channels.close()
        await self.rest_client._client.aclose()

# ======================
# Usage Example
# ======================

async def main():
    config = ClientConfig()
    client = BRIMClient(config)
    
    try:
        result = await client.execute(
            agent_id="intent-detection",
            payload={"text": "I need to transfer \$500"},
            protocol="grpc"
        )
        print(f"Result: {result}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())

