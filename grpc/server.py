"""
Euouxe AI - Enterprise AI Agent Server
Combines gRPC and REST APIs with advanced security, observability, and cluster coordination
"""

import os
import logging
import asyncio
from typing import Dict, Optional, List, Tuple

# Core dependencies
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, BaseSettings, Field, AnyUrl, validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# gRPC/gRPC-Web support
import grpc
from grpc import aio
from grpc_reflection.v1alpha import reflection
from concurrent import futures

# Security
from cryptography.fernet import Fernet
from jose import JWTError, jwt
from passlib.context import CryptContext

# Monitoring
from prometheus_client import generate_latest, REGISTRY, Counter, Histogram, Gauge
from starlette_exporter import PrometheusMiddleware, handle_metrics

# Internal components
from .base_agent import BaseAgent
from .data_agent.cache_manager import CacheManager
from .data_agent.connectors.redis_connector import RedisPool

logger = logging.getLogger(__name__)

# ======================
# Configuration Models
# ======================

class ServerConfig(BaseSettings):
    # Network
    host: str = Field("0.0.0.0", env="BRIM_HOST")
    port: int = Field(8000, env="BRIM_PORT")
    grpc_port: int = Field(50051, env="BRIM_GRPC_PORT")
    
    # Security
    tls_cert: Optional[str] = Field(None, env="BRIM_TLS_CERT")
    tls_key: Optional[str] = Field(None, env="BRIM_TLS_KEY")
    jwt_secret: str = Field(..., env="BRIM_JWT_SECRET")
    fernet_key: str = Field(..., env="BRIM_FERNET_KEY")
    
    # Cluster
    node_id: str = Field("primary", env="BRIM_NODE_ID")
    cluster_seeds: List[str] = Field(["localhost:50051"], env="BRIM_CLUSTER_SEEDS")
    
    # Rate limiting
    rps_limit: int = Field(1000, env="BRIM_RPS_LIMIT")
    burst_limit: int = Field(100, env="BRIM_BURST_LIMIT")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# ======================
# Security Components
# ======================

class AuthHandler:
    def __init__(self, secret_key: str, fernet_key: str):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = secret_key
        self.fernet = Fernet(fernet_key.encode())
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    def encrypt_payload(self, payload: dict) -> str:
        return self.fernet.encrypt(json.dumps(payload).encode()).decode()

    def decrypt_payload(self, token: str) -> dict:
        return json.loads(self.fernet.decrypt(token.encode()))

    async def get_current_user(self, token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload.get("sub")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid credentials")

# ======================
# gRPC Service
# ======================

class AgentServiceServicer(agent_pb2_grpc.AgentServiceServicer):
    def __init__(self, cache: CacheManager, agents: Dict[str, BaseAgent]):
        self.cache = cache
        self.agents = agents
        self._lock = asyncio.Lock()
        
    async def ProcessTask(self, request, context):
        try:
            # Authentication
            metadata = dict(context.invocation_metadata())
            auth_handler.validate_grpc_token(metadata.get('authorization'))
            
            # Task processing
            async with self._lock:
                agent = self.agents.get(request.agent_id)
                if not agent:
                    context.abort(grpc.StatusCode.NOT_FOUND, "Agent not found")
                
                result = await agent.execute(request.payload)
                return agent_pb2.TaskResponse(
                    task_id=request.task_id,
                    payload=result.encrypted_payload
                )
        except Exception as e:
            logger.error(f"gRPC error: {str(e)}")
            context.abort(grpc.StatusCode.INTERNAL, str(e))

# ======================
# REST API
# ======================

app = FastAPI(
    title="BRIM Network Server",
    description="Enterprise AI Agent Orchestration API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    PrometheusMiddleware,
    app_name="brim_server",
    prefix="brim",
    buckets=[0.1, 0.5, 1, 5]
)

# Rate limiter
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# ======================
# Endpoints
# ======================

class TaskRequest(BaseModel):
    agent_id: str
    payload: dict
    priority: int = Field(1, ge=1, le=10)

class TaskResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[dict]

@app.post("/tasks", response_model=TaskResponse)
@limiter.limit("1000/minute")
async def create_task(
    request: Request,
    task: TaskRequest,
    background_tasks: BackgroundTasks,
    user: str = Depends(auth_handler.get_current_user)
):
    """Submit new task to agent pipeline"""
    try:
        task_id = generate_task_id()
        background_tasks.add_task(process_task, task_id, task.dict())
        return {"task_id": task_id, "status": "queued"}
    except Exception as e:
        logger.error(f"REST API error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(REGISTRY), media_type="text/plain")

# ======================
# Server Core
# ======================

class Server:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.agents: Dict[str, BaseAgent] = {}
        self.grpc_server: Optional[aio.Server] = None
        self.cache = CacheManager({
            'memory': MemoryCache(),
            'redis': RedisCache()
        })
        self.auth = AuthHandler(config.jwt_secret, config.fernet_key)
        
    async def register_agent(self, agent: BaseAgent):
        self.agents[agent.agent_id] = agent
        await agent.initialize()

    async def start(self):
        # Start gRPC server
        self.grpc_server = aio.server()
        agent_pb2_grpc.add_AgentServiceServicer_to_server(
            AgentServiceServicer(self.cache, self.agents),
            self.grpc_server
        )
        
        # Enable reflection
        SERVICE_NAMES = (
            agent_pb2.DESCRIPTOR.services_by_name['AgentService'].full_name,
            reflection.SERVICE_NAME,
        )
        reflection.enable_server_reflection(SERVICE_NAMES, self.grpc_server)
        
        # Listen on ports
        listen_addr = f'[::]:{self.config.grpc_port}'
        self.grpc_server.add_insecure_port(listen_addr)
        
        # Start servers
        await self.grpc_server.start()
        uvicorn_config = uvicorn.Config(
            app,
            host=self.config.host,
            port=self.config.port,
            ssl_keyfile=self.config.tls_key,
            ssl_certfile=self.config.tls_cert,
            workers=os.cpu_count() or 1
        )
        server = uvicorn.Server(uvicorn_config)
        await server.serve()

    async def graceful_shutdown(self):
        if self.grpc_server:
            await self.grpc_server.stop(5)
        for agent in self.agents.values():
            await agent.shutdown()

# ======================
# Entry Point
# ======================

if __name__ == "__main__":
    config = ServerConfig()
    server = Server(config)
    
    # Load agents dynamically
    from .intent_detection import IntentDetectionAgent
    from .entity_recognition import EntityRecognitionAgent
    
    server.register_agent(IntentDetectionAgent())
    server.register_agent(EntityRecognitionAgent())
    
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        loop.run_until_complete(server.graceful_shutdown())
    finally:
        loop.close()
