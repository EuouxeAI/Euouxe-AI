"""
Euouxe AI - Base Agent Class
Defines the abstract foundation for all AI agents in the framework.
"""

from __future__ import annotations
import abc
import logging
import time
from typing import Optional, Dict, Any, Type, Callable, Coroutine
from pydantic import BaseModel, ValidationError
from cryptography.fernet import Fernet
import requests
from prometheus_client import Counter, Gauge, Histogram
import redis
import json

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Prometheus metrics
AGENT_START_COUNTER = Counter('agent_start_total', 'Total agent startups')
TASK_PROCESSED_COUNTER = Counter('agent_tasks_processed', 'Tasks processed', ['agent_type', 'status'])
HEARTBEAT_GAUGE = Gauge('agent_heartbeat', 'Agent liveness status')
TASK_LATENCY = Histogram('agent_task_latency_seconds', 'Task processing latency', buckets=[0.1, 0.5, 1, 5])

class AgentConfig(BaseModel):
    """Pydantic model for agent configuration validation"""
    agent_id: str
    agent_type: str
    heartbeat_interval: int = 30
    max_retries: int = 3
    encryption_key: Optional[str] = None
    api_endpoint: Optional[str] = None
    redis_host: str = 'localhost'
    redis_port: int = 6379

class TaskPayload(BaseModel):
    """Base model for task input validation"""
    task_id: str
    parameters: Dict[str, Any]
    metadata: Dict[str, str] = {}

class AgentException(Exception):
    """Base exception for agent-related errors"""
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable

class BaseAgent(abc.ABC):
    """Abstract base class for all BRIM Network agents"""
    
    def __init__(self, config: AgentConfig):
        self._validate_config(config)
        self.config = config
        self._heartbeat_active = False
        self._redis_conn = redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            decode_responses=True
        )
        self._setup_encryption()
        self._register_service_discovery()
        
        # Initialize hooks
        self.pre_task_hooks: list[Callable] = []
        self.post_task_hooks: list[Callable] = []

    def _validate_config(self, config: AgentConfig) -> None:
        """Validate configuration with Pydantic"""
        if not isinstance(config, AgentConfig):
            raise AgentException("Invalid configuration type")
        
    def _setup_encryption(self) -> None:
        """Initialize Fernet encryption if key provided"""
        if self.config.encryption_key:
            try:
                self.cipher_suite = Fernet(self.config.encryption_key.encode())
            except Exception as e:
                logger.error(f"Encryption setup failed: {str(e)}")
                raise AgentException("Invalid encryption key format") from e

    def _register_service_discovery(self) -> None:
        """Register agent with central service registry"""
        if self.config.api_endpoint:
            try:
                response = requests.post(
                    f"{self.config.api_endpoint}/register",
                    json={
                        "agent_id": self.config.agent_id,
                        "type": self.config.agent_type,
                        "status": "initializing"
                    },
                    timeout=5
                )
                response.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"Service registration failed: {str(e)}")
                raise AgentException("Service discovery unavailable")

    @abc.abstractmethod
    async def execute_task(self, payload: TaskPayload) -> Dict[str, Any]:
        """Abstract method to be implemented by concrete agents"""
        pass

    @TASK_LATENCY.time()
    def process_task(self, raw_payload: str) -> Dict[str, Any]:
        """Main task processing pipeline with validation and encryption"""
        try:
            # Decrypt payload if needed
            if self.config.encryption_key:
                raw_payload = self.cipher_suite.decrypt(raw_payload.encode()).decode()

            # Validate input schema
            payload_dict = json.loads(raw_payload)
            task_payload = TaskPayload(**payload_dict)

            # Run pre-task hooks
            for hook in self.pre_task_hooks:
                hook(task_payload)

            # Execute concrete implementation
            result = self._execute_with_retry(task_payload)

            # Run post-task hooks
            for hook in self.post_task_hooks:
                hook(result)

            TASK_PROCESSED_COUNTER.labels(
                agent_type=self.config.agent_type,
                status="success"
            ).inc()
            return result

        except ValidationError as e:
            logger.error(f"Payload validation failed: {str(e)}")
            TASK_PROCESSED_COUNTER.labels(
                agent_type=self.config.agent_type,
                status="validation_error"
            ).inc()
            raise AgentException("Invalid task payload format")
        except Exception as e:
            logger.error(f"Task processing failed: {str(e)}")
            TASK_PROCESSED_COUNTER.labels(
                agent_type=self.config.agent_type,
                status="error"
            ).inc()
            raise

    def _execute_with_retry(self, payload: TaskPayload) -> Any:
        """Retry wrapper with exponential backoff"""
        for attempt in range(self.config.max_retries):
            try:
                return self.execute_task(payload)
            except AgentException as e:
                if not e.retryable or attempt == self.config.max_retries - 1:
                    raise
                wait_time = 2 ** attempt
                logger.warning(f"Retryable error: {str(e)}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
        raise AgentException("Max retries exceeded")

    def start_heartbeat(self) -> None:
        """Initialize periodic health reporting"""
        self._heartbeat_active = True
        while self._heartbeat_active:
            try:
                self._redis_conn.setex(
                    f"agent:{self.config.agent_id}:heartbeat",
                    self.config.heartbeat_interval * 2,
                    time.time()
                )
                HEARTBEAT_GAUGE.set(1)
                time.sleep(self.config.heartbeat_interval)
            except redis.RedisError as e:
                logger.error(f"Heartbeat failed: {str(e)}")
                HEARTBEAT_GAUGE.set(0)
                raise AgentException("Heartbeat service unavailable")

    def stop(self) -> None:
        """Graceful shutdown procedure"""
        self._heartbeat_active = False
        self._redis_conn.close()
        logger.info(f"Agent {self.config.agent_id} shut down successfully")
        AGENT_START_COUNTER.inc()

    def add_hook(self, hook_type: str, hook_fn: Callable) -> None:
        """Add pre/post task processing hooks"""
        if hook_type == 'pre':
            self.pre_task_hooks.append(hook_fn)
        elif hook_type == 'post':
            self.post_task_hooks.append(hook_fn)
        else:
            raise ValueError("Invalid hook type")

    @classmethod
    def from_env(cls: Type[BaseAgent]) -> BaseAgent:
        """Factory method for environment-based configuration"""
        config = AgentConfig(
            agent_id=os.getenv('AGENT_ID'),
            agent_type=os.getenv('AGENT_TYPE'),
            encryption_key=os.getenv('ENCRYPTION_KEY')
        )
        return cls(config)

# Example concrete agent implementation
class ExampleAgent(BaseAgent):
    async def execute_task(self, payload: TaskPayload) -> Dict[str, Any]:
        """Concrete task implementation"""
        return {"result": f"Processed {payload.task_id} with params {payload.parameters}"}
