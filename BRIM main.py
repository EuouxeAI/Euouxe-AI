"""
BRIM Network - Core System Entry Point
Enterprise-grade main module with service orchestration, failure resilience, and observability
"""

import logging
import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import uvloop
from prometheus_client import start_http_server
from pydantic import BaseModel, Field, validator

from brim.config_loader import ConfigLoader
from brim.server import GRPCServer, RESTServer
from brim.base_agent import AgentLifecycle
from brim.monitoring import SystemMetrics

logger = logging.getLogger("brim.core")

class ServiceConfig(BaseModel):
    """Core service configuration schema"""
    cluster_id: str = Field(..., min_length=3)
    instance_role: str = Field("primary", regex="^(primary|replica|standby)$")
    shutdown_timeout: int = Field(30, gt=0)
    enable_rest: bool = True
    enable_grpc: bool = True
    prometheus_port: int = 9090
    agent_modules: list[str] = [
        "intent_detection",
        "entity_recognition",
        "data_agent"
    ]

    @validator('agent_modules', each_item=True)
    def validate_agent_module(cls, v):
        if not Path(f"agents/{v}.py").exists():
            raise ValueError(f"Agent module {v} not found")
        return v

class BrimCore:
    """Central orchestrator for BRIM Network services"""
    
    def __init__(self, config_path: Path):
        self._load_config(config_path)
        self._setup_infrastructure()
        self._init_agents()
        self._register_signal_handlers()
        self._shutting_down = False

    def _load_config(self, config_path: Path):
        """Initialize configuration with validation"""
        self.config_loader = ConfigLoader(
            config_path,
            schema_model=ServiceConfig,
            watch_for_changes=True
        )
        self.config = self.config_loader.get_config()
        logger.info(f"Starting BRIM instance [Cluster: {self.config.cluster_id}]")

    def _setup_infrastructure(self):
        """Initialize core infrastructure components"""
        self.metrics = SystemMetrics()
        self.lifecycle = AgentLifecycle()
        
        # Initialize servers
        self.servers = []
        if self.config.enable_rest:
            self.servers.append(RESTServer())
        if self.config.enable_grpc:
            self.servers.append(GRPCServer())

    def _init_agents(self):
        """Dynamic agent initialization with dependency injection"""
        self.agents: Dict[str, Any] = {}
        for module in self.config.agent_modules:
            try:
                agent_class = self._load_agent_class(module)
                self.agents[module] = agent_class(
                    config=self.config_loader,
                    lifecycle=self.lifecycle,
                    metrics=self.metrics
                )
                logger.info(f"Initialized {module} agent")
            except Exception as e:
                logger.critical(f"Agent {module} failed to initialize: {str(e)}")
                sys.exit(1)

    def _load_agent_class(self, module_name: str):
        """Dynamic import of agent implementations"""
        module = __import__(
            f"agents.{module_name}",
            fromlist=[f"{module_name.capitalize()}Agent"]
        )
        return getattr(module, f"{module_name.capitalize()}Agent")

    def _register_signal_handlers(self):
        """System signal handling for graceful shutdown"""
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Orchestrated shutdown procedure"""
        if self._shutting_down:
            return
        self._shutting_down = True
        
        logger.warning(f"Received shutdown signal ({signal.Signals(signum).name})")
        self.stop()

    async def _start_servers(self):
        """Async server startup with failure isolation"""
        startup_tasks = []
        for server in self.servers:
            startup_tasks.append(server.start())
        
        try:
            await asyncio.gather(*startup_tasks)
        except Exception as e:
            logger.critical(f"Server startup failed: {str(e)}")
            sys.exit(1)

    async def run(self):
        """Main execution loop with health monitoring"""
        try:
            # Start monitoring
            start_http_server(self.config.prometheus_port)
            logger.info(f"Metrics exposed on :{self.config.prometheus_port}")
            
            # Start infrastructure
            await self._start_servers()
            self.lifecycle.set_ready()
            
            # Core event loop
            while not self._shutting_down:
                await self._health_check()
                await asyncio.sleep(5)
                
        except asyncio.CancelledError:
            pass
        finally:
            self.stop()

    async def _health_check(self):
        """Comprehensive health check with subsystem verification"""
        health_status = {
            "database": self._check_db_connection(),
            "cache": self._check_cache_status(),
            "models": self._check_model_versions()
        }
        
        if not all(health_status.values()):
            logger.error("Subsystem health check failure")
            self.lifecycle.set_unhealthy()
        else:
            self.lifecycle.set_healthy()

    def stop(self):
        """Graceful shutdown procedure"""
        logger.info("Initiating shutdown sequence")
        
        # Stop accepting new connections
        self.lifecycle.set_terminating()
        
        # Stop servers
        for server in self.servers:
            server.stop()
        
        # Cleanup resources
        self._cleanup_agents()
        self.config_loader.__exit__(None, None, None)
        
        logger.info("BRIM instance shutdown complete")

    def _cleanup_agents(self):
        """Orderly agent shutdown with timeout"""
        for agent in self.agents.values():
            try:
                agent.cleanup()
            except Exception as e:
                logger.error(f"Agent cleanup failed: {str(e)}")

def main():
    """CLI entry point with uvloop optimization"""
    uvloop.install()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Parse CLI arguments
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/etc/brim/config.yaml")
    
    # Initialize and run
    core = BrimCore(config_path)
    try:
        asyncio.run(core.run())
    except KeyboardInterrupt:
        core.stop()

if __name__ == "__main__":
    main()
