"""
Scan Agent - Worker node for distributed scanning
"""

import logging
import asyncio
import uuid
import platform
import psutil
from dataclasses import dataclass
from typing import Dict, Optional, Any, Callable
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent status"""
    OFFLINE = "offline"
    STARTING = "starting"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"


@dataclass
class AgentConfig:
    """Agent configuration"""
    coordinator_host: str
    coordinator_port: int = 8765
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    max_concurrent_tasks: int = 5
    heartbeat_interval: int = 30
    supported_tools: list = None
    
    def __post_init__(self):
        if not self.agent_id:
            self.agent_id = str(uuid.uuid4())
        if not self.hostname:
            self.hostname = platform.node()
        if self.supported_tools is None:
            self.supported_tools = [
                'nmap', 'nikto', 'nuclei', 'masscan', 'sqlmap',
                'gobuster', 'ffuf', 'subfinder'
            ]


class ScanAgent:
    """
    Distributed Scan Agent
    
    Features:
    - Connect to coordinator
    - Receive and execute tasks
    - Report results
    - Health monitoring
    - Resource management
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.status = AgentStatus.OFFLINE
        self.current_tasks: Dict[str, asyncio.Task] = {}
        self.task_executors: Dict[str, Callable] = {}
        
        self.running = False
        self._heartbeat_task = None
        self._task_receiver = None
        
    async def start(self):
        """Start the agent"""
        if self.running:
            logger.warning("Agent already running")
            return
        
        logger.info(f"Starting agent {self.config.agent_id}")
        self.status = AgentStatus.STARTING
        self.running = True
        
        try:
            # Connect to coordinator
            await self._connect_to_coordinator()
            
            # Register with coordinator
            await self._register()
            
            # Start background tasks
            self._heartbeat_task = asyncio.create_task(self._send_heartbeat())
            self._task_receiver = asyncio.create_task(self._receive_tasks())
            
            self.status = AgentStatus.READY
            logger.info(f"Agent {self.config.agent_id} ready")
            
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")
            self.status = AgentStatus.ERROR
            raise
    
    async def stop(self):
        """Stop the agent"""
        logger.info("Stopping agent")
        self.running = False
        self.status = AgentStatus.OFFLINE
        
        # Cancel all tasks
        for task_id, task in self.current_tasks.items():
            task.cancel()
            logger.info(f"Cancelled task {task_id}")
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._task_receiver:
            self._task_receiver.cancel()
        
        # Unregister from coordinator
        await self._unregister()
    
    async def _connect_to_coordinator(self):
        """Connect to coordinator"""
        logger.info(
            f"Connecting to coordinator at "
            f"{self.config.coordinator_host}:{self.config.coordinator_port}"
        )
        # Implement network connection
        # This would use WebSocket or similar
        pass
    
    async def _register(self):
        """Register with coordinator"""
        registration_data = {
            'agent_id': self.config.agent_id,
            'hostname': self.config.hostname,
            'ip_address': self._get_ip_address(),
            'supported_tools': self.config.supported_tools,
            'max_concurrent_tasks': self.config.max_concurrent_tasks
        }
        
        logger.info(f"Registering with coordinator: {registration_data}")
        # Send registration to coordinator
        pass
    
    async def _unregister(self):
        """Unregister from coordinator"""
        logger.info("Unregistering from coordinator")
        # Send unregistration to coordinator
        pass
    
    def _get_ip_address(self) -> str:
        """Get agent's IP address"""
        import socket
        try:
            # Connect to external host to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    async def _send_heartbeat(self):
        """Send periodic heartbeat to coordinator"""
        logger.info("Heartbeat sender started")
        
        while self.running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                
                metrics = self._get_metrics()
                
                heartbeat_data = {
                    'agent_id': self.config.agent_id,
                    'timestamp': datetime.now().isoformat(),
                    'status': self.status.value,
                    'current_tasks': len(self.current_tasks),
                    'metrics': metrics
                }
                
                # Send to coordinator
                logger.debug(f"Sending heartbeat: {metrics}")
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    def _get_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        try:
            return {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv
                }
            }
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {}
    
    async def _receive_tasks(self):
        """Receive tasks from coordinator"""
        logger.info("Task receiver started")
        
        while self.running:
            try:
                # Receive task from coordinator
                # This would use the network connection
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Task receiver error: {e}")
    
    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a scan task
        
        Args:
            task_data: Task information from coordinator
            
        Returns:
            Task result
        """
        task_id = task_data.get('task_id')
        scan_type = task_data.get('scan_type')
        target = task_data.get('target')
        parameters = task_data.get('parameters', {})
        
        logger.info(f"Executing task {task_id}: {scan_type} on {target}")
        
        try:
            # Update status
            self.status = AgentStatus.BUSY
            
            # Execute based on scan type
            if scan_type in self.task_executors:
                executor = self.task_executors[scan_type]
                result = await executor(target, parameters)
            else:
                result = await self._execute_generic(scan_type, target, parameters)
            
            # Send result to coordinator
            result_data = {
                'task_id': task_id,
                'agent_id': self.config.agent_id,
                'status': 'completed',
                'result': result,
                'completed_at': datetime.now().isoformat()
            }
            
            await self._send_result(result_data)
            
            return result_data
            
        except Exception as e:
            logger.error(f"Task execution failed: {e}", exc_info=True)
            
            error_result = {
                'task_id': task_id,
                'agent_id': self.config.agent_id,
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.now().isoformat()
            }
            
            await self._send_result(error_result)
            return error_result
            
        finally:
            # Update status
            if len(self.current_tasks) == 0:
                self.status = AgentStatus.READY
    
    async def _execute_generic(
        self,
        tool: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute generic tool scan"""
        logger.info(f"Executing {tool} on {target}")
        
        # Build command
        command = [tool]
        
        # Add tool-specific arguments
        if tool == 'nmap':
            command.extend(['-sV', '-sC', target])
        elif tool == 'nikto':
            command.extend(['-h', target])
        elif tool == 'nuclei':
            command.extend(['-u', target])
        
        # Add custom parameters
        for key, value in parameters.items():
            if value is True:
                command.append(f"--{key}")
            elif value:
                command.extend([f"--{key}", str(value)])
        
        # Execute command
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                'tool': tool,
                'target': target,
                'return_code': process.returncode,
                'stdout': stdout.decode('utf-8', errors='replace'),
                'stderr': stderr.decode('utf-8', errors='replace')
            }
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                'tool': tool,
                'target': target,
                'error': str(e)
            }
    
    async def _send_result(self, result_data: Dict[str, Any]):
        """Send task result to coordinator"""
        logger.info(f"Sending result for task {result_data.get('task_id')}")
        # Send via network to coordinator
        pass
    
    def register_executor(
        self,
        scan_type: str,
        executor: Callable
    ):
        """Register custom task executor"""
        self.task_executors[scan_type] = executor
        logger.info(f"Registered executor for {scan_type}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            'agent_id': self.config.agent_id,
            'hostname': self.config.hostname,
            'status': self.status.value,
            'current_tasks': len(self.current_tasks),
            'max_concurrent': self.config.max_concurrent_tasks,
            'metrics': self._get_metrics()
        }

