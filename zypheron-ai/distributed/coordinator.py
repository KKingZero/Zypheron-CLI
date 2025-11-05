"""
Scan Coordinator - Orchestrates distributed scanning across multiple agents
"""

import logging
import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Scan task status"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanTask:
    """Distributed scan task"""
    task_id: str
    target: str
    scan_type: str  # nmap, nikto, nuclei, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Assignment
    assigned_agent: Optional[str] = None
    assigned_at: Optional[datetime] = None
    
    # Execution
    status: TaskStatus = TaskStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Priority and constraints
    priority: int = 5  # 1-10, higher is more urgent
    max_retries: int = 3
    retry_count: int = 0
    timeout: int = 300
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'task_id': self.task_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'parameters': self.parameters,
            'assigned_agent': self.assigned_agent,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'status': self.status.value,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'result': self.result,
            'error': self.error,
            'priority': self.priority,
            'retry_count': self.retry_count,
            'depends_on': self.depends_on
        }


@dataclass
class AgentInfo:
    """Information about a scan agent"""
    agent_id: str
    hostname: str
    ip_address: str
    
    # Capabilities
    supported_tools: List[str] = field(default_factory=list)
    max_concurrent_tasks: int = 5
    
    # Status
    online: bool = True
    last_heartbeat: Optional[datetime] = None
    current_tasks: Set[str] = field(default_factory=set)
    
    # Performance metrics
    completed_tasks: int = 0
    failed_tasks: int = 0
    average_task_duration: float = 0.0
    
    # Load
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    
    def is_available(self) -> bool:
        """Check if agent can accept new tasks"""
        return (
            self.online and
            len(self.current_tasks) < self.max_concurrent_tasks
        )
    
    def load_score(self) -> float:
        """Calculate agent load score (lower is better)"""
        task_load = len(self.current_tasks) / self.max_concurrent_tasks
        resource_load = (self.cpu_usage + self.memory_usage) / 200
        return (task_load * 0.6) + (resource_load * 0.4)


class ScanCoordinator:
    """
    Distributed Scan Coordinator
    
    Features:
    - Task distribution across multiple agents
    - Load balancing
    - Fault tolerance and retries
    - Task dependencies
    - Result aggregation
    - Health monitoring
    """
    
    def __init__(self):
        self.agents: Dict[str, AgentInfo] = {}
        self.tasks: Dict[str, ScanTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.result_queue: asyncio.Queue = asyncio.Queue()
        
        self.coordinator_id = str(uuid.uuid4())
        self.running = False
        
        # Background tasks
        self._task_scheduler = None
        self._health_monitor = None
        self._result_collector = None
    
    async def start(self):
        """Start the coordinator"""
        if self.running:
            logger.warning("Coordinator already running")
            return
        
        self.running = True
        logger.info(f"Starting coordinator {self.coordinator_id}")
        
        # Start background tasks
        self._task_scheduler = asyncio.create_task(self._schedule_tasks())
        self._health_monitor = asyncio.create_task(self._monitor_health())
        self._result_collector = asyncio.create_task(self._collect_results())
    
    async def stop(self):
        """Stop the coordinator"""
        logger.info("Stopping coordinator")
        self.running = False
        
        # Cancel background tasks
        if self._task_scheduler:
            self._task_scheduler.cancel()
        if self._health_monitor:
            self._health_monitor.cancel()
        if self._result_collector:
            self._result_collector.cancel()
    
    def register_agent(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str,
        supported_tools: List[str],
        max_concurrent_tasks: int = 5
    ) -> bool:
        """Register a new scan agent"""
        if agent_id in self.agents:
            logger.warning(f"Agent {agent_id} already registered")
            return False
        
        agent = AgentInfo(
            agent_id=agent_id,
            hostname=hostname,
            ip_address=ip_address,
            supported_tools=supported_tools,
            max_concurrent_tasks=max_concurrent_tasks,
            last_heartbeat=datetime.now()
        )
        
        self.agents[agent_id] = agent
        logger.info(f"Registered agent {agent_id} ({hostname})")
        return True
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        
        # Reassign tasks from this agent
        for task_id in agent.current_tasks:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.assigned_agent = None
                task.status = TaskStatus.PENDING
                asyncio.create_task(self.task_queue.put(task))
        
        del self.agents[agent_id]
        logger.info(f"Unregistered agent {agent_id}")
        return True
    
    def heartbeat(self, agent_id: str, metrics: Optional[Dict[str, Any]] = None) -> bool:
        """Receive agent heartbeat"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        agent.last_heartbeat = datetime.now()
        agent.online = True
        
        if metrics:
            agent.cpu_usage = metrics.get('cpu_usage', 0.0)
            agent.memory_usage = metrics.get('memory_usage', 0.0)
        
        return True
    
    async def submit_task(
        self,
        target: str,
        scan_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        priority: int = 5,
        depends_on: Optional[List[str]] = None
    ) -> str:
        """Submit a new scan task"""
        task_id = str(uuid.uuid4())
        
        task = ScanTask(
            task_id=task_id,
            target=target,
            scan_type=scan_type,
            parameters=parameters or {},
            priority=priority,
            depends_on=depends_on or []
        )
        
        self.tasks[task_id] = task
        await self.task_queue.put(task)
        
        logger.info(f"Submitted task {task_id}: {scan_type} on {target}")
        return task_id
    
    async def submit_campaign(
        self,
        targets: List[str],
        scan_types: List[str],
        parameters: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Submit a campaign of related scans"""
        task_ids = []
        
        for target in targets:
            for scan_type in scan_types:
                task_id = await self.submit_task(
                    target=target,
                    scan_type=scan_type,
                    parameters=parameters
                )
                task_ids.append(task_id)
        
        logger.info(f"Submitted campaign with {len(task_ids)} tasks")
        return task_ids
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get status of a task"""
        task = self.tasks.get(task_id)
        return task.status if task else None
    
    def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get result of completed task"""
        task = self.tasks.get(task_id)
        if task and task.status == TaskStatus.COMPLETED:
            return task.result
        return None
    
    async def _schedule_tasks(self):
        """Background task scheduler"""
        logger.info("Task scheduler started")
        
        while self.running:
            try:
                # Get next task from queue
                task = await asyncio.wait_for(
                    self.task_queue.get(),
                    timeout=1.0
                )
                
                # Check dependencies
                if not self._check_dependencies(task):
                    # Put back in queue
                    await asyncio.sleep(1)
                    await self.task_queue.put(task)
                    continue
                
                # Find best agent for task
                agent = self._select_agent(task)
                
                if agent:
                    # Assign task to agent
                    task.assigned_agent = agent.agent_id
                    task.assigned_at = datetime.now()
                    task.status = TaskStatus.ASSIGNED
                    
                    agent.current_tasks.add(task.task_id)
                    
                    logger.info(
                        f"Assigned task {task.task_id} to agent {agent.agent_id}"
                    )
                    
                    # Notify agent (implement agent communication)
                    asyncio.create_task(self._notify_agent(agent, task))
                else:
                    # No available agent, put back in queue
                    await asyncio.sleep(2)
                    await self.task_queue.put(task)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Scheduler error: {e}", exc_info=True)
    
    def _check_dependencies(self, task: ScanTask) -> bool:
        """Check if task dependencies are satisfied"""
        for dep_id in task.depends_on:
            dep_task = self.tasks.get(dep_id)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False
        return True
    
    def _select_agent(self, task: ScanTask) -> Optional[AgentInfo]:
        """Select best agent for task using load balancing"""
        # Filter agents that support this tool
        capable_agents = [
            agent for agent in self.agents.values()
            if (agent.is_available() and
                task.scan_type in agent.supported_tools)
        ]
        
        if not capable_agents:
            return None
        
        # Select agent with lowest load
        best_agent = min(capable_agents, key=lambda a: a.load_score())
        return best_agent
    
    async def _notify_agent(self, agent: AgentInfo, task: ScanTask):
        """Notify agent of new task assignment"""
        # Implement agent notification via network
        # This would use the NetworkManager
        logger.debug(f"Notifying agent {agent.agent_id} of task {task.task_id}")
        pass
    
    async def _monitor_health(self):
        """Monitor agent health"""
        logger.info("Health monitor started")
        
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                now = datetime.now()
                for agent_id, agent in list(self.agents.items()):
                    if agent.last_heartbeat:
                        # Check if heartbeat is too old (2 minutes)
                        age = (now - agent.last_heartbeat).total_seconds()
                        if age > 120:
                            logger.warning(f"Agent {agent_id} heartbeat timeout")
                            agent.online = False
                            
                            # Reassign tasks
                            for task_id in list(agent.current_tasks):
                                await self._reassign_task(task_id)
                                
            except Exception as e:
                logger.error(f"Health monitor error: {e}", exc_info=True)
    
    async def _reassign_task(self, task_id: str):
        """Reassign a failed task"""
        task = self.tasks.get(task_id)
        if not task:
            return
        
        # Remove from current agent
        if task.assigned_agent and task.assigned_agent in self.agents:
            agent = self.agents[task.assigned_agent]
            agent.current_tasks.discard(task_id)
        
        # Check retry limit
        task.retry_count += 1
        if task.retry_count > task.max_retries:
            task.status = TaskStatus.FAILED
            task.error = "Max retries exceeded"
            logger.error(f"Task {task_id} failed after {task.retry_count} retries")
            return
        
        # Put back in queue
        task.assigned_agent = None
        task.status = TaskStatus.PENDING
        await self.task_queue.put(task)
        logger.info(f"Reassigned task {task_id} (retry {task.retry_count})")
    
    async def _collect_results(self):
        """Collect results from agents"""
        logger.info("Result collector started")
        
        while self.running:
            try:
                # Get result from queue
                result_data = await asyncio.wait_for(
                    self.result_queue.get(),
                    timeout=1.0
                )
                
                task_id = result_data.get('task_id')
                task = self.tasks.get(task_id)
                
                if task:
                    task.status = TaskStatus.COMPLETED
                    task.completed_at = datetime.now()
                    task.result = result_data.get('result')
                    
                    # Update agent stats
                    if task.assigned_agent and task.assigned_agent in self.agents:
                        agent = self.agents[task.assigned_agent]
                        agent.current_tasks.discard(task_id)
                        agent.completed_tasks += 1
                        
                        if task.started_at and task.completed_at:
                            duration = (task.completed_at - task.started_at).total_seconds()
                            # Update moving average
                            n = agent.completed_tasks
                            agent.average_task_duration = (
                                (agent.average_task_duration * (n - 1) + duration) / n
                            )
                    
                    logger.info(f"Collected result for task {task_id}")
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Result collector error: {e}", exc_info=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get coordinator statistics"""
        total_tasks = len(self.tasks)
        completed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED)
        running = sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING)
        failed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED)
        
        return {
            'coordinator_id': self.coordinator_id,
            'agents': {
                'total': len(self.agents),
                'online': sum(1 for a in self.agents.values() if a.online),
                'offline': sum(1 for a in self.agents.values() if not a.online)
            },
            'tasks': {
                'total': total_tasks,
                'pending': sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING),
                'running': running,
                'completed': completed,
                'failed': failed
            },
            'queue_size': self.task_queue.qsize()
        }
    
    def get_agent_list(self) -> List[Dict[str, Any]]:
        """Get list of all agents"""
        return [
            {
                'agent_id': agent.agent_id,
                'hostname': agent.hostname,
                'ip_address': agent.ip_address,
                'online': agent.online,
                'current_tasks': len(agent.current_tasks),
                'max_concurrent': agent.max_concurrent_tasks,
                'completed_tasks': agent.completed_tasks,
                'failed_tasks': agent.failed_tasks,
                'load_score': agent.load_score()
            }
            for agent in self.agents.values()
        ]

