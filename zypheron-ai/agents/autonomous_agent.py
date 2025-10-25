"""
Autonomous AI Agent Framework
Self-directed AI agents that can plan and execute penetration tests
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from loguru import logger

from providers.manager import ai_manager
from providers.base import AIMessage
from analysis.vulnerability_analyzer import VulnerabilityAnalyzer, Vulnerability
from ml.vulnerability_predictor import MLVulnerabilityPredictor


class AgentState(str, Enum):
    """Agent execution states"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentAction:
    """Represents an action the agent can take"""
    action_type: str  # scan, exploit, analyze, report
    tool: str  # nmap, sqlmap, etc.
    parameters: Dict[str, Any]
    reasoning: str
    priority: int = 0
    estimated_duration: int = 60  # seconds
    dependencies: List[str] = field(default_factory=list)


@dataclass
class AgentTask:
    """High-level task for the agent"""
    task_id: str
    objective: str
    target: str
    scope: List[str]
    constraints: List[str]
    max_duration: int = 3600  # seconds
    ai_provider: str = "claude"


@dataclass
class AgentMemory:
    """Agent's memory of findings and context"""
    target: str
    discovered_services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    executed_actions: List[AgentAction] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    attack_paths: List[List[str]] = field(default_factory=list)


class AutonomousAgent:
    """
    Autonomous AI Pentesting Agent
    
    Can independently:
    - Plan attack strategies
    - Execute security tests
    - Analyze results
    - Adapt based on findings
    - Report vulnerabilities
    """
    
    def __init__(
        self,
        task: AgentTask,
        tool_executor: Optional[Callable] = None
    ):
        self.task = task
        self.tool_executor = tool_executor
        self.state = AgentState.IDLE
        self.memory = AgentMemory(target=task.target)
        self.action_queue: List[AgentAction] = []
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.ml_predictor = MLVulnerabilityPredictor()
        self.conversation_history: List[AIMessage] = []
    
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the agent's task autonomously
        
        Returns:
            Dictionary containing results and findings
        """
        logger.info(f"🤖 Autonomous Agent starting task: {self.task.objective}")
        logger.info(f"   Target: {self.task.target}")
        logger.info(f"   Scope: {', '.join(self.task.scope)}")
        
        try:
            # Phase 1: Planning
            self.state = AgentState.PLANNING
            await self._planning_phase()
            
            # Phase 2: Execution
            self.state = AgentState.EXECUTING
            await self._execution_phase()
            
            # Phase 3: Analysis
            self.state = AgentState.ANALYZING
            await self._analysis_phase()
            
            # Phase 4: Reporting
            self.state = AgentState.REPORTING
            results = await self._reporting_phase()
            
            self.state = AgentState.COMPLETED
            logger.info("🎯 Autonomous Agent completed successfully")
            
            return results
        
        except Exception as e:
            self.state = AgentState.FAILED
            logger.error(f"❌ Autonomous Agent failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'partial_results': {
                    'vulnerabilities': [v.__dict__ for v in self.memory.vulnerabilities],
                    'findings': self.memory.findings,
                }
            }
    
    async def _planning_phase(self):
        """Phase 1: Plan the penetration test strategy"""
        logger.info("📋 Planning Phase: Creating attack strategy...")
        
        # Build planning prompt
        messages = self._build_planning_messages()
        
        # Get AI to create a plan
        response = await ai_manager.chat(
            messages=messages,
            provider=self.task.ai_provider,
            temperature=0.7,
            max_tokens=2000
        )
        
        # Parse the plan into actions
        self.action_queue = self._parse_action_plan(response.content)
        
        logger.info(f"✓ Created plan with {len(self.action_queue)} actions")
        for i, action in enumerate(self.action_queue[:5], 1):
            logger.info(f"  {i}. {action.tool}: {action.reasoning[:60]}...")
    
    def _build_planning_messages(self) -> List[AIMessage]:
        """Build messages for planning phase"""
        return [
            AIMessage(
                role="system",
                content="""You are an expert penetration tester planning a security assessment.
Create a comprehensive, methodical plan that:
1. Follows ethical hacking best practices
2. Respects the scope and constraints
3. Maximizes vulnerability discovery
4. Minimizes target disruption
5. Prioritizes high-impact findings

Available tools: nmap, nikto, sqlmap, dirb, gobuster, wpscan, sslscan, whatweb

Output format:
ACTION: <tool>
PARAMETERS: <params>
REASONING: <why>
PRIORITY: <1-10>
---"""
            ),
            AIMessage(
                role="user",
                content=f"""Plan a penetration test:

Objective: {self.task.objective}
Target: {self.task.target}
Scope: {', '.join(self.task.scope)}
Constraints: {', '.join(self.task.constraints)}
Max Duration: {self.task.max_duration} seconds

Create a step-by-step plan."""
            )
        ]
    
    def _parse_action_plan(self, plan_text: str) -> List[AgentAction]:
        """Parse AI's plan into structured actions"""
        actions = []
        
        # Split by action delimiter
        action_blocks = plan_text.split('---')
        
        for i, block in enumerate(action_blocks):
            if not block.strip():
                continue
            
            # Extract action components
            action_dict = {}
            for line in block.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    action_dict[key.strip().lower()] = value.strip()
            
            if 'action' in action_dict:
                actions.append(AgentAction(
                    action_type='scan',  # Infer from tool
                    tool=action_dict.get('action', 'unknown'),
                    parameters=self._parse_parameters(action_dict.get('parameters', '')),
                    reasoning=action_dict.get('reasoning', 'No reasoning provided'),
                    priority=int(action_dict.get('priority', 5)),
                ))
        
        # Sort by priority
        actions.sort(key=lambda a: a.priority, reverse=True)
        
        return actions
    
    def _parse_parameters(self, param_str: str) -> Dict[str, Any]:
        """Parse parameter string into dictionary"""
        params = {'target': self.task.target}
        
        # Simple parsing - in production, use more robust method
        if 'port' in param_str.lower():
            params['ports'] = '1-1000'
        if 'aggressive' in param_str.lower():
            params['aggressive'] = True
        
        return params
    
    async def _execution_phase(self):
        """Phase 2: Execute planned actions"""
        logger.info(f"⚡ Execution Phase: Running {len(self.action_queue)} actions...")
        
        for i, action in enumerate(self.action_queue, 1):
            logger.info(f"  [{i}/{len(self.action_queue)}] Executing: {action.tool}")
            
            try:
                # Execute the action
                result = await self._execute_action(action)
                
                # Store in memory
                self.memory.executed_actions.append(action)
                
                # Analyze results immediately
                if result:
                    await self._analyze_action_result(action, result)
                
                # Adaptive planning: adjust strategy based on findings
                if self.memory.vulnerabilities:
                    await self._adapt_strategy()
            
            except Exception as e:
                logger.error(f"    ✗ Action failed: {e}")
                continue
    
    async def _execute_action(self, action: AgentAction) -> Optional[str]:
        """Execute a single action"""
        if not self.tool_executor:
            # Simulate execution for now
            logger.info(f"    ℹ Simulated: {action.tool} {action.parameters}")
            return f"Simulated output from {action.tool}"
        
        # Call the actual tool executor
        return await self.tool_executor(action.tool, action.parameters)
    
    async def _analyze_action_result(self, action: AgentAction, result: str):
        """Analyze the result of an action"""
        # Use vulnerability analyzer
        vulns = await self.vulnerability_analyzer.analyze_scan_output(
            scan_output=result,
            tool=action.tool,
            target=self.task.target,
            use_ai=True
        )
        
        if vulns:
            logger.info(f"    ✓ Found {len(vulns)} potential vulnerabilities")
            self.memory.vulnerabilities.extend(vulns)
            
            # Extract findings
            for vuln in vulns:
                finding = f"{vuln.severity.upper()}: {vuln.title}"
                self.memory.findings.append(finding)
    
    async def _adapt_strategy(self):
        """Adapt strategy based on findings (AI-driven)"""
        if len(self.memory.vulnerabilities) < 2:
            return
        
        # Ask AI if we should pivot our strategy
        recent_vulns = self.memory.vulnerabilities[-3:]
        vuln_summary = "\n".join([
            f"- {v.severity}: {v.title}"
            for v in recent_vulns
        ])
        
        messages = [
            AIMessage(
                role="system",
                content="You are adapting a penetration test strategy based on new findings."
            ),
            AIMessage(
                role="user",
                content=f"""We've discovered:
{vuln_summary}

Should we pivot our strategy? Suggest additional actions to pursue these findings.
Format as: ACTION: <tool> | REASONING: <why> | PRIORITY: <1-10>"""
            )
        ]
        
        try:
            response = await ai_manager.chat(
                messages=messages,
                provider=self.task.ai_provider,
                temperature=0.6,
                max_tokens=500
            )
            
            # Parse and add new actions
            new_actions = self._parse_action_plan(response.content)
            if new_actions:
                logger.info(f"    🔄 Adapting strategy: Adding {len(new_actions)} new actions")
                self.action_queue.extend(new_actions)
        
        except Exception as e:
            logger.debug(f"Strategy adaptation failed: {e}")
    
    async def _analysis_phase(self):
        """Phase 3: Deep analysis of all findings"""
        logger.info("🔍 Analysis Phase: Analyzing findings...")
        
        if not self.memory.vulnerabilities:
            logger.info("   No vulnerabilities found")
            return
        
        # ML vulnerability prediction
        scan_data = {
            'target': self.task.target,
            'services': self.memory.discovered_services,
            'vulnerabilities': [v.__dict__ for v in self.memory.vulnerabilities],
        }
        
        predictions = await self.ml_predictor.predict_vulnerabilities(scan_data)
        
        if predictions:
            logger.info(f"   ✓ ML predicted {len(predictions)} additional vulnerabilities")
            for pred in predictions[:3]:
                logger.info(f"     - {pred.vulnerability_type} (confidence: {pred.confidence:.2f})")
        
        # Attack path analysis
        await self._analyze_attack_paths()
    
    async def _analyze_attack_paths(self):
        """Analyze potential attack paths"""
        if not self.memory.vulnerabilities:
            return
        
        messages = [
            AIMessage(
                role="system",
                content="You are analyzing attack paths based on discovered vulnerabilities."
            ),
            AIMessage(
                role="user",
                content=f"""Vulnerabilities found:
{chr(10).join([f"- {v.severity}: {v.title} ({v.description[:80]})" for v in self.memory.vulnerabilities[:10]])}

Identify the most likely attack paths an attacker would use.
Output as numbered list of attack chains."""
            )
        ]
        
        try:
            response = await ai_manager.chat(
                messages=messages,
                provider=self.task.ai_provider,
                temperature=0.5,
            )
            
            # Parse attack paths (simplified)
            paths = [line.strip() for line in response.content.split('\n') if line.strip()]
            self.memory.attack_paths.append(paths)
            
            logger.info(f"   ✓ Identified {len(paths)} potential attack paths")
        
        except Exception as e:
            logger.debug(f"Attack path analysis failed: {e}")
    
    async def _reporting_phase(self) -> Dict[str, Any]:
        """Phase 4: Generate comprehensive report"""
        logger.info("📊 Reporting Phase: Generating report...")
        
        # Generate executive summary with AI
        executive_summary = await self._generate_executive_summary()
        
        # Prioritize vulnerabilities
        prioritized_vulns = self.vulnerability_analyzer.prioritize_vulnerabilities(
            self.memory.vulnerabilities
        )
        
        # Create detailed report
        report = {
            'status': 'completed',
            'task': {
                'objective': self.task.objective,
                'target': self.task.target,
                'scope': self.task.scope,
            },
            'executive_summary': executive_summary,
            'statistics': {
                'actions_executed': len(self.memory.executed_actions),
                'vulnerabilities_found': len(self.memory.vulnerabilities),
                'critical': sum(1 for v in prioritized_vulns if v.severity == 'critical'),
                'high': sum(1 for v in prioritized_vulns if v.severity == 'high'),
                'medium': sum(1 for v in prioritized_vulns if v.severity == 'medium'),
                'low': sum(1 for v in prioritized_vulns if v.severity == 'low'),
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'severity': v.severity,
                    'description': v.description,
                    'cvss_score': v.cvss_score,
                    'cve_id': v.cve_id,
                    'remediation': v.remediation,
                }
                for v in prioritized_vulns
            ],
            'attack_paths': self.memory.attack_paths,
            'findings': self.memory.findings,
        }
        
        logger.info("✓ Report generated")
        return report
    
    async def _generate_executive_summary(self) -> str:
        """Generate executive summary with AI"""
        if not self.memory.vulnerabilities:
            return "No significant vulnerabilities were identified during this assessment."
        
        vuln_summary = "\n".join([
            f"- {v.severity.upper()}: {v.title}"
            for v in self.memory.vulnerabilities[:10]
        ])
        
        messages = [
            AIMessage(
                role="system",
                content="You are writing an executive summary for a penetration test report."
            ),
            AIMessage(
                role="user",
                content=f"""Create a concise executive summary (3-4 sentences) for:

Target: {self.task.target}
Objective: {self.task.objective}

Key Findings:
{vuln_summary}

Focus on business risk and recommended actions."""
            )
        ]
        
        try:
            response = await ai_manager.chat(
                messages=messages,
                provider=self.task.ai_provider,
                temperature=0.5,
                max_tokens=300
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return f"Assessment of {self.task.target} identified {len(self.memory.vulnerabilities)} potential security issues."


class AgentOrchestrator:
    """Manages multiple autonomous agents"""
    
    def __init__(self):
        self.agents: Dict[str, AutonomousAgent] = {}
    
    async def create_agent(self, task: AgentTask) -> str:
        """Create and start a new agent"""
        agent = AutonomousAgent(task)
        self.agents[task.task_id] = agent
        
        # Start agent execution in background
        asyncio.create_task(agent.execute())
        
        return task.task_id
    
    def get_agent_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get agent status"""
        agent = self.agents.get(task_id)
        if not agent:
            return None
        
        return {
            'task_id': task_id,
            'state': agent.state.value,
            'objective': agent.task.objective,
            'vulnerabilities_found': len(agent.memory.vulnerabilities),
            'actions_executed': len(agent.memory.executed_actions),
        }
    
    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents"""
        return [
            self.get_agent_status(task_id)
            for task_id in self.agents.keys()
        ]

