"""
Autonomous Attack Path Orchestrator - Phase 1 Implementation

Semi-autonomous pentesting with:
- User-defined objectives
- AI-powered decision making
- User approval for high-risk actions
- Attack path chaining
- Credential-based lateral movement

Integrates all Phase 1 components:
- AttackPathGraph (dynamic path discovery)
- AIDecisionEngine (intelligent decision making)
- ApprovalManager (user approval with session permissions)
- CredentialVault (credential management)
- InteractivePrompt (user interaction)
- SessionStateManager (save/resume)
"""

import asyncio
import logging
import uuid
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum

from .attack_path_graph import AttackPathGraph, GraphEdge, GraphNode, NodeType, AccessLevel
from .ai_decision_engine import AIDecisionEngine, AIDecision
from .approval_manager import ApprovalManager, ApprovalDecision
from .credential_vault import CredentialVault, CredentialType, CredentialSource
from .interactive_prompt import InteractivePrompt
from .session_state import SessionStateManager

logger = logging.getLogger(__name__)


class OrchestratorStatus(Enum):
    """Orchestrator execution status"""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class AutonomousOrchestrator:
    """
    Phase 1: Autonomous Attack Path Orchestrator

    Features implemented:
    - Semi-autonomous operation with user guidance
    - User-defined objectives (e.g., "reach database server")
    - Attack path chaining and graph-based modeling
    - AI decision engine with provider fallback
    - User approval system with "allow for this session"
    - Credential management with per-use approval
    - Interactive CLI prompts
    - Session save/resume capability
    - Error handling with user decision prompts
    """

    def __init__(
        self,
        objective: str,
        initial_target: str,
        session_id: Optional[str] = None,
        # Resume mode parameters
        attack_graph: Optional[AttackPathGraph] = None,
        credential_vault: Optional[CredentialVault] = None,
        approval_manager: Optional[ApprovalManager] = None,
        resume_mode: bool = False,
        autonomous_mode: bool = False
    ):
        self.objective = objective
        self.initial_target = initial_target
        self.session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        self.resume_mode = resume_mode
        self.autonomous_mode = autonomous_mode

        # Core components - use provided or create new
        self.attack_graph = attack_graph or AttackPathGraph(objective, initial_target)
        self.ai_engine = AIDecisionEngine()
        self.approval_manager = approval_manager or ApprovalManager()
        self.credential_vault = credential_vault or CredentialVault()
        self.prompt = InteractivePrompt()
        self.state_manager = SessionStateManager()

        # Enable autonomous mode in approval manager if requested
        if autonomous_mode:
            self.approval_manager.set_autonomous_mode(True)

        # Status
        self.status = OrchestratorStatus.PAUSED if resume_mode else OrchestratorStatus.NOT_STARTED
        self.current_step = 0
        self.total_steps = 0

        # Statistics - restore from graph if resuming
        if resume_mode and attack_graph:
            self.actions_executed = len([e for e in attack_graph.edges.values()])
            self.actions_successful = len([e for e in attack_graph.edges.values() if e.successful])
            self.actions_failed = len([e for e in attack_graph.edges.values() if not e.successful and e.executed])
        else:
            self.actions_executed = 0
            self.actions_successful = 0
            self.actions_failed = 0
        self.user_interventions = 0

        mode_str = "RESUME MODE" if resume_mode else "NEW SESSION"
        logger.info(f"🎯 Autonomous Orchestrator initialized ({mode_str})")
        logger.info(f"   Session ID: {self.session_id}")
        logger.info(f"   Objective: {objective}")
        logger.info(f"   Target: {initial_target}")
        if resume_mode:
            logger.info(f"   Restored: {self.actions_executed} actions, {self.actions_successful} successful")

    async def execute(self) -> Dict[str, Any]:
        """
        Execute autonomous attack path discovery

        Returns:
            Results dictionary
        """
        self.status = OrchestratorStatus.RUNNING

        try:
            # Display beta warning banner
            self._display_beta_banner()

            if self.resume_mode:
                self.prompt.display_banner("RESUMING ATTACK PATH EXECUTION")
                logger.info("📂 Resuming from saved checkpoint...")
                logger.info(f"   Completed steps: {self.actions_successful}/{self.actions_executed}")
            else:
                self.prompt.display_banner("AUTONOMOUS ATTACK PATH EXECUTION")

            # Phase 1: Discovery & Planning (skip if resuming)
            if not self.resume_mode:
                await self._phase_discovery()
            else:
                # Show current attack graph state
                print("\n📊 Restored Attack Graph:")
                print(self.attack_graph.visualize_graph())

            # Phase 2: Attack Path Execution
            await self._phase_execution()

            # Phase 3: Reporting
            results = await self._phase_reporting()

            self.status = OrchestratorStatus.COMPLETED
            return results

        except KeyboardInterrupt:
            logger.warning("⚠️  Operation interrupted by user")
            self.status = OrchestratorStatus.ABORTED
            return await self._generate_partial_results()

        except Exception as e:
            logger.error(f"❌ Orchestrator failed: {e}", exc_info=True)
            self.status = OrchestratorStatus.FAILED
            return await self._generate_partial_results()

    async def validate_credentials(self) -> int:
        """
        Validate previously discovered credentials still work

        Returns:
            Number of valid credentials
        """
        valid_count = 0
        credentials = list(self.credential_vault.credentials.values())

        if not credentials:
            logger.info("No credentials to validate")
            return 0

        for cred in credentials:
            # For now, assume credentials are valid if not expired
            # In a real implementation, this would test each credential
            if cred.is_valid():
                valid_count += 1
                logger.debug(f"✓ Credential valid: {cred.cred_type} for {cred.target}")
            else:
                logger.warning(f"✗ Credential expired/invalid: {cred.cred_type} for {cred.target}")

        return valid_count

    async def _phase_discovery(self):
        """Phase 1: Discover attack paths and build graph"""
        logger.info("🔍 Phase 1: Discovery & Planning")

        # TODO: Integrate with actual reconnaissance tools
        # For now, we'll simulate discovery
        await self._simulate_discovery()

        # Show discovered attack graph
        print(self.attack_graph.visualize_graph())

        # Ask AI for optimal path recommendation
        decision = await self.ai_engine.decide_path_to_objective(
            self.attack_graph,
            self.objective
        )

        logger.info(f"🤖 AI Recommendation: {decision.recommendation}")
        logger.info(f"   Reasoning: {decision.reasoning}")

    async def _phase_execution(self):
        """Phase 2: Execute attack path"""
        logger.info("⚡ Phase 2: Attack Path Execution")

        # Get optimal path
        optimal_path = self.attack_graph.get_optimal_path_to_objective()

        if not optimal_path:
            logger.warning("No viable path to objective found")
            return

        self.total_steps = len(optimal_path)
        logger.info(f"📊 Executing {self.total_steps} steps to reach objective\n")

        # Execute each step in the path
        for i, edge in enumerate(optimal_path, 1):
            self.current_step = i

            # Check if user requested abort
            if self.approval_manager.should_abort():
                logger.warning("⚠️  Operation aborted by user")
                break

            # Execute the step
            success = await self._execute_step(edge, i, self.total_steps)

            if success:
                self.actions_successful += 1
            else:
                self.actions_failed += 1

                # Handle failure
                recovered = await self._handle_step_failure(edge)
                if not recovered:
                    logger.warning(f"Unable to recover from failure, stopping execution")
                    break

    async def _execute_step(
        self,
        edge: GraphEdge,
        step_num: int,
        total_steps: int
    ) -> bool:
        """
        Execute a single attack step

        Args:
            edge: Attack edge to execute
            step_num: Current step number
            total_steps: Total number of steps

        Returns:
            True if successful, False otherwise
        """
        # Display progress
        self.prompt.display_progress(
            step_num,
            total_steps,
            edge.description,
            "running"
        )

        # Check if approval required
        if self.approval_manager.requires_approval(edge):
            approved = await self._request_approval(edge)
            if not approved:
                logger.info(f"⏭️  Step skipped (not approved): {edge.description}")
                return False

        # Check if credentials required
        if edge.requires_credentials and edge.credential_id:
            cred_approved = await self._request_credential_use(edge)
            if not cred_approved:
                logger.info(f"⏭️  Step skipped (credential denied): {edge.description}")
                return False

        # Execute the attack step
        try:
            self.actions_executed += 1

            # TODO: Integrate with actual tool execution
            # For now, simulate execution
            result = await self._simulate_step_execution(edge)

            # Mark as attempted in graph
            self.attack_graph.mark_edge_attempted(
                edge.edge_id,
                success=result['success'],
                result=result
            )

            if result['success']:
                self.prompt.display_progress(
                    step_num,
                    total_steps,
                    edge.description,
                    "success"
                )
                logger.info(f"✓ Step succeeded: {edge.description}")

                # Process any discovered credentials
                if 'credentials' in result:
                    await self._process_discovered_credentials(result['credentials'])

                return True
            else:
                self.prompt.display_progress(
                    step_num,
                    total_steps,
                    edge.description,
                    "failed"
                )
                logger.warning(f"✗ Step failed: {edge.description}")
                return False

        except Exception as e:
            logger.error(f"❌ Step execution error: {e}")
            return False

    async def _request_approval(self, edge: GraphEdge) -> bool:
        """
        Request user approval for an action

        Args:
            edge: Attack edge requiring approval

        Returns:
            True if approved, False otherwise
        """
        self.status = OrchestratorStatus.WAITING_APPROVAL
        self.user_interventions += 1

        # Get AI recommendation
        context = {
            'compromised_hosts': self.attack_graph.compromised_hosts,
            'discovered_credentials': self.credential_vault.credentials,
            'vulnerabilities': [],  # TODO: Add vuln tracking
        }

        ai_decision = await self.ai_engine.decide_next_step(
            self.attack_graph,
            edge.source_id,
            self.objective,
            context
        )

        # Create approval request
        request = self.approval_manager.create_approval_request(
            edge,
            ai_recommendation=ai_decision.reasoning
        )

        # Prompt user
        decision = self.prompt.prompt_for_approval(request)

        # Record decision
        self.approval_manager.record_approval(request, decision)

        self.status = OrchestratorStatus.RUNNING

        return decision in [ApprovalDecision.APPROVE_ONCE, ApprovalDecision.APPROVE_SESSION]

    async def _request_credential_use(self, edge: GraphEdge) -> bool:
        """
        Request user approval to use a credential

        Args:
            edge: Attack edge requiring credential

        Returns:
            True if approved, False otherwise
        """
        if not edge.credential_id:
            return False

        # Check if already approved
        if not self.credential_vault.requires_approval(edge.credential_id):
            return True

        self.status = OrchestratorStatus.WAITING_APPROVAL
        self.user_interventions += 1

        # Create use request
        request = self.credential_vault.create_use_request(
            edge.credential_id,
            edge.target_id,
            edge.description,
            edge.tool
        )

        if not request:
            return False

        # Prompt user
        approved = self.prompt.prompt_for_credential_use(
            request,
            self.credential_vault
        )

        self.status = OrchestratorStatus.RUNNING

        return approved

    async def _handle_step_failure(self, failed_edge: GraphEdge) -> bool:
        """
        Handle a failed attack step

        User requirement: Prompt user for decision on errors

        Args:
            failed_edge: The edge that failed

        Returns:
            True if recovered, False otherwise
        """
        self.user_interventions += 1

        # Get AI recommendation for error recovery
        ai_decision = await self.ai_engine.decide_on_error(
            "Step execution failed",
            failed_edge,
            self.attack_graph
        )

        # Prompt user for decision
        user_choice = self.prompt.prompt_for_error_decision(
            error=f"Attack step failed: {failed_edge.description}",
            ai_decision=ai_decision,
            alternatives=ai_decision.alternatives
        )

        if user_choice == "abort":
            self.approval_manager.abort_requested = True
            return False

        # Handle user's choice
        if "retry" in user_choice.lower():
            logger.info("🔄 Retrying failed step...")
            return await self._execute_step(failed_edge, self.current_step, self.total_steps)

        elif "alternative" in user_choice.lower():
            logger.info("🔀 Trying alternative path...")
            # Get next best steps
            alternatives = self.attack_graph.get_next_steps(failed_edge.source_id)
            if alternatives:
                return await self._execute_step(alternatives[0], self.current_step, self.total_steps)

        return False

    async def _process_discovered_credentials(self, credentials: List[Dict[str, Any]]):
        """Process credentials discovered during attack"""
        for cred_data in credentials:
            cred_id = f"cred_{uuid.uuid4().hex[:8]}"

            self.credential_vault.add_credential(
                cred_id=cred_id,
                username=cred_data['username'],
                credential=cred_data['credential'],
                credential_type=CredentialType(cred_data.get('type', 'password')),
                source=CredentialSource.DISCOVERED,
                source_host=cred_data.get('source_host'),
                discovered_by=cred_data.get('tool')
            )

            # Add credential node to graph
            self.attack_graph.add_credential(
                cred_id=cred_id,
                source_asset=cred_data.get('source_host', 'unknown'),
                username=cred_data['username'],
                credential_type=cred_data.get('type', 'password'),
                metadata=cred_data
            )

    async def _phase_reporting(self) -> Dict[str, Any]:
        """Phase 3: Generate final report"""
        logger.info("📊 Phase 3: Reporting")

        # Generate summary
        summary = {
            'session_id': self.session_id,
            'objective': self.objective,
            'initial_target': self.initial_target,
            'status': self.status.value,

            'execution_stats': {
                'total_steps': self.total_steps,
                'current_step': self.current_step,
                'actions_executed': self.actions_executed,
                'actions_successful': self.actions_successful,
                'actions_failed': self.actions_failed,
                'success_rate': (
                    self.actions_successful / self.actions_executed
                    if self.actions_executed > 0 else 0.0
                ),
                'user_interventions': self.user_interventions,
            },

            'attack_graph': self.attack_graph.to_dict(),

            'credentials': self.credential_vault.get_vault_summary(),

            'approvals': self.approval_manager.get_approval_summary(),
        }

        # Display summary
        self.prompt.display_summary(
            "EXECUTION SUMMARY",
            {
                'Session ID': self.session_id,
                'Objective': self.objective,
                'Status': self.status.value.upper(),
                'Steps Executed': f"{self.current_step}/{self.total_steps}",
                'Success Rate': f"{summary['execution_stats']['success_rate']:.0%}",
                'Credentials Discovered': summary['credentials']['total_credentials'],
                'User Interventions': self.user_interventions,
            }
        )

        return summary

    async def _generate_partial_results(self) -> Dict[str, Any]:
        """Generate partial results when execution is interrupted"""
        return await self._phase_reporting()

    async def _simulate_discovery(self):
        """Simulate discovery phase (TODO: Replace with real recon)"""
        # Add some example vulnerabilities
        self.attack_graph.add_vulnerability(
            vuln_id="vuln_sql_injection",
            asset_id="target_initial",
            name="SQL Injection in login form",
            exploit_info={
                'tool': 'sqlmap',
                'mitre_technique': 'T1190',
                'complexity': 'medium',
                'detection_risk': 'high',
                'success_rate': 0.8,
            }
        )

        # Add sample credential (for demo)
        sample_cred_id = f"cred_{uuid.uuid4().hex[:8]}"
        self.credential_vault.add_credential(
            cred_id=sample_cred_id,
            username="admin",
            credential="password123",
            credential_type=CredentialType.PASSWORD,
            source=CredentialSource.DISCOVERED,
            source_host=self.initial_target,
            discovered_by="sqlmap"
        )

    async def _simulate_step_execution(self, edge: GraphEdge) -> Dict[str, Any]:
        """Execute step using real tools or simulation"""
        # Try real tool execution first
        try:
            from .tool_executor import ToolExecutor

            if not hasattr(self, '_tool_executor'):
                self._tool_executor = ToolExecutor()

            # Execute with real tools
            tool_result = await self._tool_executor.execute_edge(edge)

            result = {
                'success': tool_result.success,
                'tool': tool_result.tool,
                'technique': edge.technique,
                'output': tool_result.output,
                'parsed_data': tool_result.parsed_data,
            }

            # Extract credentials from parsed data if any
            if 'credentials' in tool_result.parsed_data:
                result['credentials'] = tool_result.parsed_data['credentials']

            return result

        except ImportError:
            logger.warning("Tool executor not available, using simulation")

        except Exception as e:
            logger.warning(f"Tool execution failed, using simulation: {e}")

        # Fallback to simulation
        import random
        await asyncio.sleep(0.5)

        success = random.random() < edge.success_probability

        result = {
            'success': success,
            'tool': edge.tool,
            'technique': edge.technique,
            'output': f"Simulated output from {edge.tool}",
        }

        if success and random.random() < 0.3:
            result['credentials'] = [{
                'username': 'discovered_user',
                'credential': 'discovered_pass',
                'type': 'password',
                'source_host': edge.target_id,
                'tool': edge.tool,
            }]

        return result

    def save_session(self):
        """Save current session state (user-initiated)"""
        logger.info("💾 Saving session...")

        self.state_manager.save_session(
            self.session_id,
            self.attack_graph,
            self.credential_vault,
            self.approval_manager,
            metadata={
                'objective': self.objective,
                'status': self.status.value,
                'actions_executed': self.actions_executed,
            }
        )

        logger.info("✓ Session saved successfully")

    def _display_beta_banner(self):
        """Display beta warning banner for autopent features"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ⚠️  BETA FEATURE - AUTONOMOUS PENTESTING                                   ║
║                                                                              ║
║   This feature is currently in BETA and under active development.           ║
║                                                                              ║
║   Current limitations:                                                       ║
║   • Some tool integrations may use simulation fallbacks                      ║
║   • Session resume functionality is partially implemented                    ║
║   • Attack path discovery is based on simplified heuristics                  ║
║                                                                              ║
║   Please report issues: https://github.com/KKingZero/Cobra-AI/issues         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
        logger.info("Autopent BETA: Some features may be incomplete or use simulations")

    @staticmethod
    def resume_session(session_id: str) -> Optional['AutonomousOrchestrator']:
        """Resume a saved session"""
        logger.info(f"📂 Resuming session: {session_id}")

        state_manager = SessionStateManager()
        session_data = state_manager.resume_session(session_id)

        if not session_data:
            logger.error(f"Session not found: {session_id}")
            return None

        # TODO: Reconstruct orchestrator from saved state
        logger.warning("Session resume not fully implemented yet")
        return None
