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
import sys
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
from .tool_executor import ToolExecutor
from tasks.store import TaskStore
from contracts.runtime import AuditEvent, PolicyMode, TaskRecord, TaskStatus

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


class StepOutcome(Enum):
    """Execution result for a single autopent step."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
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
        autonomous_mode: bool = False,
        demo_mode: bool = False,
    ):
        self.objective = objective
        self.initial_target = initial_target
        self.session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        self.resume_mode = resume_mode
        self.autonomous_mode = autonomous_mode
        self.demo_mode = demo_mode

        # Core components - use provided or create new
        self.attack_graph = attack_graph or AttackPathGraph(objective, initial_target)
        self.ai_engine = AIDecisionEngine()
        self.approval_manager = approval_manager or ApprovalManager()
        self.credential_vault = credential_vault or CredentialVault()
        self.prompt = InteractivePrompt()
        self.state_manager = SessionStateManager()
        self.task_store = TaskStore()
        self.task_id = f"autopent-{self.session_id}"

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
        self._sync_task(TaskStatus.PAUSED if resume_mode else TaskStatus.QUEUED)
        self._emit_event("autopent_initialized", {
            "objective": self.objective,
            "target": self.initial_target,
            "resume_mode": self.resume_mode,
            "autonomous_mode": self.autonomous_mode,
        })

    async def execute(self) -> Dict[str, Any]:
        """
        Execute autonomous attack path discovery

        Returns:
            Results dictionary
        """
        self.status = OrchestratorStatus.RUNNING
        self._sync_task(TaskStatus.RUNNING)

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
                discovery_ready = await self._phase_discovery()
                if not discovery_ready:
                    self.status = OrchestratorStatus.FAILED
                    self._sync_task(TaskStatus.FAILED, {
                        "error": "no discovery provider configured",
                    })
                    self._emit_event("autopent_failed", {
                        "reason": "no discovery provider configured",
                        "hint": "enable demo mode only for sample fixtures, or configure a real discovery provider",
                    })
                    return await self._phase_reporting()
            else:
                # Show current attack graph state
                print("\n📊 Restored Attack Graph:")
                print(self.attack_graph.visualize_graph())

            # Phase 2: Attack Path Execution
            execution_status = await self._phase_execution()

            self.status = execution_status
            final_task_status = {
                OrchestratorStatus.COMPLETED: TaskStatus.COMPLETED,
                OrchestratorStatus.FAILED: TaskStatus.FAILED,
                OrchestratorStatus.ABORTED: TaskStatus.ABORTED,
            }.get(execution_status, TaskStatus.FAILED)
            self._sync_task(final_task_status)
            terminal_event = {
                OrchestratorStatus.COMPLETED: "autopent_completed",
                OrchestratorStatus.FAILED: "autopent_failed",
                OrchestratorStatus.ABORTED: "autopent_aborted",
            }.get(execution_status, "autopent_failed")
            self._emit_event(terminal_event, {"status": self.status.value})
            # Phase 3: Reporting
            results = await self._phase_reporting()
            return results

        except KeyboardInterrupt:
            logger.warning("⚠️  Operation interrupted by user")
            self.status = OrchestratorStatus.ABORTED
            self._sync_task(TaskStatus.ABORTED)
            self._emit_event("autopent_aborted", {"status": self.status.value})
            return await self._generate_partial_results()

        except Exception as e:
            logger.error(f"❌ Orchestrator failed: {e}", exc_info=True)
            self.status = OrchestratorStatus.FAILED
            self._sync_task(TaskStatus.FAILED, {"error": str(e)})
            self._emit_event("autopent_failed", {"error": str(e)})
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

    async def _phase_discovery(self) -> bool:
        """Phase 1: Discover attack paths and build graph"""
        logger.info("🔍 Phase 1: Discovery & Planning")
        self._emit_event("phase_started", {"phase": "discovery"})

        # TODO: Integrate with actual reconnaissance tools
        if not await self._simulate_discovery():
            logger.warning("Discovery stopped: no real recon provider configured")
            return False

        # Show discovered attack graph
        print(self.attack_graph.visualize_graph())

        # Ask AI for optimal path recommendation
        decision = await self.ai_engine.decide_path_to_objective(
            self.attack_graph,
            self.objective
        )

        logger.info(f"🤖 AI Recommendation: {decision.recommendation}")
        logger.info(f"   Reasoning: {decision.reasoning}")
        return True

    async def _phase_execution(self) -> OrchestratorStatus:
        """Phase 2: Execute attack path"""
        logger.info("⚡ Phase 2: Attack Path Execution")
        self._emit_event("phase_started", {"phase": "execution"})

        # Get optimal path
        optimal_path = self.attack_graph.get_optimal_path_to_objective()

        if not optimal_path:
            logger.warning("No viable path to objective found")
            self._emit_event("execution_failed", {
                "reason": "no viable path to objective found",
                "objective": self.objective,
            })
            return OrchestratorStatus.FAILED

        self.total_steps = len(optimal_path)
        logger.info(f"📊 Executing {self.total_steps} steps to reach objective\n")
        self._emit_event("execution_plan", {"total_steps": self.total_steps})
        had_unrecovered_failure = False
        aborted = False

        # Execute each step in the path
        for i, edge in enumerate(optimal_path, 1):
            self.current_step = i

            # Check if user requested abort
            if self.approval_manager.should_abort():
                logger.warning("⚠️  Operation aborted by user")
                aborted = True
                break

            # Execute the step
            outcome = await self._execute_step(edge, i, self.total_steps)

            if outcome == StepOutcome.SUCCEEDED:
                self.actions_successful += 1
                self._sync_task(TaskStatus.RUNNING)
            elif outcome == StepOutcome.FAILED:
                self.actions_failed += 1
                self._sync_task(TaskStatus.RUNNING)

                # Handle failure
                recovery_outcome = await self._handle_step_failure(edge)
                if recovery_outcome == StepOutcome.SUCCEEDED:
                    self.actions_successful += 1
                    self._sync_task(TaskStatus.RUNNING)
                elif recovery_outcome == StepOutcome.SKIPPED:
                    self._sync_task(TaskStatus.RUNNING)
                elif recovery_outcome == StepOutcome.ABORTED:
                    aborted = True
                    break
                else:
                    logger.warning(f"Unable to recover from failure, stopping execution")
                    had_unrecovered_failure = True
                    break
            elif outcome == StepOutcome.ABORTED:
                logger.warning("Stopping execution after operator abort")
                aborted = True
                break
            else:
                self._sync_task(TaskStatus.RUNNING)

        if aborted:
            return OrchestratorStatus.ABORTED
        if had_unrecovered_failure:
            return OrchestratorStatus.FAILED
        return OrchestratorStatus.COMPLETED

    async def _execute_step(
        self,
        edge: GraphEdge,
        step_num: int,
        total_steps: int
    ) -> StepOutcome:
        """
        Execute a single attack step

        Args:
            edge: Attack edge to execute
            step_num: Current step number
            total_steps: Total number of steps

        Returns:
            Step outcome classification
        """
        # Display progress
        self._emit_event("step_started", {
            "step_num": step_num,
            "total_steps": total_steps,
            "edge_id": edge.edge_id,
            "description": edge.description,
            "tool": edge.tool,
        })
        self.prompt.display_progress(
            step_num,
            total_steps,
            edge.description,
            "running"
        )

        shared_policy_decision = self._get_tool_executor().get_shared_policy_decision(edge)

        # Check if approval required through the legacy autopent path only when the
        # edge is not already governed by the shared tool contract.
        if shared_policy_decision is None and self.approval_manager.requires_approval(edge):
            approved = await self._request_approval(edge)
            if not approved:
                logger.info(f"⏭️  Step skipped (not approved): {edge.description}")
                self._emit_event("step_skipped", {
                    "edge_id": edge.edge_id,
                    "reason": "not approved",
                    "description": edge.description,
                })
                if self.approval_manager.should_abort():
                    return StepOutcome.ABORTED
                return StepOutcome.SKIPPED

        # Check if credentials required
        if edge.requires_credentials and edge.credential_id:
            cred_approved = await self._request_credential_use(edge)
            if not cred_approved:
                logger.info(f"⏭️  Step skipped (credential denied): {edge.description}")
                self._emit_event("step_skipped", {
                    "edge_id": edge.edge_id,
                    "reason": "credential denied",
                    "description": edge.description,
                })
                return StepOutcome.SKIPPED

        shared_tool_allowed, shared_approval_granted = await self._ensure_shared_tool_authorized(
            edge,
            policy_decision=shared_policy_decision,
        )
        if not shared_tool_allowed:
            logger.info(f"⏭️  Step skipped (shared tool not approved): {edge.description}")
            self._emit_event("step_skipped", {
                "edge_id": edge.edge_id,
                "reason": "shared tool not approved",
                "description": edge.description,
            })
            if self.approval_manager.should_abort():
                return StepOutcome.ABORTED
            return StepOutcome.SKIPPED

        # Execute the attack step
        try:
            self.actions_executed += 1

            # TODO: Integrate with actual tool execution
            # For now, simulate execution
            result = await self._simulate_step_execution(edge, shared_approval_granted=shared_approval_granted)

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
                self._emit_event("step_completed", {
                    "edge_id": edge.edge_id,
                    "success": True,
                    "description": edge.description,
                    "tool": edge.tool,
                })

                # Process any discovered credentials
                if 'credentials' in result:
                    await self._process_discovered_credentials(result['credentials'])

                return StepOutcome.SUCCEEDED
            else:
                self.prompt.display_progress(
                    step_num,
                    total_steps,
                    edge.description,
                    "failed"
                )
                logger.warning(f"✗ Step failed: {edge.description}")
                self._emit_event("step_completed", {
                    "edge_id": edge.edge_id,
                    "success": False,
                    "description": edge.description,
                    "tool": edge.tool,
                })
                return StepOutcome.FAILED

        except Exception as e:
            logger.error(f"❌ Step execution error: {e}")
            self._emit_event("step_error", {
                "edge_id": edge.edge_id,
                "description": edge.description,
                "error": str(e),
            })
            return StepOutcome.FAILED

    async def _ensure_shared_tool_authorized(
        self,
        edge: GraphEdge,
        policy_decision=None,
    ) -> tuple[bool, bool]:
        """Prompt for approval when the shared tool contract requires it."""
        tool_executor = self._get_tool_executor()
        if policy_decision is None:
            policy_decision = tool_executor.get_shared_policy_decision(edge)
        if policy_decision is None or not policy_decision.requires_approval:
            return True, False

        self.status = OrchestratorStatus.WAITING_APPROVAL
        self._sync_task(TaskStatus.WAITING_APPROVAL)
        self.user_interventions += 1
        request = self.approval_manager.create_approval_request(
            edge,
            ai_recommendation=policy_decision.reason,
        )
        request_id = request.action_id
        self._sync_task(TaskStatus.WAITING_APPROVAL, metadata={
            "pending_approval_request": {
                "request_id": request_id,
                "tool_name": edge.tool,
                "reason": policy_decision.reason,
                "risk_category": getattr(policy_decision.approval_request, "risk_category", None).value
                if getattr(policy_decision, "approval_request", None) is not None
                else "medium",
                "approval_kind": "shared_tool",
            },
        })
        self._emit_event("approval_required", {
            "edge_id": edge.edge_id,
            "description": edge.description,
            "tool": edge.tool,
            "target": edge.target_id,
            "reason": policy_decision.reason,
            "source": "shared_tool_policy",
            "request_id": request_id,
        })
        decision = await self._resolve_action_approval(request)
        self.approval_manager.record_approval(request, decision)

        self.status = OrchestratorStatus.RUNNING
        self._sync_task(TaskStatus.RUNNING, metadata={
            "pending_approval_request": None,
            "pending_approval_response": None,
        })
        self._emit_event("approval_decision", {
            "edge_id": edge.edge_id,
            "decision": decision.value,
            "source": "shared_tool_policy",
            "request_id": request_id,
        })
        if decision == ApprovalDecision.APPROVE_SESSION:
            shared_mapping = tool_executor._map_edge_to_shared_tool(edge)
            if shared_mapping:
                self.task_store.add_session_approval(self.session_id, shared_mapping[0])
        return decision in [ApprovalDecision.APPROVE_ONCE, ApprovalDecision.APPROVE_SESSION], True

    async def _request_approval(self, edge: GraphEdge) -> bool:
        """
        Request user approval for an action

        Args:
            edge: Attack edge requiring approval

        Returns:
            True if approved, False otherwise
        """
        self.status = OrchestratorStatus.WAITING_APPROVAL
        self._sync_task(TaskStatus.WAITING_APPROVAL)
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

        self._emit_event("approval_required", {
            "edge_id": edge.edge_id,
            "description": edge.description,
            "tool": edge.tool,
            "target": edge.target_id,
            "request_id": request.action_id,
        })
        self._sync_task(TaskStatus.WAITING_APPROVAL, metadata={
            "pending_approval_request": {
                "request_id": request.action_id,
                "tool_name": edge.tool,
                "reason": ai_decision.reasoning,
                "risk_category": request.risk_level,
                "approval_kind": "edge",
            },
        })
        decision = await self._resolve_action_approval(request)

        # Record decision
        self.approval_manager.record_approval(request, decision)

        self.status = OrchestratorStatus.RUNNING
        self._sync_task(TaskStatus.RUNNING, metadata={
            "pending_approval_request": None,
            "pending_approval_response": None,
        })
        self._emit_event("approval_decision", {
            "edge_id": edge.edge_id,
            "decision": decision.value,
            "request_id": request.action_id,
        })

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
        self._sync_task(TaskStatus.WAITING_APPROVAL)
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

        request_id = f"credential-{edge.edge_id}-{edge.credential_id}"
        self._sync_task(TaskStatus.WAITING_APPROVAL, metadata={
            "pending_approval_request": {
                "request_id": request_id,
                "tool_name": edge.tool,
                "reason": f"Use credential {edge.credential_id} against {edge.target_id}",
                "risk_category": "medium",
                "approval_kind": "credential",
            },
        })
        self._emit_event("approval_required", {
            "edge_id": edge.edge_id,
            "credential_id": edge.credential_id,
            "tool": edge.tool,
            "target": edge.target_id,
            "request_id": request_id,
            "reason": f"Credential use requires approval for {edge.target_id}",
        })
        approved = await self._resolve_credential_approval(request, request_id)

        self.status = OrchestratorStatus.RUNNING
        self._sync_task(TaskStatus.RUNNING, metadata={
            "pending_approval_request": None,
            "pending_approval_response": None,
        })
        self._emit_event("credential_approval_decision", {
            "edge_id": edge.edge_id,
            "credential_id": edge.credential_id,
            "approved": approved,
            "request_id": request_id,
        })

        return approved

    async def _handle_step_failure(self, failed_edge: GraphEdge) -> StepOutcome:
        """
        Handle a failed attack step

        User requirement: Prompt user for decision on errors

        Args:
            failed_edge: The edge that failed

        Returns:
            Step outcome for the selected recovery action.
        """
        self.user_interventions += 1

        # Get AI recommendation for error recovery
        ai_decision = await self.ai_engine.decide_on_error(
            "Step execution failed",
            failed_edge,
            self.attack_graph
        )

        if sys.stdin.isatty():
            user_choice = self.prompt.prompt_for_error_decision(
                error=f"Attack step failed: {failed_edge.description}",
                ai_decision=ai_decision,
                alternatives=ai_decision.alternatives
            )
        else:
            self.status = OrchestratorStatus.WAITING_APPROVAL
            self._sync_task(TaskStatus.WAITING_APPROVAL)
            request_id = f"recovery-{failed_edge.edge_id}"
            self._sync_task(TaskStatus.WAITING_APPROVAL, metadata={
                "pending_approval_request": {
                    "request_id": request_id,
                    "tool_name": failed_edge.tool,
                    "reason": ai_decision.reasoning,
                    "risk_category": "medium",
                    "approval_kind": "failure_recovery",
                },
            })
            self._emit_event("recovery_decision_required", {
                "edge_id": failed_edge.edge_id,
                "description": failed_edge.description,
                "request_id": request_id,
                "recommendation": ai_decision.recommendation,
                "alternatives": ai_decision.alternatives,
                "reason": ai_decision.reasoning,
            })
            external = await self._wait_for_external_approval(request_id, max_polls=40)
            self.status = OrchestratorStatus.RUNNING
            self._sync_task(TaskStatus.RUNNING, metadata={
                "pending_approval_request": None,
                "pending_approval_response": None,
            })
            if external is None:
                logger.warning("No external recovery decision received; aborting execution")
                return StepOutcome.FAILED
            decision_map = {
                ApprovalDecision.APPROVE_ONCE: "retry",
                ApprovalDecision.APPROVE_SESSION: "alternative",
                ApprovalDecision.DENY: "abort",
                ApprovalDecision.ABORT: "abort",
            }
            user_choice = decision_map.get(external, "abort")

        if user_choice == "abort":
            self.approval_manager.abort_requested = True
            return StepOutcome.ABORTED

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

        return StepOutcome.FAILED

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
        self._emit_event("phase_started", {"phase": "reporting"})

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

    async def _simulate_discovery(self) -> bool:
        """Seed demo discovery state only when demo mode is explicitly enabled."""
        if not self.demo_mode:
            logger.info("Discovery has no real recon provider configured; no demo findings were seeded")
            self._emit_event("discovery_skipped", {"reason": "demo mode disabled"})
            return False

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

        objective_lower = self.objective.lower()
        if "admin" in objective_lower:
            admin_node = GraphNode(
                node_id="access_admin",
                node_type=NodeType.ACCESS,
                name="admin access",
                metadata={"access_level": AccessLevel.ADMIN.value},
            )
            self.attack_graph.add_node(admin_node)
            self.attack_graph.add_edge(
                GraphEdge(
                    edge_id="privesc_admin",
                    source_id="vuln_sql_injection",
                    target_id="access_admin",
                    technique="T1068",
                    tool="sqlmap",
                    description="Escalate to admin using SQL injection foothold",
                    complexity="medium",
                    detection_likelihood="high",
                    success_probability=0.7,
                )
            )

        if "database" in objective_lower:
            database_node = GraphNode(
                node_id="asset_database",
                node_type=NodeType.ASSET,
                name="database server",
                metadata={"asset_type": "database"},
            )
            self.attack_graph.add_node(database_node)
            self.attack_graph.add_edge(
                GraphEdge(
                    edge_id="pivot_database",
                    source_id="vuln_sql_injection",
                    target_id="asset_database",
                    technique="T1210",
                    tool="nmap",
                    description="Pivot to database server after exploiting SQL injection",
                    complexity="medium",
                    detection_likelihood="high",
                    success_probability=0.6,
                )
            )

        return True

    async def _simulate_step_execution(self, edge: GraphEdge, shared_approval_granted: bool = False) -> Dict[str, Any]:
        """Execute step using real tools or simulation"""
        # Try real tool execution first
        try:
            # Execute with real tools
            tool_result = await self._get_tool_executor().execute_edge(
                edge,
                approval_granted=shared_approval_granted,
            )

            if tool_result.parsed_data.get('approval_required'):
                raise RuntimeError(tool_result.error or "approval required")

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
            logger.error(f"Tool execution failed: {e}")
            raise

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

    def _get_tool_executor(self) -> ToolExecutor:
        """Lazily create the shared tool executor with the current policy mode."""
        if not hasattr(self, '_tool_executor'):
            policy_mode = PolicyMode.AUTONOMOUS_LAB if self.autonomous_mode else PolicyMode.INTERACTIVE_SAFE
            self._tool_executor = ToolExecutor(
                policy_mode=policy_mode,
                session_id=self.session_id,
                task_id=self.task_id,
            )
        return self._tool_executor

    async def _resolve_action_approval(self, request) -> ApprovalDecision:
        """Resolve an action approval through external runtime events or local prompt."""
        max_polls = 40 if not sys.stdin.isatty() else 4
        external = await self._wait_for_external_approval(request.action_id, max_polls=max_polls)
        if external is not None:
            return external
        if sys.stdin.isatty():
            return self.prompt.prompt_for_approval(request)
        return ApprovalDecision.ABORT

    async def _resolve_credential_approval(self, request, request_id: str) -> bool:
        """Resolve credential approval through external runtime events or local prompt."""
        max_polls = 40 if not sys.stdin.isatty() else 4
        external = await self._wait_for_external_approval(request_id, is_credential=True, max_polls=max_polls)
        if external is not None:
            return external
        if sys.stdin.isatty():
            return self.prompt.prompt_for_credential_use(request, self.credential_vault)
        return False

    async def _wait_for_external_approval(
        self,
        request_id: str,
        is_credential: bool = False,
        max_polls: Optional[int] = 4,
    ):
        """
        Wait briefly for an external runtime approval decision before falling back to local input.
        """
        poll_count = 0
        while max_polls is None or poll_count < max_polls:
            task = self.task_store.get_task(self.task_id)
            if task:
                pending = task.metadata.get("pending_approval_response") or {}
                if pending.get("request_id") == request_id:
                    decision = str(pending.get("decision", "")).strip().lower()
                    task.metadata.pop("pending_approval_response", None)
                    self.task_store.upsert_task(task)
                    if is_credential:
                        return decision in {"approve_once", "approve_session"}
                    if decision == "approve_once":
                        return ApprovalDecision.APPROVE_ONCE
                    if decision == "approve_session":
                        return ApprovalDecision.APPROVE_SESSION
                    if decision == "deny":
                        return ApprovalDecision.DENY
                    if decision == "abort":
                        return ApprovalDecision.ABORT
            poll_count += 1
            await asyncio.sleep(0.25)
        return None

    def save_session(self):
        """Save current session state (user-initiated)"""
        logger.info("💾 Saving session...")
        self._emit_event("session_save_requested", {"session_id": self.session_id})

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
        self._emit_event("session_saved", {"session_id": self.session_id})

    def _sync_task(self, status: TaskStatus, metadata: Optional[Dict[str, Any]] = None):
        """Persist the current autopent task state to the shared task store."""
        record = TaskRecord(
            task_id=self.task_id,
            kind="autopent",
            status=status,
            session_id=self.session_id,
            input_summary=f"{self.objective} on {self.initial_target}",
            provider="",
            model="",
            metadata={
                "objective": self.objective,
                "target": self.initial_target,
                "orchestrator_status": self.status.value,
                "actions_executed": self.actions_executed,
                "actions_successful": self.actions_successful,
                "actions_failed": self.actions_failed,
                **{
                    k: v for k, v in (metadata or {}).items()
                    if v is not None
                },
            },
        )
        self.task_store.upsert_task(record)

    def _emit_event(self, event_type: str, payload: Optional[Dict[str, Any]] = None):
        """Append an autopent event to the shared audit log."""
        self.task_store.append_event(
            AuditEvent(
                task_id=self.task_id,
                event_type=event_type,
                payload=payload or {},
            )
        )

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
