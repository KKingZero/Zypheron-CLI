"""
Approval Manager - Handles user approval for security actions

Supports:
- Per-action approval
- "Allow for this session" to avoid repeated prompts
- Safety gates for high-risk actions
"""

import logging
from typing import Dict, Set, Optional, List
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from .attack_path_graph import GraphEdge

logger = logging.getLogger(__name__)


class ActionCategory(Enum):
    """Categories of actions requiring approval"""
    RECONNAISSANCE = "reconnaissance"  # Usually auto-approved
    SCANNING = "scanning"  # Usually auto-approved
    EXPLOITATION = "exploitation"  # ALWAYS requires approval
    CREDENTIAL_ATTACK = "credential_attack"  # Requires approval
    LATERAL_MOVEMENT = "lateral_movement"  # Requires approval
    HIGH_DETECTION_RISK = "high_detection_risk"  # Requires approval
    DATA_ACCESS = "data_access"  # Requires approval


class ApprovalDecision(Enum):
    """User's approval decision"""
    APPROVE_ONCE = "approve_once"  # Approve this single action
    APPROVE_SESSION = "approve_session"  # Approve this category for entire session
    DENY = "deny"  # Deny this action
    ABORT = "abort"  # Abort entire operation


@dataclass
class ApprovalRequest:
    """Request for user approval"""
    action_id: str
    category: ActionCategory
    description: str
    target: str
    tool: str
    risk_level: str  # low, medium, high, critical
    detection_likelihood: str  # low, medium, high

    # Context
    technique: str
    reasoning: str
    ai_recommendation: Optional[str] = None

    # Timestamp
    requested_at: datetime = None

    def __post_init__(self):
        if self.requested_at is None:
            self.requested_at = datetime.now()


@dataclass
class ApprovalResponse:
    """User's response to approval request"""
    decision: ApprovalDecision
    action_id: str
    approved_at: datetime = None

    def __post_init__(self):
        if self.approved_at is None:
            self.approved_at = datetime.now()


class ApprovalManager:
    """
    Manages user approvals for security actions

    Features:
    - Safety gates (some actions ALWAYS require approval)
    - Session-wide approvals to reduce repeated prompts
    - Audit trail of all approvals
    """

    # Actions that ALWAYS require approval (cannot be session-approved)
    ALWAYS_REQUIRE_APPROVAL = {
        ActionCategory.EXPLOITATION,
    }

    # Actions that are auto-approved (safe reconnaissance)
    AUTO_APPROVED = {
        ActionCategory.RECONNAISSANCE,
        ActionCategory.SCANNING,
    }

    def __init__(self):
        # Session-wide approvals
        self.session_approvals: Set[ActionCategory] = set()

        # Individual action approvals (for audit trail)
        self.approval_history: List[ApprovalResponse] = []

        # Denied actions
        self.denied_actions: Set[str] = set()

        # Track if user requested abort
        self.abort_requested = False

        # Autonomous mode - AI decides all (except critical safety gates)
        self.autonomous_mode = False

    def set_autonomous_mode(self, enabled: bool):
        """
        Enable or disable autonomous mode.

        In autonomous mode:
        - Most actions are auto-approved
        - Only EXPLOITATION category still requires approval (safety gate)
        - All decisions are logged for audit
        """
        self.autonomous_mode = enabled
        if enabled:
            logger.warning("⚠️  AUTONOMOUS MODE ENABLED - AI will auto-approve most actions")
            # Auto-approve all categories except exploitation
            for category in ActionCategory:
                if category not in self.ALWAYS_REQUIRE_APPROVAL:
                    self.session_approvals.add(category)
        else:
            logger.info("Autonomous mode disabled - returning to interactive mode")

    def requires_approval(self, edge: GraphEdge) -> bool:
        """
        Check if an edge (attack step) requires user approval

        Args:
            edge: Attack edge to check

        Returns:
            True if approval is required
        """
        category = self._categorize_edge(edge)

        # Auto-approved categories
        if category in self.AUTO_APPROVED:
            return False

        # Session-approved categories (unless in ALWAYS_REQUIRE_APPROVAL)
        if category not in self.ALWAYS_REQUIRE_APPROVAL:
            if category in self.session_approvals:
                logger.debug(f"Action auto-approved via session approval: {category.value}")
                return False

        # Everything else requires approval
        return True

    def _categorize_edge(self, edge: GraphEdge) -> ActionCategory:
        """Categorize an edge by action type"""
        # Check description and technique for keywords
        desc_lower = edge.description.lower()
        tech_lower = edge.technique.lower()

        # Exploitation
        if any(keyword in desc_lower for keyword in ['exploit', 'rce', 'injection', 'overflow']):
            return ActionCategory.EXPLOITATION

        # Credential attacks
        if any(keyword in desc_lower for keyword in ['credential', 'password', 'hash', 'spray', 'brute']):
            return ActionCategory.CREDENTIAL_ATTACK

        # Lateral movement
        if any(keyword in desc_lower for keyword in ['lateral', 'pivot', 'move', 'smb', 'rdp', 'ssh']):
            return ActionCategory.LATERAL_MOVEMENT

        # High detection risk
        if edge.detection_likelihood == "high":
            return ActionCategory.HIGH_DETECTION_RISK

        # Data access
        if any(keyword in desc_lower for keyword in ['data', 'exfil', 'download', 'copy']):
            return ActionCategory.DATA_ACCESS

        # Default: scanning
        if any(keyword in desc_lower for keyword in ['scan', 'enum', 'discover', 'recon']):
            return ActionCategory.SCANNING

        # If unclear, require approval (safe default)
        return ActionCategory.EXPLOITATION

    def create_approval_request(
        self,
        edge: GraphEdge,
        ai_recommendation: Optional[str] = None
    ) -> ApprovalRequest:
        """
        Create an approval request for an edge

        Args:
            edge: Attack edge requiring approval
            ai_recommendation: Optional AI reasoning for this action

        Returns:
            ApprovalRequest object
        """
        category = self._categorize_edge(edge)

        # Determine risk level from edge metadata
        risk_level = "medium"
        if edge.complexity == "high" or edge.detection_likelihood == "high":
            risk_level = "high"
        elif edge.complexity == "low" and edge.detection_likelihood == "low":
            risk_level = "low"

        return ApprovalRequest(
            action_id=edge.edge_id,
            category=category,
            description=edge.description,
            target=edge.target_id,
            tool=edge.tool,
            risk_level=risk_level,
            detection_likelihood=edge.detection_likelihood,
            technique=edge.technique,
            reasoning=f"Part of attack path to objective",
            ai_recommendation=ai_recommendation,
        )

    def record_approval(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision
    ) -> ApprovalResponse:
        """
        Record user's approval decision

        Args:
            request: The approval request
            decision: User's decision

        Returns:
            ApprovalResponse
        """
        response = ApprovalResponse(
            decision=decision,
            action_id=request.action_id,
        )

        # Record in history
        self.approval_history.append(response)

        # Handle decision
        if decision == ApprovalDecision.APPROVE_SESSION:
            # Add to session approvals (unless it's in ALWAYS_REQUIRE_APPROVAL)
            if request.category not in self.ALWAYS_REQUIRE_APPROVAL:
                self.session_approvals.add(request.category)
                logger.info(f"✓ Session approval granted for: {request.category.value}")
            else:
                logger.warning(
                    f"Cannot grant session approval for {request.category.value} - "
                    "this category always requires individual approval"
                )

        elif decision == ApprovalDecision.DENY:
            self.denied_actions.add(request.action_id)
            logger.info(f"✗ Action denied: {request.description}")

        elif decision == ApprovalDecision.ABORT:
            self.abort_requested = True
            logger.warning("⚠️  User requested abort of entire operation")

        elif decision == ApprovalDecision.APPROVE_ONCE:
            logger.info(f"✓ Action approved (once): {request.description}")

        return response

    def is_approved(self, action_id: str) -> bool:
        """Check if an action was approved"""
        # Check if denied
        if action_id in self.denied_actions:
            return False

        # Check approval history
        for response in self.approval_history:
            if response.action_id == action_id:
                return response.decision in [
                    ApprovalDecision.APPROVE_ONCE,
                    ApprovalDecision.APPROVE_SESSION
                ]

        return False

    def should_abort(self) -> bool:
        """Check if user requested to abort"""
        return self.abort_requested

    def get_session_approvals(self) -> List[str]:
        """Get list of session-approved categories"""
        return [cat.value for cat in self.session_approvals]

    def get_approval_summary(self) -> Dict[str, any]:
        """Get summary of approvals"""
        total = len(self.approval_history)
        approved = sum(
            1 for r in self.approval_history
            if r.decision in [ApprovalDecision.APPROVE_ONCE, ApprovalDecision.APPROVE_SESSION]
        )
        denied = len(self.denied_actions)

        return {
            'total_requests': total,
            'approved': approved,
            'denied': denied,
            'session_approvals': self.get_session_approvals(),
            'abort_requested': self.abort_requested,
        }

    def reset_session_approvals(self):
        """Reset all session approvals (e.g., for new session)"""
        self.session_approvals.clear()
        logger.info("Session approvals reset")

    def format_approval_request(self, request: ApprovalRequest) -> str:
        """
        Format approval request for display to user

        Returns:
            Formatted string for terminal display
        """
        lines = []
        lines.append("\n" + "="*70)
        lines.append("APPROVAL REQUIRED")
        lines.append("="*70)

        # Action details
        lines.append(f"\n📋 Action: {request.description}")
        lines.append(f"🎯 Target: {request.target}")
        lines.append(f"🔧 Tool: {request.tool}")
        lines.append(f"📊 Technique: {request.technique}")

        # Risk assessment
        risk_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🟠',
            'critical': '🔴'
        }.get(request.risk_level, '⚪')

        detection_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🔴'
        }.get(request.detection_likelihood, '⚪')

        lines.append(f"\n⚠️  Risk Level: {risk_emoji} {request.risk_level.upper()}")
        lines.append(f"👁️  Detection Likelihood: {detection_emoji} {request.detection_likelihood.upper()}")

        # AI recommendation if available
        if request.ai_recommendation:
            lines.append(f"\n🤖 AI Recommendation:")
            lines.append(f"   {request.ai_recommendation}")

        # Category info
        lines.append(f"\n📂 Category: {request.category.value}")

        # Session approval notice
        if request.category in self.ALWAYS_REQUIRE_APPROVAL:
            lines.append("   ⚡ This category ALWAYS requires approval (cannot be session-approved)")

        lines.append("\n" + "="*70)

        return "\n".join(lines)

    def restore_from_dict(self, data: Dict) -> None:
        """
        Restore approval state from saved dictionary

        Args:
            data: Dictionary containing approval data from session save
        """
        # Restore session approvals
        session_approval_strs = data.get('session_approvals', {})
        for category_str in session_approval_strs:
            try:
                category = ActionCategory(category_str)
                self.session_approvals.add(category)
            except ValueError:
                logger.warning(f"Unknown action category: {category_str}")

        # Restore denied actions
        self.denied_actions = set(data.get('denied_actions', []))

        logger.info(f"✓ Restored {len(self.session_approvals)} session approvals, {len(self.denied_actions)} denied actions")
