"""Shared policy evaluation for query-engine tools."""

from __future__ import annotations

from dataclasses import dataclass

from contracts.runtime import ApprovalRequest, PolicyMode, RiskCategory, ToolSpec


@dataclass
class PolicyDecision:
    """Outcome of policy evaluation for a tool call."""

    allowed: bool
    requires_approval: bool
    reason: str = ""
    approval_request: ApprovalRequest | None = None


class PolicyEngine:
    """Runtime policy evaluation for tool execution."""

    def evaluate(
        self,
        tool_spec: ToolSpec,
        policy_mode: PolicyMode,
        reason: str,
        arguments: dict,
    ) -> PolicyDecision:
        """Evaluate whether a tool can run in the given policy mode."""
        if policy_mode == PolicyMode.READ_ONLY and not tool_spec.read_only:
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                reason="tool is not permitted in read-only mode",
            )

        if policy_mode == PolicyMode.INTERACTIVE_SAFE:
            if tool_spec.requires_approval or tool_spec.risk_category in {
                RiskCategory.MEDIUM,
                RiskCategory.HIGH,
                RiskCategory.CRITICAL,
            }:
                return PolicyDecision(
                    allowed=False,
                    requires_approval=True,
                    reason=reason,
                    approval_request=ApprovalRequest(
                        tool_name=tool_spec.name,
                        reason=reason,
                        risk_category=tool_spec.risk_category,
                        arguments=arguments,
                    ),
                )
            return PolicyDecision(allowed=True, requires_approval=False, reason="auto-approved low-risk tool")

        if policy_mode == PolicyMode.GUIDED_AUTO:
            if tool_spec.requires_approval or tool_spec.risk_category in {
                RiskCategory.HIGH,
                RiskCategory.CRITICAL,
            }:
                return PolicyDecision(
                    allowed=False,
                    requires_approval=True,
                    reason=reason,
                    approval_request=ApprovalRequest(
                        tool_name=tool_spec.name,
                        reason=reason,
                        risk_category=tool_spec.risk_category,
                        arguments=arguments,
                    ),
                )
            return PolicyDecision(allowed=True, requires_approval=False, reason="guided auto policy permits tool")

        if policy_mode == PolicyMode.AUTONOMOUS_LAB:
            if tool_spec.risk_category == RiskCategory.CRITICAL and tool_spec.requires_approval:
                return PolicyDecision(
                    allowed=False,
                    requires_approval=True,
                    reason=reason,
                    approval_request=ApprovalRequest(
                        tool_name=tool_spec.name,
                        reason=reason,
                        risk_category=tool_spec.risk_category,
                        arguments=arguments,
                    ),
                )
            return PolicyDecision(allowed=True, requires_approval=False, reason="autonomous lab mode permits tool")

        return PolicyDecision(allowed=True, requires_approval=False, reason="default allow")


def coerce_policy_mode(policy_mode: PolicyMode | str | None) -> PolicyMode:
    """Normalize mixed string/enum policy inputs."""
    if isinstance(policy_mode, PolicyMode):
        return policy_mode
    if isinstance(policy_mode, str):
        try:
            return PolicyMode(policy_mode)
        except ValueError:
            pass
    return PolicyMode.INTERACTIVE_SAFE


def authorize_tool_call(
    tool_spec: ToolSpec,
    policy_mode: PolicyMode | str | None,
    reason: str,
    arguments: dict,
    approval_granted: bool = False,
) -> PolicyDecision:
    """
    Evaluate a tool call and optionally convert an approval-required decision
    into an executable one after the operator has approved it.
    """
    normalized_mode = coerce_policy_mode(policy_mode)
    decision = policy_engine.evaluate(
        tool_spec=tool_spec,
        policy_mode=normalized_mode,
        reason=reason,
        arguments=arguments,
    )
    if approval_granted and decision.requires_approval:
        return PolicyDecision(
            allowed=True,
            requires_approval=False,
            reason="approved by operator",
        )
    return decision


policy_engine = PolicyEngine()
