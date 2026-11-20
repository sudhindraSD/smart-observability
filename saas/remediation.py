"""Slice 3 remediation: policy gate, plan builder and approval lifecycle.

Every incident carries a ``RemediationPlan``. The policy gate only ever
passes reversible *simulation* actions; destructive operations are blocked
with ``POLICY_BLOCKED`` and never reach an approval flow. All state
transitions append UTC ``RemediationAuditEntry`` records.
"""

from __future__ import annotations

import uuid
from typing import Optional, Tuple

from shared.contracts import (
    ConnectivityState,
    Metrics,
    RemediationAuditEntry,
    RemediationPlan,
    RemediationState,
    SecurityRisk,
    utc_now_iso,
)

# Reversible simulation actions (safe by construction: they simulate a failover
# / block / throttle / restart in a sandbox, never touch production state).
ACTION_FAILOVER_UPLINK = "SIMULATE_FAILOVER_UPLINK"
ACTION_BLOCK_SOURCE_AUTH = "SIMULATE_BLOCK_SOURCE_AUTH"
ACTION_SCALE_OR_THROTTLE = "SIMULATE_SCALE_OR_THROTTLE_WORKLOAD"
ACTION_RESTART_AND_REROUTE = "SIMULATE_RESTART_AND_REROUTE"

REVERSIBLE_ACTIONS = frozenset(
    {
        ACTION_FAILOVER_UPLINK,
        ACTION_BLOCK_SOURCE_AUTH,
        ACTION_SCALE_OR_THROTTLE,
        ACTION_RESTART_AND_REROUTE,
    }
)

# Destructive actions are always blocked by the policy gate.
DESTRUCTIVE_ACTIONS = frozenset(
    {
        "DROP_PRODUCTION_DB",
        "WIPE_DISK",
        "DELETE_DATABASE",
        "FORMAT_DISK",
    }
)

_ROLLBACK_PLANS = {
    ACTION_FAILOVER_UPLINK: (
        "Restore primary uplink routing table and re-enable the original WAN path."
    ),
    ACTION_BLOCK_SOURCE_AUTH: (
        "Remove the temporary firewall deny rule and re-open authentication "
        "for the blocked source."
    ),
    ACTION_SCALE_OR_THROTTLE: (
        "Revert workload throttles and scale the service back to its previous "
        "instance count."
    ),
    ACTION_RESTART_AND_REROUTE: (
        "Restore the previous service routing configuration; the simulated "
        "restart leaves no persistent changes."
    ),
}


def evaluate_policy(proposed_action: str) -> Tuple[bool, str]:
    """Return ``(policy_check_passed, policy_rule_matched)`` for an action."""
    if proposed_action in REVERSIBLE_ACTIONS:
        return True, f"ALLOW_REVERSIBLE_SIMULATION:{proposed_action}"
    if proposed_action in DESTRUCTIVE_ACTIONS:
        return False, "BLOCK_DESTRUCTIVE_ACTION"
    return False, "BLOCK_UNKNOWN_ACTION"


def choose_remediation_action(
    *,
    event_category: str,
    security_risk: str,
    metrics: Optional[Metrics],
    top_metric: Optional[str],
) -> str:
    """Pick the remediation action tailored to the incident's root cause."""
    if event_category == "security" or security_risk in (
        SecurityRisk.HIGH.value,
        SecurityRisk.CRITICAL.value,
    ):
        return ACTION_BLOCK_SOURCE_AUTH
    if metrics is not None:
        if metrics.connectivity == ConnectivityState.DOWN:
            return ACTION_RESTART_AND_REROUTE
        if metrics.service_up is False:
            return ACTION_RESTART_AND_REROUTE
    if top_metric in ("latency_ms", "packet_loss_pct", "bandwidth_mbps"):
        return ACTION_FAILOVER_UPLINK
    if top_metric in ("cpu_pct", "memory_pct", "disk_pct"):
        return ACTION_SCALE_OR_THROTTLE
    return ACTION_RESTART_AND_REROUTE


def _new_action_id() -> str:
    return f"REM-{uuid.uuid4().hex[:12]}"


def build_remediation_plan(
    proposed_action: str,
    context: str,
) -> RemediationPlan:
    """Build a plan in ``AWAITING_APPROVAL`` or ``POLICY_BLOCKED`` state."""
    passed, rule = evaluate_policy(proposed_action)
    if passed:
        state = RemediationState.AWAITING_APPROVAL
        rollback_plan = _ROLLBACK_PLANS.get(
            proposed_action, "Revert the simulated change; no persistent effect."
        )
    else:
        state = RemediationState.POLICY_BLOCKED
        rollback_plan = "Not applicable: the action was blocked before execution."
    audit = RemediationAuditEntry(
        timestamp_utc=utc_now_iso(),
        actor="system",
        action="policy_evaluation",
        details=f"{rule} | context: {context}",
    )
    return RemediationPlan(
        action_id=_new_action_id(),
        proposed_action=proposed_action,
        policy_check_passed=passed,
        policy_rule_matched=rule,
        state=state,
        rollback_plan=rollback_plan,
        audit_trail=[audit],
    )


def _append_audit(plan: RemediationPlan, actor: str, action: str, details: str) -> RemediationPlan:
    entry = RemediationAuditEntry(
        timestamp_utc=utc_now_iso(),
        actor=actor,
        action=action,
        details=details,
    )
    return plan.model_copy(
        update={"audit_trail": [*plan.audit_trail, entry]},
    )


def approve_remediation(plan: RemediationPlan, actor: str) -> RemediationPlan:
    """Transition ``AWAITING_APPROVAL -> APPROVED_EXECUTED`` with an audit entry."""
    if not plan.policy_check_passed or plan.state == RemediationState.POLICY_BLOCKED:
        raise ValueError(
            "remediation plan is policy-blocked and cannot be approved"
        )
    if plan.state != RemediationState.AWAITING_APPROVAL:
        raise ValueError(
            f"cannot approve remediation from state {plan.state}"
        )
    updated = plan.model_copy(update={"state": RemediationState.APPROVED_EXECUTED})
    return _append_audit(
        updated,
        actor,
        "approve",
        f"action {plan.proposed_action} approved and executed by {actor}",
    )


def rollback_remediation(plan: RemediationPlan, actor: str) -> RemediationPlan:
    """Transition ``APPROVED_EXECUTED -> ROLLED_BACK`` with an audit entry."""
    if plan.state != RemediationState.APPROVED_EXECUTED:
        raise ValueError(
            f"cannot roll back remediation from state {plan.state}"
        )
    updated = plan.model_copy(update={"state": RemediationState.ROLLED_BACK})
    return _append_audit(
        updated,
        actor,
        "rollback",
        f"action {plan.proposed_action} rolled back by {actor}: {plan.rollback_plan}",
    )
