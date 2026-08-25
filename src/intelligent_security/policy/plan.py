from datetime import datetime, timezone
from typing import Dict, List

from intelligent_security.domain import (
    Audit,
    AuditOperation,
    CapabilityStage,
    PlanValidation,
    PlanValidationStatus,
    PluginHealth,
)


class PlanPolicyError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def validate_plan(audit: Audit) -> PlanValidation:
    """Re-check the model-produced plan against persisted, deterministic context."""
    if audit.audit_plan is None or audit.scope_policy is None or audit.target_profile is None:
        raise PlanPolicyError("missing_plan_context", "Plan, scope policy, and target profile are required.")
    if audit.capability_discovery is None:
        raise PlanPolicyError("missing_capability_discovery", "Capability discovery is required.")
    if audit.audit_plan.registry_snapshot_id != audit.capability_discovery.registry_snapshot_id:
        raise PlanPolicyError(
            "registry_snapshot_mismatch",
            "The proposed plan does not match the capability registry snapshot used for discovery.",
        )
    if audit.audit_plan.recon_snapshot_id and (
        audit.recon_snapshot is None or audit.audit_plan.recon_snapshot_id != audit.recon_snapshot.snapshot_id
    ):
        raise PlanPolicyError("recon_snapshot_mismatch", "The proposed plan does not match the finalized recon snapshot.")

    candidates: Dict[str, List] = {}
    for candidate in audit.capability_discovery.candidates:
        candidates.setdefault(candidate.capability, []).append(candidate)

    duration = 0
    cost = 0.0
    reasons = []
    requires_human_approval = audit.approval_policy == "human_approval_required"
    for step in audit.audit_plan.steps:
        matches = candidates.get(step.capability, [])
        if not matches:
            raise PlanPolicyError("capability_not_discovered", "Step {} references an undiscovered capability.".format(step.id))
        candidate = matches[0]
        if candidate.stage == CapabilityStage.OFFENSIVE:
            raise PlanPolicyError("offensive_capability_disabled", "Offensive capabilities cannot be included in an audit plan.")
        if candidate.health != PluginHealth.DECLARED_HEALTHY:
            raise PlanPolicyError("plugin_unhealthy", "Step {} requires an unhealthy plugin.".format(step.id))
        if candidate.required_operation not in audit.scope_policy.allowed_operations:
            raise PlanPolicyError("operation_not_authorized", "Step {} requires an unauthorized operation.".format(step.id))
        if candidate.required_operation in {AuditOperation.EXPLOIT, AuditOperation.DESTRUCTIVE_ACTION}:
            requires_human_approval = True
        duration += candidate.estimated_duration_seconds
        cost += candidate.estimated_cost_usd

    if duration > audit.time_budget_seconds:
        raise PlanPolicyError(
            "time_budget_exceeded",
            "Plan duration {} seconds exceeds the audit budget of {} seconds.".format(duration, audit.time_budget_seconds),
        )
    if cost > audit.cost_budget_usd:
        raise PlanPolicyError(
            "cost_budget_exceeded",
            "Plan cost {} exceeds the audit budget of {}.".format(cost, audit.cost_budget_usd),
        )

    if requires_human_approval:
        status = PlanValidationStatus.PENDING_HUMAN_APPROVAL
        reasons.append("Human approval is required by the audit approval policy.")
    else:
        status = PlanValidationStatus.APPROVED
        reasons.append("All steps satisfy deterministic scope, capability, and budget checks.")
    return PlanValidation(
        status=status,
        estimated_duration_seconds=duration,
        estimated_cost_usd=cost,
        approval_required=requires_human_approval,
        registry_snapshot_id=audit.capability_discovery.registry_snapshot_id,
        reasons=reasons,
        validated_at=datetime.now(timezone.utc),
    )
