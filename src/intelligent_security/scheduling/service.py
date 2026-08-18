from datetime import datetime, timezone
from typing import Dict, List

from intelligent_security.domain import (
    Audit,
    ExecutionSchedule,
    ScheduledStep,
    ScheduledStepStatus,
)


class ScheduleError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def schedule_plan(audit: Audit) -> ExecutionSchedule:
    """Persist a capability-level DAG without resolving or running a plugin."""
    if audit.audit_plan is None or audit.capability_discovery is None:
        raise ScheduleError("missing_schedule_context", "Approved plan and capability discovery are required.")
    if audit.plan_validation is None:
        raise ScheduleError("missing_plan_validation", "Plan validation is required before scheduling.")
    if audit.plan_validation.registry_snapshot_id != audit.capability_discovery.registry_snapshot_id:
        raise ScheduleError("registry_snapshot_mismatch", "Validated plan does not match capability discovery.")
    candidates: Dict[str, List] = {}
    for candidate in audit.capability_discovery.candidates:
        candidates.setdefault(candidate.capability, []).append(candidate)

    scheduled_steps = []
    reserved_duration = 0
    reserved_cost = 0.0
    for plan_step in audit.audit_plan.steps:
        matches = candidates.get(plan_step.capability, [])
        if not matches:
            raise ScheduleError(
                "scheduled_capability_missing",
                "Step {} no longer has a discovered capability.".format(plan_step.id),
            )
        candidate = matches[0]
        reserved_duration += candidate.estimated_duration_seconds
        reserved_cost += candidate.estimated_cost_usd
        scheduled_steps.append(
            ScheduledStep(
                plan_step_id=plan_step.id,
                capability=plan_step.capability,
                contract_version=candidate.contract_version,
                depends_on=plan_step.depends_on,
                status=(ScheduledStepStatus.READY if not plan_step.depends_on else ScheduledStepStatus.PENDING),
                estimated_duration_seconds=candidate.estimated_duration_seconds,
                estimated_cost_usd=candidate.estimated_cost_usd,
            )
        )
    if reserved_duration > audit.time_budget_seconds:
        raise ScheduleError("time_budget_exceeded", "Schedule exceeds the audit time budget.")
    if reserved_cost > audit.cost_budget_usd:
        raise ScheduleError("cost_budget_exceeded", "Schedule exceeds the audit cost budget.")
    return ExecutionSchedule(
        schedule_version="1",
        registry_snapshot_id=audit.plan_validation.registry_snapshot_id,
        steps=scheduled_steps,
        reserved_duration_seconds=reserved_duration,
        reserved_cost_usd=reserved_cost,
        scheduled_at=datetime.now(timezone.utc),
    )
