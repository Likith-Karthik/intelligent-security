"""Scheduling and lifecycle helpers for bounded recon plans."""

from datetime import datetime, timezone

from intelligent_security.domain import (
    Audit,
    ReconExecutionSchedule,
    ScheduledStep,
    ScheduledStepStatus,
)


class ReconScheduleError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def schedule_recon_plan(audit: Audit) -> ReconExecutionSchedule:
    """Create a schedule from a recon plan without binding it to a plugin implementation."""
    if audit.recon_plan is None or audit.recon_capability_discovery is None:
        raise ReconScheduleError("missing_recon_plan", "Recon plan and capability discovery are required.")
    if audit.recon_plan.registry_snapshot_id != audit.recon_capability_discovery.registry_snapshot_id:
        raise ReconScheduleError("registry_snapshot_mismatch", "Recon plan does not match capability discovery.")

    candidates = {
        (candidate.capability, candidate.contract_version): candidate
        for candidate in audit.recon_capability_discovery.candidates
    }
    steps = []
    for plan_step in audit.recon_plan.steps:
        candidate = candidates.get((plan_step.capability, plan_step.contract_version))
        if candidate is None:
            raise ReconScheduleError(
                "scheduled_capability_missing",
                "Recon step {} no longer has a discovered capability.".format(plan_step.step_id),
            )
        steps.append(
            ScheduledStep(
                plan_step_id=plan_step.step_id,
                capability=plan_step.capability,
                contract_version=plan_step.contract_version,
                depends_on=plan_step.depends_on,
                status=ScheduledStepStatus.READY if not plan_step.depends_on else ScheduledStepStatus.PENDING,
                estimated_duration_seconds=candidate.estimated_duration_seconds,
                estimated_cost_usd=candidate.estimated_cost_usd,
            )
        )

    duration = sum(step.estimated_duration_seconds for step in steps)
    cost = sum(step.estimated_cost_usd for step in steps)
    if duration > audit.time_budget_seconds:
        raise ReconScheduleError("time_budget_exceeded", "Recon schedule exceeds the audit time budget.")
    if cost > audit.cost_budget_usd:
        raise ReconScheduleError("cost_budget_exceeded", "Recon schedule exceeds the audit cost budget.")
    return ReconExecutionSchedule(
        registry_snapshot_id=audit.recon_plan.registry_snapshot_id,
        policy_version=audit.recon_plan.policy_version,
        steps=steps,
        reserved_duration_seconds=duration,
        reserved_cost_usd=cost,
        scheduled_at=datetime.now(timezone.utc),
    )


def release_dependent_recon_steps(schedule: ReconExecutionSchedule) -> None:
    """Make a pending step ready only after all its plan dependencies have succeeded."""
    statuses = {step.plan_step_id: step.status for step in schedule.steps}
    for step in schedule.steps:
        if step.status == ScheduledStepStatus.PENDING and all(
            statuses.get(dependency) == ScheduledStepStatus.SUCCEEDED for dependency in step.depends_on
        ):
            step.status = ScheduledStepStatus.READY
