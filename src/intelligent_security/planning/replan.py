import hashlib
from datetime import datetime, timezone

from intelligent_security.domain import (
    Audit, AuditPlan, CapabilityDiscovery, CapabilityStage, PlanStep,
    ReplanRecord, ReplanStatus, ValidationDecisionType,
)
from intelligent_security.planning.service import AuditPlanner, PlanningError


class ReplanError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ReplanService:
    """Create one incremental plan without allowing a new autonomous audit loop."""

    max_attempts_per_audit = 3
    max_attempts_per_finding = 2

    @staticmethod
    def step_digest(capability: str, contract_version: str) -> str:
        return hashlib.sha256("{}\x1f{}".format(capability, contract_version).encode("utf-8")).hexdigest()

    def create(self, audit: Audit, discovery: CapabilityDiscovery, planner: AuditPlanner, profile) -> tuple[AuditPlan, ReplanRecord]:
        decision = audit.validation_decision
        if decision is None or decision.decision != ValidationDecisionType.MORE_TESTING_REQUIRED:
            raise ReplanError("replan_not_requested", "Replanning requires a persisted MORE_TESTING_REQUIRED validation decision.")
        if any(item.source_decision_id == decision.decision_id for item in audit.replan_history):
            raise ReplanError("replan_already_consumed", "The current validation decision has already been used for replanning.")
        if len(audit.replan_history) >= self.max_attempts_per_audit:
            raise ReplanError("replan_limit_exhausted", "The audit replan limit has been reached.")
        for finding_id in decision.finding_ids:
            attempts = sum(finding_id in item.finding_ids for item in audit.replan_history)
            if attempts >= self.max_attempts_per_finding:
                raise ReplanError("finding_replan_limit_exhausted", "A finding has reached its replan limit.")

        prior_digests = self._prior_digests(audit)
        candidates = [
            candidate for candidate in discovery.candidates
            if candidate.stage in {CapabilityStage.EXECUTE, CapabilityStage.VALIDATE}
            and self.step_digest(candidate.capability, candidate.contract_version) not in prior_digests
        ]
        if not candidates:
            raise ReplanError("no_incremental_capability", "No unused executable capability is available for the evidence gap.")
        working = audit.model_copy(deep=True)
        working.capability_discovery = discovery.model_copy(update={"candidates": candidates})
        used_duration, used_cost = self._reserved_budget(audit)
        working.time_budget_seconds = max(0, audit.time_budget_seconds - used_duration)
        working.cost_budget_usd = max(0, audit.cost_budget_usd - used_cost)
        if working.time_budget_seconds <= 0 or working.cost_budget_usd < 0:
            raise ReplanError("replan_budget_exhausted", "No audit budget remains for additional testing.")
        context = {
            "source_validation_decision": decision.model_dump(mode="json"),
            "findings_requiring_more_evidence": [
                finding.model_dump(mode="json") for finding in audit.candidate_findings if finding.finding_id in decision.finding_ids
            ],
            "prior_step_digests": sorted(prior_digests),
            "instruction": "Create only incremental evidence-gathering steps. Do not repeat prior capability contracts.",
        }
        try:
            generated = planner.generate(working, profile, replan_context=context)
        except PlanningError:
            raise
        proposed_digests = [self.step_digest(step.capability, self._contract(discovery, step.capability)) for step in generated.steps]
        if len(proposed_digests) != len(set(proposed_digests)) or set(proposed_digests).intersection(prior_digests):
            raise ReplanError("duplicate_replan_step", "Replan repeats a capability contract already attempted in this audit.")
        attempt = len(audit.replan_history) + 1
        generated = self._prefix_step_ids(generated, attempt)
        record = ReplanRecord(
            source_decision_id=decision.decision_id, attempt=attempt, finding_ids=decision.finding_ids,
            prior_step_digests=sorted(prior_digests), new_step_digests=proposed_digests,
            status=ReplanStatus.SCHEDULED, reason=decision.reason, created_at=datetime.now(timezone.utc),
        )
        return generated, record

    def _prior_digests(self, audit: Audit) -> set[str]:
        digests = {digest for item in audit.replan_history for digest in item.new_step_digests}
        if audit.audit_plan is not None:
            for step in audit.audit_plan.steps:
                contract = self._contract(audit.capability_discovery, step.capability)
                if contract:
                    digests.add(self.step_digest(step.capability, contract))
        return digests

    @staticmethod
    def _contract(discovery, capability: str) -> str:
        candidate = next((item for item in discovery.candidates if item.capability == capability), None)
        return candidate.contract_version if candidate else ""

    @staticmethod
    def _reserved_budget(audit: Audit) -> tuple[int, float]:
        """Return total committed work once, even after the active schedule is replaced.

        Each replan replaces ``execution_schedule``.  The latest scheduled replan
        therefore records the cumulative reservation so prior audit work is never
        forgotten or counted twice on a later iteration.
        """
        scheduled_history = [item for item in audit.replan_history if item.status == ReplanStatus.SCHEDULED]
        if scheduled_history:
            latest = scheduled_history[-1]
            if latest.cumulative_reserved_duration_seconds or latest.cumulative_reserved_cost_usd:
                return latest.cumulative_reserved_duration_seconds, latest.cumulative_reserved_cost_usd
        duration = audit.execution_schedule.reserved_duration_seconds if audit.execution_schedule else 0
        cost = audit.execution_schedule.reserved_cost_usd if audit.execution_schedule else 0.0
        return duration, cost

    @staticmethod
    def _prefix_step_ids(plan: AuditPlan, attempt: int) -> AuditPlan:
        mapping = {step.id: "replan-{:02d}-{}".format(attempt, step.id) for step in plan.steps}
        steps = [step.model_copy(update={"id": mapping[step.id], "depends_on": [mapping[item] for item in step.depends_on]}) for step in plan.steps]
        return plan.model_copy(update={"steps": steps})
