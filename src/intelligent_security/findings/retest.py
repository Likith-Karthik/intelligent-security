from datetime import datetime, timezone

from intelligent_security.domain import (
    Audit, CandidateFinding, FindingState, RetestCreateRequest, RetestPlan, RetestPlanStatus, RetestStep,
    ScheduledStepStatus,
)
from intelligent_security.policy.scope import validate_scope
from intelligent_security.profiling.service import profile_target


class RetestError(Exception):
    pass


class RetestService:
    def create(self, audit: Audit, request: RetestCreateRequest) -> RetestPlan:
        findings = {item.finding_id: item for item in audit.candidate_findings}
        selected = []
        for finding_id in request.finding_ids:
            finding = findings.get(finding_id)
            if finding is None or finding.state not in {FindingState.CONFIRMED, FindingState.INCONCLUSIVE}:
                raise RetestError("Retests can select only confirmed or inconclusive findings.")
            if finding.validation_proposal is None:
                raise RetestError("No approved validation capability is available for finding {}.".format(finding_id))
            selected.append(finding)
        if len(set(request.finding_ids)) != len(request.finding_ids):
            raise RetestError("A finding may appear only once in a retest plan.")
        try:
            scope_policy = validate_scope(audit)
            target_profile = profile_target(audit)
        except Exception as error:
            raise RetestError("Retest scope or target revalidation failed: {}".format(error))
        if audit.scope_policy is None or audit.target_profile is None or scope_policy.model_dump() != audit.scope_policy.model_dump() or target_profile.canonical_identifier != audit.target_profile.canonical_identifier:
            raise RetestError("Retest scope or target no longer matches the persisted audit context.")
        now = datetime.now(timezone.utc)
        return RetestPlan(
            finding_ids=[item.finding_id for item in selected],
            steps=[RetestStep(
                retest_step_id="retest-{}".format(item.finding_id), finding_id=item.finding_id,
                capability=item.validation_proposal.capability, contract_version=item.validation_proposal.contract_version,
            ) for item in selected],
            scope_revalidated_at=now, target_revalidated_at=now, created_at=now,
        )

    @staticmethod
    def compare(audit: Audit, retest: RetestPlan) -> None:
        for step in retest.steps:
            finding = next(item for item in audit.candidate_findings if item.finding_id == step.finding_id)
            if step.evidence_id is None:
                finding.state = FindingState.INCONCLUSIVE
                continue
            new_observations = [item for item in audit.observations if item.evidence_id == step.evidence_id]
            matching = any(
                item.category.lower() == finding.category.lower()
                and (item.affected_asset or "").lower() == (finding.affected_asset or "").lower()
                and (item.location or "").lower() == (finding.location or "").lower()
                and item.title.lower() == finding.title.lower()
                for item in new_observations
            )
            finding.state = FindingState.STILL_PRESENT if matching else FindingState.FIXED
            finding.updated_at = datetime.now(timezone.utc)
        retest.status = RetestPlanStatus.COMPLETED
        retest.completed_at = datetime.now(timezone.utc)
