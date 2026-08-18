from datetime import datetime, timezone

from intelligent_security.domain import (
    Audit, CandidateFinding, FindingState, FindingValidationBasis, FindingValidationOutcome, FindingValidationRequest,
)


class FindingServiceError(Exception):
    pass


class FindingService:
    @staticmethod
    def record_validation(audit: Audit, finding: CandidateFinding, request: FindingValidationRequest) -> CandidateFinding:
        if request.evidence_id not in finding.evidence_ids:
            raise FindingServiceError("Validation evidence must be linked to the candidate finding.")
        if not any(evidence.evidence_id == request.evidence_id for evidence in audit.raw_evidence):
            raise FindingServiceError("Validation evidence record does not exist in this audit.")
        if finding.state not in {FindingState.CANDIDATE, FindingState.VALIDATION_PENDING, FindingState.INCONCLUSIVE}:
            raise FindingServiceError("Finding is not eligible for validation in its current state.")
        target_state = FindingState(request.outcome.value)
        basis = FindingValidationBasis(
            outcome=request.outcome, evidence_id=request.evidence_id, validated_by=request.validated_by,
            basis=request.basis, recorded_at=datetime.now(timezone.utc),
        )
        finding.validation_history.append(basis)
        finding.state = target_state
        finding.updated_at = basis.recorded_at
        return finding
