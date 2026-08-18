import hashlib
from datetime import datetime, timezone

from intelligent_security.domain import Audit, CandidateFinding, FindingState, FindingValidationProposal


class FindingCorrelator:
    """Deterministically group observations without making a confirmation decision."""

    def correlate(self, audit: Audit) -> list:
        grouped = {}
        executions = {execution.execution_id: execution for execution in audit.plugin_executions}
        for observation in audit.observations:
            key_parts = (
                observation.category.strip().lower(),
                (observation.affected_asset or "").strip().lower(),
                (observation.location or "").strip().lower(),
                ",".join(sorted(identifier.strip().lower() for identifier in observation.identifiers)),
                observation.title.strip().lower(),
            )
            grouped.setdefault(key_parts, []).append(observation)

        findings = []
        for key_parts, observations in sorted(grouped.items()):
            first = observations[0]
            source_capabilities = sorted({
                executions[item.execution_id].capability for item in observations if item.execution_id in executions
            })
            validation_candidate = next(
                (
                    candidate for candidate in (audit.capability_discovery.candidates if audit.capability_discovery else [])
                    if set(source_capabilities).intersection(candidate.validation_for)
                ),
                None,
            )
            proposal = None
            state = FindingState.CANDIDATE
            if validation_candidate is not None:
                proposal = FindingValidationProposal(
                    capability=validation_candidate.capability,
                    contract_version=validation_candidate.contract_version,
                    reason="Validate correlated {} observation(s) through the normal approval flow.".format(len(observations)),
                )
                state = FindingState.VALIDATION_PENDING
            now = datetime.now(timezone.utc)
            correlation_key = hashlib.sha256("\x1f".join(key_parts).encode("utf-8")).hexdigest()
            findings.append(CandidateFinding(
                state=state, correlation_key=correlation_key, category=first.category, title=first.title,
                affected_asset=first.affected_asset, location=first.location,
                severity_reported=self._highest_severity(observations),
                confidence=max((item.confidence or 0 for item in observations), default=None),
                observation_ids=[item.observation_id for item in observations],
                evidence_ids=sorted({item.evidence_id for item in observations}, key=str),
                source_capabilities=source_capabilities, validation_proposal=proposal,
                created_at=now, updated_at=now,
            ))
        return findings

    @staticmethod
    def _highest_severity(observations):
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
        values = [item.severity_reported for item in observations if item.severity_reported]
        return max(values, key=lambda value: rank.get(value.lower(), -1)) if values else None
