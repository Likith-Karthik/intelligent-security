import json
from typing import Optional

from intelligent_security.domain import Audit, PluginExecution, RawEvidenceRecord
from intelligent_security.evidence.artifact_store import ArtifactStore
from intelligent_security.execution.result import AdapterExecutionResult


class EvidenceCollector:
    """Captures raw adapter output before any future tool-specific normalization."""

    def __init__(self, artifact_store: ArtifactStore) -> None:
        self.artifact_store = artifact_store

    def capture(
        self,
        audit: Audit,
        execution: PluginExecution,
        result: AdapterExecutionResult,
        image_reference: Optional[str],
    ) -> RawEvidenceRecord:
        target = audit.target_profile.canonical_identifier if audit.target_profile else audit.target.identifier
        record = RawEvidenceRecord(
            execution_id=execution.execution_id,
            audit_id=audit.id,
            plan_step_id=execution.plan_step_id,
            target_identifier=target,
            plugin_id=execution.plugin_id,
            plugin_version=execution.plugin_version,
            container_image_digest=image_reference if image_reference and "@sha256:" in image_reference else None,
            redacted_invocation=self._redact_invocation(result.invocation),
            started_at=execution.started_at,
            completed_at=execution.completed_at,
            exit_code=result.exit_code,
        )
        artifacts = [
            self.artifact_store.write_text(
                audit.id, record.evidence_id, "invocation",
                json.dumps(record.redacted_invocation, separators=(",", ":")), "application/json",
            ),
            self.artifact_store.write_text(audit.id, record.evidence_id, "stdout", result.stdout, "text/plain; charset=utf-8"),
            self.artifact_store.write_text(audit.id, record.evidence_id, "stderr", result.stderr, "text/plain; charset=utf-8"),
        ]
        for kind, content, content_type in result.artifacts:
            artifacts.append(
                self.artifact_store.write_text(audit.id, record.evidence_id, kind, content, content_type)
            )
        return record.model_copy(update={"artifacts": artifacts})

    @staticmethod
    def _redact_invocation(arguments: list[str]) -> list[str]:
        redacted = []
        redact_next = False
        sensitive_words = ("token", "secret", "password", "apikey", "api-key", "authorization")
        for argument in arguments:
            if redact_next:
                redacted.append("[REDACTED]")
                redact_next = False
                continue
            lowered = argument.lower()
            if any(word in lowered for word in sensitive_words):
                if "=" in argument:
                    redacted.append(argument.split("=", 1)[0] + "=[REDACTED]")
                else:
                    redacted.append(argument)
                    redact_next = True
                continue
            redacted.append(argument)
        return redacted
