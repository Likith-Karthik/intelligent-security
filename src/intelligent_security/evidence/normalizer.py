import json
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import ValidationError

from intelligent_security.domain import (
    Audit,
    Observation,
    ObservationNormalization,
    ObservationNormalizationStatus,
    RawEvidenceRecord,
)
from intelligent_security.evidence.artifact_store import ArtifactStore
from intelligent_security.registry.service import PluginPackage


class NormalizationError(Exception):
    pass


class EvidenceNormalizer:
    """Generic JSONL normalizer driven solely by an admitted package mapping."""

    required_fields = {"category", "title"}

    def __init__(self, artifact_store: ArtifactStore) -> None:
        self.artifact_store = artifact_store

    def normalize(self, audit: Audit, evidence: RawEvidenceRecord, package: Optional[PluginPackage]) -> tuple:
        if package is None or package.normalizer is None:
            return self._result(evidence, ObservationNormalizationStatus.FAILED, 0, 0, ["normalizer_unavailable"]), []
        spec = package.normalizer
        if not self.required_fields.issubset(spec.fields):
            return self._result(evidence, ObservationNormalizationStatus.FAILED, 0, 0, ["normalizer_contract_invalid"]), []
        artifact = next((item for item in evidence.artifacts if item.kind == spec.input_artifact_kind), None)
        if artifact is None:
            return self._result(evidence, ObservationNormalizationStatus.FAILED, 0, 0, ["normalizer_input_missing"]), []
        try:
            raw_output = self.artifact_store.read_text(artifact.storage_uri, artifact.sha256)
        except RuntimeError as error:
            return self._result(evidence, ObservationNormalizationStatus.FAILED, 0, 0, [str(error)]), []

        observations, errors = [], []
        for line_number, line in enumerate(raw_output.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("record is not an object")
                observations.append(self._observation(audit, evidence, artifact.artifact_id, payload, spec.fields))
            except (ValueError, TypeError, ValidationError) as error:
                errors.append("line {}: {}".format(line_number, str(error)))
        status = ObservationNormalizationStatus.SUCCEEDED if not errors else (
            ObservationNormalizationStatus.PARTIAL if observations else ObservationNormalizationStatus.FAILED
        )
        return self._result(evidence, status, len(observations), len(errors), errors), observations

    @staticmethod
    def _value(payload: dict, path: Optional[str], default: Any) -> Any:
        if not path:
            return default
        value: Any = payload
        for segment in path.split("."):
            if not isinstance(value, dict) or segment not in value:
                return default
            value = value[segment]
        return value

    def _observation(self, audit, evidence, artifact_id, payload, fields) -> Observation:
        values = {name: self._value(payload, field.path, field.default) for name, field in fields.items()}
        identifiers = values.get("identifiers", [])
        if identifiers is None:
            identifiers = []
        if not isinstance(identifiers, list):
            identifiers = [identifiers]
        return Observation(
            audit_id=audit.id, execution_id=evidence.execution_id, evidence_id=evidence.evidence_id,
            category=str(values["category"]), title=str(values["title"]),
            description=self._optional_text(values.get("description")),
            affected_asset=self._optional_text(values.get("affected_asset")),
            location=self._optional_text(values.get("location")),
            severity_reported=self._optional_text(values.get("severity_reported")),
            confidence=values.get("confidence"), identifiers=[str(item) for item in identifiers if item is not None],
            evidence_artifact_ids=[artifact_id], tool_metadata=payload,
        )

    @staticmethod
    def _optional_text(value: Any) -> Optional[str]:
        return None if value is None else str(value)

    @staticmethod
    def _result(evidence, status, accepted, rejected, errors) -> ObservationNormalization:
        return ObservationNormalization(
            evidence_id=evidence.evidence_id, execution_id=evidence.execution_id,
            plugin_id=evidence.plugin_id, plugin_version=evidence.plugin_version, status=status,
            normalized_at=datetime.now(timezone.utc), accepted_count=accepted, rejected_count=rejected, errors=errors,
        )
