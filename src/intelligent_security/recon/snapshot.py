"""Immutable, deterministic recon snapshot creation."""

import hashlib
import json
from datetime import datetime, timezone

from intelligent_security.domain import Audit, ReconEvidencePack, ReconSnapshot, ReconScopeStatus


class ReconSnapshotError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def create_recon_snapshot(audit: Audit) -> ReconSnapshot:
    if audit.recon_plan is None:
        raise ReconSnapshotError("missing_recon_context", "A recon plan is required.")
    # Discovery can legitimately yield no executable recon contracts.  That is
    # a completed, zero-work recon pass: retain its coverage gaps and allow the
    # main planner to decide whether a different stage can proceed.
    if audit.recon_plan.steps and audit.recon_execution_schedule is None:
        raise ReconSnapshotError("missing_recon_context", "A schedule is required for non-empty recon plans.")
    if audit.recon_execution_schedule is not None and any(
        step.status.value not in {"SUCCEEDED", "FAILED", "CAPABILITY_UNAVAILABLE"}
        for step in audit.recon_execution_schedule.steps
    ):
        raise ReconSnapshotError("recon_incomplete", "All recon steps must be terminal before finalization.")
    in_scope = [item for item in audit.recon_observations if item.scope_status == ReconScopeStatus.IN_SCOPE]
    values = {
        "assets": sorted({item.value for item in in_scope if item.observation_type == "asset"}),
        "services": sorted({item.value for item in in_scope if item.observation_type == "service"}),
        "technologies": sorted({item.value for item in in_scope if item.observation_type == "technology"}),
        "endpoints": sorted({item.value for item in in_scope if item.observation_type == "endpoint"}),
        "interfaces": sorted({item.value for item in in_scope if item.observation_type == "interface"}),
        "evidence_ids": sorted({str(item.source_evidence_id) for item in in_scope}),
        "registry_snapshot_id": audit.recon_plan.registry_snapshot_id,
    }
    digest = hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return ReconSnapshot(
        snapshot_id="recon-{}".format(digest[:16]), audit_id=audit.id,
        registry_snapshot_id=audit.recon_plan.registry_snapshot_id,
        assets=values["assets"], services=values["services"], technologies=values["technologies"],
        endpoints=values["endpoints"], interfaces=values["interfaces"],
        coverage_gaps=audit.recon_plan.coverage_gaps,
        evidence_ids=values["evidence_ids"], digest=digest, created_at=datetime.now(timezone.utc),
    )


def create_recon_evidence_pack(audit: Audit, snapshot: ReconSnapshot, character_budget: int = 60000) -> ReconEvidencePack:
    """Select cited, in-scope chunks without silently discarding the raw evidence store."""
    in_scope = [item for item in audit.recon_observations if item.scope_status == ReconScopeStatus.IN_SCOPE]
    required = {chunk_id for item in in_scope for chunk_id in item.source_chunk_ids}
    selected, used = [], 0
    for chunk in sorted(audit.recon_evidence_chunks, key=lambda item: (item.chunk_id not in required, item.chunk_id)):
        if used + len(chunk.text) > character_budget:
            continue
        selected.append(chunk)
        used += len(chunk.text)
    return ReconEvidencePack(
        snapshot_id=snapshot.snapshot_id, observations=in_scope, chunks=selected,
        omitted_chunk_count=len(audit.recon_evidence_chunks) - len(selected),
        character_budget=character_budget, included_characters=used,
    )
