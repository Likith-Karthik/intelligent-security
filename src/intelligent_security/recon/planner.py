"""Deterministic selection of safe, executable recon capability contracts."""

from datetime import datetime, timezone
from typing import Dict, Iterable, List, Set

from intelligent_security.domain import (
    Audit,
    AuditOperation,
    CapabilityCandidate,
    CapabilityStage,
    ReconPlan,
    ReconPlanGap,
    ReconPlanStep,
    ReconPolicy,
)


class ReconPlanningError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class ReconPlanner:
    """Creates a capability-level recon DAG without selecting a plugin or calling an LLM."""

    # Dependencies are capability-contract relationships, not tool-specific behavior.
    _dependencies: Dict[str, tuple[str, ...]] = {
        "network.service_fingerprint": ("network.port_discovery",),
        "web.endpoint_enumeration": ("web.http_fingerprint",),
    }
    _unsafe_operations: Set[AuditOperation] = {
        AuditOperation.EXPLOIT,
        AuditOperation.DESTRUCTIVE_ACTION,
    }

    def create(self, audit: Audit, policy: ReconPolicy) -> ReconPlan:
        discovery = audit.recon_capability_discovery
        if discovery is None:
            raise ReconPlanningError(
                "missing_recon_discovery", "Executable recon capability discovery is required."
            )
        if audit.target_profile is None:
            raise ReconPlanningError("missing_target_profile", "Target profile is required for recon planning.")

        candidates = list(discovery.candidates)
        unsafe = [candidate for candidate in candidates if candidate.required_operation in self._unsafe_operations]
        if unsafe:
            raise ReconPlanningError(
                "unsafe_recon_capability",
                "Recon catalog includes offensive or destructive capability contracts: {}.".format(
                    ", ".join(sorted({candidate.capability for candidate in unsafe}))
                ),
            )
        non_recon = [candidate for candidate in candidates if candidate.stage != CapabilityStage.RECON]
        if non_recon:
            raise ReconPlanningError(
                "invalid_recon_catalog",
                "Recon catalog contains non-recon capability contracts.",
            )

        gaps = [
            ReconPlanGap(capability_family=gap.operation.value, reason=gap.reason)
            for gap in discovery.gaps
        ]
        selected_by_capability = self._best_candidate_per_capability(candidates)
        allowed_candidates = {}
        for capability, candidate in selected_by_capability.items():
            if candidate.required_operation not in policy.allowed_operations:
                gaps.append(ReconPlanGap(
                    capability_family=capability,
                    reason="Excluded by {}: operation {} is not allowed for baseline recon.".format(
                        policy.policy_version, candidate.required_operation.value
                    ),
                ))
                continue
            allowed_candidates[capability] = candidate

        duration_limit = min(audit.time_budget_seconds, policy.max_duration_seconds)
        cost_limit = min(audit.cost_budget_usd, policy.max_cost_usd)
        selected: List[CapabilityCandidate] = []
        skipped: Set[str] = set()

        for candidate in self._dependency_order(allowed_candidates.values()):
            dependencies = self._dependencies.get(candidate.capability, ())
            if any(dependency not in {item.capability for item in selected} for dependency in dependencies):
                gaps.append(ReconPlanGap(
                    capability_family=candidate.capability,
                    reason="Required recon dependency is unavailable or outside the current recon budget.",
                ))
                skipped.add(candidate.capability)
                continue
            if len(selected) >= policy.max_steps:
                gaps.append(ReconPlanGap(
                    capability_family=candidate.capability,
                    reason="Excluded because the {} step limit was reached.".format(policy.policy_version),
                ))
                skipped.add(candidate.capability)
                continue
            duration = sum(item.estimated_duration_seconds for item in selected) + candidate.estimated_duration_seconds
            cost = sum(item.estimated_cost_usd for item in selected) + candidate.estimated_cost_usd
            if duration > duration_limit or cost > cost_limit:
                limits = []
                if duration > duration_limit:
                    limits.append("time")
                if cost > cost_limit:
                    limits.append("cost")
                gaps.append(ReconPlanGap(
                    capability_family=candidate.capability,
                    reason="Excluded because the recon {} budget would be exceeded.".format(" and ".join(limits)),
                ))
                skipped.add(candidate.capability)
                continue
            selected.append(candidate)

        step_ids = {candidate.capability: "recon-{:02d}".format(index) for index, candidate in enumerate(selected, start=1)}
        steps = [
            ReconPlanStep(
                step_id=step_ids[candidate.capability],
                capability=candidate.capability,
                contract_version=candidate.contract_version,
                depends_on=[step_ids[dependency] for dependency in self._dependencies.get(candidate.capability, ())],
                rationale_codes=["baseline_recon", "highest_ranked_contract", "policy_allowed"],
            )
            for candidate in selected
        ]
        return ReconPlan(
            policy_version=policy.policy_version,
            registry_snapshot_id=discovery.registry_snapshot_id,
            target_type=audit.target_profile.target_type,
            max_concurrency=policy.max_concurrency,
            reserved_duration_seconds=sum(candidate.estimated_duration_seconds for candidate in selected),
            reserved_cost_usd=sum(candidate.estimated_cost_usd for candidate in selected),
            steps=steps,
            coverage_gaps=self._deduplicate_gaps(gaps),
            generated_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _best_candidate_per_capability(candidates: Iterable[CapabilityCandidate]) -> Dict[str, CapabilityCandidate]:
        best = {}
        for candidate in sorted(
            candidates,
            key=lambda item: (item.rank, -item.reliability, item.estimated_cost_usd, item.estimated_duration_seconds, item.capability),
        ):
            best.setdefault(candidate.capability, candidate)
        return best

    def _dependency_order(self, candidates: Iterable[CapabilityCandidate]) -> List[CapabilityCandidate]:
        candidates_by_capability = {candidate.capability: candidate for candidate in candidates}
        ordered = []
        visiting = set()
        visited = set()

        def visit(capability: str) -> None:
            if capability in visited or capability not in candidates_by_capability:
                return
            if capability in visiting:
                raise ReconPlanningError("invalid_recon_dependencies", "Recon capability dependencies contain a cycle.")
            visiting.add(capability)
            for dependency in self._dependencies.get(capability, ()):
                visit(dependency)
            visiting.remove(capability)
            visited.add(capability)
            ordered.append(candidates_by_capability[capability])

        for candidate in sorted(
            candidates_by_capability.values(),
            key=lambda item: (item.rank, -item.reliability, item.estimated_cost_usd, item.estimated_duration_seconds, item.capability),
        ):
            visit(candidate.capability)
        return ordered

    @staticmethod
    def _deduplicate_gaps(gaps: List[ReconPlanGap]) -> List[ReconPlanGap]:
        result = []
        seen = set()
        for gap in gaps:
            key = (gap.capability_family, gap.reason)
            if key not in seen:
                result.append(gap)
                seen.add(key)
        return result
