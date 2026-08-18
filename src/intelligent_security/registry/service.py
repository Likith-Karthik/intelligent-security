import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from intelligent_security.domain import (
    Audit,
    CapabilityCandidate,
    CapabilityDiscovery,
    CapabilityGap,
    PluginHealth,
    PluginManifest,
)


class RegistryError(Exception):
    pass


class CapabilityRegistry:
    registry_version = "1"

    def __init__(self, manifest_directory: Optional[str] = None) -> None:
        default_directory = Path(__file__).resolve().parents[1] / "plugins" / "manifests"
        self.manifest_directory = Path(manifest_directory) if manifest_directory else default_directory

    def load_manifests(self) -> List[PluginManifest]:
        if not self.manifest_directory.exists():
            return []
        manifests = []
        for path in sorted(self.manifest_directory.glob("*.json")):
            try:
                with path.open(encoding="utf-8") as manifest_file:
                    manifests.append(PluginManifest.model_validate(json.load(manifest_file)))
            except (OSError, ValueError) as error:
                raise RegistryError("Unable to load plugin manifest {}: {}".format(path.name, error))
        return manifests

    def discover(self, audit: Audit) -> CapabilityDiscovery:
        if audit.target_profile is None or audit.scope_policy is None:
            raise RegistryError("Target profile and scope policy are required for capability discovery.")

        available_inputs = {"target_profile", "scope_policy"}
        if audit.credential_references:
            available_inputs.add("credential_reference")

        candidates = []
        for manifest in self.load_manifests():
            if not manifest.enabled or manifest.health != PluginHealth.DECLARED_HEALTHY:
                continue
            for capability in manifest.capabilities:
                if audit.target_profile.target_type not in capability.target_types:
                    continue
                if capability.required_operation not in audit.scope_policy.allowed_operations:
                    continue
                if not set(capability.required_inputs).issubset(available_inputs):
                    continue
                candidates.append(
                    CapabilityCandidate(
                        rank=0,
                        capability=capability.capability,
                        description=capability.description,
                        plugin_id=manifest.plugin_id,
                        plugin_version=manifest.plugin_version,
                        required_operation=capability.required_operation,
                        required_inputs=capability.required_inputs,
                        estimated_duration_seconds=capability.estimated_duration_seconds,
                        estimated_cost_usd=capability.estimated_cost_usd,
                        reliability=capability.reliability,
                        health=manifest.health,
                    )
                )

        candidates.sort(
            key=lambda item: (
                -item.reliability,
                item.estimated_cost_usd,
                item.estimated_duration_seconds,
                item.plugin_id,
            )
        )
        ranked_candidates = [
            candidate.model_copy(update={"rank": rank})
            for rank, candidate in enumerate(candidates, start=1)
        ]
        discovered_operations = {candidate.required_operation for candidate in ranked_candidates}
        gaps = [
            CapabilityGap(
                operation=operation,
                reason="No enabled, declared-healthy capability supports this authorized operation for the target.",
            )
            for operation in sorted(
                set(audit.scope_policy.allowed_operations).difference(discovered_operations),
                key=lambda operation: operation.value,
            )
        ]
        return CapabilityDiscovery(
            registry_version=self.registry_version,
            target_type=audit.target_profile.target_type,
            candidates=ranked_candidates,
            gaps=gaps,
            discovered_at=datetime.now(timezone.utc),
        )
