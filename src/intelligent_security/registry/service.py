import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from intelligent_security.domain import (
    Audit,
    CapabilityCandidate,
    CapabilityDiscovery,
    CapabilityGap,
    PluginHealth,
    PluginExecutionSpec,
    PluginManifest,
)


class RegistryError(Exception):
    pass


class PluginPackage:
    """An admitted plugin package; execution details remain internal to the registry."""

    def __init__(self, manifest: PluginManifest, root: Path, execution: Optional[PluginExecutionSpec]) -> None:
        self.manifest = manifest
        self.root = root
        self.execution = execution


class RegistrySnapshot:
    def __init__(self, snapshot_id: str, packages: List[PluginPackage], created_at: datetime) -> None:
        self.snapshot_id = snapshot_id
        self.packages = packages
        self.created_at = created_at

    @property
    def manifests(self) -> List[PluginManifest]:
        return [package.manifest for package in self.packages]

    def package_for_plugin(self, plugin_id: str) -> Optional[PluginPackage]:
        return next((package for package in self.packages if package.manifest.plugin_id == plugin_id), None)

    def summary(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "registry_version": CapabilityRegistry.registry_version,
            "plugin_count": len(self.manifests),
            "capability_count": sum(len(manifest.capabilities) for manifest in self.manifests),
            "created_at": self.created_at,
        }


class CapabilityRegistry:
    registry_version = "1"

    def __init__(self, manifest_directory: Optional[str] = None) -> None:
        default_directory = Path(__file__).resolve().parents[1] / "plugins" / "packages"
        self.manifest_directory = Path(manifest_directory) if manifest_directory else default_directory
        self._snapshot: Optional[RegistrySnapshot] = None

    def load_manifests(self) -> List[PluginManifest]:
        return [package.manifest for package in self.load_packages()]

    def load_packages(self) -> List[PluginPackage]:
        if not self.manifest_directory.exists():
            return []
        manifest_paths = sorted(self.manifest_directory.rglob("manifest.json"))
        # Flat manifests remain accepted for backward-compatible operator configuration.
        manifest_paths.extend(
            path for path in sorted(self.manifest_directory.glob("*.json")) if path not in manifest_paths
        )
        packages = []
        for path in manifest_paths:
            try:
                with path.open(encoding="utf-8") as manifest_file:
                    manifest = PluginManifest.model_validate(json.load(manifest_file))
                execution_path = path.parent / "execution.json"
                execution = None
                if execution_path.exists():
                    with execution_path.open(encoding="utf-8") as execution_file:
                        execution = PluginExecutionSpec.model_validate(json.load(execution_file))
                    if execution.adapter != manifest.adapter:
                        raise RegistryError("Execution adapter must match manifest adapter.")
                    self._validate_execution_mounts(path.parent, execution)
                packages.append(PluginPackage(manifest, path.parent, execution))
            except (OSError, ValueError) as error:
                raise RegistryError("Unable to load plugin manifest {}: {}".format(path.name, error))
        return packages

    @staticmethod
    def _validate_execution_mounts(package_root: Path, execution: PluginExecutionSpec) -> None:
        root = package_root.resolve()
        for mount in execution.mounts:
            source = (root / mount.source).resolve()
            if root not in source.parents and source != root:
                raise RegistryError("Plugin execution mount escapes its package root.")
            if not source.exists():
                raise RegistryError("Plugin execution mount source does not exist: {}".format(mount.source))

    def refresh(self) -> RegistrySnapshot:
        """Atomically replace the active snapshot after complete manifest admission."""
        packages = self.load_packages()
        plugin_ids = [package.manifest.plugin_id for package in packages]
        if len(plugin_ids) != len(set(plugin_ids)):
            raise RegistryError("Plugin manifest admission failed: duplicate plugin_id.")
        serialized = json.dumps(
            [
                {
                    "manifest": package.manifest.model_dump(mode="json"),
                    "execution": package.execution.model_dump(mode="json") if package.execution else None,
                }
                for package in packages
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        snapshot_id = "registry-{}".format(hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16])
        snapshot = RegistrySnapshot(snapshot_id, packages, datetime.now(timezone.utc))
        self._snapshot = snapshot
        return snapshot

    def active_snapshot(self) -> RegistrySnapshot:
        if self._snapshot is None:
            return self.refresh()
        return self._snapshot

    def discover(self, audit: Audit) -> CapabilityDiscovery:
        if audit.target_profile is None or audit.scope_policy is None:
            raise RegistryError("Target profile and scope policy are required for capability discovery.")

        available_inputs = {"target_profile", "scope_policy"}
        if audit.credential_references:
            available_inputs.add("credential_reference")

        snapshot = self.active_snapshot()
        candidates = []
        for package in snapshot.packages:
            manifest = package.manifest
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
                        contract_version=capability.contract_version,
                        description=capability.description,
                        plugin_id=manifest.plugin_id,
                        plugin_version=manifest.plugin_version,
                        adapter=manifest.adapter,
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
            registry_snapshot_id=snapshot.snapshot_id,
            target_type=audit.target_profile.target_type,
            candidates=ranked_candidates,
            gaps=gaps,
            discovered_at=datetime.now(timezone.utc),
        )
