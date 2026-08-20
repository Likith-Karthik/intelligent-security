from datetime import datetime, timezone
from typing import Dict, Protocol
from urllib.parse import urlparse

from intelligent_security.domain import (
    Audit,
    CapabilityCandidate,
    PluginExecution,
    PluginExecutionStatus,
    ScheduledStep,
    ScheduledStepStatus,
)
from intelligent_security.execution.runtime_profiles import (
    PluginRuntimeProfile,
    PluginRuntimeProfileRegistry,
    RuntimeProfileError,
)
from intelligent_security.execution.result import AdapterExecutionResult
from intelligent_security.evidence.collector import EvidenceCollector
from intelligent_security.registry.service import CapabilityRegistry, PluginPackage, RegistryError


class ExecutionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class PluginAdapter(Protocol):
    def execute(self, runtime: PluginRuntimeProfile, audit: Audit, step: ScheduledStep, package: PluginPackage) -> AdapterExecutionResult:
        """Execute a policy-controlled step and return raw output for evidence capture."""


class ExecutionService:
    """Late-bind a scheduled capability to an operator-configured plugin runtime."""

    def __init__(self, runtime_profiles: PluginRuntimeProfileRegistry, adapters: Dict[str, PluginAdapter] = None, evidence_collector: EvidenceCollector = None) -> None:
        self.runtime_profiles = runtime_profiles
        self.adapters = adapters or {}
        self.evidence_collector = evidence_collector

    def execute(self, audit: Audit, step: ScheduledStep, registry: CapabilityRegistry) -> PluginExecution:
        if step.status != ScheduledStepStatus.READY:
            raise ExecutionError("step_not_ready", "Step {} is not ready for execution.".format(step.plan_step_id))
        if audit.execution_schedule is None:
            raise ExecutionError("missing_execution_schedule", "Execution schedule is required.")

        started_at = datetime.now(timezone.utc)
        try:
            current_discovery = registry.discover(audit)
            profiles = self.runtime_profiles.load()
        except (RegistryError, RuntimeProfileError) as error:
            raise ExecutionError("runtime_configuration_error", str(error))

        candidate, runtime, package = self._resolve(audit, step, current_discovery.candidates, profiles, registry)
        adapter = self.adapters.get(runtime.adapter.value)
        if adapter is None:
            raise ExecutionError(
                "adapter_unavailable",
                "No approved adapter is registered for {}.".format(runtime.adapter.value),
            )

        step.status = ScheduledStepStatus.RUNNING
        try:
            result = adapter.execute(runtime, audit, step, package)
        except Exception as error:
            step.status = ScheduledStepStatus.FAILED
            result = AdapterExecutionResult(error_code="adapter_execution_failed", error_message=str(error))
        if isinstance(result, dict):
            # Compatibility for simple custom adapters during the POC migration.
            result = AdapterExecutionResult(output_summary=result)

        if result.error_code or result.exit_code not in (None, 0):
            step.status = ScheduledStepStatus.FAILED
            execution = PluginExecution(
                plan_step_id=step.plan_step_id,
                capability=step.capability,
                contract_version=step.contract_version,
                plugin_id=candidate.plugin_id,
                plugin_version=candidate.plugin_version,
                adapter=runtime.adapter,
                registry_snapshot_id=current_discovery.registry_snapshot_id,
                status=PluginExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                output_summary=result.output_summary,
                error_code=result.error_code or "adapter_nonzero_exit",
                error_message=result.error_message or "Plugin adapter returned a non-zero exit status.",
            )
        else:
            step.status = ScheduledStepStatus.SUCCEEDED
            execution = PluginExecution(
                plan_step_id=step.plan_step_id,
                capability=step.capability,
                contract_version=step.contract_version,
                plugin_id=candidate.plugin_id,
                plugin_version=candidate.plugin_version,
                adapter=runtime.adapter,
                registry_snapshot_id=current_discovery.registry_snapshot_id,
                status=PluginExecutionStatus.SUCCEEDED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                output_summary=result.output_summary,
            )
        if self.evidence_collector is not None:
            evidence = self.evidence_collector.capture(audit, execution, result, runtime.image_reference)
            audit.raw_evidence.append(evidence)
            execution.evidence_record_id = evidence.evidence_id
        return execution

    def executable_plugin_ids(self, audit: Audit, registry: CapabilityRegistry) -> set[str]:
        """Return plugins that can be selected now without exposing runtime details.

        This is used by capability discovery before planner context is built. Plugin
        packages remain declarative and no plugin-specific code is required here.
        """
        try:
            profiles = self.runtime_profiles.load()
        except RuntimeProfileError as error:
            raise ExecutionError("runtime_configuration_error", str(error))
        eligible = set()
        for package in registry.active_snapshot().packages:
            runtime = profiles.get(package.manifest.plugin_id)
            if runtime is None or not runtime.enabled:
                continue
            if runtime.adapter != package.manifest.adapter or package.execution is None:
                continue
            if package.execution.adapter != runtime.adapter or runtime.adapter.value not in self.adapters:
                continue
            if self._runtime_allows_target(runtime, audit):
                eligible.add(package.manifest.plugin_id)
        return eligible

    @staticmethod
    def _resolve(
        audit: Audit,
        step: ScheduledStep,
        candidates: list,
        profiles: Dict[str, PluginRuntimeProfile],
        registry: CapabilityRegistry,
    ) -> tuple:
        for candidate in candidates:
            if candidate.capability != step.capability or candidate.contract_version != step.contract_version:
                continue
            runtime = profiles.get(candidate.plugin_id)
            if runtime is None or not runtime.enabled or runtime.adapter.value not in {"native", "container_cli", "rest", "restricted_mcp", "llm_testing"}:
                continue
            if runtime.adapter != candidate.adapter:
                continue
            if not ExecutionService._runtime_allows_target(runtime, audit):
                continue
            package = registry.active_snapshot().package_for_plugin(candidate.plugin_id)
            if package is None or package.execution is None or package.execution.adapter != runtime.adapter:
                continue
            return candidate, runtime, package
        raise ExecutionError(
            "capability_unavailable",
            "No active operator-configured implementation satisfies {} contract {}.".format(
                step.capability, step.contract_version
            ),
        )

    @staticmethod
    def _runtime_allows_target(runtime: PluginRuntimeProfile, audit: Audit) -> bool:
        if audit.target_profile is None:
            return False
        target = audit.target_profile.canonical_identifier
        parsed = urlparse(target)
        hostname = (parsed.hostname or target.split("/")[0]).lower().rstrip(".")
        allowed_hosts = {host.lower().rstrip(".") for host in runtime.allowed_target_hosts}
        return hostname in allowed_hosts or target in allowed_hosts
