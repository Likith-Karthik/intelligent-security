from datetime import datetime, timezone
from typing import Dict, Protocol

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
from intelligent_security.registry.service import CapabilityRegistry, RegistryError


class ExecutionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class PluginAdapter(Protocol):
    def execute(self, runtime: PluginRuntimeProfile, audit: Audit, step: ScheduledStep) -> dict:
        """Execute a policy-controlled step and return summary metadata only."""


class ExecutionService:
    """Late-bind a scheduled capability to an operator-configured plugin runtime."""

    def __init__(self, runtime_profiles: PluginRuntimeProfileRegistry, adapters: Dict[str, PluginAdapter] = None) -> None:
        self.runtime_profiles = runtime_profiles
        self.adapters = adapters or {}

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

        candidate, runtime = self._resolve(step, current_discovery.candidates, profiles)
        adapter = self.adapters.get(runtime.adapter.value)
        if adapter is None:
            raise ExecutionError(
                "adapter_unavailable",
                "No approved adapter is registered for {}.".format(runtime.adapter.value),
            )

        step.status = ScheduledStepStatus.RUNNING
        try:
            output_summary = adapter.execute(runtime, audit, step)
        except Exception as error:
            step.status = ScheduledStepStatus.FAILED
            return PluginExecution(
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
                error_code="adapter_execution_failed",
                error_message=str(error),
            )

        step.status = ScheduledStepStatus.SUCCEEDED
        return PluginExecution(
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
            output_summary=output_summary,
        )

    @staticmethod
    def _resolve(
        step: ScheduledStep,
        candidates: list,
        profiles: Dict[str, PluginRuntimeProfile],
    ) -> tuple:
        for candidate in candidates:
            if candidate.capability != step.capability or candidate.contract_version != step.contract_version:
                continue
            runtime = profiles.get(candidate.plugin_id)
            if runtime is None or not runtime.enabled or runtime.adapter.value not in {"native", "container_cli", "rest", "restricted_mcp", "llm_testing"}:
                continue
            if runtime.adapter != candidate.adapter:
                continue
            return candidate, runtime
        raise ExecutionError(
            "capability_unavailable",
            "No active operator-configured implementation satisfies {} contract {}.".format(
                step.capability, step.contract_version
            ),
        )
