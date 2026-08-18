import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, status

from .domain import (
    Audit,
    AuditCreateRequest,
    AuditEvent,
    AuditState,
    PlanApprovalRequest,
    PlanValidationStatus,
    PluginExecution,
    PluginExecutionStatus,
    ScheduledStepStatus,
)
from .execution.runtime_profiles import PluginRuntimeProfileRegistry
from .execution.adapters import ContainerCliAdapter
from .execution.service import ExecutionError, ExecutionService
from .policy.plan import PlanPolicyError, validate_plan
from .policy.scope import ScopeValidationError, validate_scope
from .planning.model_gateway import ModelGatewayError, OpenAICompatibleModelGateway
from .planning.model_profiles import ModelProfileError, ModelProfileRegistry
from .planning.service import AuditPlanner, PlanningError
from .profiling.service import TargetProfilingError, profile_target
from .registry.service import CapabilityRegistry, RegistryError
from .repository import AuditRepository
from .scheduling.service import ScheduleError, schedule_plan


def create_app(
    database_path: str = None,
    plugin_manifest_directory: str = None,
    model_profiles_path: str = None,
    registry_admin_token: str = None,
    plugin_runtime_profiles_path: str = None,
) -> FastAPI:
    resolved_path = database_path or os.getenv("AUDIT_DATABASE_PATH", "data/audits.db")
    app = FastAPI(title="Intelligent Security Audit Orchestrator", version="0.1.0")
    app.state.audit_repository = AuditRepository(resolved_path)
    app.state.capability_registry = CapabilityRegistry(plugin_manifest_directory)
    app.state.registry_admin_token = registry_admin_token or os.getenv("PLUGIN_REGISTRY_ADMIN_TOKEN")
    app.state.model_profile_registry = ModelProfileRegistry(model_profiles_path)
    app.state.audit_planner = AuditPlanner(OpenAICompatibleModelGateway())
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(plugin_runtime_profiles_path),
        {"container_cli": ContainerCliAdapter()},
    )

    @app.post("/audits", response_model=Audit, status_code=status.HTTP_201_CREATED)
    def create_audit(request: AuditCreateRequest) -> Audit:
        return app.state.audit_repository.create(request)

    @app.get("/audits/{audit_id}", response_model=Audit)
    def get_audit(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return audit

    @app.get("/audits/{audit_id}/events", response_model=List[AuditEvent])
    def get_audit_events(audit_id: UUID) -> List[AuditEvent]:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return app.state.audit_repository.list_events(audit_id)

    @app.post("/admin/plugins/refresh")
    def refresh_plugin_registry(
        x_plugin_registry_token: str = Header(default=None),
    ) -> dict:
        configured_token = app.state.registry_admin_token
        if not configured_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "registry_refresh_not_configured", "message": "Registry refresh token is not configured."},
            )
        if x_plugin_registry_token != configured_token:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Registry refresh is not authorized")
        try:
            snapshot = app.state.capability_registry.refresh()
        except RegistryError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "registry_admission_failed", "message": str(error)},
            )
        return snapshot.summary()

    @app.post("/audits/{audit_id}/scope/validate", response_model=Audit)
    def validate_audit_scope(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.scope_policy is not None and audit.state in {
            AuditState.SCOPE_VALIDATED,
            AuditState.TARGET_PROFILED,
            AuditState.CAPABILITIES_DISCOVERED,
        }:
            return audit
        if audit.state != AuditState.CREATED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit scope cannot be validated in its current state",
            )
        try:
            scope_policy = validate_scope(audit)
        except ScopeValidationError as error:
            audit.state = AuditState.SCOPE_REJECTED
            app.state.audit_repository.save_with_event(
                audit,
                "scope.rejected",
                {"code": error.code, "message": error.message},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )

        audit.scope_policy = scope_policy
        audit.scope_validated_at = datetime.now(timezone.utc)
        audit.state = AuditState.SCOPE_VALIDATED
        return app.state.audit_repository.save_with_event(
            audit,
            "scope.validated",
            {"authorization_id": scope_policy.authorization_id},
        )

    @app.post("/audits/{audit_id}/profile", response_model=Audit)
    def profile_audit_target(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.target_profile is not None and audit.state in {
            AuditState.TARGET_PROFILED,
            AuditState.CAPABILITIES_DISCOVERED,
        }:
            return audit
        if audit.state != AuditState.SCOPE_VALIDATED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit target cannot be profiled before scope validation",
            )
        try:
            target_profile = profile_target(audit)
        except TargetProfilingError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )

        audit.target_profile = target_profile
        audit.target_profiled_at = target_profile.profiled_at
        audit.state = AuditState.TARGET_PROFILED
        return app.state.audit_repository.save_with_event(
            audit,
            "target.profiled",
            {
                "profile_version": target_profile.profile_version,
                "profile_method": target_profile.profile_method,
                "target_type": target_profile.target_type,
            },
        )

    @app.post("/audits/{audit_id}/capabilities/discover", response_model=Audit)
    def discover_audit_capabilities(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state == AuditState.CAPABILITIES_DISCOVERED:
            return audit
        if audit.state != AuditState.TARGET_PROFILED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit capabilities cannot be discovered before target profiling",
            )
        try:
            discovery = app.state.capability_registry.discover(audit)
        except RegistryError as error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Capability registry error: {}".format(error),
            )

        audit.capability_discovery = discovery
        audit.capabilities_discovered_at = discovery.discovered_at
        audit.state = AuditState.CAPABILITIES_DISCOVERED
        return app.state.audit_repository.save_with_event(
            audit,
            "capabilities.discovered",
            {
                "candidate_count": len(discovery.candidates),
                "gap_count": len(discovery.gaps),
                "registry_version": discovery.registry_version,
                "registry_snapshot_id": discovery.registry_snapshot_id,
            },
        )

    @app.post("/audits/{audit_id}/plan/generate", response_model=Audit)
    def generate_audit_plan(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state == AuditState.PLAN_PROPOSED and audit.audit_plan is not None:
            return audit
        if audit.state != AuditState.CAPABILITIES_DISCOVERED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit plan cannot be generated before capability discovery",
            )
        try:
            profile = app.state.model_profile_registry.select_planner_profile(
                audit.planner_model_profile
            )
            audit_plan = app.state.audit_planner.generate(audit, profile)
        except ModelProfileError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "model_profile_unavailable", "message": str(error)},
            )
        except ModelGatewayError as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"code": error.code, "message": error.message},
            )
        except PlanningError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )

        audit.audit_plan = audit_plan
        audit.plan_proposed_at = audit_plan.generated_at
        audit.state = AuditState.PLAN_PROPOSED
        return app.state.audit_repository.save_with_event(
            audit,
            "plan.proposed",
            {
                "model_profile_id": audit_plan.model_profile_id,
                "step_count": len(audit_plan.steps),
                "plan_version": audit_plan.plan_version,
                "registry_snapshot_id": audit_plan.registry_snapshot_id,
            },
        )

    @app.post("/audits/{audit_id}/plan/validate", response_model=Audit)
    def validate_audit_plan(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state in {AuditState.PLAN_APPROVED, AuditState.PLAN_PENDING_APPROVAL}:
            return audit
        if audit.state != AuditState.PLAN_PROPOSED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit plan cannot be validated before it is proposed",
            )
        try:
            validation = validate_plan(audit)
        except PlanPolicyError as error:
            audit.state = AuditState.PLAN_REJECTED
            audit.plan_validated_at = datetime.now(timezone.utc)
            return app.state.audit_repository.save_with_event(
                audit,
                "plan.rejected",
                {"code": error.code, "message": error.message},
            )

        audit.plan_validation = validation
        audit.plan_validated_at = validation.validated_at
        if validation.status == PlanValidationStatus.PENDING_HUMAN_APPROVAL:
            audit.state = AuditState.PLAN_PENDING_APPROVAL
            return app.state.audit_repository.save_with_event(
                audit,
                "plan.approval_requested",
                {
                    "estimated_duration_seconds": validation.estimated_duration_seconds,
                    "estimated_cost_usd": validation.estimated_cost_usd,
                    "reasons": validation.reasons,
                },
            )
        audit.state = AuditState.PLAN_APPROVED
        audit.plan_approved_at = validation.validated_at
        audit.plan_approved_by = "policy-engine"
        return app.state.audit_repository.save_with_event(
            audit,
            "plan.approved",
            {
                "approved_by": audit.plan_approved_by,
                "approval_required": False,
                "registry_snapshot_id": validation.registry_snapshot_id,
            },
        )

    @app.post("/audits/{audit_id}/plan/approval", response_model=Audit)
    def decide_audit_plan(audit_id: UUID, request: PlanApprovalRequest) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state != AuditState.PLAN_PENDING_APPROVAL:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit plan is not awaiting human approval",
            )
        if request.decision == "reject":
            audit.state = AuditState.PLAN_REJECTED
            return app.state.audit_repository.save_with_event(
                audit,
                "plan.rejected",
                {"code": "human_rejected", "reviewed_by": request.reviewed_by, "reason": request.reason},
            )
        audit.state = AuditState.PLAN_APPROVED
        audit.plan_approved_at = datetime.now(timezone.utc)
        audit.plan_approved_by = request.reviewed_by
        return app.state.audit_repository.save_with_event(
            audit,
            "plan.approved",
            {"approved_by": request.reviewed_by, "approval_required": True, "reason": request.reason},
        )

    @app.post("/audits/{audit_id}/plan/schedule", response_model=Audit)
    def schedule_audit_plan(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state == AuditState.PLAN_SCHEDULED and audit.execution_schedule is not None:
            return audit
        if audit.state != AuditState.PLAN_APPROVED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit plan cannot be scheduled before approval",
            )
        try:
            execution_schedule = schedule_plan(audit)
        except ScheduleError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )
        audit.execution_schedule = execution_schedule
        audit.plan_scheduled_at = execution_schedule.scheduled_at
        audit.state = AuditState.PLAN_SCHEDULED
        ready_count = sum(step.status.value == "READY" for step in execution_schedule.steps)
        return app.state.audit_repository.save_with_event(
            audit,
            "plan.scheduled",
            {
                "step_count": len(execution_schedule.steps),
                "ready_count": ready_count,
                "pending_count": len(execution_schedule.steps) - ready_count,
                "reserved_duration_seconds": execution_schedule.reserved_duration_seconds,
                "reserved_cost_usd": execution_schedule.reserved_cost_usd,
                "registry_snapshot_id": execution_schedule.registry_snapshot_id,
            },
        )

    @app.post("/audits/{audit_id}/steps/{step_id}/execute", response_model=Audit)
    def execute_scheduled_step(audit_id: UUID, step_id: str) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state != AuditState.PLAN_SCHEDULED or audit.execution_schedule is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Audit step cannot be executed before scheduling",
            )
        step = next(
            (item for item in audit.execution_schedule.steps if item.plan_step_id == step_id), None
        )
        if step is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled step not found")
        try:
            execution = app.state.execution_service.execute(
                audit, step, app.state.capability_registry
            )
        except ExecutionError as error:
            if error.code == "capability_unavailable":
                step.status = ScheduledStepStatus.CAPABILITY_UNAVAILABLE
            snapshot_id = app.state.capability_registry.active_snapshot().snapshot_id
            audit.plugin_executions.append(
                PluginExecution(
                    plan_step_id=step.plan_step_id,
                    capability=step.capability,
                    contract_version=step.contract_version,
                    registry_snapshot_id=snapshot_id,
                    status=PluginExecutionStatus.CAPABILITY_UNAVAILABLE,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    error_code=error.code,
                    error_message=error.message,
                )
            )
            app.state.audit_repository.save_with_event(
                audit,
                "step.execution_blocked",
                {"step_id": step.plan_step_id, "code": error.code, "message": error.message},
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": error.code, "message": error.message},
            )

        audit.plugin_executions.append(execution)
        event_type = "step.completed" if execution.status == PluginExecutionStatus.SUCCEEDED else "step.failed"
        return app.state.audit_repository.save_with_event(
            audit,
            event_type,
            {
                "step_id": step.plan_step_id,
                "execution_id": str(execution.execution_id),
                "plugin_id": execution.plugin_id,
                "plugin_version": execution.plugin_version,
                "adapter": execution.adapter.value if execution.adapter else None,
                "status": execution.status.value,
            },
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
