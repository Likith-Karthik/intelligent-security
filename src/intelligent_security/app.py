import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import FastAPI, HTTPException, status

from .domain import Audit, AuditCreateRequest, AuditEvent, AuditState
from .policy.scope import ScopeValidationError, validate_scope
from .planning.model_gateway import ModelGatewayError, OpenAICompatibleModelGateway
from .planning.model_profiles import ModelProfileError, ModelProfileRegistry
from .planning.service import AuditPlanner, PlanningError
from .profiling.service import TargetProfilingError, profile_target
from .registry.service import CapabilityRegistry, RegistryError
from .repository import AuditRepository


def create_app(
    database_path: str = None,
    plugin_manifest_directory: str = None,
    model_profiles_path: str = None,
) -> FastAPI:
    resolved_path = database_path or os.getenv("AUDIT_DATABASE_PATH", "data/audits.db")
    app = FastAPI(title="Intelligent Security Audit Orchestrator", version="0.1.0")
    app.state.audit_repository = AuditRepository(resolved_path)
    app.state.capability_registry = CapabilityRegistry(plugin_manifest_directory)
    app.state.model_profile_registry = ModelProfileRegistry(model_profiles_path)
    app.state.audit_planner = AuditPlanner(OpenAICompatibleModelGateway())

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
            },
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
