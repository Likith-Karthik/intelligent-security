import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import FastAPI, HTTPException, status

from .domain import Audit, AuditCreateRequest, AuditEvent, AuditState
from .policy.scope import ScopeValidationError, validate_scope
from .profiling.service import TargetProfilingError, profile_target
from .repository import AuditRepository


def create_app(database_path: str = None) -> FastAPI:
    resolved_path = database_path or os.getenv("AUDIT_DATABASE_PATH", "data/audits.db")
    app = FastAPI(title="Intelligent Security Audit Orchestrator", version="0.1.0")
    app.state.audit_repository = AuditRepository(resolved_path)

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
        if audit.state == AuditState.SCOPE_VALIDATED:
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
        if audit.state == AuditState.TARGET_PROFILED:
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

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
