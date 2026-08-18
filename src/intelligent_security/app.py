import os
from typing import List
from uuid import UUID

from fastapi import FastAPI, HTTPException, status

from .domain import Audit, AuditCreateRequest, AuditCreatedEvent
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

    @app.get("/audits/{audit_id}/events", response_model=List[AuditCreatedEvent])
    def get_audit_events(audit_id: UUID) -> List[AuditCreatedEvent]:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return app.state.audit_repository.list_events(audit_id)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
