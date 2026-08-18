import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import UUID, uuid4

from .domain import Audit, AuditCreateRequest, AuditEvent, AuditState


class AuditRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    FOREIGN KEY (audit_id) REFERENCES audits(id)
                );
                """
            )

    def create(self, request: AuditCreateRequest) -> Audit:
        created_at = datetime.now(timezone.utc)
        audit = Audit(
            id=uuid4(),
            name=request.name,
            objective=request.objective,
            target=request.target,
            scope=request.scope,
            authorization=request.authorization,
            credential_references=request.credential_references,
            time_budget_seconds=request.time_budget_seconds,
            cost_budget_usd=request.cost_budget_usd,
            approval_policy=request.approval_policy,
            state=AuditState.CREATED,
            created_at=created_at,
        )
        payload = audit.model_dump_json()
        event = AuditEvent(
            event_id=uuid4(),
            event_type="audit.created",
            audit_id=audit.id,
            occurred_at=created_at,
            payload={"state": audit.state.value},
        )

        with self._connection() as connection:
            connection.execute(
                "INSERT INTO audits (id, payload, created_at) VALUES (?, ?, ?)",
                (str(audit.id), payload, created_at.isoformat()),
            )
            connection.execute(
                """
                INSERT INTO audit_events (id, audit_id, event_type, payload, occurred_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    str(audit.id),
                    event.event_type,
                    event.model_dump_json(),
                    created_at.isoformat(),
                ),
            )
        return audit

    def save_with_event(self, audit: Audit, event_type: str, payload: dict) -> Audit:
        occurred_at = datetime.now(timezone.utc)
        event = AuditEvent(
            event_id=uuid4(),
            event_type=event_type,
            audit_id=audit.id,
            occurred_at=occurred_at,
            payload=payload,
        )
        with self._connection() as connection:
            connection.execute(
                "UPDATE audits SET payload = ? WHERE id = ?",
                (audit.model_dump_json(), str(audit.id)),
            )
            connection.execute(
                """
                INSERT INTO audit_events (id, audit_id, event_type, payload, occurred_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    str(audit.id),
                    event.event_type,
                    event.model_dump_json(),
                    occurred_at.isoformat(),
                ),
            )
        return audit

    def get(self, audit_id: UUID) -> Optional[Audit]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM audits WHERE id = ?", (str(audit_id),)
            ).fetchone()
        return Audit.model_validate_json(row["payload"]) if row else None

    def list_events(self, audit_id: UUID) -> List[AuditEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT payload FROM audit_events
                WHERE audit_id = ? ORDER BY occurred_at ASC
                """,
                (str(audit_id),),
            ).fetchall()
        return [AuditEvent.model_validate_json(row["payload"]) for row in rows]
