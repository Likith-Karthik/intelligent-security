from datetime import datetime
from enum import Enum
from typing import Annotated, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


CredentialReference = Annotated[
    str,
    Field(
        min_length=8,
        max_length=1024,
        pattern=r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$",
        description="Opaque reference to a secret held outside this service.",
    ),
]


class AuditState(str, Enum):
    CREATED = "CREATED"
    SCOPE_VALIDATED = "SCOPE_VALIDATED"
    SCOPE_REJECTED = "SCOPE_REJECTED"


class AuditOperation(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    WEB_SCAN = "web_scan"
    PORT_DISCOVERY = "port_discovery"
    LLM_RED_TEAM = "llm_red_team"
    EXPLOIT = "exploit"
    DESTRUCTIVE_ACTION = "destructive_action"


class TargetDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_type: str = Field(..., min_length=1, max_length=100)
    identifier: str = Field(..., min_length=1, max_length=2048)


class ScopeDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorized_assets: List[str] = Field(..., min_length=1, max_length=500)
    excluded_assets: List[str] = Field(default_factory=list, max_length=500)
    prohibited_operations: List[AuditOperation] = Field(
        default_factory=lambda: [AuditOperation.EXPLOIT, AuditOperation.DESTRUCTIVE_ACTION],
        max_length=50,
    )


class AuthorizationMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization_id: str = Field(..., min_length=3, max_length=200)
    authorized_by: str = Field(..., min_length=3, max_length=200)
    valid_until: datetime
    allowed_operations: List[AuditOperation] = Field(..., min_length=1, max_length=50)


class ScopePolicy(BaseModel):
    authorized_assets: List[str]
    excluded_assets: List[str]
    network_allowlist: List[str]
    filesystem_boundaries: List[str]
    allowed_operations: List[AuditOperation]
    prohibited_operations: List[AuditOperation]
    authorization_id: str
    valid_until: datetime


class AuditCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., min_length=1, max_length=4000)
    target: TargetDefinition
    scope: ScopeDefinition
    authorization: AuthorizationMetadata
    credential_references: List[CredentialReference] = Field(default_factory=list, max_length=100)
    time_budget_seconds: int = Field(..., ge=60, le=604800)
    cost_budget_usd: float = Field(..., ge=0, le=1000000)
    approval_policy: str = Field(..., min_length=1, max_length=100)



class Audit(BaseModel):
    id: UUID
    name: str
    objective: str
    target: TargetDefinition
    scope: ScopeDefinition
    authorization: AuthorizationMetadata
    credential_references: List[CredentialReference]
    time_budget_seconds: int
    cost_budget_usd: float
    approval_policy: str
    state: AuditState
    created_at: datetime
    scope_policy: Optional[ScopePolicy] = None
    scope_validated_at: Optional[datetime] = None


class AuditEvent(BaseModel):
    event_id: UUID
    event_type: str
    audit_id: UUID
    occurred_at: datetime
    payload: dict
