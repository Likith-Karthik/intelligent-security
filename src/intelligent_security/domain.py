from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    TARGET_PROFILED = "TARGET_PROFILED"
    CAPABILITIES_DISCOVERED = "CAPABILITIES_DISCOVERED"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    PLAN_PENDING_APPROVAL = "PLAN_PENDING_APPROVAL"
    PLAN_APPROVED = "PLAN_APPROVED"
    PLAN_REJECTED = "PLAN_REJECTED"
    PLAN_SCHEDULED = "PLAN_SCHEDULED"


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


class TargetProfile(BaseModel):
    profile_version: str
    profile_method: str
    target_type: str
    canonical_identifier: str
    interfaces: List[str]
    technologies: List[str]
    source_available: bool
    authentication: str
    confidence: float = Field(..., ge=0, le=1)
    profiled_at: datetime


class PluginHealth(str, Enum):
    DECLARED_HEALTHY = "declared_healthy"
    DECLARED_UNHEALTHY = "declared_unhealthy"


class PluginAdapter(str, Enum):
    NATIVE = "native"
    CONTAINER_CLI = "container_cli"
    REST = "rest"
    RESTRICTED_MCP = "restricted_mcp"
    LLM_TESTING = "llm_testing"


class PluginCapability(BaseModel):
    capability: str = Field(..., min_length=3, max_length=200)
    contract_version: str = Field(default="1", min_length=1, max_length=50)
    description: str = Field(..., min_length=1, max_length=1000)
    target_types: List[str] = Field(..., min_length=1, max_length=50)
    required_operation: AuditOperation
    required_inputs: List[str] = Field(default_factory=list, max_length=20)
    estimated_duration_seconds: int = Field(..., ge=1, le=604800)
    estimated_cost_usd: float = Field(..., ge=0, le=1000000)
    reliability: float = Field(..., ge=0, le=1)
    input_schema: str = Field(default="policy-controlled/v1", min_length=1, max_length=200)
    output_schema: str = Field(default="finding-batch/v1", min_length=1, max_length=200)
    validation_for: List[str] = Field(default_factory=list, max_length=50)


class PluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plugin_id: str = Field(..., min_length=3, max_length=200)
    plugin_version: str = Field(..., min_length=1, max_length=100)
    kind: str = Field(default="native_security_tool", min_length=1, max_length=100)
    adapter: PluginAdapter = PluginAdapter.CONTAINER_CLI
    enabled: bool = True
    health: PluginHealth = PluginHealth.DECLARED_HEALTHY
    capabilities: List[PluginCapability] = Field(..., min_length=1, max_length=100)


class PluginPackageMount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_./-]+$")
    target: str = Field(..., min_length=2, max_length=200, pattern=r"^/[A-Za-z0-9_./-]+$")
    read_only: bool = True


class PluginExecutionSpec(BaseModel):
    """Trusted, package-owned invocation descriptor; never shown to the planner."""

    model_config = ConfigDict(extra="forbid")

    adapter: PluginAdapter
    arguments: List[str] = Field(..., min_length=1, max_length=100)
    mounts: List[PluginPackageMount] = Field(default_factory=list, max_length=20)
    output_format: str = Field(default="jsonl", pattern=r"^(jsonl|text)$")


class NormalizerField(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Optional[str] = Field(default=None, max_length=500)
    default: Optional[Any] = None


class PluginNormalizerSpec(BaseModel):
    """Trusted declarative mapping from a package's JSONL output to observation/v1."""

    model_config = ConfigDict(extra="forbid")

    input_artifact_kind: str = Field(default="stdout", pattern=r"^[a-z0-9_-]+$")
    input_format: str = Field(default="jsonl", pattern=r"^jsonl$")
    fields: Dict[str, NormalizerField] = Field(..., min_length=1, max_length=30)


class CapabilityCandidate(BaseModel):
    rank: int
    capability: str
    contract_version: str = "1"
    description: str
    plugin_id: str
    plugin_version: str
    adapter: PluginAdapter = PluginAdapter.CONTAINER_CLI
    required_operation: AuditOperation
    required_inputs: List[str]
    estimated_duration_seconds: int
    estimated_cost_usd: float
    reliability: float
    health: PluginHealth
    validation_for: List[str] = Field(default_factory=list)


class CapabilityGap(BaseModel):
    operation: AuditOperation
    reason: str


class CapabilityDiscovery(BaseModel):
    registry_version: str
    registry_snapshot_id: str = "legacy"
    target_type: str
    candidates: List[CapabilityCandidate]
    gaps: List[CapabilityGap]
    discovered_at: datetime


class ModelProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str = Field(..., min_length=3, max_length=100)
    purpose: str = Field(..., min_length=1, max_length=100)
    provider: str = Field(..., min_length=1, max_length=100)
    model: str = Field(..., min_length=1, max_length=200)
    credential_reference: CredentialReference
    base_url: str = Field(..., min_length=1, max_length=2048)
    temperature: float = Field(..., ge=0, le=2)
    max_output_tokens: int = Field(..., ge=100, le=100000)
    timeout_seconds: int = Field(..., ge=1, le=600)
    enabled: bool = True
    default_for_purpose: bool = False


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=100)
    capability: str = Field(..., min_length=3, max_length=200)
    depends_on: List[str] = Field(default_factory=list, max_length=100)
    inputs: dict = Field(default_factory=dict)
    reason: str = Field(..., min_length=1, max_length=2000)

    @field_validator("id", mode="before")
    @classmethod
    def normalize_numeric_step_id(cls, value):
        if isinstance(value, bool):
            raise ValueError("Plan step IDs must be strings or integers.")
        if isinstance(value, int):
            return str(value)
        return value

    @field_validator("inputs")
    @classmethod
    def inputs_must_be_empty_during_planning(cls, value: dict) -> dict:
        if value:
            raise ValueError(
                "Planning cannot supply tool inputs; execution supplies policy-controlled typed inputs."
            )
        return value


class AuditPlan(BaseModel):
    plan_version: str
    model_profile_id: str
    registry_snapshot_id: str = "legacy"
    steps: List[PlanStep] = Field(..., min_length=1, max_length=100)
    generated_at: datetime


class PlanValidationStatus(str, Enum):
    APPROVED = "APPROVED"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    REJECTED = "REJECTED"


class PlanValidation(BaseModel):
    status: PlanValidationStatus
    estimated_duration_seconds: int = Field(..., ge=0)
    estimated_cost_usd: float = Field(..., ge=0)
    approval_required: bool
    registry_snapshot_id: str = "legacy"
    reasons: List[str] = Field(default_factory=list)
    validated_at: datetime


class PlanApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(..., pattern=r"^(approve|reject)$")
    reviewed_by: str = Field(..., min_length=3, max_length=200)
    reason: str = Field(..., min_length=1, max_length=1000)


class ScheduledStepStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"


class ScheduledStep(BaseModel):
    plan_step_id: str
    capability: str
    contract_version: str = "1"
    depends_on: List[str]
    status: ScheduledStepStatus
    estimated_duration_seconds: int = Field(..., ge=1)
    estimated_cost_usd: float = Field(..., ge=0)


class ExecutionSchedule(BaseModel):
    schedule_version: str
    registry_snapshot_id: str = "legacy"
    steps: List[ScheduledStep] = Field(..., min_length=1, max_length=100)
    reserved_duration_seconds: int = Field(..., ge=0)
    reserved_cost_usd: float = Field(..., ge=0)
    scheduled_at: datetime


class PluginExecutionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"


class EvidenceArtifact(BaseModel):
    """Metadata for a raw evidence artifact; the artifact body is never embedded in an audit."""

    model_config = ConfigDict(frozen=True)

    artifact_id: UUID = Field(default_factory=uuid4)
    kind: str = Field(..., min_length=1, max_length=100)
    content_type: str = Field(..., min_length=1, max_length=200)
    storage_uri: str = Field(..., min_length=1, max_length=2048)
    byte_size: int = Field(..., ge=0)
    sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")


class RawEvidenceRecord(BaseModel):
    """Immutable provenance and artifact index captured before output normalization."""

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID = Field(default_factory=uuid4)
    execution_id: UUID
    audit_id: UUID
    plan_step_id: str
    target_identifier: str
    plugin_id: Optional[str] = None
    plugin_version: Optional[str] = None
    container_image_digest: Optional[str] = None
    redacted_invocation: List[str] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime
    exit_code: Optional[int] = None
    artifacts: List[EvidenceArtifact] = Field(default_factory=list)


class ObservationNormalizationStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class Observation(BaseModel):
    """Versioned, plugin-neutral representation of one tool-reported observation."""

    model_config = ConfigDict(frozen=True)

    observation_id: UUID = Field(default_factory=uuid4)
    schema_version: str = "observation/v1"
    audit_id: UUID
    execution_id: UUID
    evidence_id: UUID
    category: str = Field(..., min_length=1, max_length=200)
    title: str = Field(..., min_length=1, max_length=1000)
    description: Optional[str] = Field(default=None, max_length=10000)
    affected_asset: Optional[str] = Field(default=None, max_length=2048)
    location: Optional[str] = Field(default=None, max_length=4096)
    severity_reported: Optional[str] = Field(default=None, max_length=100)
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    identifiers: List[str] = Field(default_factory=list, max_length=100)
    evidence_artifact_ids: List[UUID] = Field(default_factory=list, min_length=1, max_length=100)
    tool_metadata: dict = Field(default_factory=dict)


class ObservationNormalization(BaseModel):
    model_config = ConfigDict(frozen=True)

    normalization_id: UUID = Field(default_factory=uuid4)
    evidence_id: UUID
    execution_id: UUID
    plugin_id: Optional[str] = None
    plugin_version: Optional[str] = None
    status: ObservationNormalizationStatus
    normalized_at: datetime
    accepted_count: int = Field(..., ge=0)
    rejected_count: int = Field(..., ge=0)
    errors: List[str] = Field(default_factory=list, max_length=100)


class FindingState(str, Enum):
    CANDIDATE = "CANDIDATE"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    RETEST_PENDING = "RETEST_PENDING"
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"


class FindingValidationOutcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingValidationProposal(BaseModel):
    capability: str
    contract_version: str
    reason: str
    requires_normal_plan_approval: bool = True


class FindingValidationBasis(BaseModel):
    validation_id: UUID = Field(default_factory=uuid4)
    outcome: FindingValidationOutcome
    evidence_id: UUID
    validated_by: str = Field(..., min_length=3, max_length=200)
    basis: str = Field(..., min_length=3, max_length=4000)
    recorded_at: datetime


class FindingValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: FindingValidationOutcome
    evidence_id: UUID
    validated_by: str = Field(..., min_length=3, max_length=200)
    basis: str = Field(..., min_length=3, max_length=4000)


class CandidateFinding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    state: FindingState = FindingState.CANDIDATE
    correlation_key: str = Field(..., min_length=1, max_length=500)
    category: str = Field(..., min_length=1, max_length=200)
    title: str = Field(..., min_length=1, max_length=1000)
    affected_asset: Optional[str] = Field(default=None, max_length=2048)
    location: Optional[str] = Field(default=None, max_length=4096)
    severity_reported: Optional[str] = Field(default=None, max_length=100)
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    observation_ids: List[UUID] = Field(..., min_length=1, max_length=1000)
    evidence_ids: List[UUID] = Field(..., min_length=1, max_length=1000)
    source_capabilities: List[str] = Field(default_factory=list)
    validation_proposal: Optional[FindingValidationProposal] = None
    validation_history: List[FindingValidationBasis] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class PluginExecution(BaseModel):
    execution_id: UUID = Field(default_factory=uuid4)
    plan_step_id: str
    capability: str
    contract_version: str
    plugin_id: Optional[str] = None
    plugin_version: Optional[str] = None
    adapter: Optional[PluginAdapter] = None
    registry_snapshot_id: str
    status: PluginExecutionStatus
    started_at: datetime
    completed_at: datetime
    output_summary: dict = Field(default_factory=dict)
    evidence_record_id: Optional[UUID] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


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
    planner_model_profile: Optional[str] = Field(default=None, min_length=3, max_length=100)



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
    target_profile: Optional[TargetProfile] = None
    target_profiled_at: Optional[datetime] = None
    capability_discovery: Optional[CapabilityDiscovery] = None
    capabilities_discovered_at: Optional[datetime] = None
    planner_model_profile: Optional[str] = None
    audit_plan: Optional[AuditPlan] = None
    plan_proposed_at: Optional[datetime] = None
    plan_validation: Optional[PlanValidation] = None
    plan_validated_at: Optional[datetime] = None
    plan_approved_at: Optional[datetime] = None
    plan_approved_by: Optional[str] = None
    execution_schedule: Optional[ExecutionSchedule] = None
    plan_scheduled_at: Optional[datetime] = None
    plugin_executions: List[PluginExecution] = Field(default_factory=list)
    raw_evidence: List[RawEvidenceRecord] = Field(default_factory=list)
    observations: List[Observation] = Field(default_factory=list)
    observation_normalizations: List[ObservationNormalization] = Field(default_factory=list)
    candidate_findings: List[CandidateFinding] = Field(default_factory=list)


class AuditEvent(BaseModel):
    event_id: UUID
    event_type: str
    audit_id: UUID
    occurred_at: datetime
    payload: dict
