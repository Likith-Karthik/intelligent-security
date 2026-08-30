from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class PipelineStage(str, Enum):
    PREFLIGHT = "PREFLIGHT"
    RECON = "RECON"
    PLAN = "PLAN"
    EXECUTE = "EXECUTE"
    VALIDATE = "VALIDATE"
    REPORT = "REPORT"
    OFFENSIVE = "OFFENSIVE"
    CLOSED = "CLOSED"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


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


class CapabilityStage(str, Enum):
    """The audit-pipeline compartment a capability is allowed to serve."""

    RECON = "recon"
    EXECUTE = "execute"
    VALIDATE = "validate"
    OFFENSIVE = "offensive"


class PluginCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability: str = Field(..., min_length=3, max_length=200)
    contract_version: str = Field(default="1", min_length=1, max_length=50)
    stage: CapabilityStage
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
    target_input: str = Field(default="url", pattern=r"^(url|hostname)$")
    arguments: List[str] = Field(default_factory=list, max_length=100)
    mounts: List[PluginPackageMount] = Field(default_factory=list, max_length=20)
    output_format: str = Field(default="jsonl", pattern=r"^(jsonl|text)$")
    request_method: Optional[str] = Field(default=None, pattern=r"^(GET|POST)$")
    request_path: Optional[str] = Field(default=None, pattern=r"^/[A-Za-z0-9_./-]*$")
    request_body: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def validate_adapter_shape(self):
        if self.adapter in {PluginAdapter.CONTAINER_CLI, PluginAdapter.NATIVE} and not self.arguments:
            raise ValueError("CLI execution specifications require at least one fixed argument.")
        if self.adapter == PluginAdapter.REST:
            if not self.request_method or not self.request_path:
                raise ValueError("REST execution specifications require request_method and request_path.")
            if self.arguments or self.mounts:
                raise ValueError("REST execution specifications cannot declare CLI arguments or mounts.")
        elif self.request_method or self.request_path or self.request_body is not None:
            raise ValueError("HTTP request fields are only valid for REST execution specifications.")
        return self


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
    stage: CapabilityStage
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

    @model_validator(mode="before")
    @classmethod
    def assign_legacy_stage(cls, value):
        """Load candidates persisted before pipeline stages were introduced.

        A legacy candidate with a validation relationship is constrained to
        VALIDATE; every other unknown legacy candidate is constrained to
        EXECUTE.  This never broadens a candidate into RECON or OFFENSIVE.
        """
        if isinstance(value, dict) and not value.get("stage"):
            value = dict(value)
            value["stage"] = (
                CapabilityStage.VALIDATE
                if value.get("validation_for")
                else CapabilityStage.EXECUTE
            )
        return value


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


class ReconPolicy(BaseModel):
    """Versioned, non-destructive bounds for deterministic recon selection."""

    policy_version: str = Field(default="recon-policy/v1", min_length=1, max_length=100)
    allowed_operations: List[AuditOperation] = Field(
        default_factory=lambda: [
            AuditOperation.PORT_DISCOVERY,
            AuditOperation.WEB_SCAN,
            AuditOperation.STATIC_ANALYSIS,
        ],
        min_length=1,
        max_length=20,
    )
    max_steps: int = Field(default=5, ge=1, le=100)
    max_concurrency: int = Field(default=2, ge=1, le=20)
    max_duration_seconds: int = Field(default=900, ge=1, le=604800)
    max_cost_usd: float = Field(default=5.0, ge=0, le=1000000)


class ReconPlanGap(BaseModel):
    capability_family: str = Field(..., min_length=1, max_length=200)
    reason: str = Field(..., min_length=1, max_length=2000)


class ReconPlanStep(BaseModel):
    step_id: str = Field(..., min_length=1, max_length=100)
    capability: str = Field(..., min_length=3, max_length=200)
    contract_version: str = Field(default="1", min_length=1, max_length=50)
    depends_on: List[str] = Field(default_factory=list, max_length=100)
    rationale_codes: List[str] = Field(..., min_length=1, max_length=20)


class ReconPlan(BaseModel):
    plan_version: str = Field(default="recon-plan/v1", min_length=1, max_length=100)
    policy_version: str = Field(..., min_length=1, max_length=100)
    registry_snapshot_id: str = Field(..., min_length=1, max_length=200)
    target_type: str = Field(..., min_length=1, max_length=100)
    max_concurrency: int = Field(..., ge=1, le=20)
    reserved_duration_seconds: int = Field(..., ge=0)
    reserved_cost_usd: float = Field(..., ge=0)
    steps: List[ReconPlanStep] = Field(default_factory=list, max_length=100)
    coverage_gaps: List[ReconPlanGap] = Field(default_factory=list, max_length=100)
    generated_at: datetime


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

    @field_validator("depends_on", mode="before")
    @classmethod
    def normalize_numeric_dependency_ids(cls, value):
        """Canonicalize harmless ordinal references emitted by smaller local models.

        Dependency values are ultimately validated against the declared step IDs, so
        this conversion cannot introduce a new dependency or bypass plan policy.
        """
        if not isinstance(value, list):
            return value
        normalized = []
        for dependency in value:
            if isinstance(dependency, bool):
                raise ValueError("Plan dependencies must be string step IDs, not booleans.")
            normalized.append(str(dependency) if isinstance(dependency, int) else dependency)
        return normalized

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
    recon_snapshot_id: Optional[str] = None
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


class ReconExecutionSchedule(BaseModel):
    """Bounded schedule for a persisted recon plan, before plugin resolution."""

    schedule_version: str = Field(default="recon-schedule/v1", min_length=1, max_length=100)
    registry_snapshot_id: str = Field(..., min_length=1, max_length=200)
    policy_version: str = Field(..., min_length=1, max_length=100)
    steps: List[ScheduledStep] = Field(..., min_length=1, max_length=100)
    reserved_duration_seconds: int = Field(..., ge=0)
    reserved_cost_usd: float = Field(..., ge=0)
    scheduled_at: datetime


class ReconScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class ReconObservation(BaseModel):
    observation_id: UUID = Field(default_factory=uuid4)
    observation_type: str = Field(..., pattern=r"^(asset|service|technology|endpoint|interface)$")
    value: str = Field(..., min_length=1, max_length=2048)
    parent_asset: Optional[str] = Field(default=None, max_length=2048)
    source_evidence_id: UUID
    confidence: float = Field(..., ge=0, le=1)
    first_observed_at: datetime
    last_observed_at: datetime
    scope_status: ReconScopeStatus
    source_chunk_ids: List[str] = Field(default_factory=list, max_length=100)
    normalized_summary: Optional[str] = Field(default=None, max_length=2000)
    semantic_cluster_id: Optional[str] = Field(default=None, max_length=200)
    model_assisted: bool = False


class ReconEvidenceChunk(BaseModel):
    chunk_id: str = Field(..., pattern=r"^chunk-[a-f0-9]{16}$")
    evidence_id: UUID
    artifact_kind: str = Field(..., min_length=1, max_length=100)
    sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    source_artifact_sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    start_offset: int = Field(..., ge=0)
    end_offset: int = Field(..., ge=0)
    text: str = Field(..., min_length=1, max_length=12000)
    redacted: bool = True


class ReconEvidencePack(BaseModel):
    snapshot_id: str
    observations: List[ReconObservation] = Field(default_factory=list, max_length=5000)
    chunks: List[ReconEvidenceChunk] = Field(default_factory=list, max_length=200)
    omitted_chunk_count: int = Field(default=0, ge=0)
    character_budget: int = Field(..., ge=1)
    included_characters: int = Field(..., ge=0)


class ReconSnapshot(BaseModel):
    snapshot_id: str = Field(..., pattern=r"^recon-[a-f0-9]{16}$")
    audit_id: UUID
    registry_snapshot_id: str = Field(..., min_length=1, max_length=200)
    assets: List[str] = Field(default_factory=list, max_length=1000)
    services: List[str] = Field(default_factory=list, max_length=1000)
    technologies: List[str] = Field(default_factory=list, max_length=1000)
    endpoints: List[str] = Field(default_factory=list, max_length=1000)
    interfaces: List[str] = Field(default_factory=list, max_length=1000)
    coverage_gaps: List[ReconPlanGap] = Field(default_factory=list, max_length=100)
    evidence_ids: List[UUID] = Field(default_factory=list, max_length=1000)
    digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    created_at: datetime


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
    model_profile_id: Optional[str] = None
    input_digest: Optional[str] = None
    output_digest: Optional[str] = None


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


class ValidationDecisionType(str, Enum):
    """The bounded next action selected after evidence-based validation."""

    REPORT_READY = "REPORT_READY"
    MORE_TESTING_REQUIRED = "MORE_TESTING_REQUIRED"
    OFFENSIVE_PERMISSION_REQUIRED = "OFFENSIVE_PERMISSION_REQUIRED"


class OffensiveState(str, Enum):
    OFFENSIVE_PERMISSION_REQUIRED = "OFFENSIVE_PERMISSION_REQUIRED"
    OFFENSIVE_BLOCKED = "OFFENSIVE_BLOCKED"
    OFFENSIVE_APPROVED = "OFFENSIVE_APPROVED"
    OFFENSIVE_DISABLED = "OFFENSIVE_DISABLED"


class OffensivePermissionGrant(BaseModel):
    """Reserved schema only; no grant is actionable while policy is disabled."""

    grant_id: UUID = Field(default_factory=uuid4)
    audit_id: UUID
    exact_assets: List[str] = Field(..., min_length=1, max_length=500)
    allowed_operations: List[AuditOperation] = Field(..., min_length=1, max_length=50)
    approved_by: str = Field(..., min_length=3, max_length=200)
    issued_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = Field(default=None, min_length=3, max_length=200)


class OffensiveStep(BaseModel):
    step_id: str = Field(..., min_length=1, max_length=100)
    capability: str = Field(..., min_length=3, max_length=200)
    contract_version: str = Field(..., min_length=1, max_length=50)
    reason: str = Field(..., min_length=3, max_length=2000)


class OffensivePlan(BaseModel):
    plan_id: UUID = Field(default_factory=uuid4)
    grant_id: UUID
    state: OffensiveState = OffensiveState.OFFENSIVE_DISABLED
    steps: List[OffensiveStep] = Field(..., min_length=1, max_length=100)
    created_at: datetime


class OffensiveRequest(BaseModel):
    """A non-authorizing record of a future offensive permission request."""

    model_config = ConfigDict(extra="forbid")

    requested_by: str = Field(..., min_length=3, max_length=200)
    reason: str = Field(..., min_length=3, max_length=2000)


class OffensiveRequestRecord(OffensiveRequest):
    request_id: UUID = Field(default_factory=uuid4)
    requested_at: datetime
    state: OffensiveState = OffensiveState.OFFENSIVE_DISABLED


class ValidationDecision(BaseModel):
    """Immutable provenance for the audit-level conclusion of the VALIDATE stage."""

    decision_id: UUID = Field(default_factory=uuid4)
    decision: ValidationDecisionType
    finding_ids: List[UUID] = Field(default_factory=list, max_length=1000)
    reason: str = Field(..., min_length=3, max_length=4000)
    created_at: datetime
    model_profile_id: str = Field(..., min_length=3, max_length=100)
    input_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    output_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")


class ReplanStatus(str, Enum):
    SCHEDULED = "SCHEDULED"
    EXHAUSTED = "EXHAUSTED"


class ReplanRecord(BaseModel):
    """Audit trail for one bounded, evidence-gap-driven incremental plan."""

    replan_id: UUID = Field(default_factory=uuid4)
    source_decision_id: UUID
    attempt: int = Field(..., ge=1, le=100)
    finding_ids: List[UUID] = Field(..., min_length=1, max_length=1000)
    prior_step_digests: List[str] = Field(default_factory=list, max_length=1000)
    new_step_digests: List[str] = Field(default_factory=list, max_length=100)
    status: ReplanStatus
    reason: str = Field(..., min_length=3, max_length=4000)
    created_at: datetime
    reserved_duration_seconds: int = Field(default=0, ge=0)
    reserved_cost_usd: float = Field(default=0, ge=0)
    cumulative_reserved_duration_seconds: int = Field(default=0, ge=0)
    cumulative_reserved_cost_usd: float = Field(default=0, ge=0)


class ReportSnapshot(BaseModel):
    """Stored, evidence-cited report output for one immutable audit-state digest."""

    report_id: UUID = Field(default_factory=uuid4)
    report_version: str = Field(..., min_length=1, max_length=50)
    input_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    report_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    report: dict
    generated_at: datetime
    model_profile_id: Optional[str] = Field(default=None, min_length=3, max_length=100)
    model_input_digest: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    model_output_digest: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")


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
    model_profile_id: Optional[str] = None
    input_digest: Optional[str] = None
    output_digest: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RetestPlanStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    COMPLETED = "COMPLETED"


class RetestStep(BaseModel):
    retest_step_id: str
    finding_id: UUID
    capability: str
    contract_version: str
    status: ScheduledStepStatus = ScheduledStepStatus.PENDING
    execution_id: Optional[UUID] = None
    evidence_id: Optional[UUID] = None


class RetestPlan(BaseModel):
    retest_id: UUID = Field(default_factory=uuid4)
    status: RetestPlanStatus = RetestPlanStatus.PENDING_APPROVAL
    finding_ids: List[UUID] = Field(..., min_length=1, max_length=100)
    steps: List[RetestStep] = Field(..., min_length=1, max_length=100)
    scope_revalidated_at: datetime
    target_revalidated_at: datetime
    created_at: datetime
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    completed_at: Optional[datetime] = None


class RetestCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_ids: List[UUID] = Field(..., min_length=1, max_length=100)


class RetestApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved_by: str = Field(..., min_length=3, max_length=200)
    reason: str = Field(..., min_length=3, max_length=2000)


class AuditCloseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    closed_by: str = Field(..., min_length=3, max_length=200)
    reason: str = Field(..., min_length=3, max_length=2000)


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


class PipelineStageProgress(BaseModel):
    stage: PipelineStage
    status: StageStatus = StageStatus.PENDING
    attempt_count: int = Field(default=0, ge=0, le=1000)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    blocked_at: Optional[datetime] = None
    reason: Optional[str] = Field(default=None, max_length=2000)


class AuditPipeline(BaseModel):
    """Versioned Stage 2 progress, separate from the legacy audit state machine."""

    pipeline_version: str = Field(default="2", min_length=1, max_length=50)
    current_stage: PipelineStage = PipelineStage.PREFLIGHT
    stages: List[PipelineStageProgress] = Field(..., min_length=1, max_length=20)
    created_at: datetime
    updated_at: datetime

    @classmethod
    def new(cls, created_at: datetime) -> "AuditPipeline":
        return cls(
            current_stage=PipelineStage.PREFLIGHT,
            stages=[
                PipelineStageProgress(stage=stage, status=StageStatus.PENDING)
                for stage in PipelineStage
            ],
            created_at=created_at,
            updated_at=created_at,
        )


class PipelineTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: PipelineStage
    status: StageStatus
    reason: Optional[str] = Field(default=None, max_length=2000)


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
    pipeline: Optional[AuditPipeline] = None
    scope_policy: Optional[ScopePolicy] = None
    scope_validated_at: Optional[datetime] = None
    target_profile: Optional[TargetProfile] = None
    target_profiled_at: Optional[datetime] = None
    recon_capability_discovery: Optional[CapabilityDiscovery] = None
    recon_capabilities_discovered_at: Optional[datetime] = None
    recon_plan: Optional[ReconPlan] = None
    recon_plan_created_at: Optional[datetime] = None
    recon_execution_schedule: Optional[ReconExecutionSchedule] = None
    recon_plan_scheduled_at: Optional[datetime] = None
    recon_observations: List[ReconObservation] = Field(default_factory=list)
    recon_evidence_chunks: List[ReconEvidenceChunk] = Field(default_factory=list)
    recon_normalized_evidence_ids: List[UUID] = Field(default_factory=list)
    recon_snapshot: Optional[ReconSnapshot] = None
    recon_evidence_pack: Optional[ReconEvidencePack] = None
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
    finding_correlation_completed_at: Optional[datetime] = None
    validation_decision: Optional[ValidationDecision] = None
    replan_history: List[ReplanRecord] = Field(default_factory=list, max_length=100)
    report_snapshot: Optional[ReportSnapshot] = None
    offensive_state: OffensiveState = OffensiveState.OFFENSIVE_DISABLED
    offensive_requests: List[OffensiveRequestRecord] = Field(default_factory=list, max_length=100)
    offensive_permission_grants: List[OffensivePermissionGrant] = Field(default_factory=list, max_length=100)
    offensive_plans: List[OffensivePlan] = Field(default_factory=list, max_length=100)
    retest_plans: List[RetestPlan] = Field(default_factory=list)
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None
    close_reason: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def migrate_recon_normalization_markers(cls, value):
        """Treat persisted chunks as successful markers for pre-marker audits."""
        if isinstance(value, dict) and "recon_normalized_evidence_ids" not in value:
            migrated = dict(value)
            migrated["recon_normalized_evidence_ids"] = list(dict.fromkeys(
                str(chunk.get("evidence_id"))
                for chunk in migrated.get("recon_evidence_chunks", [])
                if isinstance(chunk, dict) and chunk.get("evidence_id")
            ))
            return migrated
        return value


class AuditEvent(BaseModel):
    event_id: UUID
    event_type: str
    audit_id: UUID
    occurred_at: datetime
    payload: dict
