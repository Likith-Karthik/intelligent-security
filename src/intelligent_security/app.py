import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from .domain import (
    Audit,
    AuditCreateRequest,
    AuditEvent,
    AuditState,
    PlanApprovalRequest,
    PlanValidationStatus,
    FindingValidationRequest,
    RetestCreateRequest,
    RetestApprovalRequest,
    AuditCloseRequest,
    PluginExecution,
    PluginExecutionStatus,
    ScheduledStep,
    ScheduledStepStatus,
)
from .execution.runtime_profiles import PluginRuntimeProfileRegistry
from .execution.adapters import ContainerCliAdapter
from .execution.service import ExecutionError, ExecutionService
from .evidence.artifact_store import ArtifactStore
from .evidence.collector import EvidenceCollector
from .evidence.normalizer import EvidenceNormalizer
from .findings.correlator import FindingCorrelator
from .findings.service import FindingService, FindingServiceError
from .findings.retest import RetestError, RetestService
from .reporting.generator import ReportGenerationError, ReportGenerator
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
    evidence_directory: str = None,
) -> FastAPI:
    resolved_path = database_path or os.getenv("AUDIT_DATABASE_PATH", "data/audits.db")
    app = FastAPI(title="Intelligent Security Audit Orchestrator", version="0.1.0")
    app.state.audit_repository = AuditRepository(resolved_path)
    app.state.capability_registry = CapabilityRegistry(plugin_manifest_directory)
    app.state.registry_admin_token = registry_admin_token or os.getenv("PLUGIN_REGISTRY_ADMIN_TOKEN")
    app.state.model_profile_registry = ModelProfileRegistry(model_profiles_path)
    app.state.audit_planner = AuditPlanner(OpenAICompatibleModelGateway())
    app.state.evidence_store = ArtifactStore(evidence_directory or os.getenv("EVIDENCE_DIRECTORY", "data/evidence"))
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(plugin_runtime_profiles_path),
        {"container_cli": ContainerCliAdapter()},
        EvidenceCollector(app.state.evidence_store),
    )
    app.state.evidence_normalizer = EvidenceNormalizer(app.state.evidence_store)
    app.state.finding_correlator = FindingCorrelator()
    app.state.finding_service = FindingService()
    app.state.retest_service = RetestService()
    app.state.report_generator = ReportGenerator()

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

    @app.post("/audits/{audit_id}/evidence/{evidence_id}/normalize", response_model=Audit)
    def normalize_evidence(audit_id: UUID, evidence_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        evidence = next((item for item in audit.raw_evidence if item.evidence_id == evidence_id), None)
        if evidence is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")
        prior = next(
            (item for item in audit.observation_normalizations if item.evidence_id == evidence_id and item.status.value == "SUCCEEDED"),
            None,
        )
        if prior is not None:
            return audit
        package = app.state.capability_registry.active_snapshot().package_for_plugin(evidence.plugin_id or "")
        normalization, observations = app.state.evidence_normalizer.normalize(audit, evidence, package)
        audit.observation_normalizations.append(normalization)
        audit.observations.extend(observations)
        return app.state.audit_repository.save_with_event(
            audit,
            "evidence.normalized" if normalization.status.value != "FAILED" else "evidence.normalization_failed",
            {
                "evidence_id": str(evidence.evidence_id),
                "normalization_id": str(normalization.normalization_id),
                "status": normalization.status.value,
                "accepted_count": normalization.accepted_count,
                "rejected_count": normalization.rejected_count,
            },
        )

    @app.get("/audits/{audit_id}/observations", response_model=List[dict])
    def list_observations(audit_id: UUID) -> List[dict]:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return [observation.model_dump(mode="json") for observation in audit.observations]

    @app.post("/audits/{audit_id}/findings/correlate", response_model=Audit)
    def correlate_findings(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.candidate_findings:
            return audit
        audit.candidate_findings = app.state.finding_correlator.correlate(audit)
        return app.state.audit_repository.save_with_event(
            audit,
            "findings.correlated",
            {
                "candidate_count": len(audit.candidate_findings),
                "validation_pending_count": sum(item.state.value == "VALIDATION_PENDING" for item in audit.candidate_findings),
            },
        )

    @app.post("/audits/{audit_id}/findings/{finding_id}/validation", response_model=Audit)
    def record_finding_validation(
        audit_id: UUID, finding_id: UUID, request: FindingValidationRequest
    ) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        finding = next((item for item in audit.candidate_findings if item.finding_id == finding_id), None)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate finding not found")
        try:
            app.state.finding_service.record_validation(audit, finding, request)
        except FindingServiceError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "validation_rejected", "message": str(error)})
        return app.state.audit_repository.save_with_event(
            audit,
            "finding.validation_recorded",
            {
                "finding_id": str(finding.finding_id), "state": finding.state.value,
                "validation_evidence_id": str(request.evidence_id),
            },
        )

    @app.get("/audits/{audit_id}/report.json")
    def generate_json_report(audit_id: UUID) -> dict:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        try:
            return app.state.report_generator.generate_json(audit, app.state.audit_repository.list_events(audit_id))
        except ReportGenerationError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "report_evidence_missing", "message": str(error)})

    @app.get("/audits/{audit_id}/report.md", response_class=PlainTextResponse)
    def generate_markdown_report(audit_id: UUID) -> PlainTextResponse:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        try:
            report = app.state.report_generator.generate_json(audit, app.state.audit_repository.list_events(audit_id))
            return PlainTextResponse(app.state.report_generator.generate_markdown(report), media_type="text/markdown")
        except ReportGenerationError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "report_evidence_missing", "message": str(error)})

    @app.post("/audits/{audit_id}/retests", response_model=Audit)
    def create_retest_plan(audit_id: UUID, request: RetestCreateRequest) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.closed_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Closed audits cannot create retests")
        try:
            retest = app.state.retest_service.create(audit, request)
        except RetestError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "retest_rejected", "message": str(error)})
        audit.retest_plans.append(retest)
        return app.state.audit_repository.save_with_event(
            audit, "retest.proposed", {"retest_id": str(retest.retest_id), "finding_count": len(retest.finding_ids), "step_count": len(retest.steps)}
        )

    @app.post("/audits/{audit_id}/retests/{retest_id}/approve", response_model=Audit)
    def approve_retest_plan(audit_id: UUID, retest_id: UUID, request: RetestApprovalRequest) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        retest = next((item for item in audit.retest_plans if item.retest_id == retest_id), None)
        if retest is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Retest plan not found")
        if retest.status.value != "PENDING_APPROVAL":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Retest plan is not awaiting approval")
        retest.status = retest.status.APPROVED
        retest.approved_at = datetime.now(timezone.utc)
        retest.approved_by = request.approved_by
        for step in retest.steps:
            step.status = ScheduledStepStatus.READY
        return app.state.audit_repository.save_with_event(
            audit, "retest.approved", {"retest_id": str(retest.retest_id), "approved_by": request.approved_by, "reason": request.reason}
        )

    @app.post("/audits/{audit_id}/retests/{retest_id}/steps/{retest_step_id}/execute", response_model=Audit)
    def execute_retest_step(audit_id: UUID, retest_id: UUID, retest_step_id: str) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        retest = next((item for item in audit.retest_plans if item.retest_id == retest_id), None)
        if retest is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Retest plan not found")
        if retest.status.value != "APPROVED":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Retest plan cannot execute before approval")
        step = next((item for item in retest.steps if item.retest_step_id == retest_step_id), None)
        if step is None or step.status != ScheduledStepStatus.READY:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Retest step is not ready")
        scheduled = ScheduledStep(plan_step_id=step.retest_step_id, capability=step.capability, contract_version=step.contract_version,
                                  depends_on=[], status=ScheduledStepStatus.READY, estimated_duration_seconds=1, estimated_cost_usd=0)
        try:
            execution = app.state.execution_service.execute(audit, scheduled, app.state.capability_registry)
        except ExecutionError as error:
            step.status = ScheduledStepStatus.FAILED
            return app.state.audit_repository.save_with_event(audit, "retest.step_failed", {"retest_step_id": step.retest_step_id, "code": error.code})
        audit.plugin_executions.append(execution)
        step.status = scheduled.status
        step.execution_id = execution.execution_id
        step.evidence_id = execution.evidence_record_id
        return app.state.audit_repository.save_with_event(
            audit, "retest.step_completed" if execution.status == PluginExecutionStatus.SUCCEEDED else "retest.step_failed",
            {"retest_id": str(retest.retest_id), "retest_step_id": step.retest_step_id, "execution_id": str(execution.execution_id), "evidence_id": str(execution.evidence_record_id) if execution.evidence_record_id else None},
        )

    @app.post("/audits/{audit_id}/retests/{retest_id}/compare", response_model=Audit)
    def compare_retest(audit_id: UUID, retest_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        retest = next((item for item in audit.retest_plans if item.retest_id == retest_id), None)
        if retest is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Retest plan not found")
        if retest.status.value != "APPROVED" or any(item.status != ScheduledStepStatus.SUCCEEDED for item in retest.steps):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="All approved retest steps must succeed before comparison")
        if any(not any(result.evidence_id == item.evidence_id and result.status.value == "SUCCEEDED" for result in audit.observation_normalizations) for item in retest.steps):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Retest evidence must be normalized before comparison")
        app.state.retest_service.compare(audit, retest)
        return app.state.audit_repository.save_with_event(audit, "retest.compared", {"retest_id": str(retest.retest_id)})

    @app.post("/audits/{audit_id}/close", response_model=Audit)
    def close_audit(audit_id: UUID, request: AuditCloseRequest) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.closed_at is not None:
            return audit
        unresolved = {"CANDIDATE", "VALIDATION_PENDING", "RETEST_PENDING"}
        if any(item.state.value in unresolved for item in audit.candidate_findings) or any(item.status.value != "COMPLETED" for item in audit.retest_plans):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Audit has unresolved findings or incomplete retests")
        audit.closed_at = datetime.now(timezone.utc)
        audit.closed_by = request.closed_by
        audit.close_reason = request.reason
        return app.state.audit_repository.save_with_event(audit, "audit.closed", {"closed_by": request.closed_by, "reason": request.reason})

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
                "evidence_record_id": str(execution.evidence_record_id) if execution.evidence_record_id else None,
            },
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
