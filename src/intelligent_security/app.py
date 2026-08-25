import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse

from .domain import (
    Audit,
    AuditCreateRequest,
    AuditEvent,
    AuditState,
    AuditPipeline,
    PipelineStage,
    PipelineTransitionRequest,
    StageStatus,
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
from .evidence.normalizer import AIEvidenceNormalizer
from .findings.correlator import AIFindingCorrelator
from .findings.service import FindingService, FindingServiceError
from .intelligence.service import IntelligenceService
from .findings.retest import RetestError, RetestService
from .reporting.generator import ReportGenerationError, ReportGenerator
from .policy.plan import PlanPolicyError, validate_plan
from .policy.scope import ScopeValidationError, validate_scope
from .pipeline.service import AuditPipelineService, PipelineTransitionError
from .recon.service import ReconDiscoveryService
from .recon.policy import default_recon_policy
from .recon.planner import ReconPlanner, ReconPlanningError
from .recon.scheduling import (
    ReconScheduleError,
    release_dependent_recon_steps,
    schedule_recon_plan,
)
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
    app.state.intelligence_service = IntelligenceService(app.state.model_profile_registry)
    app.state.audit_planner = AuditPlanner(OpenAICompatibleModelGateway())
    app.state.evidence_store = ArtifactStore(evidence_directory or os.getenv("EVIDENCE_DIRECTORY", "data/evidence"))
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(plugin_runtime_profiles_path),
        {"container_cli": ContainerCliAdapter()},
        EvidenceCollector(app.state.evidence_store),
    )
    app.state.evidence_normalizer = AIEvidenceNormalizer(app.state.evidence_store, app.state.intelligence_service)
    app.state.finding_correlator = AIFindingCorrelator(app.state.intelligence_service)
    app.state.finding_service = FindingService()
    app.state.retest_service = RetestService()
    app.state.report_generator = ReportGenerator(app.state.intelligence_service)
    app.state.audit_pipeline_service = AuditPipelineService()
    app.state.recon_discovery_service = ReconDiscoveryService()
    app.state.recon_policy = default_recon_policy()
    app.state.recon_planner = ReconPlanner()

    @app.get("/", include_in_schema=False)
    def audit_console() -> FileResponse:
        """Serve the lightweight operator console; all actions remain API-backed."""
        return FileResponse(os.path.join(os.path.dirname(__file__), "ui", "index.html"))

    @app.get("/ui.css", include_in_schema=False)
    def audit_console_css() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "ui", "ui.css"), media_type="text/css")

    @app.get("/ui.js", include_in_schema=False)
    def audit_console_js() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "ui", "ui.js"), media_type="application/javascript")

    @app.get("/admin", include_in_schema=False)
    def admin_console() -> FileResponse:
        """Serve the internal system and plugin console (non-customer facing)."""
        return FileResponse(os.path.join(os.path.dirname(__file__), "ui", "admin.html"))

    @app.get("/admin.js", include_in_schema=False)
    def admin_console_js() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "ui", "admin.js"), media_type="application/javascript")

    @app.get("/admin/plugins")
    def list_plugins_info() -> dict:
        import shutil
        snapshot = app.state.capability_registry.active_snapshot()
        runtime_profiles = {}
        try:
            runtime_profiles = app.state.execution_service.runtime_profiles.load()
        except Exception:
            pass

        # Check Docker presence on host
        docker_path = shutil.which("docker")
        if not docker_path:
            for pfx in ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"]:
                cand = os.path.join(pfx, "docker")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    docker_path = cand
                    break

        def find_cli_binary(pid: str) -> tuple:
            bin_map = {
                "nmap": "nmap",
                "semgrep": "semgrep",
                "promptfoo": "promptfoo",
                "nuclei": "nuclei",
            }
            target_bin = bin_map.get(pid, pid)
            found = shutil.which(target_bin)
            if not found:
                for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]:
                    candidate = os.path.join(prefix, target_bin)
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        found = candidate
                        break
            return (found is not None, found, target_bin)

        plugins = []
        for package in snapshot.packages:
            manifest = package.manifest
            runtime = runtime_profiles.get(manifest.plugin_id)

            is_enabled_manifest = bool(manifest.enabled)
            is_enabled_runtime = bool(runtime.enabled) if runtime else False

            cli_avail, cli_path, bin_name = find_cli_binary(manifest.plugin_id)
            docker_avail = bool(docker_path and runtime and runtime.image_reference)

            # Plugin is active if manifest enabled AND (runtime profile active OR CLI binary available on host)
            is_active = is_enabled_manifest and (is_enabled_runtime or cli_avail)

            if is_enabled_manifest and cli_avail and docker_avail:
                mode = "hybrid"
                mode_label = "Active (Host CLI & Docker)"
            elif is_enabled_manifest and cli_avail:
                mode = "host_cli"
                mode_label = f"Active (Host CLI: {cli_path})"
            elif is_enabled_manifest and (is_enabled_runtime or docker_avail):
                mode = "docker"
                mode_label = "Active (Docker Container)"
            elif not is_enabled_manifest:
                mode = "disabled"
                mode_label = "Manifest Disabled"
            else:
                mode = "standby"
                mode_label = "No Runtime / CLI Not Found"

            health_str = manifest.health.value if hasattr(manifest.health, "value") else str(manifest.health)
            adapter_str = manifest.adapter.value if hasattr(manifest.adapter, "value") else str(manifest.adapter)

            capabilities_data = []
            for cap in manifest.capabilities:
                capabilities_data.append({
                    "capability": cap.capability,
                    "contract_version": cap.contract_version,
                    "description": cap.description,
                    "target_types": [t.value if hasattr(t, "value") else str(t) for t in cap.target_types],
                    "required_operation": cap.required_operation.value if hasattr(cap.required_operation, "value") else str(cap.required_operation),
                    "required_inputs": cap.required_inputs,
                    "estimated_duration_seconds": cap.estimated_duration_seconds,
                    "estimated_cost_usd": cap.estimated_cost_usd,
                    "reliability": cap.reliability,
                    "validation_for": cap.validation_for or [],
                })

            runtime_data = None
            if runtime:
                runtime_data = {
                    "enabled": runtime.enabled,
                    "adapter": runtime.adapter.value if hasattr(runtime.adapter, "value") else str(runtime.adapter),
                    "runtime_reference": runtime.runtime_reference,
                    "image_reference": runtime.image_reference,
                    "max_runtime_seconds": runtime.max_runtime_seconds,
                    "allowed_target_hosts": runtime.allowed_target_hosts,
                }

            plugins.append({
                "plugin_id": manifest.plugin_id,
                "plugin_version": manifest.plugin_version,
                "kind": manifest.kind,
                "adapter": adapter_str,
                "manifest_enabled": is_enabled_manifest,
                "health": health_str,
                "is_active": is_active,
                "execution_mode": mode,
                "execution_mode_label": mode_label,
                "cli": {
                    "available": cli_avail,
                    "binary_path": cli_path,
                    "binary_name": bin_name,
                },
                "docker": {
                    "available": docker_avail,
                    "docker_binary": docker_path,
                    "image_reference": runtime.image_reference if runtime else None,
                },
                "has_runtime_profile": runtime is not None,
                "runtime_profile": runtime_data,
                "capabilities": capabilities_data,
                "capability_count": len(capabilities_data),
                "has_execution_spec": package.execution is not None,
                "has_normalizer_spec": package.normalizer is not None,
                "package_path": str(package.root),
            })

        return {
            "snapshot_id": snapshot.snapshot_id,
            "registry_version": snapshot.summary().get("registry_version", "1"),
            "created_at": snapshot.created_at.isoformat() if hasattr(snapshot.created_at, "isoformat") else str(snapshot.created_at),
            "docker_available": bool(docker_path),
            "docker_path": docker_path,
            "plugins": plugins,
        }

    @app.get("/admin/model-profiles")
    def list_model_profiles_info() -> dict:
        profiles_list = []
        try:
            loaded = app.state.model_profile_registry.load_profiles()
            profiles_list = [p.model_dump(mode="json") for p in loaded]
        except Exception:
            pass

        purposes = ["audit_planning", "evidence_normalization", "finding_correlation", "report_generation"]
        assignments = {}
        for purpose in purposes:
            try:
                selected = app.state.model_profile_registry.select_profile(purpose)
                assignments[purpose] = {
                    "profile_id": selected.profile_id,
                    "model": selected.model,
                    "provider": selected.provider,
                    "status": "resolved",
                }
            except Exception as e:
                assignments[purpose] = {
                    "status": "unresolved",
                    "reason": str(e),
                }

        return {
            "profiles": profiles_list,
            "assignments": assignments,
        }

    @app.get("/admin/summary")
    def get_admin_summary() -> dict:
        import shutil
        snapshot = app.state.capability_registry.active_snapshot()
        runtime_profiles = {}
        try:
            runtime_profiles = app.state.execution_service.runtime_profiles.load()
        except Exception:
            pass

        def has_cli(pid: str) -> bool:
            bin_map = {"nmap": "nmap", "semgrep": "semgrep", "promptfoo": "promptfoo", "nuclei": "nuclei"}
            tb = bin_map.get(pid, pid)
            if shutil.which(tb):
                return True
            for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]:
                if os.path.isfile(os.path.join(prefix, tb)) and os.access(os.path.join(prefix, tb), os.X_OK):
                    return True
            return False

        packages = snapshot.packages
        active_count = 0
        cli_count = 0
        docker_count = 0
        disabled_count = 0
        total_caps = 0

        for p in packages:
            runtime = runtime_profiles.get(p.manifest.plugin_id)
            cli_ok = has_cli(p.manifest.plugin_id)
            runtime_ok = bool(runtime and runtime.enabled)
            is_active = bool(p.manifest.enabled) and (runtime_ok or cli_ok)

            if is_active:
                active_count += 1
            else:
                disabled_count += 1

            if cli_ok:
                cli_count += 1
            if runtime_ok and runtime and runtime.image_reference:
                docker_count += 1

            total_caps += len(p.manifest.capabilities)

        models_count = 0
        active_models_count = 0
        try:
            models = app.state.model_profile_registry.load_profiles()
            models_count = len(models)
            active_models_count = sum(1 for m in models if m.enabled)
        except Exception:
            pass

        return {
            "snapshot_id": snapshot.snapshot_id,
            "registry_version": CapabilityRegistry.registry_version,
            "total_plugins": len(packages),
            "active_plugins": active_count,
            "cli_active_plugins": cli_count,
            "docker_active_plugins": docker_count,
            "disabled_plugins": disabled_count,
            "total_capabilities": total_caps,
            "total_model_profiles": models_count,
            "active_model_profiles": active_models_count,
            "configured_runtime_profiles": len(runtime_profiles),
        }

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

    @app.get("/audits/{audit_id}/pipeline", response_model=AuditPipeline)
    def get_audit_pipeline(audit_id: UUID) -> AuditPipeline:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return app.state.audit_pipeline_service.effective_pipeline(audit)

    @app.post("/audits/{audit_id}/pipeline/transition", response_model=Audit)
    def transition_audit_pipeline(audit_id: UUID, request: PipelineTransitionRequest) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        try:
            pipeline, changed, transition = app.state.audit_pipeline_service.transition(audit, request)
        except PipelineTransitionError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": error.code, "message": error.message},
            )
        if not changed:
            return audit
        return app.state.audit_repository.save_with_event(
            audit,
            "pipeline.stage_{}".format(
                "started" if request.status == StageStatus.RUNNING else "completed"
                if request.status == StageStatus.SUCCEEDED else "failed"
                if request.status == StageStatus.FAILED else "blocked"
                if request.status == StageStatus.BLOCKED else "ready"
            ),
            {"pipeline_version": pipeline.pipeline_version, **transition, "reason": request.reason},
        )

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
        if audit.scope_policy is not None and audit.state == AuditState.SCOPE_VALIDATED:
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
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": error.code, "message": error.message},
            )

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
            eligible_plugin_ids = app.state.execution_service.executable_plugin_ids(
                audit, app.state.capability_registry
            )
            discovery = app.state.capability_registry.discover(audit, eligible_plugin_ids)
        except (RegistryError, ExecutionError) as error:
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

    @app.post("/audits/{audit_id}/recon/capabilities/discover", response_model=Audit)
    def discover_recon_capabilities(audit_id: UUID) -> Audit:
        """Persist the current recon-stage capabilities that are executable for this target."""
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.recon_capability_discovery is not None:
            return audit
        if audit.scope_policy is None or audit.target_profile is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Recon capabilities cannot be discovered before scope validation and target profiling",
            )

        pipeline = app.state.audit_pipeline_service.effective_pipeline(audit)
        recon_progress = next(item for item in pipeline.stages if item.stage == PipelineStage.RECON)
        if pipeline.current_stage != PipelineStage.RECON or recon_progress.status not in {
            StageStatus.READY,
            StageStatus.RUNNING,
        }:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Recon capabilities can only be discovered while the RECON stage is ready or running",
            )
        try:
            discovery = app.state.recon_discovery_service.discover(
                audit,
                app.state.capability_registry,
                app.state.execution_service,
            )
        except (RegistryError, ExecutionError) as error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Recon capability registry error: {}".format(error),
            )

        audit.recon_capability_discovery = discovery
        audit.recon_capabilities_discovered_at = discovery.discovered_at
        return app.state.audit_repository.save_with_event(
            audit,
            "recon.capabilities_discovered",
            {
                "candidate_count": len(discovery.candidates),
                "gap_count": len(discovery.gaps),
                "registry_version": discovery.registry_version,
                "registry_snapshot_id": discovery.registry_snapshot_id,
            },
        )

    @app.post("/audits/{audit_id}/recon/plan", response_model=Audit)
    def create_recon_plan(audit_id: UUID) -> Audit:
        """Create a bounded, capability-level recon DAG without invoking a model."""
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.recon_plan is not None:
            return audit
        pipeline = app.state.audit_pipeline_service.effective_pipeline(audit)
        recon_progress = next(item for item in pipeline.stages if item.stage == PipelineStage.RECON)
        if pipeline.current_stage != PipelineStage.RECON or recon_progress.status not in {
            StageStatus.READY,
            StageStatus.RUNNING,
        }:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A recon plan can only be created while the RECON stage is ready or running",
            )
        try:
            plan = app.state.recon_planner.create(audit, app.state.recon_policy)
        except ReconPlanningError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )
        audit.recon_plan = plan
        audit.recon_plan_created_at = plan.generated_at
        return app.state.audit_repository.save_with_event(
            audit,
            "recon.plan_created",
            {
                "plan_version": plan.plan_version,
                "policy_version": plan.policy_version,
                "registry_snapshot_id": plan.registry_snapshot_id,
                "step_count": len(plan.steps),
                "coverage_gap_count": len(plan.coverage_gaps),
            },
        )

    @app.post("/audits/{audit_id}/recon/schedule", response_model=Audit)
    def schedule_recon(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.recon_execution_schedule is not None:
            return audit
        pipeline = app.state.audit_pipeline_service.effective_pipeline(audit)
        recon_progress = next(item for item in pipeline.stages if item.stage == PipelineStage.RECON)
        if pipeline.current_stage != PipelineStage.RECON or recon_progress.status not in {
            StageStatus.READY,
            StageStatus.RUNNING,
        }:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Recon can only be scheduled during RECON")
        try:
            schedule = schedule_recon_plan(audit)
        except ReconScheduleError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )
        audit.recon_execution_schedule = schedule
        audit.recon_plan_scheduled_at = schedule.scheduled_at
        return app.state.audit_repository.save_with_event(
            audit,
            "recon.scheduled",
            {
                "schedule_version": schedule.schedule_version,
                "registry_snapshot_id": schedule.registry_snapshot_id,
                "step_count": len(schedule.steps),
                "reserved_duration_seconds": schedule.reserved_duration_seconds,
                "reserved_cost_usd": schedule.reserved_cost_usd,
            },
        )

    @app.post("/audits/{audit_id}/recon/steps/{step_id}/execute", response_model=Audit)
    def execute_recon_step(audit_id: UUID, step_id: str) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        schedule = audit.recon_execution_schedule
        if schedule is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Recon must be scheduled before execution")
        step = next((item for item in schedule.steps if item.plan_step_id == step_id), None)
        if step is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recon step not found")
        if step.status != ScheduledStepStatus.READY:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Recon step is not ready")
        try:
            validated_scope = validate_scope(audit)
        except ScopeValidationError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": error.code, "message": error.message},
            )
        if audit.scope_policy is None or validated_scope.model_dump(mode="json") != audit.scope_policy.model_dump(mode="json"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Recon scope changed; validate scope and rediscover recon capabilities")
        try:
            execution = app.state.execution_service.execute_recon(
                audit,
                step,
                app.state.capability_registry,
                schedule.registry_snapshot_id,
            )
        except ExecutionError as error:
            step.status = ScheduledStepStatus.FAILED
            return app.state.audit_repository.save_with_event(
                audit,
                "recon.step_failed",
                {"step_id": step_id, "code": error.code, "message": error.message},
            )

        audit.plugin_executions.append(execution)
        release_dependent_recon_steps(schedule)
        return app.state.audit_repository.save_with_event(
            audit,
            "recon.step_completed" if execution.status == PluginExecutionStatus.SUCCEEDED else "recon.step_failed",
            {
                "step_id": step_id,
                "execution_id": str(execution.execution_id),
                "evidence_id": str(execution.evidence_record_id) if execution.evidence_record_id else None,
                "status": execution.status.value,
                "error_code": execution.error_code,
            },
        )

    @app.post("/audits/{audit_id}/plan/generate", response_model=Audit)
    def generate_audit_plan(audit_id: UUID) -> Audit:
        audit = app.state.audit_repository.get(audit_id)
        if audit is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        if audit.state == AuditState.PLAN_PROPOSED and audit.audit_plan is not None:
            return audit
        if audit.state == AuditState.PLAN_REJECTED:
            # Allow re-generation after rejection — reset to CAPABILITIES_DISCOVERED first.
            audit.state = AuditState.CAPABILITIES_DISCOVERED
            audit.audit_plan = None
            audit.plan_validation = None
            app.state.audit_repository.save_with_event(
                audit,
                "plan.regeneration_requested",
                {"previous_state": "PLAN_REJECTED"},
            )
        elif audit.state != AuditState.CAPABILITIES_DISCOVERED:
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
            status_code = (
                status.HTTP_503_SERVICE_UNAVAILABLE
                if error.code in {"credential_unavailable", "unsupported_credential_reference"}
                else status.HTTP_502_BAD_GATEWAY
            )
            raise HTTPException(
                status_code=status_code,
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
        if execution.status == PluginExecutionStatus.SUCCEEDED:
            succeeded_step_ids = {
                item.plan_step_id
                for item in audit.execution_schedule.steps
                if item.status == ScheduledStepStatus.SUCCEEDED
            }
            for scheduled_step in audit.execution_schedule.steps:
                if (
                    scheduled_step.status == ScheduledStepStatus.PENDING
                    and set(scheduled_step.depends_on).issubset(succeeded_step_ids)
                ):
                    scheduled_step.status = ScheduledStepStatus.READY
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
