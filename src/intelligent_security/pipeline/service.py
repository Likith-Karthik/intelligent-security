from datetime import datetime, timezone
from typing import Dict, Tuple

from intelligent_security.domain import (
    Audit,
    AuditPipeline,
    AuditState,
    PipelineStage,
    PipelineStageProgress,
    PipelineTransitionRequest,
    StageStatus,
)


class PipelineTransitionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuditPipelineService:
    """Owns legal Stage 2 pipeline transitions without changing Stage 1 state semantics."""

    _next_stages: Dict[PipelineStage, set[PipelineStage]] = {
        PipelineStage.PREFLIGHT: {PipelineStage.RECON},
        PipelineStage.RECON: {PipelineStage.PLAN},
        PipelineStage.PLAN: {PipelineStage.EXECUTE},
        PipelineStage.EXECUTE: {PipelineStage.VALIDATE},
        PipelineStage.VALIDATE: {PipelineStage.PLAN, PipelineStage.REPORT, PipelineStage.OFFENSIVE},
        PipelineStage.OFFENSIVE: {PipelineStage.VALIDATE},
        PipelineStage.REPORT: {PipelineStage.CLOSED},
        PipelineStage.CLOSED: set(),
    }

    @staticmethod
    def effective_pipeline(audit: Audit) -> AuditPipeline:
        return audit.pipeline or AuditPipelineService._derive_stage1_pipeline(audit)

    @staticmethod
    def transition(audit: Audit, request: PipelineTransitionRequest) -> Tuple[AuditPipeline, bool, dict]:
        pipeline = audit.pipeline or AuditPipelineService._derive_stage1_pipeline(audit)
        progress = AuditPipelineService._progress_for(pipeline, request.stage)
        now = datetime.now(timezone.utc)

        if request.stage != pipeline.current_stage:
            current = AuditPipelineService._progress_for(pipeline, pipeline.current_stage)
            if (
                current.status == StageStatus.SUCCEEDED
                and request.status == StageStatus.READY
                and request.stage in AuditPipelineService._next_stages[pipeline.current_stage]
            ):
                progress.status = StageStatus.READY
                progress.reason = request.reason
                progress.blocked_at = None
                pipeline.current_stage = request.stage
                pipeline.updated_at = now
                audit.pipeline = pipeline
                return pipeline, True, {
                    "from_stage": current.stage.value,
                    "from_status": current.status.value,
                    "to_stage": request.stage.value,
                    "to_status": request.status.value,
                }
            raise PipelineTransitionError(
                "invalid_pipeline_transition",
                "Cannot transition from {} ({}) to {} ({}).".format(
                    pipeline.current_stage.value,
                    current.status.value,
                    request.stage.value,
                    request.status.value,
                ),
            )

        if progress.status == request.status and progress.reason == request.reason:
            return pipeline, False, {
                "from_stage": request.stage.value,
                "from_status": request.status.value,
                "to_stage": request.stage.value,
                "to_status": request.status.value,
            }

        prior_status = progress.status
        if request.status == StageStatus.RUNNING and progress.status in {StageStatus.PENDING, StageStatus.READY}:
            progress.status = StageStatus.RUNNING
            progress.attempt_count += 1
            progress.started_at = now
            progress.completed_at = None
            progress.blocked_at = None
        elif request.status == StageStatus.SUCCEEDED and progress.status == StageStatus.RUNNING:
            progress.status = StageStatus.SUCCEEDED
            progress.completed_at = now
            progress.reason = request.reason
        elif request.status in {StageStatus.FAILED, StageStatus.BLOCKED} and progress.status in {
            StageStatus.PENDING,
            StageStatus.READY,
            StageStatus.RUNNING,
        }:
            progress.status = request.status
            progress.reason = request.reason
            progress.blocked_at = now if request.status == StageStatus.BLOCKED else None
            progress.completed_at = now if request.status == StageStatus.FAILED else None
        elif request.status == StageStatus.READY and progress.status in {StageStatus.FAILED, StageStatus.BLOCKED}:
            progress.status = StageStatus.READY
            progress.reason = request.reason
            progress.blocked_at = None
            progress.completed_at = None
        else:
            raise PipelineTransitionError(
                "invalid_pipeline_transition",
                "Cannot change {} from {} to {}.".format(
                    request.stage.value, progress.status.value, request.status.value
                ),
            )

        pipeline.updated_at = now
        audit.pipeline = pipeline
        return pipeline, True, {
            "from_stage": request.stage.value,
            "from_status": prior_status.value,
            "to_stage": request.stage.value,
            "to_status": request.status.value,
        }

    @staticmethod
    def _progress_for(pipeline: AuditPipeline, stage: PipelineStage) -> PipelineStageProgress:
        progress = next((item for item in pipeline.stages if item.stage == stage), None)
        if progress is None:
            raise PipelineTransitionError("invalid_pipeline", "Pipeline is missing {} progress.".format(stage.value))
        return progress

    @staticmethod
    def _derive_stage1_pipeline(audit: Audit) -> AuditPipeline:
        pipeline = AuditPipeline.new(audit.created_at)
        pipeline.pipeline_version = "stage1-compat/v1"
        preflight = AuditPipelineService._progress_for(pipeline, PipelineStage.PREFLIGHT)
        recon = AuditPipelineService._progress_for(pipeline, PipelineStage.RECON)
        plan = AuditPipelineService._progress_for(pipeline, PipelineStage.PLAN)
        execute = AuditPipelineService._progress_for(pipeline, PipelineStage.EXECUTE)
        validate = AuditPipelineService._progress_for(pipeline, PipelineStage.VALIDATE)

        if audit.state == AuditState.CREATED:
            preflight.status = StageStatus.READY
        elif audit.state == AuditState.SCOPE_REJECTED:
            preflight.status = StageStatus.FAILED
        else:
            preflight.status = StageStatus.SUCCEEDED
            recon.status = StageStatus.SKIPPED
            pipeline.current_stage = PipelineStage.PLAN

        if audit.state == AuditState.CAPABILITIES_DISCOVERED:
            plan.status = StageStatus.READY
        elif audit.state == AuditState.PLAN_PROPOSED:
            plan.status = StageStatus.RUNNING
        elif audit.state == AuditState.PLAN_PENDING_APPROVAL:
            plan.status = StageStatus.BLOCKED
        elif audit.state == AuditState.PLAN_REJECTED:
            plan.status = StageStatus.FAILED
        elif audit.state in {AuditState.PLAN_APPROVED, AuditState.PLAN_SCHEDULED}:
            plan.status = StageStatus.SUCCEEDED
            pipeline.current_stage = PipelineStage.EXECUTE
            execute.status = StageStatus.RUNNING
            if audit.execution_schedule and all(
                step.status.value == "SUCCEEDED" for step in audit.execution_schedule.steps
            ):
                execute.status = StageStatus.SUCCEEDED
                validate.status = StageStatus.READY
                pipeline.current_stage = PipelineStage.VALIDATE
        return pipeline
