from datetime import datetime, timezone

from intelligent_security.domain import Audit, AuditEvent, CandidateFinding, FindingState
from intelligent_security.intelligence.service import IntelligenceService


class ReportGenerationError(Exception):
    pass


class ReportGenerator:
    report_version = "1"

    def __init__(self, intelligence: IntelligenceService = None) -> None:
        self.intelligence = intelligence

    def generate_json(self, audit: Audit, events: list) -> dict:
        evidence_by_id = {item.evidence_id: item for item in audit.raw_evidence}
        confirmed = [item for item in audit.candidate_findings if item.state == FindingState.CONFIRMED]
        inconclusive = [item for item in audit.candidate_findings if item.state == FindingState.INCONCLUSIVE]
        report = {
            "report_version": self.report_version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit": {"id": str(audit.id), "name": audit.name, "objective": audit.objective, "state": audit.state.value},
            "executive_summary": {
                "confirmed_finding_count": len(confirmed),
                "inconclusive_candidate_count": len(inconclusive),
                "observations_normalized": len(audit.observations),
                "plugin_executions": len(audit.plugin_executions),
            },
            "scope": {
                "authorized_assets": audit.scope.authorized_assets,
                "excluded_assets": audit.scope.excluded_assets,
                "allowed_operations": [item.value for item in (audit.scope_policy.allowed_operations if audit.scope_policy else [])],
            },
            "methodology": self._methodology(audit),
            "tools": self._tools(audit),
            "confirmed_findings": [self._finding(item, evidence_by_id) for item in confirmed],
            "inconclusive_candidates": [self._finding(item, evidence_by_id) for item in inconclusive],
            "audit_limitations": self._limitations(audit),
            "execution_and_approval_history": [self._event(event) for event in events],
        }
        if self.intelligence is not None:
            try:
                draft, provenance = self.intelligence.generate(
                    "report_generation",
                    "Return JSON only: {executive_summary, finding_guidance:[{finding_id,reproduction_guidance,remediation_recommendation}]}. Use only supplied finding IDs. Do not invent findings or evidence.",
                    {"audit": report["audit"], "scope": report["scope"], "tools": report["tools"],
                     "confirmed_findings": report["confirmed_findings"], "inconclusive_candidates": report["inconclusive_candidates"],
                     "limitations": report["audit_limitations"]},
                )
                known = {item["finding_id"]: item for item in report["confirmed_findings"] + report["inconclusive_candidates"]}
                for guidance in draft.get("finding_guidance", []):
                    finding = known.get(guidance.get("finding_id"))
                    if finding is None:
                        raise ReportGenerationError("AI report draft references an unknown finding.")
                    for field in ("reproduction_guidance", "remediation_recommendation"):
                        if isinstance(guidance.get(field), str) and len(guidance[field]) <= 4000:
                            finding[field] = guidance[field]
                if isinstance(draft.get("executive_summary"), str) and len(draft["executive_summary"]) <= 4000:
                    report["executive_summary"]["narrative"] = draft["executive_summary"]
                report["ai_provenance"] = provenance
            except ReportGenerationError:
                raise
            except Exception as error:
                raise ReportGenerationError("AI report generation failed: {}".format(error))
        return report

    def generate_markdown(self, report: dict) -> str:
        lines = [
            "# Security Audit Report: {}".format(self._escape(report["audit"]["name"])), "",
            "Generated: `{}`".format(report["generated_at"]), "",
            "## Executive summary", "",
            "- Confirmed findings: {}".format(report["executive_summary"]["confirmed_finding_count"]),
            "- Inconclusive candidates: {}".format(report["executive_summary"]["inconclusive_candidate_count"]),
            "- Normalized observations: {}".format(report["executive_summary"]["observations_normalized"]), "",
            "## Scope and exclusions", "",
            "- Authorized assets: {}".format(", ".join("`{}`".format(self._escape(item)) for item in report["scope"]["authorized_assets"])),
            "- Excluded assets: {}".format(", ".join("`{}`".format(self._escape(item)) for item in report["scope"]["excluded_assets"]) or "None"), "",
            "## Methodology and plan", "",
        ]
        for step in report["methodology"]["plan_steps"]:
            lines.append("- `{}` — {}".format(self._escape(step["capability"]), self._escape(step["reason"])))
        if not report["methodology"]["plan_steps"]:
            lines.append("- No persisted audit plan.")
        lines.extend(["", "## Tools and versions", ""])
        for tool in report["tools"]:
            lines.append("- `{}` version `{}` ({})".format(self._escape(tool["plugin_id"]), self._escape(tool["plugin_version"] or "unknown"), tool["status"]))
        if not report["tools"]:
            lines.append("- No plugin execution was recorded.")
        lines.extend(self._findings_markdown("Confirmed findings", report["confirmed_findings"]))
        lines.extend(self._findings_markdown("Inconclusive candidates", report["inconclusive_candidates"]))
        lines.extend(["## Audit limitations", ""])
        lines.extend("- {}".format(self._escape(item)) for item in report["audit_limitations"])
        lines.extend(["", "## Execution and approval history", ""])
        for event in report["execution_and_approval_history"]:
            lines.append("- `{}` — `{}`".format(event["occurred_at"], self._escape(event["event_type"])))
        if not report["execution_and_approval_history"]:
            lines.append("- No audit events were recorded.")
        return "\n".join(lines) + "\n"

    def _finding(self, finding: CandidateFinding, evidence_by_id: dict) -> dict:
        missing = [item for item in finding.evidence_ids if item not in evidence_by_id]
        if missing:
            raise ReportGenerationError("Finding {} references unavailable evidence.".format(finding.finding_id))
        return {
            "finding_id": str(finding.finding_id), "state": finding.state.value, "category": finding.category,
            "title": finding.title, "affected_asset": finding.affected_asset, "location": finding.location,
            "severity_reported": finding.severity_reported, "confidence": finding.confidence,
            "validation_history": [item.model_dump(mode="json") for item in finding.validation_history],
            "evidence_references": [
                {"evidence_id": str(evidence.evidence_id), "execution_id": str(evidence.execution_id),
                 "plugin_id": evidence.plugin_id, "plugin_version": evidence.plugin_version,
                 "artifacts": [item.model_dump(mode="json") for item in evidence.artifacts]}
                for evidence in (evidence_by_id[item] for item in finding.evidence_ids)
            ],
            "reproduction_guidance": "Review the linked immutable evidence and repeat only through an approved validation plan.",
            "remediation_recommendation": "Assess the affected asset and apply the control indicated by the validated observation.",
        }

    @staticmethod
    def _methodology(audit: Audit) -> dict:
        return {"plan_steps": [
            {"id": item.id, "capability": item.capability, "reason": item.reason}
            for item in (audit.audit_plan.steps if audit.audit_plan else [])
        ], "registry_snapshot_id": audit.audit_plan.registry_snapshot_id if audit.audit_plan else None}

    @staticmethod
    def _tools(audit: Audit) -> list:
        return [
            {"plugin_id": item.plugin_id or "unresolved", "plugin_version": item.plugin_version,
             "adapter": item.adapter.value if item.adapter else None, "status": item.status.value,
             "execution_id": str(item.execution_id)}
            for item in audit.plugin_executions
        ]

    @staticmethod
    def _limitations(audit: Audit) -> list:
        limitations = ["Report generated from persisted audit state; no tool was invoked during report generation."]
        if not audit.raw_evidence:
            limitations.append("No plugin execution evidence was captured.")
        if any(item.state == FindingState.VALIDATION_PENDING for item in audit.candidate_findings):
            limitations.append("Some candidates remain pending validation and are excluded from confirmed findings.")
        return limitations

    @staticmethod
    def _event(event: AuditEvent) -> dict:
        return {"event_type": event.event_type, "occurred_at": event.occurred_at.isoformat(), "payload": event.payload}

    def _findings_markdown(self, heading: str, findings: list) -> list:
        lines = ["", "## {}".format(heading), ""]
        if not findings:
            return lines + ["- None."]
        for finding in findings:
            lines.extend([
                "### {}".format(self._escape(finding["title"])), "",
                "- State: `{}`".format(finding["state"]),
                "- Severity reported: `{}`".format(finding["severity_reported"] or "not reported"),
                "- Asset: `{}`".format(self._escape(finding["affected_asset"] or "not reported")),
                "- Evidence: {}".format(", ".join("`{}`".format(item["evidence_id"]) for item in finding["evidence_references"])),
                "- Reproduction: {}".format(self._escape(finding["reproduction_guidance"])),
                "- Remediation: {}".format(self._escape(finding["remediation_recommendation"])), "",
            ])
        return lines

    @staticmethod
    def _escape(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace("`", "\\`").replace("\n", " ")
