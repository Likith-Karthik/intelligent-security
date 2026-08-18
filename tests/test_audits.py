import json
import subprocess

from fastapi.testclient import TestClient

from intelligent_security.app import create_app
from intelligent_security.execution.runtime_profiles import PluginRuntimeProfileRegistry
from intelligent_security.execution.service import ExecutionService
from intelligent_security.execution.adapters import ContainerCliAdapter
from intelligent_security.evidence.artifact_store import ArtifactStore
from intelligent_security.evidence.collector import EvidenceCollector
from intelligent_security.evidence.normalizer import EvidenceNormalizer
from intelligent_security.findings.correlator import AIFindingCorrelator
from intelligent_security.reporting.generator import ReportGenerator
from intelligent_security.execution.runtime_profiles import PluginRuntimeProfile
from intelligent_security.planning.service import AuditPlanner


def valid_request() -> dict:
    return {
        "name": "Staging web audit",
        "objective": "Identify security issues in the authorized staging environment.",
        "target": {
            "target_type": "web_application",
            "identifier": "https://staging.example.test",
        },
        "scope": {
            "authorized_assets": ["staging.example.test"],
            "excluded_assets": ["production.example.test"],
        },
        "authorization": {
            "authorization_id": "SEC-123",
            "authorized_by": "security@example.test",
            "valid_until": "2099-01-01T00:00:00Z",
            "allowed_operations": ["web_scan"],
        },
        "credential_references": ["vault://security/staging-test-account"],
        "time_budget_seconds": 3600,
        "cost_budget_usd": 25,
        "approval_policy": "human_approval_for_destructive_actions",
    }


def test_create_audit_persists_request_and_emits_event(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))

    response = client.post("/audits", json=valid_request())

    assert response.status_code == 201
    audit = response.json()
    assert audit["state"] == "CREATED"
    assert audit["credential_references"] == ["vault://security/staging-test-account"]

    retrieved = client.get(f"/audits/{audit['id']}")
    assert retrieved.status_code == 200
    assert retrieved.json() == audit

    events = client.get(f"/audits/{audit['id']}/events")
    assert events.status_code == 200
    assert events.json()[0]["event_type"] == "audit.created"
    assert events.json()[0]["payload"] == {"state": "CREATED"}


def test_create_audit_rejects_invalid_scope() -> None:
    client = TestClient(create_app(":memory:"))
    request = valid_request()
    request["scope"]["authorized_assets"] = []

    response = client.post("/audits", json=request)

    assert response.status_code == 422


def test_create_audit_rejects_credential_values() -> None:
    client = TestClient(create_app(":memory:"))
    request = valid_request()
    request["credential_references"] = ["super-secret-password"]

    response = client.post("/audits", json=request)

    assert response.status_code == 422


def test_unknown_audit_returns_not_found(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))

    response = client.get("/audits/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404


def test_scope_validation_normalizes_scope_and_emits_event(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["target"]["identifier"] = "https://STAGING.EXAMPLE.TEST/"
    request["scope"]["authorized_assets"] = ["staging.example.test."]

    created = client.post("/audits", json=request).json()
    response = client.post(f"/audits/{created['id']}/scope/validate")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "SCOPE_VALIDATED"
    assert audit["scope_policy"]["authorized_assets"] == ["staging.example.test"]
    assert audit["scope_policy"]["network_allowlist"] == ["staging.example.test"]
    assert audit["scope_policy"]["allowed_operations"] == ["web_scan"]
    assert audit["scope_policy"]["prohibited_operations"] == ["destructive_action", "exploit"]

    events = client.get(f"/audits/{created['id']}/events").json()
    assert [event["event_type"] for event in events] == ["audit.created", "scope.validated"]


def test_scope_validation_rejects_out_of_scope_target_and_records_rejection(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["target"]["identifier"] = "https://unapproved.example.test"

    created = client.post("/audits", json=request).json()
    response = client.post(f"/audits/{created['id']}/scope/validate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "target_out_of_scope"
    rejected = client.get(f"/audits/{created['id']}").json()
    assert rejected["state"] == "SCOPE_REJECTED"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "scope.rejected"


def test_scope_validation_rejects_expired_authorization(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["authorization"]["valid_until"] = "2020-01-01T00:00:00Z"

    created = client.post("/audits", json=request).json()
    response = client.post(f"/audits/{created['id']}/scope/validate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "authorization_expired"


def test_scope_validation_rejects_operations_prohibited_by_scope(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["authorization"]["allowed_operations"] = ["exploit"]

    created = client.post("/audits", json=request).json()
    response = client.post(f"/audits/{created['id']}/scope/validate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "no_permitted_operations"


def test_scope_validation_compiles_source_repository_filesystem_boundary(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["target"] = {
        "target_type": "source_repository",
        "identifier": "https://github.com/example/security-demo/",
    }
    request["scope"]["authorized_assets"] = ["https://github.com/example/security-demo"]
    request["scope"]["excluded_assets"] = []
    request["authorization"]["allowed_operations"] = ["static_analysis"]

    created = client.post("/audits", json=request).json()
    response = client.post(f"/audits/{created['id']}/scope/validate")

    assert response.status_code == 200
    policy = response.json()["scope_policy"]
    assert policy["filesystem_boundaries"] == ["https://github.com/example/security-demo"]
    assert policy["network_allowlist"] == []


def test_target_profiling_requires_validated_scope(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()

    response = client.post(f"/audits/{created['id']}/profile")

    assert response.status_code == 409


def test_target_profiling_builds_deterministic_web_profile_and_event(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["target"]["identifier"] = "https://STAGING.EXAMPLE.TEST/"
    request["scope"]["authorized_assets"] = ["staging.example.test"]
    created = client.post("/audits", json=request).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200

    response = client.post(f"/audits/{created['id']}/profile")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "TARGET_PROFILED"
    assert audit["target_profile"] == {
        "profile_version": "1",
        "profile_method": "declared_metadata",
        "target_type": "web_application",
        "canonical_identifier": "https://staging.example.test/",
        "interfaces": ["https://staging.example.test/"],
        "technologies": [],
        "source_available": False,
        "authentication": "credential_reference_available",
        "confidence": 0.75,
        "profiled_at": audit["target_profile"]["profiled_at"],
    }
    events = client.get(f"/audits/{created['id']}/events").json()
    assert [event["event_type"] for event in events] == [
        "audit.created",
        "scope.validated",
        "target.profiled",
    ]


def test_target_profiling_marks_source_repository_as_source_available(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    request = valid_request()
    request["target"] = {
        "target_type": "source_repository",
        "identifier": "https://github.com/example/security-demo/",
    }
    request["scope"]["authorized_assets"] = ["https://github.com/example/security-demo"]
    request["scope"]["excluded_assets"] = []
    request["authorization"]["allowed_operations"] = ["static_analysis"]
    request["credential_references"] = []
    created = client.post("/audits", json=request).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200

    response = client.post(f"/audits/{created['id']}/profile")

    assert response.status_code == 200
    profile = response.json()["target_profile"]
    assert profile["source_available"] is True
    assert profile["authentication"] == "unknown"


def test_target_profiling_is_idempotent(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200

    first = client.post(f"/audits/{created['id']}/profile")
    second = client.post(f"/audits/{created['id']}/profile")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    events = client.get(f"/audits/{created['id']}/events").json()
    assert [event["event_type"] for event in events].count("target.profiled") == 1


def test_capability_discovery_requires_profiled_target(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200

    response = client.post(f"/audits/{created['id']}/capabilities/discover")

    assert response.status_code == 409


def test_capability_discovery_matches_web_scan_to_nuclei(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200

    response = client.post(f"/audits/{created['id']}/capabilities/discover")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "CAPABILITIES_DISCOVERED"
    discovery = audit["capability_discovery"]
    assert discovery["gaps"] == []
    scan = next(item for item in discovery["candidates"] if item["capability"] == "web.vulnerability_scan")
    assert scan == {
        "rank": 1, "capability": "web.vulnerability_scan", "contract_version": "1",
        "description": "Run template-based vulnerability scans against an authorized web application or API.",
        "plugin_id": "nuclei", "plugin_version": "1", "adapter": "container_cli",
        "required_operation": "web_scan", "required_inputs": ["target_profile", "scope_policy"],
        "estimated_duration_seconds": 600, "estimated_cost_usd": 0.0, "reliability": 0.85,
        "health": "declared_healthy", "validation_for": [],
    }
    validation = next(item for item in discovery["candidates"] if item["capability"] == "web.vulnerability.validate")
    assert validation["validation_for"] == ["web.vulnerability_scan"]
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "capabilities.discovered"


def test_capability_discovery_reports_gap_when_no_plugin_is_available(tmp_path) -> None:
    manifest_directory = tmp_path / "empty-manifests"
    manifest_directory.mkdir()
    client = TestClient(
        create_app(str(tmp_path / "audits.db"), plugin_manifest_directory=str(manifest_directory))
    )
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200

    response = client.post(f"/audits/{created['id']}/capabilities/discover")

    assert response.status_code == 200
    discovery = response.json()["capability_discovery"]
    assert discovery["candidates"] == []
    assert discovery["gaps"] == [
        {
            "operation": "web_scan",
            "reason": "No enabled, declared-healthy capability supports this authorized operation for the target.",
        }
    ]


def test_capability_discovery_is_idempotent(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200

    first = client.post(f"/audits/{created['id']}/capabilities/discover")
    second = client.post(f"/audits/{created['id']}/capabilities/discover")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    events = client.get(f"/audits/{created['id']}/events").json()
    assert [event["event_type"] for event in events].count("capabilities.discovered") == 1


def test_completed_scope_and_profile_stages_remain_readable_after_discovery(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "audits.db")))
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200
    assert client.post(f"/audits/{created['id']}/capabilities/discover").status_code == 200

    scope = client.post(f"/audits/{created['id']}/scope/validate")
    profile = client.post(f"/audits/{created['id']}/profile")

    assert scope.status_code == 200
    assert profile.status_code == 200
    assert scope.json()["state"] == "CAPABILITIES_DISCOVERED"
    assert profile.json()["state"] == "CAPABILITIES_DISCOVERED"


def test_capability_discovery_loads_a_new_manifest_without_code_changes(tmp_path) -> None:
    manifest_directory = tmp_path / "manifests"
    manifest_directory.mkdir()
    (manifest_directory / "custom-web-scanner.json").write_text(
        json.dumps(
            {
                "plugin_id": "custom-web-scanner",
                "plugin_version": "2026.1",
                "enabled": True,
                "health": "declared_healthy",
                "capabilities": [
                    {
                        "capability": "web.custom_scan",
                        "description": "Custom web scan for an authorized target.",
                        "target_types": ["web_application"],
                        "required_operation": "web_scan",
                        "required_inputs": ["target_profile", "scope_policy"],
                        "estimated_duration_seconds": 120,
                        "estimated_cost_usd": 1.5,
                        "reliability": 0.7,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(
        create_app(str(tmp_path / "audits.db"), plugin_manifest_directory=str(manifest_directory))
    )
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200

    response = client.post(f"/audits/{created['id']}/capabilities/discover")

    assert response.status_code == 200
    candidate = response.json()["capability_discovery"]["candidates"][0]
    assert candidate["plugin_id"] == "custom-web-scanner"
    assert candidate["capability"] == "web.custom_scan"


def test_package_removal_updates_new_discoveries_after_refresh(tmp_path) -> None:
    package_root = tmp_path / "packages" / "removable-scanner"
    package_root.mkdir(parents=True)
    manifest_path = package_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "plugin_id": "removable-scanner",
                "plugin_version": "1",
                "adapter": "container_cli",
                "enabled": True,
                "health": "declared_healthy",
                "capabilities": [{
                    "capability": "web.removable_scan",
                    "description": "A removable package capability.",
                    "target_types": ["web_application"],
                    "required_operation": "web_scan",
                    "required_inputs": ["target_profile", "scope_policy"],
                    "estimated_duration_seconds": 60,
                    "estimated_cost_usd": 0,
                    "reliability": 0.5,
                }],
            }
        ),
        encoding="utf-8",
    )
    app = create_app(
        str(tmp_path / "audits.db"),
        plugin_manifest_directory=str(tmp_path / "packages"),
        registry_admin_token="test-admin-token",
    )
    client = TestClient(app)
    initial = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    )
    assert initial.status_code == 200
    assert app.state.capability_registry.active_snapshot().package_for_plugin("removable-scanner") is not None

    manifest_path.unlink()
    refreshed = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    )
    assert refreshed.status_code == 200
    assert app.state.capability_registry.active_snapshot().package_for_plugin("removable-scanner") is None


class FakeModelGateway:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.system_prompt = None
        self.user_prompt = None

    def generate_json(self, profile, system_prompt: str, user_prompt: str) -> dict:
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        return self.response


class FakeIntelligence:
    def generate(self, purpose, system_prompt, context):
        if purpose == "finding_correlation":
            observation = context["observations"][0]
            validation = context["available_validation_capabilities"][0]
            return ({"findings": [{
                "observation_ids": [observation["observation_id"]], "evidence_ids": [observation["evidence_id"]],
                "category": observation["category"], "title": observation["title"],
                "affected_asset": observation["affected_asset"], "location": observation["location"],
                "severity_reported": observation["severity_reported"], "confidence": observation["confidence"],
                "validation_capability": validation["capability"], "rationale": "Evidence-linked test proposal.",
            }]}, {"model_profile_id": "test-intelligence", "input_digest": "input", "output_digest": "output"})
        if purpose == "report_generation":
            return ({"executive_summary": "AI-composed test summary.", "finding_guidance": []}, {"model_profile_id": "test-intelligence", "input_digest": "input", "output_digest": "output"})
        raise AssertionError("Unexpected intelligence purpose: {}".format(purpose))


def write_model_profiles(path) -> None:
    path.write_text(
        json.dumps(
            {
                "profiles": [
                    {
                        "profile_id": "test-planner",
                        "purpose": "audit_planning",
                        "provider": "openai_compatible",
                        "model": "test-model",
                        "credential_reference": "env://TEST_MODEL_KEY",
                        "base_url": "http://test-model.invalid/v1",
                        "temperature": 0.1,
                        "max_output_tokens": 3000,
                        "timeout_seconds": 60,
                        "enabled": True,
                        "default_for_purpose": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def prepared_plan_client(
    tmp_path, generated_plan: dict, approval_policy: str = None, time_budget_seconds: int = None
) -> tuple:
    profiles_path = tmp_path / "model_profiles.json"
    write_model_profiles(profiles_path)
    app = create_app(
        str(tmp_path / "audits.db"),
        model_profiles_path=str(profiles_path),
        plugin_runtime_profiles_path=str(tmp_path / "no-plugin-runtimes.json"),
    )
    app.state.audit_planner = AuditPlanner(FakeModelGateway(generated_plan))
    client = TestClient(app)
    request = valid_request()
    if approval_policy is not None:
        request["approval_policy"] = approval_policy
    if time_budget_seconds is not None:
        request["time_budget_seconds"] = time_budget_seconds
    created = client.post("/audits", json=request).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200
    assert client.post(f"/audits/{created['id']}/capabilities/discover").status_code == 200
    return client, created


def test_plan_generation_creates_a_validated_plan_and_event(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path,
        {
            "steps": [
                {
                    "id": "scan-web-app",
                    "capability": "web.vulnerability_scan",
                    "depends_on": [],
                    "inputs": {},
                    "reason": "The target is an authorized web application.",
                }
            ]
        },
    )

    response = client.post(f"/audits/{created['id']}/plan/generate")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "PLAN_PROPOSED"
    assert audit["audit_plan"]["model_profile_id"] == "test-planner"
    assert audit["audit_plan"]["registry_snapshot_id"] == audit["capability_discovery"]["registry_snapshot_id"]
    assert audit["audit_plan"]["steps"][0]["capability"] == "web.vulnerability_scan"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "plan.proposed"


def test_plan_generation_rejects_an_unknown_capability(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path,
        {
            "steps": [
                {
                    "id": "unapproved-step",
                    "capability": "network.port_discovery",
                    "depends_on": [],
                    "inputs": {},
                    "reason": "This must be rejected because it was not discovered.",
                }
            ]
        },
    )

    response = client.post(f"/audits/{created['id']}/plan/generate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_capability"
    audit = client.get(f"/audits/{created['id']}").json()
    assert audit["state"] == "CAPABILITIES_DISCOVERED"


def test_plan_generation_rejects_cyclic_dependencies(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path,
        {
            "steps": [
                {
                    "id": "first",
                    "capability": "web.vulnerability_scan",
                    "depends_on": ["second"],
                    "inputs": {},
                    "reason": "Cycle test first step.",
                },
                {
                    "id": "second",
                    "capability": "web.vulnerability_scan",
                    "depends_on": ["first"],
                    "inputs": {},
                    "reason": "Cycle test second step.",
                },
            ]
        },
    )

    response = client.post(f"/audits/{created['id']}/plan/generate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "cyclic_plan"


def test_plan_generation_rejects_model_supplied_tool_inputs(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path,
        {
            "steps": [
                {
                    "id": "scan-web-app",
                    "capability": "web.vulnerability_scan",
                    "depends_on": [],
                    "inputs": {"url": "https://untrusted.example.test"},
                    "reason": "Inputs must be rejected during planning.",
                }
            ]
        },
    )

    response = client.post(f"/audits/{created['id']}/plan/generate")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_model_output"


def test_plan_generation_normalizes_numeric_step_ids(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path,
        {
            "steps": [
                {
                    "id": 1,
                    "capability": "web.vulnerability_scan",
                    "depends_on": [],
                    "inputs": {},
                    "reason": "The local model may represent sequential IDs as numbers.",
                }
            ]
        },
    )

    response = client.post(f"/audits/{created['id']}/plan/generate")

    assert response.status_code == 200
    assert response.json()["audit_plan"]["steps"][0]["id"] == "1"


def generated_web_scan_plan() -> dict:
    return {
        "steps": [
            {
                "id": "scan-web-app",
                "capability": "web.vulnerability_scan",
                "depends_on": [],
                "inputs": {},
                "reason": "Scan the authorized web application.",
            }
        ]
    }


def test_plan_validation_auto_approves_a_compliant_plan(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200

    response = client.post(f"/audits/{created['id']}/plan/validate")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "PLAN_APPROVED"
    assert audit["plan_approved_by"] == "policy-engine"
    assert audit["plan_validation"]["status"] == "APPROVED"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "plan.approved"


def test_plan_validation_requests_human_approval_when_policy_requires_it(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path, generated_web_scan_plan(), approval_policy="human_approval_required"
    )
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200

    pending = client.post(f"/audits/{created['id']}/plan/validate")
    assert pending.status_code == 200
    assert pending.json()["state"] == "PLAN_PENDING_APPROVAL"
    assert pending.json()["plan_validation"]["approval_required"] is True

    approved = client.post(
        f"/audits/{created['id']}/plan/approval",
        json={"decision": "approve", "reviewed_by": "security@example.test", "reason": "Scope confirmed."},
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == "PLAN_APPROVED"
    assert approved.json()["plan_approved_by"] == "security@example.test"


def test_plan_validation_rejects_a_plan_that_exceeds_its_time_budget(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path, generated_web_scan_plan(), time_budget_seconds=60
    )
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200

    response = client.post(f"/audits/{created['id']}/plan/validate")

    assert response.status_code == 200
    assert response.json()["state"] == "PLAN_REJECTED"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "plan.rejected"
    assert events[-1]["payload"]["code"] == "time_budget_exceeded"


def test_plan_approval_rejects_a_plan_with_an_auditable_reason(tmp_path) -> None:
    client, created = prepared_plan_client(
        tmp_path, generated_web_scan_plan(), approval_policy="human_approval_required"
    )
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200
    assert client.post(f"/audits/{created['id']}/plan/validate").status_code == 200

    response = client.post(
        f"/audits/{created['id']}/plan/approval",
        json={"decision": "reject", "reviewed_by": "security@example.test", "reason": "Maintenance window closed."},
    )

    assert response.status_code == 200
    assert response.json()["state"] == "PLAN_REJECTED"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "plan.rejected"
    assert events[-1]["payload"]["code"] == "human_rejected"


def approve_generated_plan(client, audit_id: str) -> None:
    assert client.post(f"/audits/{audit_id}/plan/generate").status_code == 200
    assert client.post(f"/audits/{audit_id}/plan/validate").status_code == 200


def test_scheduler_creates_a_ready_step_for_an_approved_plan(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    approve_generated_plan(client, created["id"])

    response = client.post(f"/audits/{created['id']}/plan/schedule")

    assert response.status_code == 200
    audit = response.json()
    assert audit["state"] == "PLAN_SCHEDULED"
    assert audit["execution_schedule"]["steps"][0]["status"] == "READY"
    assert audit["execution_schedule"]["steps"][0]["capability"] == "web.vulnerability_scan"
    assert "plugin_id" not in audit["execution_schedule"]["steps"][0]
    assert audit["execution_schedule"]["reserved_duration_seconds"] == 600
    assert audit["execution_schedule"]["registry_snapshot_id"] == audit["audit_plan"]["registry_snapshot_id"]
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "plan.scheduled"


def test_scheduler_holds_dependent_steps_pending(tmp_path) -> None:
    dependent_plan = {
        "steps": [
            {
                "id": "first",
                "capability": "web.vulnerability_scan",
                "depends_on": [],
                "inputs": {},
                "reason": "First approved scan.",
            },
            {
                "id": "second",
                "capability": "web.vulnerability_scan",
                "depends_on": ["first"],
                "inputs": {},
                "reason": "Follow-up only after the first step completes.",
            },
        ]
    }
    client, created = prepared_plan_client(tmp_path, dependent_plan)
    approve_generated_plan(client, created["id"])

    response = client.post(f"/audits/{created['id']}/plan/schedule")

    assert response.status_code == 200
    steps = response.json()["execution_schedule"]["steps"]
    assert [step["status"] for step in steps] == ["READY", "PENDING"]
    assert response.json()["execution_schedule"]["reserved_duration_seconds"] == 1200


def test_scheduler_is_approval_gated_and_idempotent(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 409
    assert client.post(f"/audits/{created['id']}/plan/validate").status_code == 200

    first = client.post(f"/audits/{created['id']}/plan/schedule")
    second = client.post(f"/audits/{created['id']}/plan/schedule")

    assert first.status_code == 200
    assert first.json() == second.json()
    events = client.get(f"/audits/{created['id']}/events").json()
    assert [event["event_type"] for event in events].count("plan.scheduled") == 1


def test_registry_refresh_is_authorized_and_atomically_updates_new_discoveries(tmp_path) -> None:
    manifest_directory = tmp_path / "manifests"
    manifest_directory.mkdir()
    manifest_path = manifest_directory / "scanner.json"
    manifest_path.write_text(
        json.dumps(
            {
                "plugin_id": "custom-scanner",
                "plugin_version": "1",
                "kind": "mcp_security_server",
                "adapter": "restricted_mcp",
                "enabled": True,
                "health": "declared_healthy",
                "capabilities": [
                    {
                        "capability": "web.custom_scan",
                        "contract_version": "1",
                        "description": "Scan an authorized web application.",
                        "target_types": ["web_application"],
                        "required_operation": "web_scan",
                        "required_inputs": ["target_profile", "scope_policy"],
                        "estimated_duration_seconds": 120,
                        "estimated_cost_usd": 0,
                        "reliability": 0.7,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    app = create_app(
        str(tmp_path / "audits.db"),
        plugin_manifest_directory=str(manifest_directory),
        registry_admin_token="test-admin-token",
    )
    client = TestClient(app)
    assert client.post("/admin/plugins/refresh").status_code == 403
    refreshed = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    )
    assert refreshed.status_code == 200
    first_snapshot_id = refreshed.json()["snapshot_id"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["enabled"] = False
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    second_refresh = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    )
    assert second_refresh.status_code == 200
    assert second_refresh.json()["snapshot_id"] != first_snapshot_id

    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200
    discovery = client.post(f"/audits/{created['id']}/capabilities/discover").json()["capability_discovery"]
    assert discovery["candidates"] == []
    assert discovery["registry_snapshot_id"] == second_refresh.json()["snapshot_id"]


def test_failed_registry_refresh_preserves_the_active_snapshot(tmp_path) -> None:
    manifest_directory = tmp_path / "manifests"
    manifest_directory.mkdir()
    valid_manifest = {
        "plugin_id": "custom-scanner",
        "plugin_version": "1",
        "enabled": True,
        "health": "declared_healthy",
        "capabilities": [
            {
                "capability": "web.custom_scan",
                "description": "Scan an authorized web application.",
                "target_types": ["web_application"],
                "required_operation": "web_scan",
                "required_inputs": ["target_profile", "scope_policy"],
                "estimated_duration_seconds": 120,
                "estimated_cost_usd": 0,
                "reliability": 0.7,
            }
        ],
    }
    (manifest_directory / "first.json").write_text(json.dumps(valid_manifest), encoding="utf-8")
    app = create_app(
        str(tmp_path / "audits.db"),
        plugin_manifest_directory=str(manifest_directory),
        registry_admin_token="test-admin-token",
    )
    client = TestClient(app)
    active = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    ).json()
    (manifest_directory / "duplicate.json").write_text(json.dumps(valid_manifest), encoding="utf-8")
    failed = client.post(
        "/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-admin-token"}
    )
    assert failed.status_code == 422
    assert app.state.capability_registry.active_snapshot().snapshot_id == active["snapshot_id"]


def test_planner_receives_sanitized_snapshot_capabilities(tmp_path) -> None:
    gateway = FakeModelGateway(generated_web_scan_plan())
    profiles_path = tmp_path / "model_profiles.json"
    write_model_profiles(profiles_path)
    app = create_app(str(tmp_path / "audits.db"), model_profiles_path=str(profiles_path))
    app.state.audit_planner = AuditPlanner(gateway)
    client = TestClient(app)
    created = client.post("/audits", json=valid_request()).json()
    assert client.post(f"/audits/{created['id']}/scope/validate").status_code == 200
    assert client.post(f"/audits/{created['id']}/profile").status_code == 200
    discovery = client.post(f"/audits/{created['id']}/capabilities/discover").json()["capability_discovery"]
    assert client.post(f"/audits/{created['id']}/plan/generate").status_code == 200

    assert discovery["registry_snapshot_id"] in gateway.user_prompt
    assert "plugin_id" not in gateway.user_prompt
    assert "plugin_version" not in gateway.user_prompt
    assert "arguments" not in gateway.user_prompt
    assert "mounts" not in gateway.user_prompt
    assert "image_reference" not in gateway.user_prompt


class FakeExecutionAdapter:
    def execute(self, runtime, audit, step, package) -> dict:
        return {"result": "safe-test-success", "runtime_reference_used": bool(runtime.runtime_reference)}


def configure_fake_execution_runtime(app, tmp_path) -> None:
    profiles_path = tmp_path / "plugin_runtimes.json"
    profiles_path.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "plugin_id": "nuclei",
                        "adapter": "container_cli",
                        "runtime_reference": "container-config://test-nuclei",
                        "allowed_target_hosts": ["staging.example.test"],
                        "enabled": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(str(profiles_path)),
        {"container_cli": FakeExecutionAdapter()},
        EvidenceCollector(ArtifactStore(str(tmp_path / "evidence"))),
    )


def test_execution_late_binds_a_configured_plugin_and_records_result(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    configure_fake_execution_runtime(client.app, tmp_path)
    approve_generated_plan(client, created["id"])
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 200

    response = client.post(f"/audits/{created['id']}/steps/scan-web-app/execute")

    assert response.status_code == 200
    audit = response.json()
    assert audit["execution_schedule"]["steps"][0]["status"] == "SUCCEEDED"
    execution = audit["plugin_executions"][-1]
    assert execution["status"] == "SUCCEEDED"
    assert execution["plugin_id"] == "nuclei"
    assert execution["adapter"] == "container_cli"
    assert execution["output_summary"]["result"] == "safe-test-success"
    assert execution["evidence_record_id"]
    evidence = audit["raw_evidence"][-1]
    assert evidence["execution_id"] == execution["execution_id"]
    assert {artifact["kind"] for artifact in evidence["artifacts"]} == {"invocation", "stdout", "stderr"}
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "step.completed"


def test_execution_fails_closed_without_an_operator_runtime_profile(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    approve_generated_plan(client, created["id"])
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 200

    response = client.post(f"/audits/{created['id']}/steps/scan-web-app/execute")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "capability_unavailable"
    audit = client.get(f"/audits/{created['id']}").json()
    assert audit["execution_schedule"]["steps"][0]["status"] == "CAPABILITY_UNAVAILABLE"
    assert audit["plugin_executions"][-1]["status"] == "CAPABILITY_UNAVAILABLE"
    events = client.get(f"/audits/{created['id']}/events").json()
    assert events[-1]["event_type"] == "step.execution_blocked"


def test_container_adapter_uses_an_admitted_package_execution_profile(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    approve_generated_plan(client, created["id"])
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 200
    audit = client.app.state.audit_repository.get(created["id"])
    step = audit.execution_schedule.steps[0]
    received = {}

    def runner(command, **kwargs):
        received["command"] = command
        received["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, '{"template-id":"test"}\n', "")

    runtime = PluginRuntimeProfile(
        plugin_id="nuclei",
        adapter="container_cli",
        runtime_reference="container-config://test-nuclei",
        image_reference="projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
        allowed_target_hosts=["staging.example.test"],
        enabled=True,
    )

    package = client.app.state.capability_registry.active_snapshot().package_for_plugin("nuclei")
    assert package is not None
    result = ContainerCliAdapter(runner).execute(runtime, audit, step, package)

    assert result.output_summary["finding_count"] == 1
    assert "https://staging.example.test/" in received["command"]
    assert received["command"][received["command"].index("-ni") + 1] == "-dr"
    assert "-duc" in received["command"]
    assert "/app/templates/portfolio_safe.yaml" in received["command"]
    assert received["command"][received["command"].index("-rl") + 1] == "1"
    assert received["command"][received["command"].index("-c") + 1] == "1"
    assert received["command"][received["command"].index("-retries") + 1] == "0"
    assert "-fuzz" not in received["command"]
    assert "-dast" not in received["command"]


def test_flow_9_captures_raw_failed_container_execution_with_redacted_invocation(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    approve_generated_plan(client, created["id"])
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 200
    profiles_path = tmp_path / "plugin_runtimes.json"
    profiles_path.write_text(
        json.dumps({"plugins": [{
            "plugin_id": "nuclei", "adapter": "container_cli", "runtime_reference": "container-config://test-nuclei",
            "image_reference": "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
            "allowed_target_hosts": ["staging.example.test"], "enabled": True,
        }]}),
        encoding="utf-8",
    )

    def failing_runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, "partial raw output\n", "raw diagnostic\n")

    client.app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(str(profiles_path)),
        {"container_cli": ContainerCliAdapter(failing_runner)},
        EvidenceCollector(ArtifactStore(str(tmp_path / "evidence"))),
    )
    response = client.post(f"/audits/{created['id']}/steps/scan-web-app/execute")

    assert response.status_code == 200
    audit = response.json()
    execution = audit["plugin_executions"][-1]
    evidence = audit["raw_evidence"][-1]
    assert execution["status"] == "FAILED"
    assert execution["evidence_record_id"] == evidence["evidence_id"]
    assert evidence["exit_code"] == 7
    assert evidence["container_image_digest"].endswith("582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb")
    assert all(len(artifact["sha256"]) == 64 for artifact in evidence["artifacts"])
    stdout = next(artifact for artifact in evidence["artifacts"] if artifact["kind"] == "stdout")
    stored_path = tmp_path / "evidence" / stdout["storage_uri"].removeprefix("evidence://")
    assert stored_path.read_text(encoding="utf-8") == "partial raw output\n"


def test_flow_10_normalizes_package_output_into_common_observations(tmp_path) -> None:
    client, created = prepared_plan_client(tmp_path, generated_web_scan_plan())
    approve_generated_plan(client, created["id"])
    assert client.post(f"/audits/{created['id']}/plan/schedule").status_code == 200
    profiles_path = tmp_path / "plugin_runtimes.json"
    profiles_path.write_text(
        json.dumps({"plugins": [{
            "plugin_id": "nuclei", "adapter": "container_cli", "runtime_reference": "container-config://test-nuclei",
            "image_reference": "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
            "allowed_target_hosts": ["staging.example.test"], "enabled": True,
        }]}),
        encoding="utf-8",
    )
    output = json.dumps({
        "template-id": "missing-csp", "type": "http", "host": "https://staging.example.test",
        "matched-at": "https://staging.example.test/", "extra-tool-field": "preserved",
        "info": {"name": "Content Security Policy missing", "description": "No CSP response header.",
                 "severity": "medium", "classification": {"cwe-id": ["CWE-693"]}},
    }) + "\n"

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, output, "")

    evidence_store = ArtifactStore(str(tmp_path / "evidence"))
    client.app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(str(profiles_path)),
        {"container_cli": ContainerCliAdapter(runner)}, EvidenceCollector(evidence_store),
    )
    client.app.state.evidence_normalizer = EvidenceNormalizer(evidence_store)
    client.app.state.finding_correlator = AIFindingCorrelator(FakeIntelligence())
    client.app.state.report_generator = ReportGenerator(FakeIntelligence())
    executed = client.post(f"/audits/{created['id']}/steps/scan-web-app/execute").json()
    evidence_id = executed["raw_evidence"][-1]["evidence_id"]

    normalized = client.post(f"/audits/{created['id']}/evidence/{evidence_id}/normalize")

    assert normalized.status_code == 200
    audit = normalized.json()
    result = audit["observation_normalizations"][-1]
    assert result["status"] == "SUCCEEDED"
    assert result["accepted_count"] == 1
    observation = audit["observations"][-1]
    assert observation["schema_version"] == "observation/v1"
    assert observation["category"] == "http"
    assert observation["title"] == "Content Security Policy missing"
    assert observation["identifiers"] == ["CWE-693"]
    assert observation["evidence_id"] == evidence_id
    assert observation["tool_metadata"]["extra-tool-field"] == "preserved"
    listed = client.get(f"/audits/{created['id']}/observations")
    assert listed.status_code == 200
    assert listed.json() == [observation]

    correlated = client.post(f"/audits/{created['id']}/findings/correlate")
    assert correlated.status_code == 200
    candidate = correlated.json()["candidate_findings"][-1]
    assert candidate["state"] == "VALIDATION_PENDING"
    assert candidate["observation_ids"] == [observation["observation_id"]]
    assert candidate["evidence_ids"] == [evidence_id]
    assert candidate["validation_proposal"]["capability"] == "web.vulnerability.validate"

    missing_evidence = client.post(
        f"/audits/{created['id']}/findings/{candidate['finding_id']}/validation",
        json={"outcome": "CONFIRMED", "evidence_id": "00000000-0000-0000-0000-000000000000",
              "validated_by": "policy-engine", "basis": "This must be rejected because the evidence is not linked."},
    )
    assert missing_evidence.status_code == 409

    confirmed = client.post(
        f"/audits/{created['id']}/findings/{candidate['finding_id']}/validation",
        json={"outcome": "CONFIRMED", "evidence_id": evidence_id,
              "validated_by": "policy-engine", "basis": "Recorded validation basis linked to immutable evidence."},
    )
    assert confirmed.status_code == 200
    finding = confirmed.json()["candidate_findings"][-1]
    assert finding["state"] == "CONFIRMED"
    assert finding["validation_history"][-1]["evidence_id"] == evidence_id

    events_before = client.get(f"/audits/{created['id']}/events").json()
    executions_before = client.get(f"/audits/{created['id']}").json()["plugin_executions"]
    json_report = client.get(f"/audits/{created['id']}/report.json")
    markdown_report = client.get(f"/audits/{created['id']}/report.md")

    assert json_report.status_code == 200
    report = json_report.json()
    assert report["report_version"] == "1"
    assert report["executive_summary"]["confirmed_finding_count"] == 1
    reported_finding = report["confirmed_findings"][0]
    assert reported_finding["finding_id"] == finding["finding_id"]
    assert reported_finding["evidence_references"][0]["evidence_id"] == evidence_id
    assert "extra-tool-field" not in json_report.text
    assert markdown_report.status_code == 200
    assert markdown_report.headers["content-type"].startswith("text/markdown")
    assert "## Confirmed findings" in markdown_report.text
    assert evidence_id in markdown_report.text
    assert client.get(f"/audits/{created['id']}/events").json() == events_before
    assert client.get(f"/audits/{created['id']}").json()["plugin_executions"] == executions_before

    proposed_retest = client.post(
        f"/audits/{created['id']}/retests", json={"finding_ids": [finding["finding_id"]]}
    )
    assert proposed_retest.status_code == 200
    retest = proposed_retest.json()["retest_plans"][-1]
    assert retest["status"] == "PENDING_APPROVAL"
    assert len(retest["steps"]) == 1
    assert retest["steps"][0]["capability"] == "web.vulnerability.validate"

    approved_retest = client.post(
        f"/audits/{created['id']}/retests/{retest['retest_id']}/approve",
        json={"approved_by": "reviewer@example.test", "reason": "Retest scope and capability reviewed."},
    )
    assert approved_retest.status_code == 200
    retest_step = approved_retest.json()["retest_plans"][-1]["steps"][0]
    assert retest_step["status"] == "READY"
    executed_retest = client.post(
        f"/audits/{created['id']}/retests/{retest['retest_id']}/steps/{retest_step['retest_step_id']}/execute"
    )
    assert executed_retest.status_code == 200
    retest_evidence_id = executed_retest.json()["retest_plans"][-1]["steps"][0]["evidence_id"]
    assert retest_evidence_id
    assert client.post(f"/audits/{created['id']}/evidence/{retest_evidence_id}/normalize").status_code == 200
    compared = client.post(f"/audits/{created['id']}/retests/{retest['retest_id']}/compare")
    assert compared.status_code == 200
    assert compared.json()["retest_plans"][-1]["status"] == "COMPLETED"
    assert compared.json()["candidate_findings"][-1]["state"] == "STILL_PRESENT"

    closed = client.post(
        f"/audits/{created['id']}/close",
        json={"closed_by": "reviewer@example.test", "reason": "Retest completed and audit history retained."},
    )
    assert closed.status_code == 200
    assert closed.json()["closed_at"]
    assert closed.json()["closed_by"] == "reviewer@example.test"
