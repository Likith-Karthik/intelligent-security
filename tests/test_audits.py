import json

from fastapi.testclient import TestClient

from intelligent_security.app import create_app


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
    assert discovery["candidates"] == [
        {
            "rank": 1,
            "capability": "web.vulnerability_scan",
            "description": "Run template-based vulnerability scans against an authorized web application or API.",
            "plugin_id": "nuclei",
            "plugin_version": "1",
            "required_operation": "web_scan",
            "required_inputs": ["target_profile", "scope_policy"],
            "estimated_duration_seconds": 600,
            "estimated_cost_usd": 0.0,
            "reliability": 0.85,
            "health": "declared_healthy",
        }
    ]
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
