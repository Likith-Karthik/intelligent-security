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
