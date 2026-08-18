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
