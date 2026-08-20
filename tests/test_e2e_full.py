
import json
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from intelligent_security.app import create_app
from intelligent_security.evidence.artifact_store import ArtifactStore
from intelligent_security.evidence.collector import EvidenceCollector
from intelligent_security.evidence.normalizer import EvidenceNormalizer
from intelligent_security.execution.adapters import ContainerCliAdapter
from intelligent_security.execution.result import AdapterExecutionResult
from intelligent_security.execution.runtime_profiles import PluginRuntimeProfileRegistry
from intelligent_security.execution.service import ExecutionService
from intelligent_security.findings.correlator import FindingCorrelator
from intelligent_security.planning.service import AuditPlanner
from intelligent_security.reporting.generator import ReportGenerator

TARGET_HOST = "mock-app.example.test"
NUCLEI_JSONL = json.dumps({
    "template-id": "missing-csp", "type": "http",
    "host": "https://mock-app.example.test",
    "matched-at": "https://mock-app.example.test/",
    "info": {"name": "Content-Security-Policy Header Not Set",
               "description": "Missing CSP.", "severity": "medium",
               "classification": {"cwe-id": ["CWE-693"]}},
}) + "\n"


class FakeGateway:
    def __init__(self, response): self.response = response
    def generate_json(self, p, s, u): return self.response


class FakeAdapter:
    """Simple adapter: returns a plain dict (POC compat shim tested here too)."""
    def execute(self, runtime, audit, step, package): return {"result": "ok"}


class FakeAdapterWithOutput:
    """Adapter that injects realistic JSONL stdout into the evidence artifact."""
    def __init__(self, stdout): self.stdout = stdout
    def execute(self, runtime, audit, step, package):
        return AdapterExecutionResult(output_summary={"result": "ok"}, stdout=self.stdout)


def _write_runtimes(path, host=TARGET_HOST):
    path.write_text(json.dumps({"plugins": [{
        "plugin_id": "nuclei", "adapter": "container_cli",
        "runtime_reference": "container-config://fake",
        "allowed_target_hosts": [host], "enabled": True,
    }]}), encoding="utf-8")


def _write_profiles(path):
    path.write_text(json.dumps({"profiles": [{
        "profile_id": "e2e", "purpose": "audit_planning",
        "provider": "openai_compatible", "model": "fake",
        "credential_reference": "env://KEY",
        "base_url": "http://fake.invalid/v1",
        "temperature": 0.1, "max_output_tokens": 2000,
        "timeout_seconds": 30, "enabled": True, "default_for_purpose": True,
    }]}), encoding="utf-8")


def _base_req(host=TARGET_HOST, target_type="web_application"):
    if target_type == "web_application":
        ident, assets = f"https://{host}/", [host]
    elif target_type == "source_repository":
        ident, assets = f"https://github.com/ex/{host}", [f"https://github.com/ex/{host}"]
    elif target_type == "network_host":
        ident, assets = host, [host]
    else:
        ident, assets = f"https://{host}/", [host]
    return {
        "name": f"e2e: {host}", "objective": "E2E full-lifecycle audit.",
        "target": {"target_type": target_type, "identifier": ident},
        "scope": {"authorized_assets": assets, "excluded_assets": [],
                   "prohibited_operations": ["exploit", "destructive_action"]},
        "authorization": {"authorization_id": "E2E-AUTH-001", "authorized_by": "tester",
                          "valid_until": "2099-01-01T00:00:00Z", "allowed_operations": ["web_scan"]},
        "credential_references": [], "time_budget_seconds": 3600, "cost_budget_usd": 100.0,
        "approval_policy": "human_approval_for_destructive_actions",
    }


def _plan1(cap="web.vulnerability_scan"):
    return {"steps": [{"id": "scan-step", "capability": cap,
                        "depends_on": [], "inputs": {}, "reason": "Scan"}]}


def _make_client(tmp_path, plan=None, host=TARGET_HOST, adapter=None):
    pp = tmp_path / "mp.json"; _write_profiles(pp)
    rp = tmp_path / "rp.json"; _write_runtimes(rp, host)
    ev = str(tmp_path / "ev")
    app = create_app(database_path=str(tmp_path / "db.db"), model_profiles_path=str(pp),
                     plugin_runtime_profiles_path=str(rp), evidence_directory=ev)
    if plan is not None:
        app.state.audit_planner = AuditPlanner(FakeGateway(plan))
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(str(rp)),
        {"container_cli": adapter or FakeAdapter()},
        EvidenceCollector(ArtifactStore(ev)))
    return TestClient(app)


def _advance_to_scheduled(client, host=TARGET_HOST):
    r = client.post("/audits", json=_base_req(host)); assert r.status_code == 201
    aid = r.json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover",
               "/plan/generate", "/plan/validate", "/plan/schedule"]:
        r = client.post(f"/audits/{aid}{ep}")
        assert r.status_code == 200, f"{ep} => {r.status_code}: {r.text[:200]}"
    return r.json()


def _make_with_normalizer(tmp_path, stdout=None):
    """Returns (client, audit_id) at PLAN_SCHEDULED, ready to execute."""
    if stdout is None:
        stdout = NUCLEI_JSONL
    pp = tmp_path / "mp.json"; _write_profiles(pp)
    rp = tmp_path / "rp.json"; _write_runtimes(rp)
    ev = str(tmp_path / "ev")
    app = create_app(database_path=str(tmp_path / "db.db"), model_profiles_path=str(pp),
                     plugin_runtime_profiles_path=str(rp), evidence_directory=ev)
    app.state.audit_planner = AuditPlanner(FakeGateway(_plan1()))
    store = ArtifactStore(ev)
    # Use FakeAdapterWithOutput so the JSONL stdout goes into the artifact store
    app.state.execution_service = ExecutionService(
        PluginRuntimeProfileRegistry(str(rp)),
        {"container_cli": FakeAdapterWithOutput(stdout)},
        EvidenceCollector(store))
    app.state.evidence_normalizer = EvidenceNormalizer(store)
    app.state.finding_correlator = FindingCorrelator()
    # Disable AI report generation so tests don't need a live model gateway
    app.state.report_generator = ReportGenerator()
    client = TestClient(app)
    aid = client.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover",
               "/plan/generate", "/plan/validate", "/plan/schedule"]:
        r = client.post(f"/audits/{aid}{ep}")
        assert r.status_code == 200, f"{ep} => {r.status_code}: {r.text[:200]}"
    return client, aid


def _setup_with_obs(tmp_path):
    """Execute a step and normalize evidence. Returns (client, audit_id, evidence_id)."""
    c, aid = _make_with_normalizer(tmp_path)
    r = c.post(f"/audits/{aid}/steps/scan-step/execute")
    assert r.status_code == 200, f"execute => {r.status_code}: {r.text[:200]}"
    eid = r.json()["raw_evidence"][-1]["evidence_id"]
    r2 = c.post(f"/audits/{aid}/evidence/{eid}/normalize")
    assert r2.status_code == 200
    assert r2.json()["observation_normalizations"][-1]["accepted_count"] >= 1, (
        "Normalization produced 0 observations.")
    return c, aid, eid


def _setup_confirmed(tmp_path):
    """Correlate findings and confirm the first one. Returns (client, audit_id, finding_id, evidence_id)."""
    c, aid, eid = _setup_with_obs(tmp_path)
    r = c.post(f"/audits/{aid}/findings/correlate")
    assert r.status_code == 200
    findings = r.json()["candidate_findings"]
    assert len(findings) >= 1, f"No findings correlated. Response: {r.text[:300]}"
    fid = findings[0]["finding_id"]
    c.post(f"/audits/{aid}/findings/{fid}/validation",
           json={"outcome": "CONFIRMED", "evidence_id": eid, "validated_by": "e2e-tester", "basis": "confirmed"})
    return c, aid, fid, eid


# ─── Flow 1: Create ──────────────────────────────────────────────────────────

def test_create_returns_201(tmp_path):
    c = _make_client(tmp_path, _plan1())
    r = c.post("/audits", json=_base_req()); assert r.status_code == 201
    b = r.json(); assert b["state"] == "CREATED"
    aid = b["id"]
    assert c.get(f"/audits/{aid}/events").json()[0]["event_type"] == "audit.created"

def test_get_nonexistent_404(tmp_path):
    c = _make_client(tmp_path, _plan1()); assert c.get(f"/audits/{uuid4()}").status_code == 404

def test_create_rejects_empty_objective(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["objective"] = ""
    assert c.post("/audits", json=req).status_code == 422

def test_create_rejects_bare_credential(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["credential_references"] = ["plain-secret"]
    assert c.post("/audits", json=req).status_code == 422

def test_create_accepts_vault_ref(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["credential_references"] = ["vault://sec/tok"]
    r = c.post("/audits", json=req); assert r.status_code == 201
    assert "vault://sec/tok" in r.json()["credential_references"]


# ─── Flow 2: Scope validation ─────────────────────────────────────────────────

def test_scope_validate_transitions_state(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    r = c.post(f"/audits/{aid}/scope/validate"); assert r.status_code == 200
    b = r.json(); assert b["state"] == "SCOPE_VALIDATED"
    assert b["scope_policy"]["network_allowlist"] == [TARGET_HOST]
    assert "web_scan" in b["scope_policy"]["allowed_operations"]
    types = [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()]
    assert types == ["audit.created", "scope.validated"]

def test_scope_validate_idempotent(tmp_path):
    """Calling scope/validate twice should emit only one event — idempotency gap if it emits two."""
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    cnt = [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()].count("scope.validated")
    assert cnt == 1, f"BUG: scope.validated emitted {cnt} times (should be idempotent)"

def test_scope_rejects_expired_auth(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req()
    req["authorization"]["valid_until"] = "2000-01-01T00:00:00Z"
    aid = c.post("/audits", json=req).json()["id"]
    r = c.post(f"/audits/{aid}/scope/validate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "authorization_expired"
    # GAP: SCOPE_REJECTED is terminal — no way to re-validate with fixed dates
    assert c.get(f"/audits/{aid}").json()["state"] == "SCOPE_REJECTED"

def test_scope_rejects_target_out_of_scope(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req()
    req["target"]["identifier"] = "https://rogue.example.test/"
    aid = c.post("/audits", json=req).json()["id"]
    r = c.post(f"/audits/{aid}/scope/validate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "target_out_of_scope"

def test_scope_rejects_conflicting_scope(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req()
    req["scope"]["excluded_assets"] = [TARGET_HOST]
    aid = c.post("/audits", json=req).json()["id"]
    r = c.post(f"/audits/{aid}/scope/validate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "conflicting_scope"

def test_scope_rejects_all_ops_prohibited(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req()
    req["authorization"]["allowed_operations"] = ["exploit"]
    aid = c.post("/audits", json=req).json()["id"]
    r = c.post(f"/audits/{aid}/scope/validate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "no_permitted_operations"

def test_scope_after_target_profiled_returns_409(tmp_path):
    """scope/validate after TARGET_PROFILED must return 409 — scope cannot be
    re-validated once the target has already been profiled against it."""
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    r = c.post(f"/audits/{aid}/scope/validate")
    assert r.status_code == 409


# ─── Flow 3: Target profiling ─────────────────────────────────────────────────

def test_profile_requires_scope(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/profile").status_code == 409

def test_profile_web_app(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    r = c.post(f"/audits/{aid}/profile"); assert r.status_code == 200
    p = r.json()["target_profile"]
    assert r.json()["state"] == "TARGET_PROFILED"
    assert p["target_type"] == "web_application"
    assert p["confidence"] == 0.75
    assert TARGET_HOST in p["canonical_identifier"]

def test_profile_idempotent(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    assert [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()].count("target.profiled") == 1

def test_profile_source_repo(tmp_path):
    req = _base_req(host="myrepo", target_type="source_repository")
    req["authorization"]["allowed_operations"] = ["static_analysis"]
    c = _make_client(tmp_path, _plan1("code.sast_scan"), host="myrepo")
    aid = c.post("/audits", json=req).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    r = c.post(f"/audits/{aid}/profile"); assert r.status_code == 200
    assert r.json()["target_profile"]["source_available"] is True

def test_profile_network_host(tmp_path):
    req = _base_req(host="192.168.1.1", target_type="network_host")
    req["authorization"]["allowed_operations"] = ["port_discovery"]
    c = _make_client(tmp_path, _plan1("network.port_discovery"), host="192.168.1.1")
    aid = c.post("/audits", json=req).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    r = c.post(f"/audits/{aid}/profile"); assert r.status_code == 200
    assert r.json()["target_profile"]["target_type"] == "network_host"


# ─── Flow 4: Capability discovery ─────────────────────────────────────────────

def test_discover_requires_profile(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/capabilities/discover").status_code == 409

def test_discover_finds_nuclei(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    r = c.post(f"/audits/{aid}/capabilities/discover"); assert r.status_code == 200
    assert any(x["plugin_id"] == "nuclei" for x in r.json()["capability_discovery"]["candidates"])

def test_discover_empty_registry_reports_gap(tmp_path):
    """GAP: With no plugins, capability discovery returns gaps (no 500 error)."""
    d = tmp_path / "empty"; d.mkdir()
    app = create_app(database_path=str(tmp_path / "db.db"), plugin_manifest_directory=str(d))
    c = TestClient(app); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    r = c.post(f"/audits/{aid}/capabilities/discover"); assert r.status_code == 200
    d2 = r.json()["capability_discovery"]
    assert d2["candidates"] == []
    assert any(g["operation"] == "web_scan" for g in d2["gaps"])

def test_discover_idempotent(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    assert c.post(f"/audits/{aid}/capabilities/discover").status_code == 200
    assert c.post(f"/audits/{aid}/capabilities/discover").status_code == 200
    assert [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()].count("capabilities.discovered") == 1


# ─── Flow 5: Plan generation ───────────────────────────────────────────────────

def test_plan_gen_requires_discovery(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/scope/validate").status_code == 200
    assert c.post(f"/audits/{aid}/profile").status_code == 200
    assert c.post(f"/audits/{aid}/plan/generate").status_code == 409

def test_plan_gen_creates_proposed(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 200
    assert r.json()["state"] == "PLAN_PROPOSED"
    assert r.json()["audit_plan"]["registry_snapshot_id"] == r.json()["capability_discovery"]["registry_snapshot_id"]

def test_plan_gen_rejects_unknown_capability(tmp_path):
    c = _make_client(tmp_path, _plan1("nope.unknown")); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "unknown_capability"
    assert c.get(f"/audits/{aid}").json()["state"] == "CAPABILITIES_DISCOVERED"

def test_plan_gen_rejects_model_inputs(tmp_path):
    bad = {"steps": [{"id": "s", "capability": "web.vulnerability_scan",
                        "depends_on": [], "inputs": {"url": "https://evil.test"}, "reason": "x"}]}
    c = _make_client(tmp_path, bad); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "invalid_model_output"

def test_plan_gen_rejects_cyclic_deps(tmp_path):
    cyc = {"steps": [
        {"id": "a", "capability": "web.vulnerability_scan", "depends_on": ["b"], "inputs": {}, "reason": "A"},
        {"id": "b", "capability": "web.vulnerability_scan", "depends_on": ["a"], "inputs": {}, "reason": "B"},
    ]}
    c = _make_client(tmp_path, cyc); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "cyclic_plan"

def test_plan_gen_rejects_duplicate_ids(tmp_path):
    dup = {"steps": [
        {"id": "dup", "capability": "web.vulnerability_scan", "depends_on": [], "inputs": {}, "reason": "1"},
        {"id": "dup", "capability": "web.vulnerability_scan", "depends_on": [], "inputs": {}, "reason": "2"},
    ]}
    c = _make_client(tmp_path, dup); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 422
    assert r.json()["detail"]["code"] == "duplicate_step_id"

def test_plan_gen_normalizes_numeric_ids(tmp_path):
    num = {"steps": [{"id": 1, "capability": "web.vulnerability_scan",
                        "depends_on": [], "inputs": {}, "reason": "n"}]}
    c = _make_client(tmp_path, num); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate"); assert r.status_code == 200
    assert r.json()["audit_plan"]["steps"][0]["id"] == "1"

def test_plan_gen_no_credentials_returns_5xx(tmp_path):
    """GAP: With no model credentials configured, plan/generate returns 502 with
    credential_unavailable (not 503 model_profile_unavailable). This means the
    error code depends on whether a profile is found vs whether credentials exist."""
    app = create_app(database_path=str(tmp_path / "db.db"))
    c = TestClient(app); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/generate")
    # Without credentials the gateway fails with 502 credential_unavailable (not 503).
    # This is a gap: the error code is not consistent with the no-profile case.
    assert r.status_code in (502, 503)
    assert r.json()["detail"]["code"] in ("model_profile_unavailable", "credential_unavailable")


# ─── Flow 6: Plan validation + approval ───────────────────────────────────────

def test_plan_validate_auto_approves(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/validate"); assert r.status_code == 200
    assert r.json()["state"] == "PLAN_APPROVED"
    assert r.json()["plan_approved_by"] == "policy-engine"

def test_plan_validate_requires_proposed(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    assert c.post(f"/audits/{aid}/plan/validate").status_code == 409

def test_plan_validate_time_budget_exceeded(tmp_path):
    """After PLAN_REJECTED (e.g. budget exceeded), plan/generate can be retried
    to recover — the audit resets to CAPABILITIES_DISCOVERED and re-proposes."""
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["time_budget_seconds"] = 60
    aid = c.post("/audits", json=req).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/validate"); assert r.status_code == 200
    assert r.json()["state"] == "PLAN_REJECTED"
    events = c.get(f"/audits/{aid}/events").json()
    assert any(e["payload"].get("code") == "time_budget_exceeded" for e in events)

    # BUG-3 fix: plan/generate from PLAN_REJECTED recovers the audit
    # Give the audit a higher time budget by recreating and reusing same client
    r = c.post(f"/audits/{aid}/plan/generate")
    assert r.status_code == 200
    assert r.json()["state"] == "PLAN_PROPOSED"
    ev_types = [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()]
    assert "plan.regeneration_requested" in ev_types

def test_human_approval_approve(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["approval_policy"] = "human_approval_required"
    aid = c.post("/audits", json=req).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    assert c.get(f"/audits/{aid}").json()["state"] == "PLAN_PENDING_APPROVAL"
    r = c.post(f"/audits/{aid}/plan/approval",
               json={"decision": "approve", "reviewed_by": "approver", "reason": "All good."})
    assert r.status_code == 200; assert r.json()["state"] == "PLAN_APPROVED"
    assert r.json()["plan_approved_by"] == "approver"

def test_human_approval_reject(tmp_path):
    c = _make_client(tmp_path, _plan1()); req = _base_req(); req["approval_policy"] = "human_approval_required"
    aid = c.post("/audits", json=req).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/approval",
               json={"decision": "reject", "reviewed_by": "reviewer", "reason": "Not ready."})
    assert r.status_code == 200; assert r.json()["state"] == "PLAN_REJECTED"

def test_approval_on_already_approved_returns_409(tmp_path):
    """GAP: Calling approval on a non-pending audit returns 409."""
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/approval",
               json={"decision": "approve", "reviewed_by": "reviewer", "reason": "Late approval."})
    assert r.status_code == 409


# ─── Flow 7: Scheduling ───────────────────────────────────────────────────────

def test_schedule_requires_approved(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    assert c.post(f"/audits/{aid}/plan/schedule").status_code == 409

def test_schedule_creates_ready_steps(tmp_path):
    c = _make_client(tmp_path, _plan1()); audit = _advance_to_scheduled(c)
    assert audit["state"] == "PLAN_SCHEDULED"
    s = audit["execution_schedule"]["steps"]
    assert s[0]["status"] == "READY"
    # GAP: late binding means plugin_id is NOT in the schedule step
    assert "plugin_id" not in s[0]
    assert audit["execution_schedule"]["reserved_duration_seconds"] > 0

def test_schedule_idempotent(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    assert c.post(f"/audits/{aid}/plan/schedule").status_code == 200
    assert c.post(f"/audits/{aid}/plan/schedule").status_code == 200
    assert [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()].count("plan.scheduled") == 1

def test_schedule_holds_deps_pending(tmp_path):
    two = {"steps": [
        {"id": "first", "capability": "web.vulnerability_scan", "depends_on": [], "inputs": {}, "reason": "s1"},
        {"id": "second", "capability": "web.vulnerability_scan", "depends_on": ["first"], "inputs": {}, "reason": "s2"},
    ]}
    c = _make_client(tmp_path, two); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/plan/schedule"); assert r.status_code == 200
    assert [s["status"] for s in r.json()["execution_schedule"]["steps"]] == ["READY", "PENDING"]


# ─── Flow 8: Execution ────────────────────────────────────────────────────────

def test_execute_records_evidence(tmp_path):
    c = _make_client(tmp_path, _plan1()); audit = _advance_to_scheduled(c)
    aid = audit["id"]; sid = audit["execution_schedule"]["steps"][0]["plan_step_id"]
    r = c.post(f"/audits/{aid}/steps/{sid}/execute"); assert r.status_code == 200
    ex = r.json()["plugin_executions"][-1]
    assert ex["status"] == "SUCCEEDED" and ex["plugin_id"] == "nuclei"
    ev = r.json()["raw_evidence"][-1]
    kinds = {a["kind"] for a in ev["artifacts"]}
    assert {"stdout", "stderr", "invocation"} <= kinds
    assert c.get(f"/audits/{aid}/events").json()[-1]["event_type"] == "step.completed"

def test_execute_requires_scheduled(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/steps/scan-step/execute").status_code == 409

def test_execute_unknown_step_404(tmp_path):
    c = _make_client(tmp_path, _plan1()); audit = _advance_to_scheduled(c)
    aid = audit["id"]
    assert c.post(f"/audits/{aid}/steps/does-not-exist/execute").status_code == 404

def test_execute_promotes_dependent_step(tmp_path):
    """After step[0] SUCCEEDS, step[1] (PENDING) must be promoted to READY."""
    two = {"steps": [
        {"id": "first", "capability": "web.vulnerability_scan", "depends_on": [], "inputs": {}, "reason": "s1"},
        {"id": "second", "capability": "web.vulnerability_scan", "depends_on": ["first"], "inputs": {}, "reason": "s2"},
    ]}
    c = _make_client(tmp_path, two); aid = c.post("/audits", json=_base_req()).json()["id"]
    for ep in ["/scope/validate", "/profile", "/capabilities/discover", "/plan/generate", "/plan/validate", "/plan/schedule"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200
    r = c.post(f"/audits/{aid}/steps/first/execute"); assert r.status_code == 200
    steps = r.json()["execution_schedule"]["steps"]
    assert steps[0]["status"] == "SUCCEEDED"
    assert steps[1]["status"] == "READY", f"BUG: step 2 is {steps[1]['status']} not READY"


def test_container_adapter_supports_network_host_target(tmp_path):
    """BUG-4: ContainerCliAdapter should authorize network_host targets without requiring https:// URL scheme."""
    from intelligent_security.execution.runtime_profiles import PluginRuntimeProfile
    from intelligent_security.domain import ScheduledStep
    import subprocess

    runtime = PluginRuntimeProfile(
        plugin_id="nmap",
        adapter="container_cli",
        runtime_reference="container-config://test-nmap",
        image_reference="instrumentisto/nmap@sha256:test",
        allowed_target_hosts=["192.168.1.1"],
        enabled=True,
    )
    audit = _base_req(host="192.168.1.1", target_type="network_host")
    c = _make_client(tmp_path, _plan1("network.port_discovery"), host="192.168.1.1")
    aid = c.post("/audits", json=audit).json()["id"]
    for ep in ["/scope/validate", "/profile"]:
        assert c.post(f"/audits/{aid}{ep}").status_code == 200

    audit_obj = c.app.state.audit_repository.get(aid)
    from intelligent_security.domain import ScheduledStepStatus
    step = ScheduledStep(
        plan_step_id="step-1",
        capability="network.port_discovery",
        contract_version="1",
        depends_on=[],
        status=ScheduledStepStatus.READY,
        estimated_duration_seconds=600,
        estimated_cost_usd=0.0,
    )
    pkg = c.app.state.capability_registry.active_snapshot().package_for_plugin("nmap")
    assert pkg is not None
    # package needs execution profile with hostname target_input
    from intelligent_security.registry.service import PluginExecutionSpec
    pkg.execution = PluginExecutionSpec(
        adapter=pkg.manifest.adapter,
        target_input="hostname",
        arguments=["-sV", "{{target.hostname}}"],
    )


    received = {}
    def runner(command, **kwargs):
        received["command"] = command
        return subprocess.CompletedProcess(command, 0, "", "")

    adapter = ContainerCliAdapter(runner)
    result = adapter.execute(runtime, audit_obj, step, pkg)
    assert result.exit_code == 0
    assert "192.168.1.1" in received["command"]



# ─── Evidence + Normalisation ─────────────────────────────────────────────────

def test_normalize_succeeds(tmp_path):
    c, aid = _make_with_normalizer(tmp_path)
    r = c.post(f"/audits/{aid}/steps/scan-step/execute"); assert r.status_code == 200
    eid = r.json()["raw_evidence"][-1]["evidence_id"]
    r = c.post(f"/audits/{aid}/evidence/{eid}/normalize"); assert r.status_code == 200
    norm = r.json()["observation_normalizations"][-1]
    assert norm["status"] == "SUCCEEDED" and norm["accepted_count"] == 1
    obs = r.json()["observations"][-1]
    assert obs["category"] == "http"
    assert obs["title"] == "Content-Security-Policy Header Not Set"
    assert "CWE-693" in obs["identifiers"]
    assert obs["evidence_id"] == eid

def test_normalize_idempotent(tmp_path):
    c, aid = _make_with_normalizer(tmp_path)
    r = c.post(f"/audits/{aid}/steps/scan-step/execute"); eid = r.json()["raw_evidence"][-1]["evidence_id"]
    assert c.post(f"/audits/{aid}/evidence/{eid}/normalize").status_code == 200
    r2 = c.post(f"/audits/{aid}/evidence/{eid}/normalize"); assert r2.status_code == 200
    assert len(r2.json()["observations"]) == 1 and len(r2.json()["observation_normalizations"]) == 1

def test_normalize_skips_blank_lines(tmp_path):
    c, aid = _make_with_normalizer(tmp_path, "\n" + NUCLEI_JSONL + "\n\n")
    r = c.post(f"/audits/{aid}/steps/scan-step/execute"); eid = r.json()["raw_evidence"][-1]["evidence_id"]
    r = c.post(f"/audits/{aid}/evidence/{eid}/normalize"); assert r.status_code == 200
    assert r.json()["observation_normalizations"][-1]["accepted_count"] == 1

def test_list_observations(tmp_path):
    c, aid = _make_with_normalizer(tmp_path)
    r = c.post(f"/audits/{aid}/steps/scan-step/execute"); eid = r.json()["raw_evidence"][-1]["evidence_id"]
    assert c.post(f"/audits/{aid}/evidence/{eid}/normalize").status_code == 200
    r = c.get(f"/audits/{aid}/observations"); assert r.status_code == 200 and len(r.json()) == 1

def test_normalize_unknown_evidence_404(tmp_path):
    c = _make_client(tmp_path, _plan1()); aid = c.post("/audits", json=_base_req()).json()["id"]
    assert c.post(f"/audits/{aid}/evidence/{uuid4()}/normalize").status_code == 404


# ─── Finding correlation + validation ─────────────────────────────────────────

def test_correlate_creates_candidates(tmp_path):
    c, aid, eid = _setup_with_obs(tmp_path)
    r = c.post(f"/audits/{aid}/findings/correlate"); assert r.status_code == 200
    findings = r.json()["candidate_findings"]; assert len(findings) >= 1
    assert findings[0]["state"] in ("CANDIDATE", "VALIDATION_PENDING")
    assert c.get(f"/audits/{aid}/events").json()[-1]["event_type"] == "findings.correlated"

def test_correlate_idempotent(tmp_path):
    c, aid, eid = _setup_with_obs(tmp_path)
    r1 = c.post(f"/audits/{aid}/findings/correlate")
    r2 = c.post(f"/audits/{aid}/findings/correlate")
    assert len(r1.json()["candidate_findings"]) == len(r2.json()["candidate_findings"])

def test_finding_validation_confirms(tmp_path):
    c, aid, eid = _setup_with_obs(tmp_path)
    fid = c.post(f"/audits/{aid}/findings/correlate").json()["candidate_findings"][0]["finding_id"]
    r = c.post(f"/audits/{aid}/findings/{fid}/validation",
               json={"outcome": "CONFIRMED", "evidence_id": eid, "validated_by": "e2e-tester", "basis": "Confirmed missing header."})
    assert r.status_code == 200
    found = next(f for f in r.json()["candidate_findings"] if f["finding_id"] == fid)
    assert found["state"] == "CONFIRMED"
    assert found["validation_history"][-1]["evidence_id"] == eid
    assert c.get(f"/audits/{aid}/events").json()[-1]["event_type"] == "finding.validation_recorded"

def test_finding_validation_rejects_unlinked_evidence(tmp_path):
    c, aid, eid = _setup_with_obs(tmp_path)
    fid = c.post(f"/audits/{aid}/findings/correlate").json()["candidate_findings"][0]["finding_id"]
    r = c.post(f"/audits/{aid}/findings/{fid}/validation",
               json={"outcome": "CONFIRMED", "evidence_id": str(uuid4()), "validated_by": "e2e", "basis": "Bad evidence."})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "unlinked_evidence"

def test_finding_revalidation_of_confirmed_returns_409(tmp_path):
    """BUG-5: Re-validating a CONFIRMED finding should return 409 with finding_not_eligible."""
    c, aid, eid = _setup_with_obs(tmp_path)
    fid = c.post(f"/audits/{aid}/findings/correlate").json()["candidate_findings"][0]["finding_id"]
    payload = {"outcome": "CONFIRMED", "evidence_id": eid, "validated_by": "e2e", "basis": "Manual validation."}
    assert c.post(f"/audits/{aid}/findings/{fid}/validation", json=payload).status_code == 200
    r = c.post(f"/audits/{aid}/findings/{fid}/validation", json=payload)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "finding_not_eligible"


# ─── Report ───────────────────────────────────────────────────────────────────

def test_json_report(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    r = c.get(f"/audits/{aid}/report.json"); assert r.status_code == 200
    rpt = r.json()
    assert rpt["executive_summary"]["confirmed_finding_count"] == 1
    assert rpt["confirmed_findings"][0]["finding_id"] == fid

def test_md_report(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    r = c.get(f"/audits/{aid}/report.md"); assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown") and eid in r.text

def test_report_side_effect_free(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    ev = c.get(f"/audits/{aid}/events").json()
    ex = c.get(f"/audits/{aid}").json()["plugin_executions"]
    c.get(f"/audits/{aid}/report.json"); c.get(f"/audits/{aid}/report.md")
    assert c.get(f"/audits/{aid}/events").json() == ev
    assert c.get(f"/audits/{aid}").json()["plugin_executions"] == ex

def test_json_report_no_tool_metadata(tmp_path):
    """GAP: report.json must not expose raw tool fields like template-id."""
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    report_text = c.get(f"/audits/{aid}/report.json").text
    # raw nuclei field should not bleed into the report body
    # (tool_metadata is intentionally excluded from the JSON report)
    assert "template-id" not in report_text


# ─── Retest ───────────────────────────────────────────────────────────────────

def test_retest_full_lifecycle(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    r = c.post(f"/audits/{aid}/retests", json={"finding_ids": [fid]}); assert r.status_code == 200
    rt = r.json()["retest_plans"][-1]; rtid = rt["retest_id"]; rsid = rt["steps"][0]["retest_step_id"]
    assert rt["status"] == "PENDING_APPROVAL"
    r = c.post(f"/audits/{aid}/retests/{rtid}/approve",
               json={"approved_by": "reviewer", "reason": "Approved."}); assert r.status_code == 200
    assert r.json()["retest_plans"][-1]["steps"][0]["status"] == "READY"
    r = c.post(f"/audits/{aid}/retests/{rtid}/steps/{rsid}/execute"); assert r.status_code == 200
    rte = r.json()["retest_plans"][-1]["steps"][0]["evidence_id"]; assert rte
    assert c.post(f"/audits/{aid}/evidence/{rte}/normalize").status_code == 200
    r = c.post(f"/audits/{aid}/retests/{rtid}/compare"); assert r.status_code == 200
    assert r.json()["retest_plans"][-1]["status"] == "COMPLETED"

def test_retest_rejects_candidate_findings(tmp_path):
    c, aid, eid = _setup_with_obs(tmp_path)
    fid = c.post(f"/audits/{aid}/findings/correlate").json()["candidate_findings"][0]["finding_id"]
    r = c.post(f"/audits/{aid}/retests", json={"finding_ids": [fid]}); assert r.status_code == 409
    assert r.json()["detail"]["code"] == "retest_rejected"

def test_retest_execute_requires_approved(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    rt = c.post(f"/audits/{aid}/retests", json={"finding_ids": [fid]}).json()["retest_plans"][-1]
    rtid = rt["retest_id"]; rsid = rt["steps"][0]["retest_step_id"]
    assert c.post(f"/audits/{aid}/retests/{rtid}/steps/{rsid}/execute").status_code == 409

def test_retest_approve_twice_409(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    rtid = c.post(f"/audits/{aid}/retests", json={"finding_ids": [fid]}).json()["retest_plans"][-1]["retest_id"]
    appr = {"approved_by": "reviewer", "reason": "Approved."}
    assert c.post(f"/audits/{aid}/retests/{rtid}/approve", json=appr).status_code == 200
    assert c.post(f"/audits/{aid}/retests/{rtid}/approve", json=appr).status_code == 409


# ─── Audit close ─────────────────────────────────────────────────────────────

def test_close_with_unresolved_findings_returns_409(tmp_path):
    """GAP: close/audit blocked if unresolved findings exist."""
    c, aid, eid = _setup_with_obs(tmp_path)
    assert c.post(f"/audits/{aid}/findings/correlate").status_code == 200
    # Finding still CANDIDATE — close should 409
    r = c.post(f"/audits/{aid}/close", json={"closed_by": "closer", "reason": "Premature close."})
    assert r.status_code == 409

def test_close_succeeds(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    r = c.post(f"/audits/{aid}/close", json={"closed_by": "closer", "reason": "All findings resolved."})
    assert r.status_code == 200
    assert r.json()["closed_at"] is not None and r.json()["closed_by"] == "closer"

def test_close_idempotent(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    p = {"closed_by": "closer", "reason": "Done."}
    r1 = c.post(f"/audits/{aid}/close", json=p)
    r2 = c.post(f"/audits/{aid}/close", json=p)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["closed_at"] == r2.json()["closed_at"]

def test_closed_audit_cannot_create_retest(tmp_path):
    c, aid, fid, eid = _setup_confirmed(tmp_path)
    assert c.post(f"/audits/{aid}/close", json={"closed_by": "closer", "reason": "Done."}).status_code == 200
    assert c.post(f"/audits/{aid}/retests", json={"finding_ids": [fid]}).status_code == 409


# ─── Admin ────────────────────────────────────────────────────────────────────

def test_registry_refresh_requires_token():
    app = create_app(database_path=":memory:", registry_admin_token="test-tok"); c = TestClient(app)
    assert c.post("/admin/plugins/refresh").status_code == 403
    assert c.post("/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "wrong"}).status_code == 403

def test_registry_refresh_succeeds():
    app = create_app(database_path=":memory:", registry_admin_token="test-tok"); c = TestClient(app)
    r = c.post("/admin/plugins/refresh", headers={"X-Plugin-Registry-Token": "test-tok"})
    assert r.status_code == 200 and "snapshot_id" in r.json()

def test_registry_refresh_disabled_without_token():
    """GAP: Registry refresh returns 503 with descriptive error when not configured."""
    app = create_app(database_path=":memory:", registry_admin_token=None); c = TestClient(app)
    r = c.post("/admin/plugins/refresh"); assert r.status_code == 503
    assert r.json()["detail"]["code"] == "registry_refresh_not_configured"

def test_health_check(tmp_path):
    c = _make_client(tmp_path, _plan1())
    r = c.get("/health"); assert r.status_code == 200 and r.json() == {"status": "ok"}


# ─── Full happy-path smoke: Create → Close ─────────────────────────────────────

def test_full_happy_path_create_to_close(tmp_path):
    """
    Complete end-to-end: create → scope → profile → discover → plan → validate
    → schedule → execute → normalize → correlate → validate finding → report → close.
    Checks all required event types emitted in order.
    """
    c, aid = _make_with_normalizer(tmp_path)

    r = c.post(f"/audits/{aid}/steps/scan-step/execute"); assert r.status_code == 200
    eid = r.json()["raw_evidence"][-1]["evidence_id"]

    r = c.post(f"/audits/{aid}/evidence/{eid}/normalize"); assert r.status_code == 200
    assert r.json()["observation_normalizations"][-1]["accepted_count"] == 1

    r = c.post(f"/audits/{aid}/findings/correlate"); assert r.status_code == 200
    findings = r.json()["candidate_findings"]; assert len(findings) >= 1
    fid = findings[0]["finding_id"]

    r = c.post(f"/audits/{aid}/findings/{fid}/validation",
               json={"outcome": "CONFIRMED", "evidence_id": eid, "validated_by": "e2e-tester", "basis": "Confirmed."})
    assert r.status_code == 200 and r.json()["candidate_findings"][0]["state"] == "CONFIRMED"

    r = c.get(f"/audits/{aid}/report.json"); assert r.status_code == 200
    assert r.json()["executive_summary"]["confirmed_finding_count"] == 1

    r = c.get(f"/audits/{aid}/report.md"); assert r.status_code == 200
    assert "Content-Security-Policy Header Not Set" in r.text

    types = [e["event_type"] for e in c.get(f"/audits/{aid}/events").json()]
    for exp in ["audit.created", "scope.validated", "target.profiled",
                "capabilities.discovered", "plan.proposed", "plan.approved",
                "plan.scheduled", "step.completed", "evidence.normalized",
                "findings.correlated", "finding.validation_recorded"]:
        assert exp in types, f"Missing required event: {exp}"

    r = c.post(f"/audits/{aid}/close", json={"closed_by": "e2e-runner", "reason": "Full lifecycle complete."})
    assert r.status_code == 200 and r.json()["closed_at"] is not None
