# Intelligent Security Audit Orchestrator

This repository contains a proof of concept for a plugin-based, policy-controlled security audit orchestrator.

## Flow 1: Create Audit

The current implementation supports two flows:

1. Create an audit: accept a typed audit request, persist it in SQLite, set its state to `CREATED`, and emit an immutable `audit.created` event.
2. Validate authorization and scope: compile the request into a machine-enforceable scope policy and transition the audit to `SCOPE_VALIDATED` or `SCOPE_REJECTED`.
3. Profile the target: derive a safe, deterministic target profile from validated metadata and transition the audit to `TARGET_PROFILED`.
4. Discover compatible capabilities: load plugin manifests, filter them against profile and scope, rank candidates, and transition the audit to `CAPABILITIES_DISCOVERED`.
5. Generate an audit plan: use an approved model profile to produce a structured plan, validate its shape and dependencies, and transition the audit to `PLAN_PROPOSED`.

Credential values are not accepted; only opaque credential references are persisted.

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install '.[dev]'
```

### Run

```bash
uvicorn intelligent_security.app:app --app-dir src --reload
```

The API is available at `http://127.0.0.1:8000`, with interactive docs at `/docs`.

### Test

```bash
PYTHONPATH=src pytest
```

### Manual smoke test

```bash
curl -X POST http://127.0.0.1:8000/audits \
  -H 'content-type: application/json' \
  -d '{
    "name": "Staging web audit",
    "objective": "Identify security issues in the authorized staging environment.",
    "target": {"target_type": "web_application", "identifier": "https://staging.example.test"},
    "scope": {"authorized_assets": ["staging.example.test"], "excluded_assets": ["production.example.test"]},
    "authorization": {"authorization_id": "SEC-123", "authorized_by": "security@example.test", "valid_until": "2099-01-01T00:00:00Z", "allowed_operations": ["web_scan"]},
    "credential_references": ["vault://security/staging-test-account"],
    "time_budget_seconds": 3600,
    "cost_budget_usd": 25,
    "approval_policy": "human_approval_for_destructive_actions"
  }'
```

Expected result: `201 Created`, an audit in `CREATED` state, and an ID that can be fetched from `GET /audits/{audit_id}`. `GET /audits/{audit_id}/events` should return one `audit.created` event.

### Validate scope

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/scope/validate
```

Expected result: `200 OK`, audit state `SCOPE_VALIDATED`, a normalized `scope_policy`, and a second `scope.validated` event. A target outside the authorized assets, expired authorization, or entirely prohibited operation set returns `422` and leaves the audit in `SCOPE_REJECTED`.

### Profile target

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/profile
```

Expected result: `200 OK`, audit state `TARGET_PROFILED`, a versioned `target_profile`, and a `target.profiled` event. Profiling currently uses only already-authorized metadata: it makes no DNS, HTTP, port, or repository requests. Calling it before scope validation returns `409`.

### Discover compatible capabilities

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/capabilities/discover
```

Expected result: `200 OK`, state `CAPABILITIES_DISCOVERED`, ranked `capability_discovery.candidates`, any `gaps`, and a `capabilities.discovered` event. The bundled manifests declare Semgrep, Nuclei, Promptfoo, and Nmap capabilities. They are declarations only: Flow 4 does not execute binaries or verify their runtime dependencies.

### Configure a planner model

Model profiles are held centrally in `config/model_profiles.json`. The checked-in configuration is intentionally empty until an approved provider and model are selected. API keys must be referenced, never stored in this file or an audit request.

Example profile shape:

```json
{
  "profiles": [
    {
      "profile_id": "primary-planner",
      "purpose": "audit_planning",
      "provider": "openai_compatible",
      "model": "approved-model-name",
      "credential_reference": "env://PLANNER_MODEL_API_KEY",
      "base_url": "https://approved-provider.example/v1",
      "temperature": 0.1,
      "max_output_tokens": 4000,
      "timeout_seconds": 60,
      "enabled": true,
      "default_for_purpose": true
    }
  ]
}
```

Optionally set `planner_model_profile` in `POST /audits` to select a non-default approved profile. Otherwise the unique enabled profile marked `default_for_purpose` is used.

### Generate an audit plan

After configuring a profile and making its `env://` credential available to the running service:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/generate
```

Expected result: `200 OK`, state `PLAN_PROPOSED`, a structured `audit_plan`, and a `plan.proposed` event. Before model configuration, the endpoint returns `503` with `model_profile_unavailable`.
