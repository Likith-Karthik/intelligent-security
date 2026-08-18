# Intelligent Security Audit Orchestrator

This repository contains a proof of concept for a plugin-based, policy-controlled security audit orchestrator.

## Flow 1: Create Audit

The first implementation accepts a typed audit request, stores the audit in SQLite, sets the audit state to `CREATED`, and emits an immutable `audit.created` event. Credential values are not accepted; only opaque credential references are persisted.

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
    "credential_references": ["vault://security/staging-test-account"],
    "time_budget_seconds": 3600,
    "cost_budget_usd": 25,
    "approval_policy": "human_approval_for_destructive_actions"
  }'
```

Expected result: `201 Created`, an audit in `CREATED` state, and an ID that can be fetched from `GET /audits/{audit_id}`. `GET /audits/{audit_id}/events` should return one `audit.created` event.
