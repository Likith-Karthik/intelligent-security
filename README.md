# Intelligent Security Audit Orchestrator

This repository contains a proof of concept for a plugin-based, policy-controlled security audit orchestrator.

## Flow 1: Create Audit

The current implementation supports two flows:

1. Create an audit: accept a typed audit request, persist it in SQLite, set its state to `CREATED`, and emit an immutable `audit.created` event.
2. Validate authorization and scope: compile the request into a machine-enforceable scope policy and transition the audit to `SCOPE_VALIDATED` or `SCOPE_REJECTED`.
3. Profile the target: derive a safe, deterministic target profile from validated metadata and transition the audit to `TARGET_PROFILED`.
4. Discover compatible capabilities: admit plugin packages, filter their manifests against profile and scope, rank candidates, and transition the audit to `CAPABILITIES_DISCOVERED`.
5. Generate an audit plan: use an approved model profile to produce a structured plan, validate its shape and dependencies, and transition the audit to `PLAN_PROPOSED`.
6. Validate and approve a plan: re-check proposed steps against persisted scope, discovered capabilities, plugin health, and budgets before transitioning to `PLAN_APPROVED` or a human approval checkpoint.
7. Schedule approved steps: persist the approved DAG with `READY` dependency-free steps and `PENDING` dependent steps; this stage does not execute tools.
8. Resolve and execute a plugin: late-bind a `READY` capability to an operator-configured runtime, invoke it through a trusted adapter, and record the resolved implementation and outcome.

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
The lightweight operator console is served at `http://127.0.0.1:8000/`. For the POC it asks only for a target type and target identifier. Comprehensive mode derives the authorized scope from that target and enables every supported non-destructive operation; capability discovery then selects every compatible capability from admitted plugins. It does not authorize linked, third-party, or adjacent infrastructure. The UI supplies fixed local authorization, a one-hour time budget, a $10 cost budget, and the non-destructive approval policy; production deployments should replace those defaults with authenticated, auditable engagement data. Once created, the POC operator console automatically advances lifecycle stages and runs ready plugin steps, continuously displaying plan, schedule, findings, and events. The operator can pause, exit, or restart the automation; a pause takes effect before the next stage or plugin step, so an already-running plugin is allowed to finish. It contains no plugin-specific runtime configuration, model credentials, or direct plugin invocation logic.

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

Expected result: `200 OK`, state `CAPABILITIES_DISCOVERED`, ranked `capability_discovery.candidates`, any `gaps`, and a `capabilities.discovered` event. The bundled packages declare Semgrep, Nuclei, Promptfoo, and Nmap capabilities. Flow 4 does not execute binaries or verify their runtime dependencies.

### Refresh the plugin registry

The active registry is an immutable snapshot. Configure `PLUGIN_REGISTRY_ADMIN_TOKEN` in local deployment configuration to enable the operator-only refresh endpoint, then call:

```bash
curl -X POST http://127.0.0.1:8000/admin/plugins/refresh \
  -H "X-Plugin-Registry-Token: $PLUGIN_REGISTRY_ADMIN_TOKEN"
```

Refresh reads only the configured plugin-package source, validates every manifest and package-local execution specification, and swaps in the resulting snapshot atomically. It does not install packages, execute plugin binaries, accept arbitrary executable paths, or change allowlists. If admission fails, the prior snapshot remains active. The endpoint is disabled when no token is configured.

### Configure AI model profiles

Model profiles are held centrally in `config/model_profiles.json`, which is intentionally ignored by Git because it can reveal internal endpoint details. Start from the committed `config/model_profiles.example.json`:

```bash
cp config/model_profiles.example.json config/model_profiles.json
```

API keys must be referenced, never stored in this file or an audit request.

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

`audit_planning` is used for Flow 5. The same enabled default profile is used for the other AI stages in the POC when a dedicated profile is absent; production should configure dedicated `observation_normalization`, `finding_correlation`, `finding_validation`, and `report_generation` profiles. The model always returns structured proposals; deterministic validation still controls evidence references, scope, execution, finding state, and the audit-level validation decision.

Before running the service, place a newly generated key in the process environment:

```bash
cp .env.example .env
# Edit .env locally and set PLANNER_MODEL_API_KEY plus (optionally) PLUGIN_REGISTRY_ADMIN_TOKEN.
```

Start the service with the local environment file:

```bash
uvicorn intelligent_security.app:app --app-dir src --env-file .env --reload
```

Do not commit this value, add it to `config/model_profiles.json`, or place it in an audit request.

### Generate an audit plan

After configuring a profile and making its `env://` credential available to the running service:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/generate
```

Expected result: `200 OK`, state `PLAN_PROPOSED`, a structured `audit_plan`, and a `plan.proposed` event. Before model configuration, the endpoint returns `503` with `model_profile_unavailable`.

### Validate and approve a plan

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/validate
```

The policy engine re-checks each step against the stored capability discovery, authorization, plugin health, and audit time/cost budgets. A compliant plan transitions to `PLAN_APPROVED` and emits `plan.approved`. An invalid plan transitions to `PLAN_REJECTED` and emits `plan.rejected` with a machine-readable reason.

Set `approval_policy` to `human_approval_required` when creating an audit to require a reviewer before execution. The validation call then transitions to `PLAN_PENDING_APPROVAL`; submit the reviewer decision with:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/approval \
  -H 'Content-Type: application/json' \
  -d '{"decision":"approve","reviewed_by":"security@example.test","reason":"Scope confirmed."}'
```

### Schedule an approved plan

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/schedule
```

Only `PLAN_APPROVED` audits can be scheduled. The response transitions to `PLAN_SCHEDULED`, persists only capability-level steps, reserves declared time/cost estimates, and marks dependency-free steps `READY`. It does not bind a plugin implementation; Flow 8 resolves a healthy compatible implementation immediately before invocation. No plugin is invoked during scheduling.

### Configure and execute a plugin

Runtime profiles are local, operator-managed configuration. Copy the example and configure an already-installed or already-running approved tool; do not add credentials, Git URLs, or arbitrary commands to a manifest.

```bash
cp config/plugin_runtimes.example.json config/plugin_runtimes.json
```

After a `PLAN_SCHEDULED` audit has a `READY` step and a matching adapter/runtime implementation is registered, execute it with:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/steps/{step_id}/execute
```

The resolver selects the best currently admitted package that matches the capability contract and has an enabled runtime profile. If none is configured, the endpoint returns `409` with `capability_unavailable`, records an auditable blocked execution, and invokes nothing. The core includes only a generic constrained container adapter: it accepts a digest-pinned image from the local runtime profile, renders policy-controlled typed inputs, and uses package-owned fixed arguments and read-only package-local mounts. Every invoked execution is then captured as immutable Flow 9 evidence: redacted invocation plus checksummed stdout/stderr artifacts, with optional adapter-supplied files, HTTP records, or screenshots. Raw artifact bodies remain in the evidence store rather than the audit API. Nuclei is merely the bundled example package; deleting its directory and refreshing removes it without changing core source code.

### Generate a report

Reports are derived only from persisted audit state; they do not call the planner or execute a plugin. Use either format after findings have been correlated and validated:

```bash
curl -sS "http://127.0.0.1:8000/audits/{audit_id}/report.json"
curl -sS "http://127.0.0.1:8000/audits/{audit_id}/report.md"
```

The output includes confirmed findings and inconclusive candidates with immutable evidence metadata references. Flow 12 uses the configured report-generation model to improve the executive summary and evidence-backed guidance, then validates every finding ID before rendering. It intentionally excludes raw artifact bodies and tool-specific raw observation fields.
