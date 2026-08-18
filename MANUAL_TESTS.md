# Flow 1 and Flow 2 — Manual Test Checklist

## Preconditions

```bash
source .venv/bin/activate
PYTHONPATH=src uvicorn intelligent_security.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` or use `curl` for the tests below.

## Flow 1 Manual Tests

### 1. Create an audit

Submit a valid `POST /audits` request using the example in the README.

Expected:

- Response status is `201 Created`.
- Response contains a UUID `id`.
- `state` is `CREATED`.
- `created_at` is UTC.
- `credential_references` contains only the supplied reference, never a credential value.

### 2. Retrieve the audit and event

Call:

```bash
curl http://127.0.0.1:8000/audits/{audit_id}
curl http://127.0.0.1:8000/audits/{audit_id}/events
```

Expected:

- The first call returns the same audit payload.
- The second returns exactly one `audit.created` event.
- The event payload contains only `{ "state": "CREATED" }`.

### 3. Validate invalid input is rejected

Try each of these changes independently:

- Remove `objective`.
- Send `authorized_assets: []`.
- Send `time_budget_seconds: 0`.
- Add an unexpected request property.

Expected: each request returns `422 Unprocessable Entity` and creates no audit.

### 4. Check secret handling

Set `credential_references` to a raw value such as `super-secret-password`.

Expected: the request returns `422`. A valid URI-style reference such as `vault://security/staging-test-account` is accepted.

### 5. Check unknown audit behavior

Call `GET /audits/00000000-0000-0000-0000-000000000000`.

Expected: `404 Not Found`.

### 6. Check persistence across restart

Create an audit, stop the server, start it again with the same `AUDIT_DATABASE_PATH`, then retrieve the audit by ID.

Expected: the audit and `audit.created` event are still available.

## Manual Smoke Test Already Performed

On 18 August 2026, a local loopback server smoke test successfully:

1. Created an audit with `POST /audits` (`201 Created`).
2. Retrieved the audit with `GET /audits/{audit_id}` (`200 OK`).
3. Retrieved its `audit.created` event with `GET /audits/{audit_id}/events` (`200 OK`).

The remaining manual tests focus on input rejection and restart persistence.

## Flow 2 Manual Tests

### 7. Validate an in-scope audit

Create an audit using the README request, then call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/scope/validate
```

Expected:

- Response is `200 OK`.
- Audit state is `SCOPE_VALIDATED`.
- `scope_policy.authorized_assets` contains the normalized hostname.
- `scope_policy.network_allowlist` contains only authorized assets.
- `scope_policy.allowed_operations` contains `web_scan`.
- The event list now contains `audit.created` followed by `scope.validated`.

### 8. Reject an out-of-scope target

Create an audit where the target is `https://unapproved.example.test` but the authorized asset remains `staging.example.test`, then validate it.

Expected:

- Validation returns `422` with code `target_out_of_scope`.
- Fetching the audit returns `SCOPE_REJECTED`.
- The final event is `scope.rejected`.

### 9. Reject expired authorization

Set `authorization.valid_until` to a time in the past and validate the created audit.

Expected: `422` with code `authorization_expired`, then `SCOPE_REJECTED`.

### 10. Check idempotency

Validate a successful audit twice.

Expected: both calls return `200`, the audit remains `SCOPE_VALIDATED`, and only one `scope.validated` event exists.

### 11. Check source-repository boundaries

Create an audit with target type `source_repository`, target and authorized asset `https://github.com/example/security-demo`, and allowed operation `static_analysis`. Validate it.

Expected: `scope_policy.filesystem_boundaries` contains the normalized repository URL and `network_allowlist` is empty.

## Flow 3 Manual Tests

### 12. Profile a validated web target

Create and successfully scope-validate an audit, then call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/profile
```

Expected:

- Response is `200 OK` and state is `TARGET_PROFILED`.
- `target_profile.canonical_identifier` is normalized.
- `interfaces` contains only that canonical identifier.
- `profile_method` is `declared_metadata`.
- `technologies` is empty; this POC flow has not performed active discovery.
- An `target.profiled` event follows `scope.validated`.

### 13. Verify profiling is scope-gated and idempotent

Call the profile endpoint on an audit still in `CREATED`, then call it twice on a `SCOPE_VALIDATED` audit.

Expected:

- The first call returns `409`.
- Both calls for the scope-validated audit return `200`.
- Only one `target.profiled` event exists.

### 14. Profile a source repository

Create a scope-validated `source_repository` audit, then profile it.

Expected: `source_available` is `true`, `network_allowlist` remains empty in the scope policy, and the profile interface is the normalized repository URL.

## Flow 4 Manual Tests

### 15. Discover a compatible capability

Create, scope-validate, and profile a web application audit with `web_scan` authorized. Then call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/capabilities/discover
```

Expected:

- Response is `200 OK` and state is `CAPABILITIES_DISCOVERED`.
- The candidate list contains Nuclei's `web.vulnerability_scan` capability.
- Candidate health is `declared_healthy`; no binary has been executed.
- The event list ends with `capabilities.discovered`.

### 16. Check capability gaps and idempotency

Run the service with an empty plugin-manifest directory, then discover capabilities for an otherwise valid web audit. Also call discovery twice on a normally configured audit.

Expected:

- The empty registry returns no candidates and a `web_scan` gap.
- Repeated discovery returns the stored result and creates only one `capabilities.discovered` event.

### 17. Add a manifest without application changes

Add a JSON file under `src/intelligent_security/plugins/manifests/` following the existing manifest shape, restart the service, and run discovery for a compatible target.

Expected: the new enabled `declared_healthy` capability appears in the ranked candidate list without changing the planner, API, or scheduler code.

## Flow 5 Manual Tests — After Model Details Are Configured

### 18. Verify unconfigured model behavior

Create an audit through capability discovery, then call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/generate
```

Expected before model setup: `503` with code `model_profile_unavailable`. No plan or `plan.proposed` event is created.

### 19. Generate and inspect a plan

After configuring an approved profile and its `env://` credential, call the same endpoint on a capability-discovered audit.

Expected:

- Response is `200 OK` and state is `PLAN_PROPOSED`.
- Every plan step references a discovered capability only.
- Step IDs are unique; dependencies refer only to known steps and contain no cycle.
- The audit event list ends in `plan.proposed`.
- The response contains no credential value.

### 20. Test invalid model output

Use a controlled test model or mock endpoint that returns a plan with an unknown capability, duplicate step ID, unknown dependency, or dependency cycle.

Expected: `422` with the corresponding planning error, while the audit remains `CAPABILITIES_DISCOVERED` and no `plan.proposed` event is emitted.

## Flow 6 Manual Tests

### 21. Validate and auto-approve a compliant plan

After generating a compliant plan for an audit using `human_approval_for_destructive_actions`, call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/validate
```

Expected: `200 OK`, state `PLAN_APPROVED`, a validation summary, and a final `plan.approved` event attributed to `policy-engine`.

### 22. Require and record a human decision

Create an otherwise valid audit with `approval_policy` set to `human_approval_required`, generate the plan, and validate it. Then submit a reviewer decision:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/approval \
  -H 'Content-Type: application/json' \
  -d '{"decision":"reject","reviewed_by":"security@example.test","reason":"Outside the approved maintenance window."}'
```

Expected: validation moves the audit to `PLAN_PENDING_APPROVAL`; the decision moves it to `PLAN_REJECTED` and emits `plan.rejected` with reviewer identity and reason.

### 23. Reject an over-budget plan

Create an audit with a `time_budget_seconds` lower than the chosen capability's declared duration, then generate and validate its plan.

Expected: `200 OK`, state `PLAN_REJECTED`, and a `plan.rejected` event with code `time_budget_exceeded`. The plan must not become executable.

## Flow 7 Manual Tests

### 24. Schedule an approved plan

After Flow 6 reaches `PLAN_APPROVED`, call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/plan/schedule
```

Expected: `200 OK`, state `PLAN_SCHEDULED`, an `execution_schedule`, and a `plan.scheduled` event. Steps without dependencies are `READY`; dependent steps are `PENDING`. No tool is executed.

### 25. Confirm scheduling is approval-gated and idempotent

Call the endpoint before plan approval, then call it twice after approval.

Expected: the first call returns `409`; both later calls return the same persisted schedule and only one `plan.scheduled` event exists.

### 26. Refresh the admitted plugin registry

Set `PLUGIN_REGISTRY_ADMIN_TOKEN` in `.env`, add or disable a manifest in the configured plugin-manifest source, then call:

```bash
curl -X POST http://127.0.0.1:8000/admin/plugins/refresh \
  -H "X-Plugin-Registry-Token: $PLUGIN_REGISTRY_ADMIN_TOKEN"
```

Expected: `200 OK` with a new `snapshot_id`. New Flow 4 discoveries use that snapshot. An incorrect token returns `403`; an invalid or duplicate manifest returns `422` and the prior snapshot remains active.

## Flow 8 Manual Tests

### 27. Verify execution fails closed without a runtime profile

Schedule a `READY` step, then call:

```bash
curl -X POST http://127.0.0.1:8000/audits/{audit_id}/steps/{step_id}/execute
```

Expected: `409` with `capability_unavailable`, a `step.execution_blocked` event, and no tool invocation.

### 28. Verify an approved adapter execution

Configure an operator-approved runtime profile and adapter implementation for the scheduled capability, then call the same endpoint.

Expected: the scheduled step transitions to `SUCCEEDED` or `FAILED`; a plugin execution record includes the resolved plugin/version and adapter; the event is `step.completed` or `step.failed`. Raw logs and artifacts are intentionally deferred to Flow 9.
