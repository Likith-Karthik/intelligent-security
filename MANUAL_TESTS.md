# Flow 1 — Manual Test Checklist

## Preconditions

```bash
source .venv/bin/activate
PYTHONPATH=src uvicorn intelligent_security.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` or use `curl` for the tests below.

## Required Manual Tests

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
