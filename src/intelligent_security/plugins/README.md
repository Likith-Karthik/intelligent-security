# Plugin Author Guide

Plugins extend the audit platform by advertising security capabilities. The planner chooses from the active capability catalog; it does not know or depend on a tool's command line, MCP prompt, endpoint configuration, credentials, container image, or package files.

## Core concepts

- **Plugin package**: one removable directory under `plugins/packages/<plugin-id>/`. It contains a public `manifest.json`, and may contain a trusted `execution.json`, `normalizer.json`, plus templates or other package assets.
- **Capability**: a stable action the platform can plan, such as `source.static_analysis`, `web.vulnerability_scan`, or `llm.prompt_injection_test`.
- **Adapter**: trusted core support for invoking a plugin. Supported manifest values are `native`, `container_cli`, `rest`, `restricted_mcp`, and `llm_testing`.
- **Registry snapshot**: the validated, immutable list of active plugin manifests. New discoveries and plans use the current snapshot after an operator refresh.

Adding a plugin that uses an existing adapter is manifest/configuration work. Adding a completely new transport requires a new trusted adapter implementation; it does not require changes to planning, approval, or scheduling.

## Add a plugin

1. Confirm the tool is authorized for use and can be invoked through an existing adapter.
2. Create `src/intelligent_security/plugins/packages/<plugin-id>/manifest.json`.
3. Use a unique `plugin_id` and declare one or more versioned capabilities.
4. Do not place API keys, passwords, shell commands, arbitrary executable paths, or raw MCP instructions in the manifest.
5. For an executable package, add a package-owned `execution.json` for an existing adapter and a matching operator-managed runtime profile in `config/plugin_runtimes.json`.
6. To expose tool results to later finding workflows, add a declarative `normalizer.json`. It supplies parsing hints for the AI observation-normalization stage; do not add plugin-specific semantic logic to the core service.

## Package normalizer specification

`normalizer.json` is admitted with the package and is never provided to the planner. It describes the expected artifact format and optional field hints for the bounded AI normalization prompt. The model's structured output is accepted only after deterministic schema, scope, checksum, and evidence-reference validation. Unknown tool fields may be retained as bounded `tool_metadata`.

```json
{
  "input_artifact_kind": "stdout",
  "input_format": "jsonl",
  "fields": {
    "category": {"path": "type", "default": "vulnerability"},
    "title": {"path": "info.name", "default": "Tool observation"},
    "affected_asset": {"path": "host"},
    "severity_reported": {"path": "info.severity"},
    "confidence": {"default": 0.7}
  }
}
```

Run `POST /audits/{audit_id}/evidence/{evidence_id}/normalize` after Flow 9 capture. An unavailable model or invalid model output is recorded as a normalization failure, but immutable raw evidence is retained. Query common observations with `GET /audits/{audit_id}/observations`.

## Validation capabilities

A capability may declare `validation_for` with the capability contracts it can safely re-check. This lets Flow 11 propose a compatible validation capability after correlation without embedding a plugin name in the finding logic:

```json
{
  "capability": "web.vulnerability.validate",
  "validation_for": ["web.vulnerability_scan"],
  "required_operation": "web_scan"
}
```

The proposal is not an invocation. It must become a separately approved plan step before Flow 8 can execute it.
6. Refresh the registry with an authorized operator token.
7. Create a new audit and run capability discovery to confirm the capability is available.

Example: LLM testing plugin using the LLM-testing adapter.

```json
{
  "plugin_id": "example-llm-tester",
  "plugin_version": "1.0.0",
  "kind": "llm_testing_framework",
  "adapter": "llm_testing",
  "enabled": true,
  "health": "declared_healthy",
  "capabilities": [
    {
      "capability": "llm.prompt_injection_test",
      "contract_version": "1",
      "description": "Test an authorized LLM application for prompt-injection resistance.",
      "target_types": ["llm_application"],
      "required_operation": "llm_red_team",
      "required_inputs": ["target_profile", "scope_policy"],
      "estimated_duration_seconds": 900,
      "estimated_cost_usd": 5,
      "reliability": 0.8,
      "input_schema": "policy-controlled/v1",
      "output_schema": "finding-batch/v1"
    }
  ]
}
```

An MCP-backed plugin uses `"adapter": "restricted_mcp"`; its server connection details must be held in operator-managed adapter configuration, not in the manifest.

## Package execution specification

`execution.json` is admitted with the package but is never supplied to the planner. It declares only fixed arguments, package-local read-only mounts, and the required validated target form. Set `target_input` to `url` for `{{target.url}}`, or `hostname` for `{{target.hostname}}`; the generic adapter supplies only that declared value. A package cannot provide a shell command, executable path, credentials, network allowlist, or container image.

```json
{
  "adapter": "container_cli",
  "target_input": "url",
  "arguments": ["-u", "{{target.url}}", "-t", "/app/templates/safe.yaml"],
  "mounts": [{"source": "templates", "target": "/app/templates", "read_only": true}],
  "output_format": "jsonl"
}
```

The runtime profile maps the package ID to the already-approved image or service runtime. This keeps deployment-specific values outside Git while allowing a package to be added or removed without modifying core planning, policy, scheduling, or execution code.

## Manifest reference

| Field | Required | Meaning |
| --- | --- | --- |
| `plugin_id` | Yes | Globally unique, stable plugin identifier. |
| `plugin_version` | Yes | Plugin implementation version. |
| `kind` | No | Descriptive category only; it does not change core behavior. |
| `adapter` | No | Invocation mechanism: `native`, `container_cli`, `rest`, `restricted_mcp`, or `llm_testing`. Defaults to `container_cli`. |
| `enabled` | No | Whether the plugin is eligible for discovery. Defaults to `true`. |
| `health` | No | POC declared health: `declared_healthy` or `declared_unhealthy`. |
| `capabilities` | Yes | At least one capability definition. |

Each capability must include `capability`, `description`, `target_types`, `required_operation`, `estimated_duration_seconds`, `estimated_cost_usd`, and `reliability`. `contract_version`, `required_inputs`, `input_schema`, and `output_schema` have safe defaults but should be stated explicitly for production plugins.

`required_operation` must be one of: `static_analysis`, `web_scan`, `port_discovery`, `llm_red_team`, `exploit`, or `destructive_action`. Scope policy filters out any capability the audit is not authorized to use.

## Refresh the registry

Set `PLUGIN_REGISTRY_ADMIN_TOKEN` in the service environment, then refresh after manifest changes:

```bash
curl -X POST http://127.0.0.1:8000/admin/plugins/refresh \
  -H "X-Plugin-Registry-Token: $PLUGIN_REGISTRY_ADMIN_TOKEN"
```

The refresh validates every manifest and atomically creates a new snapshot. If any manifest is invalid or two manifests use the same `plugin_id`, refresh returns `422` and the earlier snapshot stays active. A missing or invalid token is rejected. The refresh does not install software, run plugin commands, download dependencies, or accept arbitrary executable paths.

## Configure the runtime

The manifest advertises a plugin; a local runtime profile permits a particular already-installed implementation to be selected for execution. Start from `config/plugin_runtimes.example.json`:

```json
{
  "plugins": [
    {
      "plugin_id": "nuclei",
      "adapter": "container_cli",
      "runtime_reference": "container-config://nuclei-approved-runtime",
      "image_reference": "projectdiscovery/nuclei@sha256:approved-image-digest",
      "allowed_target_hosts": ["authorized.example.com"],
      "enabled": true
    }
  ]
}
```

`runtime_reference` is an opaque reference to deployment-managed adapter configuration. It is not a command, Git URL, image name, secret, or MCP prompt. `allowed_target_hosts` is mandatory in practice for network-capable plugins: the runtime is not selected unless the validated audit target hostname exactly matches this list. A runtime profile must also match both the manifest `plugin_id` and `adapter`; otherwise it is excluded during capability discovery and the planner never sees it.

Each executable package declares its required policy-controlled target form in `execution.json`: `"target_input": "url"` (the full validated HTTPS URL) or `"target_input": "hostname"` (the validated hostname). Its arguments may use only the matching placeholder, `{{target.url}}` or `{{target.hostname}}`. This is private adapter configuration: the planner receives neither the placeholder nor runtime allowlists, only capabilities that are executable for the audit target.

## Disable or remove a plugin

To temporarily remove a plugin from new discoveries, set its `enabled` field to `false` and refresh the registry.

To remove it completely, delete its package directory from the approved plugin source and refresh the registry. Remove the tool's external runtime/configuration through the normal operator deployment process; this application never performs uninstall actions.

Existing audit plans and schedules retain capability requirements, not plugin IDs. During future execution, the resolver may select another healthy plugin that implements the same capability contract. If none is available, execution must return a capability gap for replanning rather than invoke a removed tool.

## Validate a change

After refresh, create a new audit through capability discovery. Confirm that:

- The new capability is present only for compatible target types and authorized operations.
- Disabled or removed capabilities no longer appear.
- The planner can choose the capability, but its model context does not expose plugin IDs, commands, credentials, or adapter details.
- A duplicate or invalid manifest does not replace the prior registry snapshot.

See `MANUAL_TESTS.md` in the repository root for the registry-refresh test procedure.
