# Plugin Author Guide

Plugins extend the audit platform by advertising security capabilities. The planner chooses from the active capability catalog; it does not know or depend on a tool's command line, MCP prompt, endpoint configuration, or credentials.

## Core concepts

- **Plugin**: one security implementation, such as Semgrep, Nuclei, Promptfoo, Garak, or an approved MCP security server.
- **Capability**: a stable action the platform can plan, such as `source.static_analysis`, `web.vulnerability_scan`, or `llm.prompt_injection_test`.
- **Adapter**: trusted core support for invoking a plugin. Supported manifest values are `native`, `container_cli`, `rest`, `restricted_mcp`, and `llm_testing`.
- **Registry snapshot**: the validated, immutable list of active plugin manifests. New discoveries and plans use the current snapshot after an operator refresh.

Adding a plugin that uses an existing adapter is manifest/configuration work. Adding a completely new transport requires a new trusted adapter implementation; it does not require changes to planning, approval, or scheduling.

## Add a plugin

1. Confirm the tool is authorized for use and can be invoked through an existing adapter.
2. Create a JSON manifest in `src/intelligent_security/plugins/manifests/`.
3. Use a unique `plugin_id` and declare one or more versioned capabilities.
4. Do not place API keys, passwords, shell commands, arbitrary executable paths, or raw MCP instructions in the manifest.
5. Refresh the registry with an authorized operator token.
6. Create a new audit and run capability discovery to confirm the capability is available.

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

## Disable or remove a plugin

To temporarily remove a plugin from new discoveries, set its `enabled` field to `false` and refresh the registry.

To remove it completely, delete its manifest from the approved manifest source and refresh the registry. Remove the tool's external runtime/configuration through the normal operator deployment process; this application never performs uninstall actions.

Existing audit plans and schedules retain capability requirements, not plugin IDs. During future execution, the resolver may select another healthy plugin that implements the same capability contract. If none is available, execution must return a capability gap for replanning rather than invoke a removed tool.

## Validate a change

After refresh, create a new audit through capability discovery. Confirm that:

- The new capability is present only for compatible target types and authorized operations.
- Disabled or removed capabilities no longer appear.
- The planner can choose the capability, but its model context does not expose plugin IDs, commands, credentials, or adapter details.
- A duplicate or invalid manifest does not replace the prior registry snapshot.

See `MANUAL_TESTS.md` in the repository root for the registry-refresh test procedure.
