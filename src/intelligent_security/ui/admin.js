/**
 * Intelligent Security · Internal System & Plugins Console Controller
 */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

let allPlugins = [];
let allModels = [];
let currentFilter = "all";
let currentSearch = "";

// --- Theme Management ---
function initTheme() {
  const savedTheme = localStorage.getItem("security-audit-theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);

  const toggleBtn = $("#theme-toggle");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("security-audit-theme", next);
    });
  }
}

// --- Toast & Copy ---
function toast(message, error = false) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = message;
  el.className = error ? "toast error" : "toast";
  el.style.display = "block";
  setTimeout(() => {
    el.style.display = "none";
  }, 4000);
}

function copyToClipboard(text, label = "Copied to clipboard") {
  navigator.clipboard.writeText(text).then(() => {
    toast(label);
  }).catch(() => {
    toast("Failed to copy", true);
  });
}

function esc(value = "") {
  const e = document.createElement("span");
  e.textContent = String(value);
  return e.innerHTML;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail?.message || body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

// --- Tab Navigation ---
function initTabs() {
  $$(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab-btn").forEach((b) => b.classList.remove("active"));
      $$(".tab-pane").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPane = $(`#${targetId}`);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// --- Filter & Search ---
function initFilters() {
  $$(".filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      $$(".filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      currentFilter = pill.getAttribute("data-filter");
      renderPlugins();
    });
  });

  const searchInput = $("#plugin-search");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentSearch = e.target.value.toLowerCase().trim();
      renderPlugins();
    });
  }
}

// --- Data Fetching ---
async function loadSummary() {
  try {
    const summary = await api("/admin/summary");
    $("#kpi-active-plugins").textContent = summary.active_plugins;
    $("#kpi-total-plugins").textContent = `/ ${summary.total_plugins} total`;
    $("#kpi-capabilities").textContent = summary.total_capabilities;
    $("#kpi-models").textContent = summary.total_model_profiles;
    $("#kpi-snapshot").textContent = summary.snapshot_id;
  } catch (err) {
    console.error("Summary error:", err);
  }
}

async function loadPlugins() {
  try {
    const data = await api("/admin/plugins");
    allPlugins = data.plugins || [];
    $("#tab-plugins-count").textContent = allPlugins.length;
    renderPlugins();
  } catch (err) {
    $("#plugins-grid").innerHTML = `<p class="muted error">Failed to load plugins: ${esc(err.message)}</p>`;
  }
}

async function loadModelProfiles() {
  try {
    const data = await api("/admin/model-profiles");
    allModels = data.profiles || [];
    $("#tab-models-count").textContent = allModels.length;
    renderModelProfiles(data.profiles, data.assignments);
  } catch (err) {
    $("#models-grid").innerHTML = `<p class="muted error">Failed to load model profiles: ${esc(err.message)}</p>`;
  }
}

// --- Plugin Card Rendering ---
function renderPlugins() {
  const container = $("#plugins-grid");
  if (!container) return;

  const filtered = allPlugins.filter((plugin) => {
    // Filter pills
    if (currentFilter === "active" && !plugin.is_active) return false;
    if (currentFilter === "cli" && !plugin.cli?.available) return false;
    if (currentFilter === "docker" && !plugin.docker?.available) return false;
    if (currentFilter === "disabled" && plugin.is_active) return false;
    if (currentFilter === "native" && plugin.kind !== "native_security_tool") return false;
    if (currentFilter === "llm" && plugin.kind !== "llm_testing_framework") return false;

    // Text search
    if (currentSearch) {
      const matchName = plugin.plugin_id.toLowerCase().includes(currentSearch);
      const matchKind = plugin.kind.toLowerCase().includes(currentSearch);
      const matchAdapter = plugin.adapter.toLowerCase().includes(currentSearch);
      const matchCli = plugin.cli?.binary_path?.toLowerCase().includes(currentSearch);
      const matchCap = plugin.capabilities.some(
        (c) =>
          c.capability.toLowerCase().includes(currentSearch) ||
          c.description.toLowerCase().includes(currentSearch) ||
          c.target_types.some((t) => t.toLowerCase().includes(currentSearch))
      );
      if (!matchName && !matchKind && !matchAdapter && !matchCli && !matchCap) return false;
    }

    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="panel empty-panel" style="padding:36px"><p class="muted">No plugins match the selected filter or search query.</p></div>`;
    return;
  }

  container.innerHTML = filtered.map((plugin) => renderPluginCard(plugin)).join("");

  // Attach copy listeners
  container.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const text = btn.getAttribute("data-copy");
      copyToClipboard(text, "Copied to clipboard!");
    });
  });
}

function renderPluginCard(plugin) {
  const runtime = plugin.runtime_profile;
  const cli = plugin.cli;
  const docker = plugin.docker;

  // Status Badge
  let statusBadge = "";
  if (!plugin.manifest_enabled) {
    statusBadge = `<span class="badge badge-danger">MANIFEST DISABLED</span>`;
  } else if (plugin.execution_mode === "hybrid") {
    statusBadge = `<span class="badge badge-success">ACTIVE · CLI & DOCKER</span>`;
  } else if (plugin.execution_mode === "host_cli") {
    statusBadge = `<span class="badge badge-success">ACTIVE · HOST CLI</span>`;
  } else if (plugin.execution_mode === "docker") {
    statusBadge = `<span class="badge badge-success">ACTIVE · DOCKER CONTAINER</span>`;
  } else if (plugin.is_active) {
    statusBadge = `<span class="badge badge-success">ACTIVE</span>`;
  } else {
    statusBadge = `<span class="badge badge-muted">STANDBY / NO RUNTIME</span>`;
  }

  const kindLabel = plugin.kind === "native_security_tool" ? "Native Security Tool" : plugin.kind === "llm_testing_framework" ? "LLM Testing Framework" : plugin.kind;

  // Capabilities HTML
  const capsHtml = plugin.capabilities
    .map((cap) => {
      const targetPills = cap.target_types
        .map((t) => `<span class="tag-pill tag-target">${esc(t)}</span>`)
        .join(" ");

      const validationBadge = cap.validation_for?.length
        ? `<div class="cap-validation">Validates: ${cap.validation_for.map((v) => `<code>${esc(v)}</code>`).join(", ")}</div>`
        : "";

      return `
        <div class="capability-item">
          <div class="cap-header">
            <div class="cap-title-wrap">
              <span class="cap-name">${esc(cap.capability)}</span>
              <span class="tag-pill tag-op">${esc(cap.required_operation)}</span>
            </div>
            <div class="cap-metrics">
              <span class="cap-metric" title="Reliability score">★ ${Math.round(cap.reliability * 100)}%</span>
              <span class="cap-metric" title="Estimated duration">⏱ ${cap.estimated_duration_seconds}s</span>
              <span class="cap-metric" title="Estimated cost">💵 $${cap.estimated_cost_usd}</span>
            </div>
          </div>
          <p class="cap-desc">${esc(cap.description)}</p>
          <div class="cap-targets">${targetPills}</div>
          ${validationBadge}
        </div>
      `;
    })
    .join("");

  // Allowed Hosts
  let hostsHtml = `<span class="text-dim">None configured</span>`;
  if (runtime?.allowed_target_hosts?.length) {
    hostsHtml = runtime.allowed_target_hosts
      .map((h) => `<span class="tag-pill tag-host">${esc(h)}</span>`)
      .join(" ");
  }

  // Host CLI box HTML
  const cliBoxHtml = cli?.available
    ? `
      <div class="runtime-config-box cli-ready-box">
        <div class="runtime-row">
          <div style="display:flex;align-items:center;gap:8px">
            <span class="badge badge-success" style="font-size:11px">💻 Host CLI Binary Ready</span>
            <span class="runtime-value-code">
              <code>${esc(cli.binary_path)}</code>
              <button class="copy-btn icon-btn-sm" data-copy="${esc(cli.binary_path)}" title="Copy binary path">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            </span>
          </div>
          <span class="badge badge-info" style="font-size:10px">Local Executable</span>
        </div>
      </div>
    `
    : `
      <div class="runtime-config-box box-missing" style="padding:8px 12px">
        <span class="text-dim" style="font-size:11.5px">💻 Host CLI binary <code>${esc(cli?.binary_name || plugin.plugin_id)}</code> not found in system PATH.</span>
      </div>
    `;

  // Docker Runtime box HTML
  const dockerBoxHtml = runtime
    ? `
      <div class="runtime-config-box">
        <div class="runtime-row">
          <span class="runtime-label">🐳 Container Image:</span>
          <div class="runtime-value-code">
            <code>${esc(runtime.image_reference || runtime.runtime_reference)}</code>
            <button class="copy-btn icon-btn-sm" data-copy="${esc(runtime.image_reference || runtime.runtime_reference)}" title="Copy image reference">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          </div>
        </div>
        <div class="runtime-meta-grid">
          <div>
            <span class="runtime-label">Runtime Reference:</span>
            <div class="runtime-value"><code>${esc(runtime.runtime_reference)}</code></div>
          </div>
          <div>
            <span class="runtime-label">Max Runtime:</span>
            <div class="runtime-value">${runtime.max_runtime_seconds}s (${Math.round(runtime.max_runtime_seconds / 60)} min)</div>
          </div>
        </div>
        <div class="runtime-hosts-row">
          <span class="runtime-label">Allowed Target Hosts:</span>
          <div class="hosts-container">${hostsHtml}</div>
        </div>
      </div>
    `
    : `
      <div class="runtime-config-box box-missing">
        <p class="text-dim">No Docker runtime profile configured in <code>config/plugin_runtimes.json</code>.</p>
      </div>
    `;

  return `
    <div class="panel plugin-card">
      <div class="plugin-header">
        <div class="plugin-identity">
          <div class="plugin-icon-box">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
              <polyline points="2 17 12 22 22 17"></polyline>
              <polyline points="2 12 12 17 22 12"></polyline>
            </svg>
          </div>
          <div>
            <div class="plugin-title-row">
              <h3 class="plugin-id">${esc(plugin.plugin_id)}</h3>
              <span class="version-tag">v${esc(plugin.plugin_version)}</span>
              ${statusBadge}
            </div>
            <div class="plugin-meta-row">
              <span>${esc(kindLabel)}</span>
              <span class="meta-separator">·</span>
              <span>Adapter: <code>${esc(plugin.adapter)}</code></span>
              <span class="meta-separator">·</span>
              <span class="badge badge-info" style="font-size:9.5px">${esc(plugin.health)}</span>
            </div>
          </div>
        </div>

        <div class="plugin-specs-badges">
          <span class="spec-badge ${plugin.has_execution_spec ? 'spec-active' : 'spec-missing'}" title="execution.json mount specification">
            ${plugin.has_execution_spec ? '✓ Execution Spec' : '✕ No Execution Spec'}
          </span>
          <span class="spec-badge ${plugin.has_normalizer_spec ? 'spec-active' : 'spec-missing'}" title="normalizer.json schema specification">
            ${plugin.has_normalizer_spec ? '✓ Normalizer Spec' : '✕ No Normalizer Spec'}
          </span>
        </div>
      </div>

      <!-- Execution Modes Breakdown -->
      <div class="execution-modes-container">
        ${cliBoxHtml}
        ${dockerBoxHtml}
      </div>

      <!-- Capabilities Section -->
      <div class="capabilities-section">
        <div class="capabilities-header">
          <span class="eyebrow">DECLARED CAPABILITIES (${plugin.capability_count})</span>
        </div>
        <div class="capabilities-list">
          ${capsHtml}
        </div>
      </div>
    </div>
  `;
}

// --- Model Profiles & Intelligence Routing Rendering ---
function renderModelProfiles(profiles, assignments) {
  // 1. Render Intelligence Purpose Matrix
  const routingContainer = $("#routing-grid");
  if (routingContainer && assignments) {
    const purposeMeta = {
      audit_planning: {
        title: "Audit Planning",
        desc: "Synthesizes target profiles and admitted plugin capabilities into executable audit plans.",
        icon: "polygon",
      },
      evidence_normalization: {
        title: "Evidence Normalization",
        desc: "Transforms raw plugin stdout, stderr, and JSON artifacts into validated security observations.",
        icon: "circle",
      },
      finding_correlation: {
        title: "Finding Correlation",
        desc: "Aggregates observations across multiple plugins to deduplicate and validate candidate vulnerabilities.",
        icon: "polyline",
      },
      report_generation: {
        title: "Report Generation",
        desc: "Compiles evidence-backed findings into executive summaries and structured JSON / Markdown deliverables.",
        icon: "file-text",
      },
    };

    routingContainer.innerHTML = Object.entries(assignments)
      .map(([purpose, data]) => {
        const meta = purposeMeta[purpose] || { title: purpose, desc: "" };
        const isResolved = data.status === "resolved";

        return `
          <div class="panel routing-card">
            <div class="routing-card-header">
              <span class="eyebrow">${esc(purpose.toUpperCase().replace(/_/g, " "))}</span>
              <span class="badge ${isResolved ? 'badge-success' : 'badge-warning'}">${isResolved ? 'ACTIVE' : 'FALLBACK'}</span>
            </div>
            <h4>${esc(meta.title)}</h4>
            <p class="routing-desc">${esc(meta.desc)}</p>
            <div class="routing-assigned">
              <span class="routing-label">Assigned Model:</span>
              <div class="assigned-model-pill">
                <strong>${esc(data.model || "Fallback / Default")}</strong>
                ${data.profile_id ? `<span class="tag-pill tag-target">${esc(data.profile_id)}</span>` : ""}
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  }

  // 2. Render Model Profiles List
  const modelsContainer = $("#models-grid");
  if (modelsContainer) {
    if (!profiles?.length) {
      modelsContainer.innerHTML = `<div class="panel empty-panel"><p class="muted">No model profiles configured in config/model_profiles.json.</p></div>`;
      return;
    }

    modelsContainer.innerHTML = profiles
      .map((model) => {
        return `
          <div class="panel model-card">
            <div class="model-card-header">
              <div class="model-identity">
                <div class="model-icon-box">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                    <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                    <line x1="12" y1="22.08" x2="12" y2="12"></line>
                  </svg>
                </div>
                <div>
                  <div class="model-title-row">
                    <h3>${esc(model.profile_id)}</h3>
                    <span class="badge ${model.enabled ? 'badge-success' : 'badge-muted'}">${model.enabled ? 'ENABLED' : 'DISABLED'}</span>
                    ${model.default_for_purpose ? '<span class="badge badge-accent">DEFAULT</span>' : ''}
                  </div>
                  <div class="model-sub">
                    <span>Purpose: <code>${esc(model.purpose)}</code></span>
                    <span class="meta-separator">·</span>
                    <span>Provider: <strong>${esc(model.provider)}</strong></span>
                  </div>
                </div>
              </div>
            </div>

            <div class="model-details-grid">
              <div class="model-detail-item">
                <span class="detail-label">Model Identifier:</span>
                <div class="detail-value"><code>${esc(model.model)}</code></div>
              </div>
              <div class="model-detail-item">
                <span class="detail-label">Base URL Endpoint:</span>
                <div class="detail-value"><code>${esc(model.base_url || "Default Provider URL")}</code></div>
              </div>
              <div class="model-detail-item">
                <span class="detail-label">Credential Reference:</span>
                <div class="detail-value"><code>${esc(model.credential_reference || "None (hermetic/local)")}</code></div>
              </div>
              <div class="model-detail-item">
                <span class="detail-label">Inference Parameters:</span>
                <div class="params-row">
                  <span class="tag-pill tag-param">Temp: ${model.temperature ?? "Default"}</span>
                  <span class="tag-pill tag-param">Max Tokens: ${model.max_output_tokens ?? "Default"}</span>
                  <span class="tag-pill tag-param">Timeout: ${model.timeout_seconds ? model.timeout_seconds + "s" : "Default"}</span>
                </div>
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  }
}

// --- App Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initTabs();
  initFilters();

  loadSummary();
  loadPlugins();
  loadModelProfiles();

  // API Health check
  const connText = $("#connection");
  const connDot = $(".status-dot");
  api("/health")
    .then(() => {
      if (connText) connText.textContent = "API connected";
      if (connDot) connDot.classList.add("active");
    })
    .catch(() => {
      if (connText) connText.textContent = "API unavailable";
    });
});
