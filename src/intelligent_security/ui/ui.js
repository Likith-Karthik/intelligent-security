/**
 * Intelligent Security · Operator Console Controller
 */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

let audit = null;
let selectedAuditId = null;
let automationMode = localStorage.getItem("security-audit-automation") || "running";
let inFlight = false;
let driveTimer = null;

const routes = {
  CREATED: ["Validate scope", "/scope/validate"],
  SCOPE_VALIDATED: ["Profile target", "/profile"],
  TARGET_PROFILED: ["Discover capabilities", "/capabilities/discover"],
  CAPABILITIES_DISCOVERED: ["Generate AI plan", "/plan/generate"],
  PLAN_PROPOSED: ["Validate AI plan", "/plan/validate"],
  PLAN_APPROVED: ["Schedule plan", "/plan/schedule"],
};

const STAGES = [
  "CREATED",
  "SCOPE_VALIDATED",
  "TARGET_PROFILED",
  "CAPABILITIES_DISCOVERED",
  "PLAN_PROPOSED",
  "PLAN_APPROVED",
  "PLAN_SCHEDULED"
];

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

// --- Utilities ---
function toast(message, error = false) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = message;
  el.className = error ? "toast error" : "toast";
  el.style.display = "block";
  setTimeout(() => {
    el.style.display = "none";
  }, 5000);
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
  return response.headers.get("content-type")?.includes("application/json")
    ? response.json()
    : response.text();
}

function esc(value = "") {
  const e = document.createElement("span");
  e.textContent = String(value);
  return e.innerHTML;
}

function scopeAsset(identifier, targetType) {
  if (targetType === "network_host" || targetType === "source_repository") return identifier;
  try {
    const url = new URL(identifier);
    if (!/^https?:$/.test(url.protocol)) throw new Error();
    return url.hostname;
  } catch (_) {
    throw new Error("Web, repository, and LLM targets must use a valid HTTP or HTTPS URL.");
  }
}

function setAutomation(mode, message) {
  automationMode = mode;
  localStorage.setItem("security-audit-automation", mode);
  const statusEl = $("#automation-status");
  if (statusEl && message) statusEl.textContent = message;
}

function scheduleDrive() {
  clearTimeout(driveTimer);
  if (automationMode === "running") {
    driveTimer = setTimeout(drive, 300);
  }
}

// --- Status Badge Stylers ---
function getStatusBadge(status) {
  const s = String(status).toUpperCase();
  if (["SUCCEEDED", "COMPLETED", "APPROVED", "VALIDATED", "CONFIRMED"].includes(s)) {
    return `<span class="badge badge-success">${esc(s)}</span>`;
  }
  if (["READY", "PROPOSED", "RUNNING"].includes(s)) {
    return `<span class="badge badge-accent">${esc(s)}</span>`;
  }
  if (["PENDING", "PENDING_APPROVAL", "VALIDATION_PENDING", "RETEST_PENDING"].includes(s)) {
    return `<span class="badge badge-warning">${esc(s)}</span>`;
  }
  if (["FAILED", "REJECTED", "SCOPE_REJECTED", "PLAN_REJECTED", "CRITICAL", "HIGH"].includes(s)) {
    return `<span class="badge badge-danger">${esc(s)}</span>`;
  }
  if (["MEDIUM"].includes(s)) {
    return `<span class="badge badge-warning">${esc(s)}</span>`;
  }
  if (["LOW", "INFO"].includes(s)) {
    return `<span class="badge badge-info">${esc(s)}</span>`;
  }
  return `<span class="badge badge-muted">${esc(s)}</span>`;
}

// --- Stepper Updater ---
function updateStepper(currentState) {
  const currentIndex = STAGES.indexOf(currentState);
  $$(".pipeline-step").forEach((el) => {
    const stage = el.getAttribute("data-stage");
    const stageIndex = STAGES.indexOf(stage);
    el.classList.remove("completed", "active");
    if (stageIndex < currentIndex) {
      el.classList.add("completed");
    } else if (stageIndex === currentIndex) {
      el.classList.add("active");
    }
  });
}

// --- Main Render Function ---
function render() {
  const visible = Boolean(audit);
  const contentEl = $("#audit-content");
  const emptyEl = $("#empty-state");
  if (contentEl) contentEl.hidden = !visible;
  if (emptyEl) emptyEl.hidden = visible;

  if (!audit) return;

  // Header & Info
  const idInput = $("#audit-id");
  if (idInput && document.activeElement !== idInput) idInput.value = audit.id;

  const nameEl = $("#audit-name");
  if (nameEl) nameEl.textContent = audit.name || "Audit Engagement";

  const targetEl = $("#audit-target");
  if (targetEl) targetEl.textContent = `${audit.target.target_type} · ${audit.target.identifier}`;

  const stateEl = $("#audit-state");
  if (stateEl) stateEl.textContent = audit.state;

  const badgeEl = $("#lifecycle-badge");
  if (badgeEl) badgeEl.textContent = audit.state;

  updateStepper(audit.state);

  const route = routes[audit.state];
  const readyStep =
    audit.state === "PLAN_SCHEDULED"
      ? audit.execution_schedule?.steps.find((step) => step.status === "READY")
      : null;
  const blocked =
    audit.state === "PLAN_PENDING_APPROVAL" ||
    audit.state === "PLAN_REJECTED" ||
    audit.state === "SCOPE_REJECTED";
  const complete =
    audit.state === "PLAN_SCHEDULED" &&
    !readyStep &&
    audit.execution_schedule?.steps.every((step) => step.status === "SUCCEEDED");

  let statusText = "Waiting for a runnable stage.";
  if (automationMode === "paused") {
    statusText = "Paused. Current operation will finish, but no new step will begin.";
  } else if (automationMode === "exited") {
    statusText = "Exited. The audit state is preserved and can be restarted.";
  } else if (blocked) {
    statusText = "Automation stopped: Requires manual approval or was rejected by policy.";
  } else if (complete) {
    statusText = "All scheduled capabilities and plugins completed execution.";
  } else if (inFlight) {
    statusText = "Autonomous agent is executing the current pipeline stage…";
  } else if (route) {
    statusText = `Next queued action: ${route[0]}.`;
  } else if (readyStep) {
    statusText = `Next queued action: Execute step ${readyStep.plan_step_id}.`;
  }

  const autoStatusEl = $("#automation-status");
  if (autoStatusEl) autoStatusEl.textContent = statusText;

  const offensiveStatusEl = $("#offensive-status");
  if (offensiveStatusEl) offensiveStatusEl.textContent = "Offensive actions: disabled in this POC.";

  const pauseBtn = $("#pause");
  const exitBtn = $("#exit");
  const restartBtn = $("#restart");
  if (pauseBtn) pauseBtn.disabled = automationMode !== "running";
  if (exitBtn) exitBtn.disabled = automationMode === "exited";
  if (restartBtn) restartBtn.disabled = automationMode === "running";

  // Actions Container
  const actionsEl = $("#actions");
  if (actionsEl) {
    if (route) {
      actionsEl.innerHTML = `<span class="badge badge-accent">NEXT: ${esc(route[0])}</span>`;
    } else if (readyStep) {
      actionsEl.innerHTML = `<span class="badge badge-accent">NEXT: Execute ${esc(readyStep.plan_step_id)}</span>`;
    } else if (complete) {
      actionsEl.innerHTML = `<span class="badge badge-success">ALL STEPS COMPLETED</span>`;
    } else {
      actionsEl.innerHTML = "";
    }
  }

  // Plan Rendering
  const planSteps = audit.audit_plan?.steps || [];
  const planCountEl = $("#plan-count");
  if (planCountEl) planCountEl.textContent = `${planSteps.length} step${planSteps.length === 1 ? "" : "s"}`;

  const planEl = $("#plan");
  if (planEl) {
    if (planSteps.length) {
      planEl.innerHTML = planSteps
        .map(
          (step) => `
        <div class="item-card">
          <div class="item-header">
            <span class="item-title">${esc(step.id)} · ${esc(step.capability)}</span>
            <span class="badge badge-muted">Step</span>
          </div>
          <div class="item-meta">
            ${esc(step.reason || "Planned capability")}
            ${step.depends_on?.length ? `<br/><span style="color:var(--text-dim)">Depends on: ${esc(step.depends_on.join(", "))}</span>` : ""}
          </div>
        </div>`
        )
        .join("");
    } else {
      planEl.innerHTML = '<p class="muted">No plan generated.</p>';
    }
  }

  // Schedule & Execution Rendering
  const schedSteps = audit.execution_schedule?.steps || [];
  const schedCountEl = $("#schedule-count");
  if (schedCountEl) schedCountEl.textContent = `${schedSteps.length} step${schedSteps.length === 1 ? "" : "s"}`;

  const schedEl = $("#schedule");
  if (schedEl) {
    if (schedSteps.length) {
      schedEl.innerHTML = schedSteps
        .map(
          (step) => `
        <div class="item-card">
          <div class="item-header">
            <span class="item-title">${esc(step.plan_step_id)}</span>
            ${getStatusBadge(step.status)}
          </div>
          <div class="item-meta">
            Capability: <strong>${esc(step.capability)}</strong> · ${step.estimated_duration_seconds}s · $${step.estimated_cost_usd}
          </div>
        </div>`
        )
        .join("");
    } else {
      schedEl.innerHTML = '<p class="muted">No scheduled steps.</p>';
    }
  }

  // Findings Rendering
  const findings = audit.candidate_findings || [];
  const findingsCountEl = $("#findings-count");
  if (findingsCountEl) findingsCountEl.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;

  const findingsEl = $("#findings");
  if (findingsEl) {
    if (findings.length) {
      findingsEl.innerHTML = findings
        .map(
          (finding) => `
        <div class="item-card">
          <div class="item-header">
            <span class="item-title">${esc(finding.title || finding.finding_id)}</span>
            <div style="display:flex;gap:4px">
              ${getStatusBadge(finding.severity || "INFO")}
              ${getStatusBadge(finding.state)}
            </div>
          </div>
          <div class="item-meta">
            ${esc(finding.description || "Awaiting secondary validation")}
          </div>
        </div>`
        )
        .join("");
    } else {
      findingsEl.innerHTML = '<p class="muted">No findings detected yet.</p>';
    }
  }

  loadEvents();
}

// --- Events Timeline Loader ---
async function loadEvents() {
  if (!audit) return;
  const auditId = audit.id;
  try {
    const events = await api(`/audits/${auditId}/events`);
    if (selectedAuditId !== auditId) return;
    
    const countEl = $("#events-count");
    if (countEl) countEl.textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;

    const eventsEl = $("#events");
    if (eventsEl) {
      if (events.length) {
        eventsEl.innerHTML = events
          .slice()
          .reverse()
          .map(
            (event) => `
          <div class="item-card">
            <div class="item-header">
              <span class="item-title">${esc(event.event_type)}</span>
              <span class="badge badge-muted">${new Date(event.occurred_at).toLocaleTimeString()}</span>
            </div>
            <div class="item-meta" style="color:var(--text-dim);font-family:var(--font-mono);font-size:11px">
              ${new Date(event.occurred_at).toLocaleDateString()}
            </div>
          </div>`
          )
          .join("");
      } else {
        eventsEl.innerHTML = '<p class="muted">No events yet.</p>';
      }
    }
  } catch (_) {}
}

// --- Load Audit by ID ---
async function loadAudit(id = $("#audit-id")?.value.trim(), queue = true) {
  if (!id) return toast("Please enter an Audit ID.", true);
  selectedAuditId = id;
  try {
    const loaded = await api(`/audits/${id}`);
    if (selectedAuditId !== id) return;
    audit = loaded;
    localStorage.setItem("security-audit-id", audit.id);
    render();
    if (queue) scheduleDrive();
  } catch (error) {
    if (selectedAuditId === id) toast(error.message, true);
  }
}

// --- Autonomous Step Driver ---
async function drive() {
  if (!audit || inFlight || automationMode !== "running") return;
  const route = routes[audit.state];
  const step =
    audit.state === "PLAN_SCHEDULED"
      ? audit.execution_schedule?.steps.find((item) => item.status === "READY")
      : null;
  if (!route && !step) return;

  const auditId = audit.id;
  inFlight = true;
  render();

  try {
    const endpoint = route
      ? route[1]
      : `/steps/${encodeURIComponent(step.plan_step_id)}/execute`;
    const updated = await api(`/audits/${auditId}${endpoint}`, { method: "POST" });
    if (selectedAuditId !== auditId) return;
    audit = updated;
    render();
  } catch (error) {
    if (selectedAuditId !== auditId) return;
    setAutomation("paused", `Paused after an execution error: ${error.message}`);
    toast(error.message, true);
  } finally {
    inFlight = false;
    render();
    scheduleDrive();
  }
}

// --- Event Listeners Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  initTheme();

  // Create Audit Form
  const createForm = $("#create-form");
  if (createForm) {
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const values = new FormData(form);
      const identifier = values.get("identifier").trim();
      const targetType = values.get("target_type");
      const allowed = ["web_scan", "static_analysis", "port_discovery", "llm_red_team"];

      try {
        const payload = {
          name: `${targetType} audit: ${identifier}`,
          objective: `Comprehensively identify security issues in the authorized ${targetType} target using all compatible non-destructive capabilities.`,
          target: { target_type: targetType, identifier },
          scope: {
            authorized_assets: [scopeAsset(identifier, targetType)],
            excluded_assets: [],
            prohibited_operations: ["exploit", "destructive_action"],
          },
          authorization: {
            authorization_id: "poc-local-authorization",
            authorized_by: "poc-operator",
            valid_until: "2099-01-01T00:00:00Z",
            allowed_operations: allowed,
          },
          credential_references: [],
          time_budget_seconds: 3600,
          cost_budget_usd: 10,
          approval_policy: "human_approval_for_destructive_actions",
        };

        const created = await api("/audits", {
          method: "POST",
          body: JSON.stringify(payload),
        });

        selectedAuditId = created.id;
        audit = created;
        localStorage.setItem("security-audit-id", audit.id);
        setAutomation("running", "Agent queued: Validate scope.");
        render();
        scheduleDrive();
        toast(`Audit created: ${audit.id}`);
      } catch (error) {
        toast(error.message, true);
      }
    });
  }

  // Load Audit
  const loadBtn = $("#load-audit");
  if (loadBtn) loadBtn.addEventListener("click", () => loadAudit());

  const auditIdInput = $("#audit-id");
  if (auditIdInput) {
    auditIdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") loadAudit();
    });
  }

  // Control Buttons
  const pauseBtn = $("#pause");
  if (pauseBtn) {
    pauseBtn.addEventListener("click", () => {
      setAutomation("paused", "Paused. The current plugin process is allowed to finish, but no next step starts.");
      render();
    });
  }

  const exitBtn = $("#exit");
  if (exitBtn) {
    exitBtn.addEventListener("click", () => {
      setAutomation("exited", "Exited. The audit is preserved; Restart resumes from its last safe state.");
      render();
    });
  }

  const restartBtn = $("#restart");
  if (restartBtn) {
    restartBtn.addEventListener("click", () => {
      setAutomation("running", "Restarting from the last safe state.");
      render();
      scheduleDrive();
    });
  }

  // Reports
  const jsonBtn = $("#json-report");
  if (jsonBtn) jsonBtn.addEventListener("click", () => audit && window.open(`/audits/${audit.id}/report.json`, "_blank"));

  const mdBtn = $("#md-report");
  if (mdBtn) mdBtn.addEventListener("click", () => audit && window.open(`/audits/${audit.id}/report.md`, "_blank"));

  // Check API health
  const connText = $("#connection");
  const connDot = $(".status-dot") || $(".connection i");
  api("/health")
    .then(() => {
      if (connText) connText.textContent = "API connected";
      if (connDot) connDot.classList.add("active");
    })
    .catch(() => {
      if (connText) connText.textContent = "API unavailable";
    });

  // Polling active audit
  setInterval(() => audit && !inFlight && loadAudit(audit.id, false), 2500);

  // Resume saved audit
  const savedId = localStorage.getItem("security-audit-id");
  if (savedId) loadAudit(savedId);
});
