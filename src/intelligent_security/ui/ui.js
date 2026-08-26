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

const STAGES = ["PREFLIGHT", "RECON", "PLAN", "EXECUTE", "VALIDATE", "REPORT", "CLOSED"];

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
function updateStepper(currentStage) {
  const currentIndex = STAGES.indexOf(currentStage);
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

function stageProgress(stage) {
  return audit?.pipeline?.stages?.find((item) => item.stage === stage);
}

function pipelineStage() {
  return audit?.pipeline?.current_stage || "PREFLIGHT";
}

function nextAction() {
  if (!audit) return null;
  const stage = pipelineStage();
  const status = stageProgress(stage)?.status;
  const post = (label, path, body) => ({ label, path, body });
  if (stage === "PREFLIGHT") {
    if (audit.state === "CREATED") return post("Validate target scope", "/scope/validate");
    if (audit.state === "SCOPE_VALIDATED") return post("Profile target", "/profile");
    if (audit.state === "TARGET_PROFILED" && status === "PENDING") return post("Start preparation", "/pipeline/transition", { stage: "PREFLIGHT", status: "RUNNING" });
    if (audit.state === "TARGET_PROFILED" && status === "RUNNING") return post("Complete preparation", "/pipeline/transition", { stage: "PREFLIGHT", status: "SUCCEEDED" });
    if (audit.state === "TARGET_PROFILED" && status === "SUCCEEDED") return post("Enter recon", "/pipeline/transition", { stage: "RECON", status: "READY" });
  }
  if (stage === "RECON") {
    if (!audit.recon_capability_discovery) return post("Discover recon capabilities", "/recon/capabilities/discover");
    if (!audit.recon_plan) return post("Build recon plan", "/recon/plan");
    // A valid recon pass may find no compatible capability.  Preserve that
    // coverage gap in the snapshot instead of attempting to construct an
    // invalid empty schedule.
    if (!audit.recon_plan.steps?.length) return post("Finalize recon snapshot", "/recon/finalize");
    if (!audit.recon_execution_schedule) return post("Schedule recon", "/recon/schedule");
    const step = audit.recon_execution_schedule.steps?.find((item) => item.status === "READY");
    if (step) return post("Run recon capability", `/recon/steps/${encodeURIComponent(step.plan_step_id)}/execute`);
    const evidence = audit.raw_evidence?.find((item) => item.plan_step_id.startsWith("recon-") && !audit.recon_evidence_chunks?.some((chunk) => chunk.evidence_id === item.evidence_id));
    if (evidence) return post("Interpret recon evidence", `/recon/evidence/${encodeURIComponent(evidence.evidence_id)}/normalize`);
    if (!audit.recon_snapshot) return post("Finalize recon snapshot", "/recon/finalize");
  }
  if (stage === "PLAN") {
    if (audit.validation_decision?.decision === "MORE_TESTING_REQUIRED") return post("Plan bounded follow-up", "/replan");
    if (!audit.audit_plan) return post("Generate AI audit plan", "/plan/generate");
    if (!audit.plan_validation) return post("Validate audit plan", "/plan/validate");
  }
  if (stage === "EXECUTE") {
    if (!audit.execution_schedule) return post("Schedule audit steps", "/plan/schedule");
    const step = audit.execution_schedule.steps?.find((item) => item.status === "READY");
    if (step) return post("Run audit capability", `/steps/${encodeURIComponent(step.plan_step_id)}/execute`);
  }
  if (stage === "VALIDATE") return post("Validate evidence and findings", "/validation/finalize");
  if (stage === "REPORT") {
    if (!audit.report_snapshot) return post("Generate final report", "/report/generate");
    return post("Close completed audit", "/close", { closed_by: "poc-autonomous", reason: "Report generated and no further safe work remains." });
  }
  return null;
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
  const nameEl = $("#audit-name");
  if (nameEl) nameEl.textContent = audit.name || "Audit Engagement";

  const targetEl = $("#audit-target");
  if (targetEl) targetEl.textContent = `${audit.target.target_type} · ${audit.target.identifier}`;

  const stateEl = $("#audit-state");
  const currentStage = pipelineStage();
  if (stateEl) stateEl.textContent = currentStage;

  const badgeEl = $("#lifecycle-badge");
  if (badgeEl) badgeEl.textContent = stageProgress(currentStage)?.status || "READY";

  updateStepper(currentStage);

  const action = nextAction();
  const blocked = audit.state === "SCOPE_REJECTED" || audit.state === "PLAN_REJECTED";
  const complete = currentStage === "CLOSED";

  let statusText = "Waiting for a runnable stage.";
  if (automationMode === "paused") {
    statusText = "Paused. Current operation will finish, but no new step will begin.";
  } else if (automationMode === "exited") {
    statusText = "Exited. The audit state is preserved and can be restarted.";
  } else if (blocked) {
    statusText = "Automation stopped: Requires manual approval or was rejected by policy.";
  } else if (complete) {
    statusText = "Audit closed. Its evidence-backed report remains available.";
  } else if (currentStage === "OFFENSIVE") {
    statusText = "Offensive actions are disabled in this POC.";
  } else if (inFlight) {
    statusText = "Autonomous agent is executing the current pipeline stage…";
  } else if (action) {
    statusText = `Next queued action: ${action.label}.`;
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
    if (action) {
      actionsEl.innerHTML = `<span class="badge badge-accent">NEXT: ${esc(action.label)}</span>`;
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
            <span class="item-title">${esc(step.capability)}</span>
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
            <span class="item-title">${esc(step.capability)}</span>
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
            <span class="item-title">${esc(finding.title || "Security observation")}</span>
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

// --- Resume the locally active audit (no audit identifier is exposed in the UI) ---
async function loadAudit(id, queue = true) {
  if (!id) return;
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
  const action = nextAction();
  if (!action) return;

  const auditId = audit.id;
  inFlight = true;
  render();

  try {
    const updated = await api(`/audits/${auditId}${action.path}`, {
      method: "POST",
      body: action.body ? JSON.stringify(action.body) : undefined,
    });
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
        toast("Audit created. Autonomous lifecycle started.");
      } catch (error) {
        toast(error.message, true);
      }
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

  // Resume the active local audit without presenting its internal identifier.
  const savedId = localStorage.getItem("security-audit-id");
  if (savedId) loadAudit(savedId);
});
