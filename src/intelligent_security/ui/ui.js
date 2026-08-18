const $ = (selector) => document.querySelector(selector);
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

function toast(message, error = false) { const el = $("#toast"); el.textContent = message; el.className = error ? "error" : ""; el.style.display = "block"; setTimeout(() => el.style.display = "none", 5200); }
async function api(path, options = {}) { const response = await fetch(path, { ...options, headers: { "content-type": "application/json", ...(options.headers || {}) } }); if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail?.message || body.detail || `Request failed (${response.status})`); } return response.headers.get("content-type")?.includes("application/json") ? response.json() : response.text(); }
function esc(value = "") { const e = document.createElement("span"); e.textContent = value; return e.innerHTML; }
function renderItems(items, renderer, empty) { return items?.length ? items.map(renderer).join("") : `<p class="muted">${empty}</p>`; }
function scopeAsset(identifier, targetType) { if (targetType === "network_host" || targetType === "source_repository") return identifier; try { const url = new URL(identifier); if (!/^https?:$/.test(url.protocol)) throw new Error(); return url.hostname; } catch (_) { throw new Error("Web, repository, and LLM targets must use a valid HTTP or HTTPS URL."); } }
function setAutomation(mode, message) { automationMode = mode; localStorage.setItem("security-audit-automation", mode); if ($("#automation-status")) $("#automation-status").textContent = message; }
function scheduleDrive() { clearTimeout(driveTimer); if (automationMode === "running") driveTimer = setTimeout(drive, 250); }

function render() {
  const visible = Boolean(audit); $("#audit-content").hidden = !visible; $("#empty-state").hidden = visible; if (!audit) return;
  $("#audit-id").value = audit.id; $("#audit-name").textContent = audit.name; $("#audit-target").textContent = `${audit.target.target_type} · ${audit.target.identifier}`; $("#audit-state").innerHTML = `State: <span class="state">${audit.state}</span>`;
  const route = routes[audit.state];
  const readyStep = audit.state === "PLAN_SCHEDULED" ? audit.execution_schedule?.steps.find(step => step.status === "READY") : null;
  const blocked = audit.state === "PLAN_PENDING_APPROVAL" || audit.state === "PLAN_REJECTED" || audit.state === "SCOPE_REJECTED";
  const complete = audit.state === "PLAN_SCHEDULED" && !readyStep && audit.execution_schedule?.steps.every(step => step.status === "SUCCEEDED");
  const status = automationMode === "paused" ? "Paused. No new stage or plugin step will start." : automationMode === "exited" ? "Exited. The audit is preserved and can be restarted." : blocked ? "Automation stopped because policy rejected or requires approval." : complete ? "All scheduled plugin steps completed." : inFlight ? "Agent is executing the current stage…" : route ? `Agent queued: ${route[0]}.` : readyStep ? `Agent queued: Execute ${readyStep.plan_step_id}.` : "Waiting for a runnable stage.";
  $("#automation-status").textContent = status;
  $("#pause").disabled = automationMode !== "running"; $("#exit").disabled = automationMode === "exited"; $("#restart").disabled = automationMode === "running";
  $("#actions").innerHTML = route ? `<span class="badge">NEXT · ${esc(route[0])}</span>` : readyStep ? `<span class="badge">NEXT · Execute ${esc(readyStep.plan_step_id)}</span>` : complete ? `<span class="badge">EXECUTION COMPLETE</span>` : "";
  $("#plan").innerHTML = audit.audit_plan ? renderItems(audit.audit_plan.steps, step => `<div class="item"><strong>${esc(step.id)} · ${esc(step.capability)}</strong><div class="meta">${esc(step.reason)}${step.depends_on?.length ? ` · depends on ${esc(step.depends_on.join(", "))}` : ""}</div></div>`, "") : "<p class=\"muted\">No plan generated.</p>";
  $("#schedule").innerHTML = renderItems(audit.execution_schedule?.steps, step => `<div class="item"><strong>${esc(step.plan_step_id)} <span class="badge">${esc(step.status)}</span></strong><div class="meta">${esc(step.capability)} · ${step.estimated_duration_seconds}s · $${step.estimated_cost_usd}</div></div>`, "No scheduled steps.");
  $("#findings").innerHTML = renderItems(audit.candidate_findings, finding => `<div class="item"><strong>${esc(finding.title || finding.finding_id)} <span class="badge">${esc(finding.state)}</span></strong><div class="meta">${esc(finding.severity || "Unrated")} · ${esc(finding.description || "Awaiting validation")}</div></div>`, "No findings yet.");
  loadEvents();
}

async function loadEvents() { if (!audit) return; const auditId = audit.id; try { const events = await api(`/audits/${auditId}/events`); if (selectedAuditId !== auditId) return; $("#events").innerHTML = renderItems(events.slice().reverse(), event => `<div class="item"><strong>${esc(event.event_type)}</strong><div class="meta">${new Date(event.occurred_at).toLocaleString()}</div></div>`, "No events yet."); } catch (_) {} }
async function loadAudit(id = $("#audit-id").value.trim(), queue = true) { if (!id) return toast("Enter an Audit ID.", true); selectedAuditId = id; try { const loaded = await api(`/audits/${id}`); if (selectedAuditId !== id) return; audit = loaded; localStorage.setItem("security-audit-id", audit.id); render(); if (queue) scheduleDrive(); } catch (error) { if (selectedAuditId === id) toast(error.message, true); } }

async function drive() {
  if (!audit || inFlight || automationMode !== "running") return;
  const route = routes[audit.state];
  const step = audit.state === "PLAN_SCHEDULED" ? audit.execution_schedule?.steps.find(item => item.status === "READY") : null;
  if (!route && !step) return;
  const auditId = audit.id;
  inFlight = true; render();
  try {
    const updated = await api(`/audits/${auditId}${route ? route[1] : `/steps/${encodeURIComponent(step.plan_step_id)}/execute`}`, { method: "POST" });
    if (selectedAuditId !== auditId) return;
    audit = updated;
    render();
  } catch (error) {
    if (selectedAuditId !== auditId) return;
    setAutomation("paused", `Paused after an execution error: ${error.message}`);
    toast(error.message, true);
  } finally {
    inFlight = false; render(); scheduleDrive();
  }
}

$("#create-form").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = new FormData(form), identifier = values.get("identifier").trim(), targetType = values.get("target_type"), allowed = ["web_scan", "static_analysis", "port_discovery", "llm_red_team"]; try { const payload = { name: `${targetType} audit: ${identifier}`, objective: `Comprehensively identify security issues in the authorized ${targetType} target using all compatible non-destructive capabilities.`, target: { target_type: targetType, identifier }, scope: { authorized_assets: [scopeAsset(identifier, targetType)], excluded_assets: [], prohibited_operations: ["exploit", "destructive_action"] }, authorization: { authorization_id: "poc-local-authorization", authorized_by: "poc-operator", valid_until: "2099-01-01T00:00:00Z", allowed_operations: allowed }, credential_references: [], time_budget_seconds: 3600, cost_budget_usd: 10, approval_policy: "human_approval_for_destructive_actions" }; const created = await api("/audits", { method: "POST", body: JSON.stringify(payload) }); selectedAuditId = created.id; audit = created; localStorage.setItem("security-audit-id", audit.id); setAutomation("running", "Agent queued: Validate scope."); render(); scheduleDrive(); toast(`Audit created: ${audit.id}`); } catch (error) { toast(error.message, true); } });
$("#load-audit").addEventListener("click", () => loadAudit());
$("#pause").addEventListener("click", () => { setAutomation("paused", "Paused. The current plugin process is allowed to finish, but no next step starts."); render(); });
$("#exit").addEventListener("click", () => { setAutomation("exited", "Exited. The audit is preserved; Restart resumes from its last safe state."); render(); });
$("#restart").addEventListener("click", () => { setAutomation("running", "Restarting from the last safe state."); render(); scheduleDrive(); });
$("#json-report").addEventListener("click", () => audit && window.open(`/audits/${audit.id}/report.json`, "_blank")); $("#md-report").addEventListener("click", () => audit && window.open(`/audits/${audit.id}/report.md`, "_blank"));
api("/health").then(() => { $("#connection").textContent = "API connected"; $(".connection i").style.background = "var(--accent)"; }).catch(() => { $("#connection").textContent = "API unavailable"; });
setInterval(() => audit && !inFlight && loadAudit(audit.id), 2500);
const saved = localStorage.getItem("security-audit-id"); if (saved) loadAudit(saved);
