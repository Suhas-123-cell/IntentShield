(function () {
  "use strict";

  const API = "/api";
  const DEFAULT_REQUESTS = {
    benign: "Summarize my unread emails.",
    injection: "Summarize my unread emails.",
    review:
      "Send Alice a synthetic status email after I explicitly approve the exact destination and message.",
    model: "Read my inbox and return the two most recent messages.",
  };

  const state = {
    runs: [],
    approvals: [],
    tools: [],
    models: [],
    security: null,
    loading: false,
  };

  const elements = {
    connectionLabel: byId("connection-label"),
    onlineLamp: byId("online-lamp"),
    refreshButton: byId("refresh-button"),
    runForm: byId("run-form"),
    runButton: byId("run-button"),
    clearButton: byId("clear-button"),
    requestInput: byId("request-input"),
    requestCount: byId("request-count"),
    requestHelp: byId("request-help"),
    requestMode: byId("request-mode"),
    providerField: byId("provider-field"),
    modelProvider: byId("model-provider"),
    geminiRuntime: byId("gemini-runtime"),
    debertaRuntime: byId("deberta-runtime"),
    runButtonLabel: byId("run-button-label"),
    formMessage: byId("form-message"),
    evidenceEmpty: byId("evidence-empty"),
    evidenceContent: byId("evidence-content"),
    decisionBadge: byId("decision-badge"),
    evidenceRunId: byId("evidence-run-id"),
    evidenceTool: byId("evidence-tool"),
    evidenceScore: byId("evidence-score"),
    evidenceAlignment: byId("evidence-alignment"),
    evidenceGrounding: byId("evidence-grounding"),
    evidenceClassifier: byId("evidence-classifier"),
    evidenceExecuted: byId("evidence-executed"),
    ruleTrace: byId("rule-trace"),
    rawRecord: byId("raw-record"),
    approvalBody: byId("approval-body"),
    approvalCount: byId("approval-count"),
    controlToken: byId("control-token"),
    auditBody: byId("audit-body"),
    toolList: byId("tool-list"),
    toastRegion: byId("toast-region"),
    clock: byId("clock"),
    metrics: {
      total: byId("metric-total"),
      allow: byId("metric-allow"),
      review: byId("metric-review"),
      block: byId("metric-block"),
    },
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function asArray(payload, keys) {
    if (Array.isArray(payload)) return payload;
    for (const key of keys) {
      if (Array.isArray(payload && payload[key])) return payload[key];
    }
    return [];
  }

  function firstDefined(source, keys, fallback) {
    if (!source || typeof source !== "object") return fallback;
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null) return source[key];
    }
    return fallback;
  }

  function normalizeDecision(value) {
    const raw = String(value || "unknown").toLowerCase();
    if (raw.includes("allow") || raw.includes("approve")) return "allow";
    if (raw.includes("review") || raw.includes("pending")) return "review";
    if (raw.includes("block") || raw.includes("deny") || raw.includes("reject")) return "block";
    return "unknown";
  }

  function normalizeRun(run) {
    const toolCall = firstDefined(run, ["tool_call", "proposed_tool_call", "action"], {}) || {};
    const policy = firstDefined(run, ["policy", "policy_result", "evaluation"], {}) || {};
    const rawDecision = firstDefined(
      run,
      ["decision", "status", "verdict"],
      firstDefined(policy, ["decision", "status", "verdict"], "unknown")
    );
    const rules = firstDefined(
      run,
      ["rule_trace", "rules", "checks", "reasons", "reason_codes"],
      firstDefined(policy, ["rule_trace", "rules", "checks", "reasons", "reason_codes"], [])
    );

    return {
      id: String(firstDefined(run, ["id", "run_id", "uuid"], "UNASSIGNED")),
      scenario: String(firstDefined(run, ["scenario", "scenario_type", "kind"], "unknown")),
      request: String(firstDefined(run, ["request", "user_request", "user_intent", "prompt", "intent"], "—")),
      tool: String(
        firstDefined(
          run,
          ["tool", "tool_name"],
          firstDefined(toolCall, ["tool", "name", "tool_name"], "—")
        )
      ),
      args: firstDefined(run, ["arguments", "args"], firstDefined(toolCall, ["arguments", "args"], {})),
      decision: normalizeDecision(rawDecision),
      decisionLabel: String(rawDecision || "unknown").toUpperCase(),
      injectionScore: firstDefined(
        run,
        ["injection_score", "risk_score", "score", "confidence"],
        firstDefined(policy, ["injection_score", "risk_score", "score"], null)
      ),
      intentAlignment: firstDefined(
        run,
        ["intent_alignment", "alignment_score"],
        firstDefined(policy, ["intent_alignment", "alignment_score"], null)
      ),
      executed: Boolean(firstDefined(run, ["executed", "tool_executed", "did_execute"], false)),
      rules: Array.isArray(rules) ? rules : rules ? [rules] : [],
      createdAt: firstDefined(run, ["created_at", "timestamp", "time"], null),
      securityAssessment: firstDefined(run, ["security_assessment"], null),
      raw: run,
    };
  }

  function normalizeApproval(approval) {
    const toolCall = firstDefined(approval, ["tool_call", "proposed_tool_call", "action"], {}) || {};
    return {
      id: String(firstDefined(approval, ["id", "approval_id", "uuid"], "UNASSIGNED")),
      runId: String(firstDefined(approval, ["run_id", "request_id"], "—")),
      request: String(firstDefined(approval, ["request", "user_request", "intent"], "Approval required")),
      tool: String(
        firstDefined(
          approval,
          ["tool", "tool_name"],
          firstDefined(toolCall, ["tool", "name", "tool_name"], "—")
        )
      ),
      args: parseJsonValue(
        firstDefined(approval, ["arguments", "args", "args_json"], firstDefined(toolCall, ["arguments", "args"], {}))
      ),
      reason: formatReason(firstDefined(approval, ["reason", "reasons", "message"], "Policy requires human review")),
      status: String(firstDefined(approval, ["status", "decision"], "pending")).toLowerCase(),
      expiresAt: firstDefined(approval, ["expires_at", "expires", "expiry"], null),
      fingerprint: String(firstDefined(approval, ["call_fingerprint", "fingerprint", "binding_hash"], "")),
    };
  }

  function formatReason(value) {
    if (Array.isArray(value)) return value.join("; ");
    if (value && typeof value === "object") return JSON.stringify(value);
    return String(value || "—");
  }

  function parseJsonValue(value) {
    if (typeof value !== "string") return value;
    try {
      return JSON.parse(value);
    } catch (_error) {
      return value;
    }
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function formatScore(score) {
    if (score === null || score === undefined || score === "") return "—";
    const numeric = Number(score);
    if (!Number.isFinite(numeric)) return "—";
    const normalized = numeric <= 1 ? numeric * 100 : numeric;
    return `${normalized.toFixed(normalized % 1 === 0 ? 0 : 1)} / 100`;
  }

  function formatTime(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.valueOf())) return String(value).slice(0, 19);
    return new Intl.DateTimeFormat("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(parsed);
  }

  async function api(path, options) {
    const config = options || {};
    const response = await fetch(`${API}${path}`, {
      ...config,
      headers: {
        "Content-Type": "application/json",
        ...(config.headers || {}),
      },
    });

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const rawDetail =
        typeof payload === "object"
          ? firstDefined(payload, ["detail", "message", "error"], response.statusText)
          : payload || response.statusText;
      const detail = rawDetail && typeof rawDetail === "object"
        ? firstDefined(rawDetail, ["message", "error", "code"], response.statusText)
        : rawDetail;
      const error = new Error(formatReason(detail));
      error.status = response.status;
      throw error;
    }

    return payload;
  }

  async function refreshAll(options) {
    const config = { announce: false, ...options };
    setConnection("probing");

    const results = await Promise.allSettled([
      api("/health"),
      api("/metrics"),
      api("/runs"),
      api("/tools"),
      api("/approvals?status=pending", { headers: operatorHeaders() }),
      api("/models"),
      api("/security/status"),
    ]);

    const [health, metrics, runs, tools, approvals, models, security] = results;
    const reachable = health.status === "fulfilled";
    setConnection(reachable ? "online" : "offline");

    if (runs.status === "fulfilled") {
      const rawRuns = asArray(runs.value, ["runs", "items", "data"]);
      state.runs = await hydrateRuns(rawRuns);
      renderRuns();
    }

    if (approvals.status === "fulfilled") {
      state.approvals = asArray(approvals.value, ["approvals", "items", "data"])
        .map(normalizeApproval)
        .filter((item) => item.status === "pending" || item.status === "review");
      renderApprovals();
    }

    if (tools.status === "fulfilled") {
      state.tools = asArray(tools.value, ["tools", "items", "data"]);
      renderTools();
    }

    if (models.status === "fulfilled") {
      state.models = asArray(models.value, ["models", "items", "data"]);
      renderModels();
    }

    if (security.status === "fulfilled") {
      state.security = security.value;
      renderSecurity();
    }

    if (metrics.status === "fulfilled") renderMetrics(metrics.value);
    else deriveMetrics();

    if (config.announce) {
      if (reachable) showToast("TELEMETRY SYNCHRONIZED", false);
      else showToast("LOCAL API UNREACHABLE. START THE INTENTSHIELD SERVER.", true);
    }
  }

  async function hydrateRuns(rawRuns) {
    const recent = rawRuns.slice(0, 25);
    const hydrated = await Promise.all(
      recent.map(async (run) => {
        const id = firstDefined(run, ["id", "run_id"], null);
        if (!id) return run;
        try {
          const events = asArray(await api(`/runs/${encodeURIComponent(id)}/events`), ["events", "items", "data"]);
          const proposed = events.find((event) => String(event.kind || "").toUpperCase() === "TOOL_CALL_PROPOSED");
          const decision = [...events]
            .reverse()
            .find((event) => String(event.kind || "").toUpperCase() === "POLICY_DECISION");
          return {
            ...run,
            ...(proposed && proposed.payload ? proposed.payload : {}),
            ...(decision && decision.payload ? decision.payload : {}),
          };
        } catch (_error) {
          return run;
        }
      })
    );
    return hydrated.map(normalizeRun);
  }

  function setConnection(status) {
    const online = status === "online";
    elements.onlineLamp.classList.toggle("is-online", online);
    elements.connectionLabel.textContent = status.toUpperCase();
  }

  function renderMetrics(payload) {
    const source = payload && payload.metrics ? payload.metrics : payload || {};
    const decisions = source.decisions || {};
    const total = firstDefined(source, ["total", "total_runs", "runs"], state.runs.length);
    const allow = firstDefined(source, ["allow", "allowed", "allowed_count"], firstDefined(decisions, ["ALLOW", "allow"], countDecision("allow")));
    const review = firstDefined(source, ["review", "pending", "review_count"], firstDefined(decisions, ["REVIEW", "review"], countDecision("review")));
    const block = firstDefined(source, ["block", "blocked", "blocked_count"], firstDefined(decisions, ["BLOCK", "block"], countDecision("block")));
    setMetric(elements.metrics.total, total);
    setMetric(elements.metrics.allow, allow);
    setMetric(elements.metrics.review, review);
    setMetric(elements.metrics.block, block);
  }

  function deriveMetrics() {
    renderMetrics({
      total: state.runs.length,
      allow: countDecision("allow"),
      review: countDecision("review"),
      block: countDecision("block"),
    });
  }

  function countDecision(decision) {
    return state.runs.filter((run) => run.decision === decision).length;
  }

  function setMetric(element, value) {
    const numeric = Number(value) || 0;
    element.value = numeric;
    element.textContent = String(numeric).padStart(3, "0");
  }

  function renderRuns() {
    elements.auditBody.replaceChildren();
    if (!state.runs.length) {
      elements.auditBody.append(emptyRow(6, "[ NO RUNS RECORDED ]"));
      return;
    }

    state.runs.slice(0, 25).forEach((run) => {
      const row = document.createElement("tr");
      appendCell(row, formatTime(run.createdAt));
      appendCell(row, run.id);
      appendCell(row, run.scenario.toUpperCase());
      appendCell(row, run.tool);

      const decisionCell = appendCell(row, run.decisionLabel);
      decisionCell.className = `decision-text ${run.decision}`;
      appendCell(row, run.executed ? "YES" : "NO");
      row.tabIndex = 0;
      row.setAttribute("aria-label", `Inspect run ${run.id}`);
      row.addEventListener("click", () => showEvidence(run));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showEvidence(run);
        }
      });
      elements.auditBody.append(row);
    });
  }

  function renderApprovals() {
    elements.approvalBody.replaceChildren();
    elements.approvalCount.textContent = `${String(state.approvals.length).padStart(2, "0")} PENDING`;

    if (!state.approvals.length) {
      elements.approvalBody.append(emptyRow(4, "[ QUEUE EMPTY ]"));
      return;
    }

    state.approvals.forEach((approval) => {
      const row = document.createElement("tr");
      const requestCell = document.createElement("td");
      const request = document.createElement("span");
      request.className = "cell-primary";
      request.textContent = approval.request;
      const id = document.createElement("span");
      id.className = "cell-secondary";
      id.textContent = `APPROVAL / ${approval.id}  RUN / ${approval.runId}`;
      requestCell.append(request, id);
      row.append(requestCell);

      const toolCell = document.createElement("td");
      const tool = document.createElement("span");
      tool.className = "cell-primary";
      tool.textContent = approval.tool;
      const args = document.createElement("code");
      args.className = "cell-secondary";
      args.textContent = formatValue(approval.args);
      toolCell.append(tool, args);
      row.append(toolCell);

      const reasonCell = document.createElement("td");
      const reason = document.createElement("span");
      reason.className = "cell-primary";
      reason.textContent = approval.reason;
      const binding = document.createElement("span");
      binding.className = "cell-secondary approval-binding";
      const shortFingerprint = approval.fingerprint
        ? approval.fingerprint.slice(0, 12).toUpperCase()
        : "UNAVAILABLE";
      binding.textContent = `EXPIRES / ${formatTimestamp(approval.expiresAt)}  BIND / ${shortFingerprint}`;
      reasonCell.append(reason, binding);
      row.append(reasonCell);

      const controlsCell = document.createElement("td");
      const controls = document.createElement("div");
      controls.className = "approval-controls";
      controls.append(
        approvalButton("APPROVE", approval.id, "approve"),
        approvalButton("REJECT", approval.id, "reject")
      );
      controlsCell.append(controls);
      row.append(controlsCell);
      elements.approvalBody.append(row);
    });
  }

  function approvalButton(label, id, decision) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `approval-action ${decision === "reject" ? "deny" : ""}`;
    button.textContent = label;
    button.setAttribute("aria-label", `${label} approval ${id}`);
    button.addEventListener("click", () => decideApproval(id, decision, button));
    return button;
  }

  async function decideApproval(id, decision, sourceButton) {
    const rowButtons = sourceButton.closest("tr").querySelectorAll("button");
    rowButtons.forEach((button) => { button.disabled = true; });

    try {
      const payload = { decision };
      await api(`/approvals/${encodeURIComponent(id)}/decision`, {
        method: "POST",
        headers: operatorHeaders(),
        body: JSON.stringify(payload),
      });
      const outcome = decision === "approve" ? "APPROVED" : "REJECTED";
      showToast(`APPROVAL ${id} ${outcome}`, false);
      await refreshAll();
    } catch (error) {
      rowButtons.forEach((button) => { button.disabled = false; });
      showToast(`APPROVAL FAILED: ${error.message}`, true);
    }
  }

  function operatorHeaders() {
    const token = elements.controlToken.value.trim();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  function renderTools() {
    elements.toolList.replaceChildren();
    if (!state.tools.length) {
      const item = document.createElement("li");
      item.textContent = "NO TOOLS REGISTERED";
      elements.toolList.append(item);
      return;
    }

    state.tools.forEach((entry) => {
      const item = document.createElement("li");
      const name = typeof entry === "string" ? entry : firstDefined(entry, ["name", "tool_name", "id"], "UNNAMED");
      const risk = typeof entry === "object" ? firstDefined(entry, ["risk", "risk_level", "classification"], null) : null;
      item.textContent = `${String(name).toUpperCase()}${risk ? ` / ${String(risk).toUpperCase()}` : ""}`;
      elements.toolList.append(item);
    });
  }

  function renderModels() {
    const entry = state.models.find((item) => item.provider === "gemini");
    const configured = Boolean(entry && entry.configured);
    const model = entry ? String(entry.model || "DEFAULT") : "UNAVAILABLE";
    elements.modelProvider.textContent = `GEMINI / ${model} / ${configured ? "READY" : "KEY MISSING"}`;
    elements.modelProvider.dataset.configured = configured ? "true" : "false";
    elements.geminiRuntime.textContent = configured ? "READY" : "KEY MISSING";
  }

  function renderSecurity() {
    const classifier = state.security && state.security.intent_classifier;
    elements.debertaRuntime.textContent = classifier && classifier.ready
      ? "VERIFIED / READY"
      : "DEGRADED / LOCAL RULES";
  }

  function showEvidence(run) {
    elements.evidenceEmpty.hidden = true;
    elements.evidenceContent.hidden = false;
    elements.decisionBadge.textContent = run.decisionLabel;
    elements.decisionBadge.className = `decision-badge ${run.decision}`;
    elements.evidenceRunId.textContent = run.id;
    elements.evidenceTool.textContent = run.tool;
    elements.evidenceScore.textContent = formatScore(run.injectionScore);
    elements.evidenceAlignment.textContent = formatScore(run.intentAlignment);
    const assessment = run.securityAssessment || {};
    const grounding = assessment.grounding || {};
    elements.evidenceGrounding.textContent = String(assessment.disposition || "—");
    elements.evidenceClassifier.textContent = grounding.classifier_label
      ? `${String(grounding.classifier_label).toUpperCase()} / ${formatScore(grounding.classifier_score)}`
      : "DEGRADED / NOT USED";
    elements.evidenceExecuted.textContent = run.executed ? "YES" : "NO";
    elements.rawRecord.textContent = JSON.stringify(run.raw, null, 2);

    elements.ruleTrace.replaceChildren();
    const rules = run.rules.length
      ? run.rules
      : [{ rule: "Policy evaluation", result: run.decisionLabel }];

    rules.forEach((entry) => {
      const row = document.createElement("li");
      const label = document.createElement("span");
      const result = document.createElement("span");
      const isObject = entry && typeof entry === "object";
      label.textContent = isObject
        ? formatReason(firstDefined(entry, ["rule", "name", "check", "reason"], "Policy check"))
        : String(entry);
      const resultText = isObject
        ? formatReason(firstDefined(entry, ["result", "status", "outcome", "passed"], "RECORDED"))
        : "TRIGGERED";
      result.textContent = String(resultText).toUpperCase();
      result.className = `trace-result ${String(resultText).toLowerCase()}`;
      row.append(label, result);
      elements.ruleTrace.append(row);
    });
  }

  async function submitRun(event) {
    event.preventDefault();
    if (state.loading) return;

    const formData = new FormData(elements.runForm);
    const scenario = String(formData.get("scenario") || "benign");
    const request = elements.requestInput.value.trim();
    if (!request) {
      setFormMessage("REQUEST CANNOT BE EMPTY.", true);
      elements.requestInput.focus();
      return;
    }
    if (scenario === "model" && elements.modelProvider.dataset.configured !== "true") {
      setFormMessage("GEMINI_API_KEY IS NOT CONFIGURED ON THE SERVER.", true);
      return;
    }

    state.loading = true;
    elements.runButton.disabled = true;
    setFormMessage(
      scenario === "model"
        ? "REQUESTING GUARDED MODEL TOOL PROPOSAL…"
        : "EVALUATING LOCAL POLICY TRACE…",
      false
    );

    try {
      const endpoint = scenario === "model" ? "/model-runs" : "/runs";
      const body = scenario === "model"
        ? { provider: "gemini", user_intent: request }
        : { scenario, user_intent: request };
      const payload = await api(endpoint, {
        method: "POST",
        body: JSON.stringify(body),
      });
      const record = payload && payload.run ? payload.run : payload;
      const run = normalizeRun(record || {});
      showEvidence(run);
      setFormMessage(`RUN ${run.id} COMPLETE / ${run.decisionLabel}`, false);
      await refreshAll();
      const hydratedRun = state.runs.find((item) => item.id === run.id);
      if (hydratedRun) showEvidence(hydratedRun);
    } catch (error) {
      setFormMessage(`RUN FAILED / ${error.message}`, true);
      showToast(`RUN FAILED: ${error.message}`, true);
    } finally {
      state.loading = false;
      elements.runButton.disabled = false;
    }
  }

  function updatePreset(event) {
    const scenario = event.target.value;
    const liveModel = scenario === "model";
    elements.providerField.hidden = !liveModel;
    elements.requestMode.textContent = liveModel ? "MODEL/LIVE" : "SIM/LOCAL";
    elements.runButtonLabel.textContent = liveModel ? "RUN GUARDED MODEL" : "RUN SECURITY CHECK";
    elements.requestHelp.textContent = liveModel
      ? "THIS INTENT IS SENT TO GEMINI AFTER LOCAL PREFLIGHT. NEVER ENTER CREDENTIALS OR SECRETS."
      : "SYNTHETIC INPUT ONLY. DO NOT ENTER REAL CREDENTIALS OR PERSONAL DATA.";
    if (DEFAULT_REQUESTS[scenario]) {
      elements.requestInput.value = DEFAULT_REQUESTS[scenario];
      updateCount();
    }
  }

  function updateCount() {
    elements.requestCount.textContent = `${String(elements.requestInput.value.length).padStart(3, "0")}/1200`;
  }

  function clearRequest() {
    elements.requestInput.value = "";
    updateCount();
    setFormMessage("REQUEST CLEARED.", false);
    elements.requestInput.focus();
  }

  function setFormMessage(message, error) {
    elements.formMessage.textContent = message;
    elements.formMessage.classList.toggle("error", Boolean(error));
  }

  function emptyRow(columns, message) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = columns;
    cell.textContent = message;
    row.append(cell);
    return row;
  }

  function appendCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = formatValue(value);
    row.append(cell);
    return cell;
  }

  function showToast(message, error) {
    const toast = document.createElement("div");
    toast.className = `toast ${error ? "error" : ""}`;
    toast.textContent = message;
    elements.toastRegion.replaceChildren(toast);
    window.setTimeout(() => {
      if (toast.isConnected) toast.remove();
    }, 5000);
  }

  function updateClock() {
    elements.clock.textContent = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date()) + " IST";
  }

  function formatTimestamp(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.valueOf())) return String(value);
    return new Intl.DateTimeFormat("en-GB", {
      year: "2-digit",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(parsed);
  }

  document.querySelectorAll('input[name="scenario"]').forEach((input) => {
    input.addEventListener("change", updatePreset);
  });
  elements.runForm.addEventListener("submit", submitRun);
  elements.requestInput.addEventListener("input", updateCount);
  elements.clearButton.addEventListener("click", clearRequest);
  elements.refreshButton.addEventListener("click", () => refreshAll({ announce: true }));
  elements.controlToken.addEventListener("change", () => refreshAll({ announce: true }));

  updateCount();
  updateClock();
  window.setInterval(updateClock, 1000);
  refreshAll();
})();
