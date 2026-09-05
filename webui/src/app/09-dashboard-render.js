  const STORE_KEY = "scriptsentry_last_result";
  const STORE_LIMIT = 2 * 1024 * 1024;  // sessionStorage is typically ~5 MB

  function persistPayload() {
    try {
      const text = JSON.stringify(payload);
      if (!text || text.length > STORE_LIMIT) return;
      sessionStorage.setItem(STORE_KEY, text);
    } catch {
      /* storage unavailable or full -- a re-scan is always possible */
    }
  }

  function restorePayload() {
    try {
      const text = sessionStorage.getItem(STORE_KEY);
      if (!text) return false;
      const parsed = JSON.parse(text);
      if (!parsed || !parsed.summary) return false;
      payload = parsed;
      return true;
    } catch {
      return false;
    }
  }

  function renderDashboard() {
    if (!payload) return;
    const results = $("#results");
    results.classList.add("show");
    renderEngineNotes();
    $("#result-meta").textContent = `${payload.meta.engine} · ${payload.meta.analysis_mode === "url" ? "Remote URL" : "Source snippet"} · ${payload.meta.generated_at || ""}`;
    renderSummary();
    renderPriorities();
    renderRiskBreakdown();
    renderSignals();
    renderScripts();
    renderDeps();
    renderCharts();
    renderTimeline();
    renderAttack();
    renderFlows();
    renderSecrets();
    renderUnifiedFindings();
    renderRuntime();
    renderScanSummary();
    renderFiles();
    persistPayload();
  }

  const SEV_COLOR = { CRITICAL: "#ff4d6d", HIGH: "#ff9f43", MEDIUM: "#ffd166", LOW: "#22d3ee", INFO: "#a78bfa" };
  const CONF_LABEL = { confirmed: "confirmed", high: "high", medium: "medium", low: "low" };

  /* Overview: answer "is it risky / why / what first" immediately. */
  function renderPriorities() {
    const priorities = (payload.summary.priorities || []).filter(Boolean);
    const panel = $("#priority-list");
    if (!panel) return;
    if (!priorities.length) {
      panel.innerHTML = `<li><span class="risk-dot" style="color:#34d399"></span><span><b>No actionable findings.</b> Only routine observations — this application looks low-risk from the analyzed code.</span></li>`;
      return;
    }
    panel.innerHTML = priorities.slice(0, 6).map((p, i) => {
      const color = SEV_COLOR[p.severity] || "#22d3ee";
      const where = p.location ? ` · ${escapeHtml(p.location)}` : "";
      const detail = p.source ? `${escapeHtml(p.source)} → ${escapeHtml(p.sink || "")}` : escapeHtml(p.sink || "");
      const limits = (p.limitations || []).length
        ? `<br><span style="color:#fbbf24;font-size:11px">⚠ ${escapeHtml(p.limitations[0])}</span>` : "";
      return `<li style="animation-delay:${i * 0.05}s">
        <span class="risk-dot" style="color:${color}"></span>
        <span><b>${escapeHtml(p.type)}</b> · ${escapeHtml(p.severity)} · confidence ${escapeHtml(CONF_LABEL[p.confidence] || p.confidence || "?")}${where}
        <br><span style="color:#8ea2c1">${detail}</span>${limits}</span>
      </li>`;
    }).join("");
  }

  function renderRiskBreakdown() {
    const contributors = payload.summary.risk_contributors || [];
    const panel = $("#risk-breakdown");
    if (!panel) return;
    if (!contributors.length) {
      panel.innerHTML = `<div class="modal-note">No risk contributors — score 0.</div>`;
      return;
    }
    const maxPoints = Math.max(...contributors.map((c) => c.points), 1);
    panel.innerHTML = contributors.map((c) => {
      const width = Math.max(4, Math.min(100, (c.points / maxPoints) * 100));
      const color = c.tier >= 3 ? "#ff4d6d" : c.tier === 2 ? "#ff9f43" : c.tier === 1 ? "#ffd166" : "#22d3ee";
      return `<div class="category">
        <div class="name"><span>+${c.points} · ${escapeHtml(c.label)}</span><b style="color:${color}">${c.points}</b></div>
        <div class="cat-bar"><i style="--cat:${color};width:${width}%"></i></div>
      </div>`;
    }).join("");
  }

  // The engine is not consistent about the shape of a finding's `evidence`:
  // coarse risk signals carry an array of strings, while source-to-sink
  // findings carry a single string. Normalise before joining so a string never
  // reaches `.join()` (which would throw and abort the whole dashboard render).
  function evidenceList(evidence) {
    if (Array.isArray(evidence)) return evidence.map((x) => String(x == null ? "" : x));
    if (evidence == null) return [];
    if (typeof evidence === "string") return evidence.trim() ? [evidence] : [];
    return [String(evidence)];
  }

  function renderSignals() {
    // Observations = interesting behavior that is not a proven vulnerability:
    // coarse risk signals plus informational/sanitized findings. This keeps
    // the Findings view honest about what is (and isn't) actionable.
    const signals = payload.summary.signals || [];
    const findings = payload.summary.findings || [];
    const observationFindings = findings.filter((f) => isObservation(f));
    const sevColor = SEV_COLOR;

    const signalHtml = signals.slice(0, 14).map((s, i) => {
      const isFlow = s.status === "open" || s.confidence === "high" || s.confidence === "confirmed";
      const color = sevColor[s.severity] || "#22d3ee";
      return `<li style="animation-delay:${i * 0.04}s">
        <span class="risk-dot" style="color:${isFlow ? "#fb7185" : color}"></span>
        <span><b>${escapeHtml(s.title || s.id)}</b> · ${escapeHtml(s.file || "")}<br>
        <span style="color:#8ea2c1">${escapeHtml(evidenceList(s.evidence).slice(0, 2).join(" · "))}</span>
        <span class="quality-chip">${escapeHtml(s.confidence || "low")} confidence</span></span>
      </li>`;
    });

    const findingHtml = observationFindings.slice(0, 10).map((f, i) => {
      const color = sevColor[f.severity] || "#22d3ee";
      return `<li style="animation-delay:${(signalHtml.length + i) * 0.04}s">
        <span class="risk-dot" style="color:${color}"></span>
        <span><b>${escapeHtml(f.type || f.id)}</b> · ${escapeHtml(f.file || "")}<br>
        <span style="color:#8ea2c1">${escapeHtml(f.sink || (Array.isArray(f.evidence) ? f.evidence.join(" ") : f.evidence) || "")}</span></span>
      </li>`;
    });

    const rows = signalHtml.concat(findingHtml);
    $("#risk-signals").innerHTML = rows.length
      ? rows.join("")
      : `<li><span class="risk-dot" style="color:#34d399"></span><span>No security observations raised. This scan found only routine code patterns.</span></li>`;
  }

  function renderScripts() {
    const scripts = payload.script_inventory || [];
    const panel = $("#script-panel");
    if (!panel) return;
    if (!scripts.length) {
      panel.innerHTML = `<div class="finding-chip"><span class="chip-title">No script inventory available for this analysis.</span></div>`;
      return;
    }

    const partyColor = { first_party: "#34d399", third_party: "#fb7185", inline: "#22d3ee", file: "#f97316", unknown: "#a78bfa" };
    const sorted = scripts.slice().sort((a, b) => ((b.risk || {}).score || 0) - ((a.risk || {}).score || 0));

    panel.innerHTML = sorted
      .map((s, i) => {
        const caps = s.capabilities || {};
        const risk = s.risk || {};
        const reads = caps.reads || [];
        const writes = caps.writes || [];
        const external = caps.external_destinations || [];
        const domains = Array.from(new Set(external.map((d) => d.domain).filter(Boolean))).slice(0, 6);
        const apis = (s.browser_apis || []).filter((a) => a.enabled);
        const runtimeRequests = s.runtime_requests || [];
        const loadedBy = s.loaded_by || [];
        const pagesPresent = s.pages_present || [];
        return `<div class="finding-chip" style="animation-delay:${i * 0.05}s">
          <span class="chip-title" style="color:${partyColor[s.party] || "#22d3ee"}">
            ${escapeHtml(s.name)} · ${escapeHtml(s.party || "unknown")} · risk ${risk.score || 0}/100
          </span>
          <div style="color:#8ea2c1">${escapeHtml(s.load_method || "unknown")} · ${escapeHtml(s.domain || "inline")} · ${s.finding_count || 0} findings</div>
          ${loadedBy.length ? `<div><b>Loaded by:</b> ${loadedBy.slice(0, 4).map(escapeHtml).join(" · ")}</div>` : ""}
          ${pagesPresent.length ? `<div><b>Present on:</b> ${pagesPresent.slice(0, 4).map(escapeHtml).join(" · ")}</div>` : ""}
          ${risk.factors && risk.factors.length ? `<div><b>Why:</b> ${risk.factors.slice(0, 4).map(escapeHtml).join(" · ")}</div>` : ""}
          ${reads.length ? `<div><b>Reads:</b> ${reads.map(escapeHtml).join(", ")}</div>` : ""}
          ${writes.length ? `<div><b>Writes:</b> ${writes.map(escapeHtml).join(", ")}</div>` : ""}
          ${domains.length ? `<div><b>External destinations:</b> ${domains.map(escapeHtml).join(", ")}</div>` : ""}
          ${apis.length ? `<div><b>Browser APIs:</b> ${apis.map((a) => `${a.label} ${a.enabled ? "✓" : "✗"}`).join(" · ")}</div>` : ""}
          ${runtimeRequests.length ? `<div><b>Runtime network initiated:</b> ${runtimeRequests.slice(0, 6).map((r) => `${r.method || "GET"} ${r.url || ""}`).map(escapeHtml).join(" · ")}</div>` : ""}
        </div>`;
      })
      .join("");
  }

  function renderDeps() {
    const summary = payload.summary;
    const items = [
      ["Dependencies", summary.dependencies || [], "#a78bfa"],
      ["Transport", summary.transport || [], "#38bdf8"],
      ["HTTP Methods", summary.methods || [], "#fb7185"],
    ];
    $("#dep-panel").innerHTML = items
      .filter(([, v]) => v && v.length)
      .map(([name, vals, color]) => `<div class="finding-chip"><span class="chip-title" style="color:${color}">${escapeHtml(name)} · ${vals.length}</span>${vals.map((v) => `<div>• ${escapeHtml(v)}</div>`).join("")}</div>`)
      .join(`<div class="finding-chip"><span class="chip-title">No external dependencies mapped</span></div>`);
  }

  /* ---------------- Dedicated view rendering ---------------- */

  function runtimeItemText(item) {
    if (typeof item === "string") return item;
    if (!item) return "";
    if (item.method && item.url) return `${item.method} ${item.url}${item.status ? ` [${item.status}]` : ""}${item.initiated_by?.length ? ` · initiated by ${item.initiated_by.slice(0, 2).join(", ")}` : ""}`;
    if (item.sink) return `${item.sink}: ${item.value || ""}`;
    if (item.kind) return item.code ? `${item.kind}: ${item.code}` : item.kind;
    if (item.storage) return item.key ? `${item.storage} ${item.operation || "setItem"} → ${item.key} (${item.valueLength || ""} chars)` : item.storage;
    return item.code || item.value || item.key || item.url || item.text || item.name || "";
  }

  function renderRuntime() {
    const evidence = payload.runtime_evidence || {};
    const findings = payload.runtime_findings || [];
    const panel = $("#runtime-panel");
    if (!panel) return;

    if (!evidence.status) {
      panel.innerHTML = `<div class="finding-chip"><span class="chip-title">No runtime pass was run for this analysis.</span></div>`;
      return;
    }

    const statusText = {
      captured: "Captured locally",
      missing_dependency: "Playwright not installed",
      disabled: "Disabled",
      browser_failed: "Browser failed",
      error: "Capture failed",
    }[evidence.status] || evidence.status;
    const statusColor = evidence.captured ? "#34d399" : "#fbbf24";
    const detail = (arr) => (arr || []).map(runtimeItemText).filter(Boolean);

    const metrics = [
      ["Status", statusText, statusColor],
      ["Duration", `${evidence.duration_ms || 0} ms`, "#22d3ee"],
      ["Requests", (evidence.requests || []).length, "#38bdf8"],
      ["Console", (evidence.console || []).length, "#a78bfa"],
      ["DOM Sinks", (evidence.dom_sinks || []).length, "#fb7185"],
      ["Eval / Timers", (evidence.eval_calls || []).length + (evidence.string_timers || []).length, "#f97316"],
      ["WebSockets", (evidence.websockets || []).length, "#f472b6"],
      ["Storage Keys", new Set([...(evidence.local_storage_keys || []), ...(evidence.session_storage_keys || []), ...(evidence.cookie_names || [])]).size, "#8b5cf6"],
      ["Messages", (evidence.post_messages || []).length + (evidence.message_listeners || []).length, "#c084fc"],
    ];

    const panels = [
      ["Network Requests", detail(evidence.requests).slice(0, 28), "#38bdf8"],
      ["Console", detail(evidence.console).slice(0, 28), "#a78bfa"],
      ["Page / Request Errors", detail([...(evidence.page_errors || []).map((x) => ({ text: x })), ...(evidence.failed_requests || [])]).slice(0, 20), "#fb7185"],
      ["WebSockets", detail(evidence.websockets).slice(0, 20), "#f472b6"],
      ["Eval & String Timers", detail([...(evidence.eval_calls || []), ...(evidence.string_timers || [])]).slice(0, 20), "#f97316"],
      ["DOM Sinks", detail(evidence.dom_sinks).slice(0, 20), "#fb7185"],
      ["Storage & Cookies", detail(evidence.storage_writes).concat(detail(evidence.storage_reads)).concat((evidence.cookie_names || []).map((n) => `cookie: ${n}`)).concat((evidence.local_storage_keys || []).map((n) => `localStorage key: ${n}`)).concat((evidence.session_storage_keys || []).map((n) => `sessionStorage key: ${n}`)).slice(0, 30), "#8b5cf6"],
      ["Messages", detail([...(evidence.post_messages || []), ...(evidence.message_listeners || [])]).slice(0, 20), "#c084fc"],
      ["Dynamic Scripts / Frames", detail([...(evidence.scripts || []), ...(evidence.frames || [])]).slice(0, 30), "#60a5fa"],
      ["Runtime Findings", findings.map((f) => `${f.severity || "MEDIUM"} · ${f.type || f.id} · ${evidenceList(f.evidence).join(" · ")}`).slice(0, 20), "#ff4d6d"],
    ].filter(([, v]) => v && v.length);

    panel.innerHTML = `
      <div class="finding-grid" style="margin-bottom:14px">
        ${metrics.map(([n, v, color]) => `<div class="finding-chip"><span class="chip-title" style="color:${color}">${escapeHtml(n)}</span><div>${escapeHtml(v)}</div></div>`).join("")}
      </div>
      ${!evidence.captured ? `<div class="finding-chip" style="margin-bottom:14px"><span class="chip-title" style="color:#fbbf24">${escapeHtml(statusText)}</span><div>${escapeHtml(evidence.reason || evidence.status)}</div></div>` : ""}
      <div class="finding-grid">
        ${panels.map(([name, vals, color]) => `<div class="finding-chip"><span class="chip-title" style="color:${color}">${escapeHtml(name)} · ${vals.length}</span>${vals.map((v) => `<div>• ${escapeHtml(v)}</div>`).join("")}</div>`).join("") || `<div class="finding-chip"><span class="chip-title">No notable runtime activity observed.</span></div>`}
      </div>
    `;
  }

  function aggregateAttackSurface() {
    const byKey = {};
    (payload.files || []).forEach((f) => {
      const as = f.attack_surface || {};
      (as.endpoints || []).forEach((e) => {
        const k = `${e.method || "GET"} ${e.url || ""}`;
        byKey[k] = byKey[k] || { method: e.method || "GET", url: e.url || "", params: e.params || {}, headers: e.headers || {}, body_fields: e.body_fields || [], auth: e.auth || "", internal: !!e.internal, count: 0 };
        byKey[k].count++;
      });
      (as.websockets || []).forEach((e) => {
        const k = `WS ${e.url || ""}`;
        byKey[k] = byKey[k] || { method: "WS", url: e.url || "", protocols: e.protocols || [], count: 0 };
        byKey[k].count++;
      });
      (as.sse || []).forEach((e) => {
        const k = `SSE ${e.url || ""}`;
        byKey[k] = byKey[k] || { method: "SSE", url: e.url || "", count: 0 };
        byKey[k].count++;
      });
    });
    return Object.values(byKey);
  }

  function renderAttack() {
    const endpoints = aggregateAttackSurface();
    const graphql = (payload.files || []).flatMap((f) => (f.attack_surface || {}).graphql?.operations || []);
    const params = [];
    const headers = [];
    const body = [];
    const auth = [];
    const internal = [];
    (payload.files || []).forEach((f) => {
      const as = f.attack_surface || {};
      params.push(...(as.parameters || []));
      headers.push(...(as.headers || []));
      body.push(...(as.body_fields || []));
      auth.push(...(as.auth_hints || []));
      internal.push(...(as.internal_endpoints || []));
    });

    const panels = [
      ["Endpoints & Realtime", endpoints, (e) => `${e.method} ${e.url}${e.internal ? " ⚠internal" : ""}`, "#22d3ee"],
      ["GraphQL Operations", graphql, (g) => `${g.operation}${g.line ? ` (L${g.line})` : ""}`, "#a78bfa"],
      ["Parameters", params, (p) => p, "#38bdf8"],
      ["Headers", headers, (h) => h, "#fb7185"],
      ["Body Fields", body, (b) => b, "#34d399"],
      ["Auth Hints", auth, (a) => a.type || a.url || "", "#fbbf24"],
      ["Internal / Hidden", internal, (e) => e.url || e.method || "", "#ff4d6d"],
    ];
    $("#attack-panel").innerHTML = panels
      .filter(([, v]) => Array.isArray(v) && v.length)
      .map(([name, vals, fmt, color]) => {
        const unique = Array.from(new Set(vals.map(fmt))).filter(Boolean).slice(0, 30);
        return `<div class="finding-chip"><span class="chip-title" style="color:${color}">${escapeHtml(name)} · ${unique.length}</span>${unique.map((v) => `<div>• ${escapeHtml(v)}</div>`).join("")}</div>`;
      })
      .join(`<div class="finding-chip"><span class="chip-title">No endpoints mapped</span></div>`);
  }

  function renderFlows() {
    const flows = (payload.files || []).flatMap((f) => (f.dataflows || []).map((flow) => ({ ...flow, file: f.name })));
    $("#flow-panel").innerHTML = flows.length
      ? flows.slice(0, 40).map((flow, i) => {
          const sev = flow.severity || "MEDIUM";
          const color = SEV_COLOR[sev] || "#22d3ee";
          const path = (flow.flow || []).slice(0, 8).join(" → ");
          const quality = flow.analysis_quality ? `<span class="quality-chip quality-${flow.analysis_quality}">${escapeHtml(flow.analysis_quality)} quality</span>` : "";
          const limits = (flow.limitations || []).slice(0, 2).map((l) => `<br><span style="color:#fbbf24;font-size:11px">⚠ ${escapeHtml(l)}</span>`).join("");
          return `<li style="animation-delay:${i * 0.04}s">
            <span class="risk-dot" style="color:${color}"></span>
            <span><b>${escapeHtml(flow.type || "Source→sink flow")}</b> · ${escapeHtml(STATUS_LABEL[getStatus(flow)] || flow.status || "open")} · conf ${escapeHtml(CONF_LABEL[flow.confidence] || flow.confidence || "?")} · ${escapeHtml(flow.file || "")} ${flow.line ? `· L${flow.line}` : ""}
            ${quality}
            <br><span style="color:#8ea2c1">source: ${escapeHtml(flow.source || "unknown")} → sink: ${escapeHtml(flow.sink || "")}</span>
            ${path ? `<br><span style="color:#c084fc">path: ${escapeHtml(path)}</span>` : ""}
            ${limits}</span>
          </li>`;
        }).join("")
      : `<li><span class="risk-dot" style="color:#22d3ee"></span><span>No source-to-sink flows detected.</span></li>`;
  }

  function renderSecrets() {
    const secrets = (payload.files || []).flatMap((f) => (f.secrets || []).map((s) => ({ s, f: f.name })));
    const keys = (payload.files || []).flatMap((f) => (f.keys || []).map((s) => ({ s, f: f.name })));
    const ivs = (payload.files || []).flatMap((f) => (f.ivs || []).map((s) => ({ s, f: f.name })));
    const configs = (payload.files || []).flatMap((f) => (f.configs || []).map((s) => ({ s, f: f.name })));
    const panels = [
      ["Secrets", secrets, (x) => `${x.s} (${x.f})`, "#ff4d6d"],
      ["Crypto Keys", keys, (x) => `${x.s} (${x.f})`, "#ff9f43"],
      ["IV / Nonce", ivs, (x) => `${x.s} (${x.f})`, "#ffd166"],
      ["Hardcoded Config", configs, (x) => `${x.s}`, "#fbbf24"],
    ];
    $("#secrets-panel").innerHTML = panels
      .filter(([, v]) => v && v.length)
      .map(([name, vals, fmt, color]) => `<div class="finding-chip"><span class="chip-title" style="color:${color}">${escapeHtml(name)} · ${vals.length}</span>${vals.slice(0, 30).map((x) => `<div>• ${escapeHtml(fmt(x))}</div>`).join("")}</div>`)
      .join(`<div class="finding-chip"><span class="chip-title">No sensitive data surfaced</span></div>`);
  }
