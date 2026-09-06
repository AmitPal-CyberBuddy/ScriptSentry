  const STATUS_CYCLE = ["open", "needs_review", "confirmed", "false_positive", "informational"];
  const STATUS_LABEL = {
    open: "Open",
    needs_review: "Needs review",
    confirmed: "Confirmed",
    false_positive: "False positive",
    informational: "Informational",
    potential: "Needs review",
  };
  const OBSERVATION_STATUSES = new Set(["informational", "false_positive"]);

  // The status the *engine* reported, before any local triage override.
  // Normalised so "potential" (legacy) maps onto the current vocabulary.
  function getStatusRaw(f) {
    const raw = String((f && f.status) || "").trim().toLowerCase();
    if (!raw) return "";
    return raw === "potential" ? "needs_review" : raw;
  }

  function isObservation(f) {
    if (f.observation) return true;
    if (f.sanitization_detected) return true;
    if (OBSERVATION_STATUSES.has(getStatusRaw(f))) return true;
    return false;
  }



  function findingKey(f) {
    return `${f.id || f.type || "finding"}|${f.file || ""}|${f.line || 0}|${String(f.sink || "").slice(0, 80)}`;
  }

  function getStatus(f) {
    const key = findingKey(f);
    const stored = (localStorage.getItem("scriptsentry-triage") || "{}");
    try {
      const map = JSON.parse(stored);
      return map[key] || f.status || "needs_review";
    } catch {
      return f.status || "needs_review";
    }
  }

  function setStatus(f) {
    const key = findingKey(f);
    const cur = STATUS_CYCLE.indexOf(getStatus(f));
    const next = STATUS_CYCLE[(cur + 1) % STATUS_CYCLE.length];
    let map;
    try { map = JSON.parse(localStorage.getItem("scriptsentry-triage") || "{}"); } catch { map = {}; }
    map[key] = next;
    localStorage.setItem("scriptsentry-triage", JSON.stringify(map));
    renderUnifiedFindings();
  }

  function renderUnifiedFindings() {
    const all = (payload.summary.findings || []).concat(payload.summary.dataflows || []).map((f) => ({ ...f, file: f.file || payload.meta.source }));
    const unique = new Map();
    all.forEach((f) => unique.set(findingKey(f), f));
    // Actionable findings only; pure observations are shown separately under
    // "Security Observations".
    const findings = Array.from(unique.values()).filter((f) => {
      const st = getStatus(f);
      return !(OBSERVATION_STATUSES.has(st) || (f.observation && st !== "open" && st !== "confirmed" && st !== "false_positive"));
    });
    // Severity counts drive the filter chips so you can see the shape of the
    // scan before clicking anything.
    const sevCounts = {};
    findings.forEach((f) => {
      const sev = String(f.severity || "MEDIUM").toUpperCase();
      sevCounts[sev] = (sevCounts[sev] || 0) + 1;
    });
    const sevButtons = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
      .filter((sev) => sevCounts[sev])
      .map((sev) => `<button class="file-tab" data-sev="${sev}" title="Filter by ${sev} severity">`
        + `${sev} <b>${sevCounts[sev]}</b></button>`)
      .join("");

    $("#finding-filters").innerHTML = [
      `<input id="finding-search" class="finding-search" type="search" placeholder="Filter by type, file, source or sink…"
              value="${escapeHtml(window.__findingSearch || "")}" aria-label="Search findings" />`,
      ["all", "All"],
      ["open", "Open"],
      ["needs_review", "Needs review"],
      ["confirmed", "Confirmed"],
      ["false_positive", "False positive"],
      ["informational", "Info"],
    ].map((entry) => (typeof entry === "string"
      ? entry
      : `<button class="file-tab ${entry[0] === "all" ? "active" : ""}" data-f="${entry[0]}">${entry[1]}</button>`)).join("")
      + sevButtons;

    const filter = (window.__findingFilter || "all");
    const severity = window.__findingSeverity || "";
    const term = String(window.__findingSearch || "").trim().toLowerCase();
    const matches = (f) => {
      if (filter !== "all" && getStatus(f) !== filter) return false;
      if (severity && String(f.severity || "").toUpperCase() !== severity) return false;
      if (!term) return true;
      return [f.type, f.id, f.file, f.source, f.sink, f.evidence]
        .map((v) => String(Array.isArray(v) ? v.join(" ") : (v == null ? "" : v)).toLowerCase())
        .join(" ").includes(term);
    };
    const list = findings.filter(matches);

    $("#unified-findings").innerHTML = list.length
      ? list.slice(0, 80).map((f, i) => {
          const sev = f.severity || "MEDIUM";
          const color = SEV_COLOR[sev] || "#22d3ee";
          const st = getStatus(f);
          const quality = f.analysis_quality ? `<span class="quality-chip quality-${f.analysis_quality}">${escapeHtml(f.analysis_quality)} quality</span>` : "";
          const limits = (f.limitations || []).length
            ? `<br><span style="color:#fbbf24;font-size:11px">⚠ Analysis limit: ${escapeHtml(f.limitations[0])}</span>` : "";
          const viaMap = f.via === "source_map"
            ? ` <span title="Found by analyzing the original source code embedded in the bundle's source map" style="color:#60a5fa;font-size:11px">🔗 source map</span>` : "";
          return `<li style="animation-delay:${i * 0.03}s">
            <span class="risk-dot" style="color:${color}"></span>
            <span><b>${escapeHtml(f.type || f.id || "finding")}</b> · ${escapeHtml(f.severity || "")} · conf ${escapeHtml(CONF_LABEL[f.confidence] || f.confidence || "?")} · ${escapeHtml(f.file || "")}${f.line ? ` · L${f.line}` : ""}${viaMap}<br>
            <span style="color:#8ea2c1">${escapeHtml(f.source ? `${f.source} → ` : "")}${escapeHtml(f.sink || (Array.isArray(f.evidence) ? f.evidence.join(" ") : f.evidence) || "")}</span>
            ${quality}${limits}
            <button class="status-chip status-${st}" data-key="${encodeURIComponent(findingKey(f))}" title="Click to cycle triage status">${escapeHtml(STATUS_LABEL[st] || st)}</button></span>
          </li>`;
        }).join("") + (list.length > 80
          ? `<li class="truncation-note">Showing the first <b>80</b> of <b>${list.length}</b> matching findings — narrow the filters to see the rest.</li>`
          : "")
      : `<li><span class="risk-dot" style="color:#34d399"></span><span>No actionable findings for this filter. See <b>Security Observations</b> for capability signals.</span></li>`;

    $("#unified-findings").querySelectorAll(".status-chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = decodeURIComponent(btn.dataset.key || "");
        const f = findings.find((x) => findingKey(x) === key);
        if (f) setStatus(f);
      });
    });

    const filters = $("#finding-filters");
    filters.querySelectorAll(".file-tab").forEach((btn) => {
      const isStatus = !!btn.dataset.f;
      btn.classList.toggle("active", isStatus ? btn.dataset.f === filter : btn.dataset.sev === severity);
      btn.onclick = () => {
        if (isStatus) {
          window.__findingFilter = btn.dataset.f;
        } else {
          // Clicking the active severity chip again clears the filter.
          window.__findingSeverity = btn.dataset.sev === severity ? "" : btn.dataset.sev;
        }
        renderUnifiedFindings();
      };
    });

    const search = $("#finding-search");
    if (search) {
      let debounce = null;
      search.addEventListener("input", () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
          window.__findingSearch = search.value;
          renderUnifiedFindings();
        }, 180);
      });
      // Keep focus and caret position while re-rendering on each keystroke.
      if (document.activeElement === search) {
        const caret = search.value.length;
        search.focus();
        try { search.setSelectionRange(caret, caret); } catch { /* not supported */ }
      }
    }
  }

  function activateView(view) {
    $$(".view-tab").forEach((t) => {
      const on = t.dataset.view === view;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
    });
    $$(".view-group").forEach((group) => {
      group.classList.toggle("is-active", group.dataset.view === view);
    });
    window.__activeView = view;
  }

  function initViews() {
    $$(".view-tab").forEach((tab) => {
      tab.addEventListener("click", () => activateView(tab.dataset.view));
    });
    window.ScriptSentryTriage = (f) => setStatus(f);
    activateView("overview");
  }
