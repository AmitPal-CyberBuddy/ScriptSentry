  let viewedScanNote = "";

  function renderHistoryChip() {
    const box = $("#history-diff");
    if (!box) return;
    const h = payload && payload.history;
    if (!h || !h.previous_scan_id) {
      box.hidden = true;
      return;
    }
    const parts = [];
    if (h.new_count) parts.push(`<strong>${h.new_count}</strong> new`);
    if (h.resolved_count) parts.push(`<strong>${h.resolved_count}</strong> resolved`);
    parts.push(`${h.unchanged_count || 0} unchanged`);
    box.innerHTML = `vs previous scan of this target: ${parts.join(" · ")}`;
    box.hidden = false;
  }

  async function refreshHistory() {
    const list = $("#history-list");
    const card = $("#history-card");
    if (!list || !card) return;
    const data = await getJSON("/api/history?limit=12");
    const scans = Array.from(data.scans || []);
    if (!scans.length && !viewedScanNote) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const note = $("#history-note");
    if (note) note.textContent = viewedScanNote || "";
    list.innerHTML = scans.map((s) => {
      const when = s.created_at ? new Date(s.created_at * 1000).toLocaleString() : "";
      const diff = s.diff && s.diff.previous_scan_id != null
        ? ` <span class="history-counts">+${s.diff.new_count || 0} / −${s.diff.resolved_count || 0}</span>`
        : "";
      const dur = s.duration_ms ? ` · ${(s.duration_ms / 1000).toFixed(1)}s` : "";
      return `<div class="history-row">` +
        `<span class="history-when">${escapeHtml(when)}</span>` +
        `<span class="history-target" title="${escapeHtml(s.target || "")}">${escapeHtml(s.target || s.mode || "")}</span>` +
        `<span class="meta">${s.files_total || 0} file(s)${dur} · ${s.findings_total || 0} finding(s)${diff}</span>` +
        (s.report_stored
          ? `<button class="btn ghost history-view" data-scan="${s.scan_id}">View</button>`
          : `<span class="meta">summary only</span>`) +
        `</div>`;
    }).join("");
    list.querySelectorAll(".history-view").forEach((btn) => {
      btn.addEventListener("click", () => viewHistoryScan(btn.dataset.scan, btn));
    });
  }

  async function viewHistoryScan(scanId, btn) {
    if (btn) btn.disabled = true;
    try {
      const data = await getJSON(`/api/history/${encodeURIComponent(scanId)}?include=payload`);
      if (!data.scan || !data.scan.payload) return;
      payload = data.scan.payload;
      const when = data.scan.created_at ? new Date(data.scan.created_at * 1000).toLocaleString() : "";
      viewedScanNote = `viewing scan #${data.scan.scan_id} from ${when} (start a new scan to return to live results)`;
      renderDashboard();
      const chip = $("#history-diff");
      if (chip) chip.hidden = true;
      refreshHistory().catch(() => {});
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function setFieldError(inputId, errorId, message, { neutral = false } = {}) {
    const err = $(errorId);
    const input = $(inputId);
    if (err) {
      err.textContent = message || "";
      err.hidden = !message;
      err.classList.toggle("is-neutral", neutral);
    }
    if (input) input.classList.toggle("input-invalid", !!message && !neutral);
    if (message && !neutral && input) {
      input.focus();
      input.setAttribute("aria-invalid", "true");
    } else if (input) {
      input.removeAttribute("aria-invalid");
    }
  }

  function isValidHttpUrl(value) {
    const v = String(value || "").trim();
    if (!v) return false;
    let u;
    try {
      u = new URL(v);
    } catch {
      return false;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (!u.hostname) return false;
    // No credentials allowed in the target URL.
    if (u.username || u.password) return false;
    return true;
  }

  async function analyzeCode() {
    const code = $("#code-input").value;
    if (!code.trim()) {
      setFieldError("#code-input", "#code-error", "Paste some JavaScript to analyze first.");
      return;
    }
    setFieldError("#code-input", "#code-error", "");
    // Build the request before the connectivity check so that, when the
    // hosted page hands off to the local dashboard, the exact analysis the
    // user asked for travels with the link.
    const query = {
      mode: "code",
      code,
      filename: $("#filename-input").value || "inline.js",
    };
    lastQuery = query;
    currentScanRequest = query;
    if (!(await ensureBackend())) return;
    showLoading("Analyzing JavaScript…");
    try {
      const data = await postJSON("/api/analyze", query);
      lastJobId = data.job_id;
      renderProgress(data.job || { percent: 0, message: "Starting…" });
      await pollJob(data.job_id);
      await finishJob(data.job_id);
    } catch (err) {
      await handleAnalysisError(err, { urlMode: false });
    } finally {
      hideLoading();
    }
  }

  async function analyzeUrl() {
    const rawUrl = $("#url-input").value.trim();
    setFieldError("#url-input", "#url-error", "");
    if (!rawUrl) {
      setFieldError("#url-input", "#url-error", "Enter a target URL to scan — for example https://example.com or a direct https://…/app.js link.");
      return;
    }
    if (!isValidHttpUrl(rawUrl)) {
      setFieldError(
        "#url-input", "#url-error",
        "That doesn't look like a valid http(s) URL. Use a full address such as https://example.com. Local/private addresses and URLs containing credentials are rejected.",
      );
      return;
    }
    const url = rawUrl;
    // Build the request before the connectivity check (see analyzeCode):
    // a hand-off to the local dashboard must carry the exact target settings.
    const query = {
      mode: "url",
      url,
      profile: $("#profile").value,
      max_depth: parseInt($("#max-depth").value, 10),
      max_files: parseInt($("#max-files").value, 10),
      max_workers: parseInt($("#workers").value, 10),
      timeout: 30,
    };
    lastQuery = query;
    currentScanRequest = query;
    if (!(await ensureBackend())) return;
    // Real stage messages take over from this line within ~200ms — the engine
    // reports recon/discover/download before the first poll lands.
    showLoading("Starting scan — the engine will report each stage below.");
    try {
      const data = await postJSON("/api/analyze", query);
      lastJobId = data.job_id;
      renderProgress(data.job || { percent: 0, message: "Starting…" });
      await pollJob(data.job_id);
      await finishJob(data.job_id);
    } catch (err) {
      await handleAnalysisError(err, { urlMode: true });
    } finally {
      hideLoading();
    }
  }


  /* ---------------- Local file upload ---------------- */
