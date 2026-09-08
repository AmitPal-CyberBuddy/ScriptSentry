  let viewedScanNote = "";
  // Same list the storage panel renders, so deletions stay consistent with
  // what the history card shows without fetching twice.
  let lastHistoryScans = [];
  // Storage panel list mode: the history card fetches the newest 12; the
  // storage section can expand to the full retained history (server caps at
  // the newest 200) so "what this machine keeps" is inspectable in one place.
  let storageScansAll = false;
  let storageScansAllData = null;
  let lastStorageCount = 0;

  function renderHistoryChip() {
    const box = $("#history-diff");
    if (!box) return;
    const link = $("#history-storage-link");
    const h = payload && payload.history;
    if (!h || !h.previous_scan_id) {
      box.hidden = true;
      if (link) link.hidden = true;
      return;
    }
    // Counts first (immediate), then the finding-level revalidation summary
    // (verdicts, severity moves, coverage honesty) once it arrives.
    const parts = [];
    if (h.new_count) parts.push(`<strong>${h.new_count}</strong> new`);
    if (h.resolved_count) parts.push(`<strong>${h.resolved_count}</strong> resolved`);
    parts.push(`${h.unchanged_count || 0} unchanged`);
    box.innerHTML = `vs previous scan of this target: ${parts.join(" · ")}`;
    box.hidden = false;
    if (link) link.hidden = false;
    refreshRevalidation(h.previous_scan_id, h.scan_id);
  }

  /* Finding-level revalidation: what happened to the INITIAL findings on
     this re-scan — still there? worse? really fixed? Fetches the engine's
     comparison and renders the plain summary plus the top verdict rows. */
  async function refreshRevalidation(fromId, toId) {
    const box = $("#history-diff");
    if (!box || !fromId || !toId) return;
    try {
      const data = await getJSON(
        `/api/history/diff?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`);
      const rv = data && (data.revalidation || data.diff);
      if (!rv || !Array.isArray(rv.summary_lines)) return;
      const verdictRows = (rv.verdicts || []).slice(0, 4).map((v) => {
        const label = { worsened: "▲ worse", persisted: "● still there", new: "＋ new",
                        improved: "▼ improved", resolved: "✓ no longer detected" }[v.verdict] || v.verdict;
        const change = v.change ? ` <i>(${escapeHtml(v.change)})</i>` : "";
        return `<div class="history-row"><span class="meta">${label}</span>` +
               `<span>${escapeHtml(v.title || v.finding_id)}${change}</span></div>`;
      }).join("");
      box.innerHTML = `revalidation vs previous scan:<br/>` +
        rv.summary_lines.map((l) => `<div>${escapeHtml(l)}</div>`).join("") +
        (verdictRows ? `<div style="margin-top:6px">${verdictRows}</div>` : "");
    } catch {
      /* The counts rendered above remain; revalidation is an enhancement. */
    }
  }

  async function refreshHistory() {
    const list = $("#history-list");
    const card = $("#history-card");
    if (!list || !card) return;
    const data = await getJSON("/api/history?limit=12");
    const scans = Array.from(data.scans || []);
    lastHistoryScans = scans;
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


  /* ---------------- Data & storage trust panel ----------------
   *
   * The inventory /api/storage reports plus the destructive actions over it:
   * per-scan delete, delete-all, browser-data clearing and the JSON export.
   * Everything runs through the token-gated DELETE/GET surface; the UI only
   * ever asks for confirmation before touching anything.
   */

  function setStorageStatus(message) {
    const node = $("#storage-status");
    if (!node) return;
    node.textContent = message || "";
    node.hidden = !message;
    node.classList.toggle("is-neutral", !message || message.startsWith("✅"));
  }

  async function refreshStoragePanel() {
    const facts = $("#storage-facts");
    if (!facts) return;
    try {
      const data = await getJSON("/api/storage");
      renderStorageFacts(data.storage || {});
    } catch {
      facts.innerHTML = `<span class="storage-unknown">Engine not paired — storage facts appear once the engine is connected.</span>`;
    }
    renderStorageScans();
  }

  function renderStorageFacts(storage) {
    const facts = $("#storage-facts");
    if (!facts || !storage) return;
    lastStorageCount = storage.scan_count || 0;
    const row = (label, value) =>
      `<div class="storage-fact"><span class="storage-fact-label">${escapeHtml(label)}</span>` +
      `<span class="storage-fact-value">${value}</span></div>`;
    const when = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "—";
    const disabled = storage.history_enabled === false;
    facts.innerHTML = [
      row("History", disabled ? "recording disabled" : "recording (SQLite, WAL)"),
      row("Database", disabled ? "—" : escapeHtml(storage.db_path || "")),
      row("DB size", formatBytes(storage.db_size_bytes)),
      row("WAL size", formatBytes(storage.wal_size_bytes)),
      row("Scans", String(storage.scan_count || 0)),
      row("Findings", String(storage.finding_count || 0)),
      row("Oldest", when(storage.oldest_scan_at)),
      row("Newest", when(storage.newest_scan_at)),
      row("Retention", `newest ${storage.retention_limit || 200} scans`),
      row("Stored report payloads", formatBytes(storage.report_bytes_stored)),
      row("ETA calibration", formatBytes(storage.eta_calibration_bytes)),
    ].join("");
  }

  function renderStorageScans() {
    const list = $("#storage-scan-list");
    if (!list) return;
    const scans = (storageScansAll ? storageScansAllData : null) || lastHistoryScans || [];
    const count = storageScansAll ? storageScansAllData.length : (lastStorageCount || scans.length);
    list.innerHTML = scans.length
      ? `<div class="storage-scan-head">Scans (${storageScansAll ? scans.length : count}${storageScansAll ? " · all" : " · newest"})</div>`
        + scans.map((s) => {
          const when = s.created_at ? new Date(s.created_at * 1000).toLocaleString() : "";
          return `<div class="storage-scan-row">` +
            `<span class="history-when">#${s.scan_id}</span>` +
            `<span class="history-target" title="${escapeHtml(s.target || "")}">${escapeHtml(s.target || s.mode || "")}</span>` +
            `<span class="meta">${when} · ${s.findings_total || 0} finding(s)</span>` +
            (s.report_stored
              ? `<button class="btn ghost btn-sm storage-scan-view" data-storage-view="${s.scan_id}" type="button">View</button>`
              : "") +
            `<button class="btn ghost btn-sm storage-scan-delete" data-storage-delete="${s.scan_id}" type="button">Delete</button>` +
            `</div>`;
        }).join("")
      : `<span class="storage-unknown">No scans stored.</span>`;
    list.querySelectorAll(".storage-scan-view").forEach((btn) => {
      btn.addEventListener("click", () => viewHistoryScan(btn.dataset.storageView, btn));
    });
    list.querySelectorAll(".storage-scan-delete").forEach((btn) => {
      btn.addEventListener("click", () => deleteHistoryScan(btn.dataset.storageDelete, btn));
    });
    const toggle = $("#storage-show-all");
    if (toggle) {
      toggle.hidden = !(count > (storageScansAll ? 0 : scans.length));
      toggle.textContent = storageScansAll
        ? "Show recent only"
        : `Show all scans (${count})`;
    }
  }

  async function toggleStorageScanList() {
    const toggle = $("#storage-show-all");
    storageScansAll = !storageScansAll;
    if (storageScansAll) {
      const data = await getJSON("/api/history?limit=200");
      storageScansAllData = Array.from(data.scans || []);
    } else {
      storageScansAllData = null;
    }
    renderStorageScans();
    if (toggle) toggle.disabled = false;
  }

  async function deleteHistoryScan(scanId, btn) {
    if (!scanId) return;
    if (!confirm(`Delete scan #${scanId} and its findings from this machine's history? This cannot be undone.`)) return;
    if (btn) btn.disabled = true;
    try {
      const res = await fetch(apiUrl(`/api/history/${encodeURIComponent(scanId)}`), {
        method: "DELETE",
        headers: authHeaders(),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || body.ok === false) throw new Error(body.error || "Delete failed.");
      setStorageStatus(`✅ Deleted scan #${scanId}.`);
      await refreshHistory();
      // Keep the storage list in the mode the user chose (all vs recent).
      if (storageScansAll) {
        const full = await getJSON("/api/history?limit=200");
        storageScansAllData = Array.from(full.scans || []);
      }
      await refreshStoragePanel();
    } catch (err) {
      setStorageStatus(err && err.message ? err.message : "Delete failed.");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function deleteAllHistory() {
    if (!confirm(
      "Delete ALL scan history (scans, findings and stored reports) from this machine? "
      + "This cannot be undone. ETA timing stats are kept — they are anonymous, not your content.",
    )) return;
    try {
      const res = await fetch(apiUrl("/api/history"), { method: "DELETE", headers: authHeaders() });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || body.ok === false) throw new Error(body.error || "Delete failed.");
      setStorageStatus(`✅ Deleted ${body.deleted_scans || 0} scan(s) and ${body.deleted_findings || 0} finding(s).`);
      await refreshHistory();
      await refreshStoragePanel();
    } catch (err) {
      setStorageStatus(err && err.message ? err.message : "Delete failed.");
    }
  }

  function clearBrowserData() {
    const tokenBox = $("#storage-clear-token");
    const alsoToken = !!(tokenBox && tokenBox.checked);
    let message = "Clear this browser's stored data? This removes triage statuses (localStorage) and the last report payload (sessionStorage).";
    if (alsoToken) {
      message += " The pairing token will be removed too, and this tab will be logged out until you re-pair.";
    }
    if (!confirm(message)) return;
    try { localStorage.removeItem("scriptsentry-triage"); } catch { /* storage unavailable */ }
    try { sessionStorage.removeItem("scriptsentry_last_result"); } catch { /* storage unavailable */ }
    if (alsoToken) setApiToken("");
    setStorageStatus("✅ Cleared this browser's stored data." + (alsoToken ? " Pairing token removed." : ""));
    renderStorageScans();
  }

  async function downloadHistoryExport() {
    try {
      const res = await fetch(apiUrl("/api/history/export?include=payload"), {
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "Export failed.");
      }
      const blob = await res.blob();
      saveBlob(blob, "scriptsentry-history-export.json");
      setStorageStatus("✅ Download started — scriptsentry-history-export.json");
    } catch (err) {
      setStorageStatus(err && err.message ? err.message : "Export failed.");
    }
  }

  function initStorageControls() {
    const link = $("#history-storage-link");
    if (link) {
      link.addEventListener("click", () => {
        openPrivacyModal();
        setTimeout(() => {
          const section = $("#storage-section");
          if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 40);
      });
    }
    const deleteAll = $("#storage-delete-all");
    if (deleteAll) deleteAll.addEventListener("click", deleteAllHistory);
    const clear = $("#storage-clear-browser");
    if (clear) clear.addEventListener("click", clearBrowserData);
    const exportBtn = $("#storage-export");
    if (exportBtn) exportBtn.addEventListener("click", downloadHistoryExport);
    const showAll = $("#storage-show-all");
    if (showAll) showAll.addEventListener("click", () => {
      showAll.disabled = true;
      toggleStorageScanList().finally(() => { showAll.disabled = false; });
    });
    // Always-visible entry point in the results header: the storage panel is
    // deliberately inside the setup dialog (not a sixth view), so
    // discoverability comes from one button that opens it and scrolls there.
    const headerLink = $("#storage-open");
    if (headerLink) {
      headerLink.addEventListener("click", () => {
        openPrivacyModal();
        setTimeout(() => {
          const section = $("#storage-section");
          if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 40);
      });
    }
  }

  /* ---------------- Local file upload ---------------- */
