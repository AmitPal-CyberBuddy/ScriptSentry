  async function retryBackend() {
    const field = $("#engine-token");
    if (field && field.value.trim()) setApiToken(field.value);
    const ok = await checkBackend();
    if (ok) closePrivacyModal();
  }

  /* ---- Picking up a scan handed off from the hosted page ---- */

  function selectInputPane(which) {
    // which: "url" | "paste" | "files"
    if (which === "url") {
      const tab = $('.tab[data-pane="url"]');
      if (tab) tab.click();
      return;
    }
    const codeTab = $('.tab[data-pane="code"]');
    if (codeTab) codeTab.click();
    const inline = $(`.inline-tab[data-input="${which === "files" ? "upload" : "paste"}"]`);
    if (inline) inline.click();
  }

  function showTransferNote(text, isWarning = false) {
    const node = $("#transfer-note");
    if (!node) return;
    node.textContent = text;
    node.classList.toggle("is-warn", !!isWarning);
    node.hidden = false;
    if (!isWarning) {
      setTimeout(() => { node.hidden = true; }, 15000);
    }
  }

  // Fill the console from a transferred request and start the scan the user
  // already launched on the hosted page. Runs only once, and only when the
  // engine is connected *and* paired (a token in this tab counts).
  async function maybeRunPendingTransfer() {
    if (!pendingScanTransfer || !backendConnected) return;
    const req = pendingScanTransfer;
    pendingScanTransfer = null;
    try {
      // An oversized request arrived without its bodies (the link budget was
      // exceeded). Pre-selecting the right tab is all we can honestly do —
      // filling the inputs with "undefined" would scan the wrong thing.
      if (req.tooLarge) {
        selectInputPane(req.mode === "url" ? "url" : req.mode === "files" ? "files" : "paste");
        const names = Array.isArray(req.names) && req.names.length
          ? ` Re-pick: ${req.names.join(", ")}.` : "";
        showTransferNote(
          "The hosted page could not fit this request inside the hand-off link (too large). "
          + "Please enter it again here." + names,
          true,
        );
        return;
      }
      if (req.mode === "url") {
        selectInputPane("url");
        $("#url-input").value = req.url;
        if (req.profile) $("#profile").value = req.profile;
        if (req.max_depth) $("#max-depth").value = String(req.max_depth);
        if (req.max_files) $("#max-files").value = String(req.max_files);
        if (req.max_workers) $("#workers").value = String(req.max_workers);
        showTransferNote(`✅ Scan carried over from the hosted page — target ${req.url}. Starting…`);
        $("#console").scrollIntoView({ behavior: "smooth", block: "start" });
        await new Promise((r) => setTimeout(r, 400));
        await analyzeUrl();
      } else if (req.mode === "code") {
        selectInputPane("paste");
        $("#code-input").value = req.code;
        if (req.filename) $("#filename-input").value = req.filename;
        showTransferNote("✅ Your pasted code was carried over from the hosted page. Starting…");
        $("#console").scrollIntoView({ behavior: "smooth", block: "start" });
        await new Promise((r) => setTimeout(r, 400));
        await analyzeCode();
      } else if (req.mode === "files") {
        selectInputPane("files");
        pendingFiles = req.files.map((f) => ({
          name: f.filename,
          size: new Blob([f.code]).size,
          content: f.code,
        }));
        updateFileList();
        showTransferNote(`✅ ${req.files.length} file(s) carried over from the hosted page. Starting…`);
        $("#console").scrollIntoView({ behavior: "smooth", block: "start" });
        await new Promise((r) => setTimeout(r, 400));
        await analyzeFiles();
      }
    } catch (err) {
      showTransferNote(`Could not carry the scan over automatically: ${err && err.message ? err.message : err}`, true);
    }
  }

  /* ---------------- Core helpers ---------------- */

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  async function postJSON(url, data) {
    const res = await fetch(apiUrl(url), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(data),
    });
    let body;
    try {
      body = await res.json();
    } catch {
      throw new Error("The analysis engine returned an unreadable response.");
    }
    if (!res.ok || body.ok === false) {
      throw new Error(body.error || "Analysis failed with an unknown error.");
    }
    return body;
  }

  async function getJSON(url) {
    const res = await fetch(apiUrl(url), { cache: "no-store", headers: authHeaders() });
    let body;
    try {
      body = await res.json();
    } catch {
      throw new Error("The analysis engine returned an unreadable response.");
    }
    if (!res.ok || body.ok === false) {
      throw new Error(body.error || "Analysis failed with an unknown error.");
    }
    return body;
  }

  function formatBytes(value) {
    const n = Number(value || 0);
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
  }

  function formatDuration(ms) {
    const total = Math.max(0, Number(ms || 0));
    const s = Math.floor(total / 1000);
    const m = Math.floor(s / 60);
    return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
  }

  // Source-map chip text: distinguish "we found a reference" from "we
  // actually analyzed the original sources embedded in the map" — the latter
  // is where the accuracy upgrade lives.
  function sourceMapChipText(sm) {
    const count = sm.sources?.length || 0;
    if (sm.analyzed_sources > 0) {
      return `${count} source(s) · ${sm.analyzed_sources} analyzed · ${sm.sources_findings || 0} finding(s) from originals`;
    }
    if (sm.available) {
      return `${count} source(s) · ${sm.sources_content_count ? "contents found" : "no embedded contents"} · ${sm.analysis_note || ""}`;
    }
    return `${count} source(s) · reference unresolved`;
  }

  /* The scan runs as a pipeline (Recon -> Discover -> Download -> Normalize ->
   * Analyze -> Correlate -> Verify -> Report). Showing the stages tells you
   * what the engine is doing; a bare percentage never did. */
  function renderStages(job) {
    const host = $("#progress-stages");
    if (!host) return;
    const stages = Array.isArray(job.stages) ? job.stages : [];
    if (!stages.length) {
      host.innerHTML = "";
      host.hidden = true;
      return;
    }
    host.hidden = false;
    host.innerHTML = stages.map((stage) => {
      const state = stage.state === "active" ? "active" : (stage.state === "done" ? "done" : "pending");
      const mark = state === "done" ? "\u2713" : (state === "active" ? "\u25c9" : "\u25cb");
      return `<span class="progress-stage is-${state}" role="listitem" title="${escapeHtml(stage.description || "")}">`
        + `<span class="stage-mark" aria-hidden="true">${mark}</span>`
        + `${escapeHtml(stage.label || stage.key || "")}</span>`;
    }).join("");
  }

  // Record one engine message in the activity log. Consecutive duplicates are
  // merged (with a refreshed timestamp) so a scan re-reporting "Normalizing
  // 1/2 … 2/2" reads as movement, while a stuck stage shows only its last
  // concrete announcement instead of a wall of identical lines.
  function recordActivity(job) {
    const message = String((job && job.message) || "").trim();
    if (!message) return;
    const last = activityLog[activityLog.length - 1];
    if (last && last.message === message) {
      last.at = Date.now();
      return;
    }
    activityLog.push({ message, at: Date.now() });
    if (activityLog.length > 8) activityLog.shift();
  }

  function renderActivity(job) {
    const host = $("#progress-activity");
    if (!host) return;
    if (!activityLog.length) {
      host.hidden = true;
      host.innerHTML = "";
      return;
    }
    // The engine reports `started_at` as an epoch (seconds); accept an ISO
    // string too, and fall back to "now − elapsed" so the relative timestamps
    // are always anchored to the real scan start.
    let startAt = 0;
    if (typeof job.started_at === "number") {
      startAt = job.started_at * 1000;
    } else if (job.started_at) {
      startAt = Date.parse(job.started_at);
    }
    if (!startAt) startAt = Date.now() - Number(job.elapsed_ms || 0);
    host.hidden = false;
    host.innerHTML = activityLog.map((entry, i) => {
      const rel = Math.max(0, entry.at - startAt);
      const latest = i === activityLog.length - 1;
      return `<span class="activity-line${latest ? " is-latest" : ""}">`
        + `<span class="activity-time">+${formatDuration(rel)}</span> ${escapeHtml(entry.message)}</span>`;
    }).join("");
    // Keep the newest line in view.
    host.scrollTop = host.scrollHeight;
  }

  // The poll loop owns the snapshot; the ticker only extrapolates the two
  // wall-clock fields (elapsed / last-update) between polls. That way the
  // engine remains the source of truth and the clock never freezes during a
  // quiet stage.