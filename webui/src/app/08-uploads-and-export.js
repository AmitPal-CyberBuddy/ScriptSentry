  let pendingFiles = [];

  const JS_EXT = /\.(js|mjs|cjs|jsx|ts|map|txt)$/i;

  function updateFileList() {
    const list = $("#file-list");
    if (!list) return;
    setFieldError("#dropzone", "#file-error", "");
    if (!pendingFiles.length) {
      list.innerHTML = "";
      return;
    }
    list.innerHTML = pendingFiles.map((f, i) => `<div class="file-item">
      <span>📄</span>
      <span class="fname">${escapeHtml(f.name)}</span>
      <span class="fsize">${formatBytes(f.size)}</span>
      <button class="fremove" data-i="${i}" title="Remove" type="button">✖</button>
    </div>`).join("");
    list.querySelectorAll(".fremove").forEach((btn) => {
      btn.addEventListener("click", () => {
        pendingFiles.splice(parseInt(btn.dataset.i, 10), 1);
        updateFileList();
      });
    });
  }

  function addFiles(fileList) {
    const files = Array.from(fileList || []);
    const rejected = [];
    for (const file of files) {
      const okExt = JS_EXT.test(file.name) || /javascript/i.test(file.type);
      if (!okExt) {
        rejected.push(file.name);
        continue;
      }
      if (file.size > 3 * 1024 * 1024) {
        rejected.push(`${file.name} (over 3 MB)`);
        continue;
      }
      // De-dupe by name+size.
      if (!pendingFiles.some((f) => f.name === file.name && f.size === file.size)) {
        pendingFiles.push({ name: file.name, size: file.size, handle: file });
      }
    }
    if (rejected.length) {
      setFieldError("#dropzone", "#file-error",
        "Skipped: " + rejected.slice(0, 4).map(escapeHtml).join(", ") +
        (rejected.length > 4 ? ` (and ${rejected.length - 4} more)` : "") +
        ". Supported: .js / .mjs / .cjs / .jsx / .ts, max 3 MB each.");
    }
    updateFileList();
  }

  function initUpload() {
    const input = $("#file-input");
    const zone = $("#dropzone");
    if (input) {
      input.addEventListener("change", () => addFiles(input.files));
    }
    if (zone) {
      ["dragenter", "dragover"].forEach((ev) =>
        zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("dragover"); }));
      ["dragleave", "drop"].forEach((ev) =>
        zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("dragover"); }));
      zone.addEventListener("drop", (e) => {
        if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
      });
    }
    const clearBtn = $("#clear-files");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        pendingFiles = [];
        if (input) input.value = "";
        setFieldError("#dropzone", "#file-error", "");
        updateFileList();
      });
    }
    const analyzeBtn = $("#analyze-files");
    if (analyzeBtn) analyzeBtn.addEventListener("click", analyzeFiles);
  }

  async function analyzeFiles() {
    setFieldError("#dropzone", "#file-error", "");
    if (!pendingFiles.length) {
      setFieldError("#dropzone", "#file-error", "Choose at least one JavaScript file to analyze.");
      return;
    }
    // Read files locally in the browser BEFORE the connectivity check, so a
    // hosted-page hand-off can carry the exact files in the transfer link
    // (they stay in the browser either way — nothing is uploaded to a cloud).
    const payloadFiles = [];
    for (const f of pendingFiles) {
      if (typeof f.content === "string" && f.content.trim()) {
        payloadFiles.push({ filename: f.name, code: f.content });
        continue;
      }
      if (!f.handle) continue;
      try {
        const text = await f.handle.text();
        if (text && text.trim()) payloadFiles.push({ filename: f.name, code: text });
      } catch {
        setFieldError("#dropzone", "#file-error", `Could not read ${f.name}.`);
        return;
      }
    }
    if (!payloadFiles.length) {
      setFieldError("#dropzone", "#file-error", "Could not read the selected files.");
      return;
    }
    const query = { mode: "code", files: payloadFiles };
    lastQuery = query;
    currentScanRequest = query;
    if (!(await ensureBackend())) return;
    showLoading(`Analyzing ${payloadFiles.length} local file(s)…`);
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

  /* ---------------- Report export ---------------- */

  async function exportReport(format) {
    if (!lastQuery) {
      setEngineStatus("checking", "Run an analysis first, then export a report.");
      $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    if (!(await ensureBackend())) return;
    showLoading("Generating report…");
    try {
      const query = lastJobId ? { ...lastQuery, job_id: lastJobId } : lastQuery;
      const res = await fetch(apiUrl(`/api/report?format=${format}`), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(query),
      });
      if (!res.ok) {
        // The engine answers errors as JSON ({ok:false, error}); surface the
        // real reason ("Analysis is still running…", unknown job, failed
        // scan) instead of a generic failure.
        let message = "";
        try {
          const body = await res.json();
          message = (body && body.error) || "";
        } catch {
          const text = await res.text().catch(() => "");
          message = text ? text.slice(0, 240) : "";
        }
        const err = new Error(message || "Report generation failed.");
        err.statusCode = res.status;
        throw err;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = {
        txt: "scriptsentry-report.txt",
        html: "scriptsentry-report.html",
        csv: "scriptsentry-report.csv",
        sarif: "scriptsentry-report.sarif",
      }[format] || "scriptsentry-report.txt";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      setEngineStatus("checking", err.message || "Report generation failed.");
      // Only a connection/pairing problem should open the setup dialog. An
      // engine *rejection* (still running, failed scan, unknown job) is an
      // analysis-state issue — it is shown in the status pill, not as a
      // "pair your engine" wizard.
      if (isConnectionFailure(err)) {
        showConnectionError(err);
        openPrivacyModal();
      }
    } finally {
      hideLoading();
    }
  }

  /* ---------------- Rendering ---------------- */

  function renderEngineNotes() {
    const node = $("#engine-notes");
    if (!node || !payload) return;
    const notes = [];
    const meta = payload.meta || {};
    const parser = meta.ast_parser || {};
    // An empty URL scan used to look identical to a successful one. Say why
    // nothing was analyzed instead of showing an empty dashboard.
    const summary = payload.summary || {};
    if (meta.analysis_mode === "url" && Number(summary.total_files || 0) === 0) {
      const scanSummary = meta.scan_summary || {};
      const page = scanSummary.page || {};
      if (page.page_fetch === "failed") {
        notes.push(
          "<b>Nothing was analyzed — the page could not be downloaded.</b> The site may be unreachable, "
          + "blocked the engine's request (bot protection), or the URL may be wrong. Check the address "
          + "and your connection, then scan again.",
        );
      } else {
        notes.push(
          "<b>No JavaScript was discovered on this page.</b> The page may genuinely have none, or its "
          + "scripts may be injected at runtime by a loader. The optional runtime pass (headless browser) "
          + "can catch scripts that only appear after execution.",
        );
      }
    }
    if (parser.available === false) {
      // Say what it *costs*, not just that something is missing: in fallback
      // mode confidence is capped and some flows are never found, so results
      // here are a floor rather than a complete picture.
      notes.push(
        `<b>Reduced-depth analysis — results are incomplete.</b> The JavaScript parser `
        + `(<code>${escapeHtml(parser.name || "esprima")}</code>) is not installed, so this scan used `
        + "line-based matching instead of full AST taint tracking. Source-to-sink flows are capped at "
        + "<b>medium</b> confidence and some are missed entirely. Treat this as a lower bound, then install "
        + `it and re-scan: <code>${escapeHtml(parser.install_hint || "pip install esprima")}</code>.`,
      );
    }
    const mappedFiles = (payload.files || []).filter((f) => Number(f.source_map?.analyzed_sources || 0) > 0);
    if (mappedFiles.length) {
      const totalSources = mappedFiles.reduce((n, f) => n + Number(f.source_map.analyzed_sources || 0), 0);
      const mapFindings = mappedFiles.reduce((n, f) => n + Number(f.source_map.sources_findings || 0), 0);
      notes.push(
        `<b>🔗 Source maps analyzed.</b> ${totalSources} original source file(s) across ${mappedFiles.length} bundle(s) `
        + `were recovered from source maps and analyzed; ${mapFindings} finding(s) are attributed to their `
        + "original pre-build file names (marked with 🔗 in the Findings view).",
      );
    }
    const warnings = new Set();
    (payload.files || []).forEach((f) => (f.analysis_warnings || []).forEach((w) => warnings.add(w)));
    warnings.forEach((w) => notes.push(escapeHtml(w)));
    node.innerHTML = notes.length
      ? notes.map((n) => `<div class="engine-note">ℹ️ ${n}</div>`).join("")
      : "";
    node.hidden = !notes.length;
  }

  /* Keep the last result for the lifetime of this tab: a reload or an
   * accidental navigation should not cost you another scan. */