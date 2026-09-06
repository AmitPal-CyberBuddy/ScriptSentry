  function renderProgress(job) {
    lastJobSnapshot = job;
    lastRenderAt = performance.now();
    recordActivity(job);
    drawProgress(job);
  }

  function tickProgress() {
    if (!lastJobSnapshot) return;
    const dt = Math.max(0, performance.now() - lastRenderAt);
    drawProgress({
      ...lastJobSnapshot,
      elapsed_ms: Number(lastJobSnapshot.elapsed_ms || 0) + dt,
      since_update_ms: Number(lastJobSnapshot.since_update_ms || 0) + dt,
    });
  }

  function drawProgress(job) {
    const text = $("#loading-text");
    const fill = $("#progress-fill");
    const stats = $("#progress-stats");
    if (!text || !fill || !stats) return;
    const pct = Math.max(0, Math.min(100, Number(job.percent || 0)));

    // A cancel is the user's own action. The instant it is requested (locally
    // or by the engine) the headline switches to "Canceling…" and stays there,
    // overriding late scan messages, until the poll loop receives the terminal
    // "canceled" status and hides the panel.
    const running = job.status === "running" || job.status === "queued";
    const canceling = (cancelRequested || job.canceling) && running;
    const panel = $("#loading");
    const cancelBtn = $("#cancel-scan");
    if (panel) panel.classList.toggle("is-canceling", canceling);
    if (cancelBtn) cancelBtn.disabled = canceling;
    if (canceling) {
      text.textContent = "Canceling scan — stopping the current work…";
    } else {
      text.textContent = job.message || (job.phase || "Working…");
    }
    fill.style.width = `${pct}%`;
    renderStages(job);
    renderActivity(job);

    // How long since the engine last reported?  A quiet stretch usually means
    // one big bundle is being parsed or beautified — normal work that simply
    // produces no events — while a *failed* poll means the engine is gone.
    // Show the age so "still working" and "lost contact" are distinguishable
    // at a glance instead of both looking like an endless spinner.
    const quietMs = running ? Math.max(0, Number(job.since_update_ms || 0)) : 0;
    const quiet = !canceling && quietMs >= QUIET_HINT_MS;
    if (panel) panel.classList.toggle("is-quiet", quiet);

    const hint = $("#progress-hint");
    if (hint) {
      if (canceling) {
        const since = Date.now() - (cancelRequestedAt || Date.now());
        hint.textContent = `Waiting for the engine to stop (${formatDuration(since)}). A large bundle may need a few seconds to wind down.`;
        hint.hidden = false;
      } else if (quiet && quietMs >= QUIET_STUCK_MS) {
        // Only after minutes of *total* silence (the engine now emits
        // in-file heartbeats, so quiet really means quiet) does cancel
        // become the suggested escape hatch — and even then the advice is to
        // check the engine's terminal first, since "stuck" and "working on a
        // very large bundle" look identical from the outside.
        hint.textContent = `No new updates for ${formatDuration(quietMs)} (elapsed ${formatDuration(job.elapsed_ms)}). `
          + "If the engine's own terminal shows no activity either, Cancel and re-run with a smaller Max files cap — partial results are not saved.";
        hint.hidden = false;
      } else if (quiet && quietMs >= QUIET_STALL_MS) {
        const stageNote = STAGE_QUIET_NOTES[job.stage || job.phase] || STAGE_QUIET_NOTES.analyze;
        const etaBit = job.eta_seconds != null
          ? ` About ${formatDuration(job.eta_seconds * 1000)} of work is estimated.`
          : "";
        hint.textContent = `${stageNote} No new updates for ${formatDuration(quietMs)}.${etaBit}`;
        hint.hidden = false;
      } else if (quiet) {
        // Explain *why* this stage is quiet before suggesting anything is wrong.
        const stageNote = STAGE_QUIET_NOTES[job.stage || job.phase] || STAGE_QUIET_NOTES.analyze;
        hint.textContent = stageNote;
        hint.hidden = false;
      } else if (running && Number(job.elapsed_ms || 0) >= LONG_SCAN_NOTE_MS) {
        hint.textContent = "Large targets can take several minutes. Keep this tab open, or Cancel to stop early — results are only written when the scan finishes.";
        hint.hidden = false;
      } else {
        hint.hidden = true;
      }
    }

    // An ETA is only as good as what the estimator knows. Early on (and in
    // long quiet stretches) the number comes from the workload model — the
    // files/bounds discovered by recon/download and the scan settings — and
    // it is labelled "estimating…" until the observed rate can back it up.
    const confidence = Number(job.eta_confidence || 0);
    let eta = "—";
    if (job.eta_seconds != null) {
      eta = confidence < 0.5 ? "estimating…" : `~${formatDuration(job.eta_seconds * 1000)} left`;
    }
    // `total` is the engine's current work estimate, not the file cap.
    const files = job.total ? `${job.files_scanned || 0}/${job.total}` : `${job.files_scanned || 0}`;
    const scanned = Number(job.bytes_scanned || 0);
    const bytesTotal = Number(job.total_bytes || 0);
    const bytesScanned = formatBytes(scanned);
    const bytesLabel = bytesTotal > scanned && scanned > 0
      ? `${bytesScanned} of ~${formatBytes(bytesTotal)}`
      : bytesScanned;
    const lastUpdate = running
      ? (quietMs >= 5000 ? `${formatDuration(quietMs)} ago` : "just now")
      : "—";
    stats.innerHTML = [
      ["stage", canceling ? "canceling" : (job.stage || job.phase || "queued")],
      ["files", files],
      ["bytes", bytesLabel],
      ["pct", `${pct.toFixed(0)}%`],
      ["elapsed", formatDuration(job.elapsed_ms)],
      ["eta", eta],
      ["last update", lastUpdate],
    ].map(([k, v]) => `<b>${escapeHtml(k)}</b>: ${escapeHtml(String(v))}`).join(" · ");
  }

  // Controls that must be unusable while a scan occupies the engine:
  // starting a second scan (the old code disabled the paste/URL buttons but
  // forgot "Analyze Files"), or exporting a report for a job that is still
  // running — the engine rejects that with 409, and the buttons should say
  // "wait" before the request is ever made.
  const SCAN_BUSY_SELECTORS = [
    "#analyze-code", "#analyze-url", "#analyze-files",
    "#export-html", "#export-txt", "#export-csv", "#export-sarif", "#export-json", "#export-openapi",
    // Data & storage controls: no destructive storage action may race a scan.
    "#storage-delete-all", "#storage-clear-browser", "#storage-export",
  ];

  function setScanBusy(busy) {
    SCAN_BUSY_SELECTORS.forEach((sel) => {
      const btn = $(sel);
      if (btn) btn.disabled = busy;
    });
    // Historical report views must not fight a live scan for the dashboard.
    document.querySelectorAll(".history-view, .storage-scan-view").forEach((btn) => { btn.disabled = busy; });
    document.querySelectorAll(".storage-scan-delete").forEach((btn) => { btn.disabled = busy; });
  }

  function showLoading(text) {
    const panel = $("#loading");
    if (panel) {
      panel.classList.add("show");
      panel.classList.remove("is-quiet");
      panel.classList.remove("is-canceling");
    }
    // New scan: reset the previous run's cancellation and activity state.
    cancelRequested = false;
    cancelRequestedAt = 0;
    lastJobSnapshot = null;
    lastRenderAt = 0;
    activityLog = [];
    const cancelBtn = $("#cancel-scan");
    if (cancelBtn) cancelBtn.disabled = false;
    $("#loading-text").textContent = text || "Analyzing…";
    setScanBusy(true);
    const activity = $("#progress-activity");
    if (activity) {
      activity.hidden = true;
      activity.innerHTML = "";
    }
    const stages = $("#progress-stages");
    if (stages) {
      stages.hidden = true;
      stages.innerHTML = "";
    }
    // Client-side clock: keeps "elapsed" and "last update … ago" moving while
    // the engine is quietly parsing one big bundle (it only advances those
    // fields when it emits an event).
    if (progressTicker) clearInterval(progressTicker);
    progressTicker = setInterval(tickProgress, 250);
  }

  function hideLoading() {
    if (progressTicker) {
      clearInterval(progressTicker);
      progressTicker = null;
    }
    lastJobSnapshot = null;
    lastRenderAt = 0;
    cancelRequested = false;
    cancelRequestedAt = 0;
    const panel = $("#loading");
    if (panel) {
      panel.classList.remove("show");
      panel.classList.remove("is-quiet");
      panel.classList.remove("is-canceling");
    }
    setScanBusy(false);
    const cancelBtn = $("#cancel-scan");
    if (cancelBtn) cancelBtn.disabled = false;
    const fill = $("#progress-fill");
    const stats = $("#progress-stats");
    const hint = $("#progress-hint");
    if (fill) fill.style.width = "0%";
    if (stats) stats.innerHTML = "";
    if (hint) {
      hint.hidden = true;
      hint.textContent = "";
    }
  }

  function animateNumber(el, target, suffix = "") {
    const start = 0;
    const duration = 900;
    const startTime = performance.now();
    function frame(now) {
      const p = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(start + (target - start) * eased) + suffix;
      if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  /* ---------------- Particle background ---------------- */
