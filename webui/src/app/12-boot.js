  function isToolPage() {
    return !!$("#code-input");
  }

  function init() {
    initParticles();
    initChrome();
    initChartResponsiveness();
    if (isToolPage()) {
      initTool();
    } else if (location.hash.startsWith("#scan=") && isLocalPage()) {
      // A hand-off link landed on a non-tool page. On the engine's own server
      // the console lives at "/", so carry the fragment over there.
      location.replace("/" + location.hash);
      return;
    }
    checkBackend().then((ok) => {
      scheduleEnginePoll();
      // A transferred scan needs pairing before it can start: open the setup
      // dialog once, with the token field ready, instead of waiting silently.
      if (!ok && pendingScanTransfer && !transferPrompted) {
        transferPrompted = true;
        openPrivacyModal();
      }
    });
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !backendConnected) checkBackend();
    });
    window.addEventListener("focus", () => {
      if (!backendConnected) checkBackend();
    });
  }

  function initTool() {
    initTabs();
    initViews();
    initUpload();

    // A scan handed off from the hosted page arrives in the #scan= fragment
    // (the fragment never leaves the browser, so the code/URL stays local).
    // Consume it once and let it run as soon as the engine is paired.
    const transfer = parseScanTransfer();
    if (transfer) {
      history.replaceState(null, "", location.pathname + location.search);
      pendingScanTransfer = transfer;
    }
    maybeRunPendingTransfer();

    // Paste / Upload sub-tab toggle inside the Paste Code pane.
    $$(".inline-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        $$(".inline-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        const which = tab.dataset.input;
        $$('[data-input-pane]').forEach((pane) => {
          pane.hidden = pane.dataset.inputPane !== which;
        });
      });
    });
    $("#code-input").value = SAMPLE;
    $("#analyze-code").addEventListener("click", analyzeCode);
    $("#analyze-url").addEventListener("click", analyzeUrl);
    $("#export-html").addEventListener("click", () => exportReport("html"));
    $("#export-txt").addEventListener("click", () => exportReport("txt"));
    $("#export-csv").addEventListener("click", () => exportReport("csv"));
    $("#export-sarif").addEventListener("click", () => exportReport("sarif"));
    $("#export-openapi").addEventListener("click", () => exportReport("openapi"));
    $("#export-json").addEventListener("click", () => exportReport("json"));
    $("#load-sample").addEventListener("click", () => {
      $("#code-input").value = SAMPLE;
      $("#pane-code").scrollIntoView({ behavior: "smooth", block: "center" });
    });
    $("#close-modal").addEventListener("click", closePrivacyModal);
    $("#retry-backend").addEventListener("click", retryBackend);
    $("#cancel-scan").addEventListener("click", cancelCurrentJob);
    initStorageControls();
    const tokenField = $("#engine-token");
    if (tokenField) tokenField.value = apiToken();
    // Copy buttons in the setup modal (generic, per data-copy target).
    $$("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-copy");
        const node = target ? document.getElementById(target) : null;
        // Copy commands only: shell comments in the sample (e.g. "# downloads
        // & starts the engine on first run") explain the command in the UI but
        // should not end up in the terminal.
        const raw = node ? node.textContent : "";
        const code = raw
          .split("\n")
          .filter((line) => !/^\s*#/.test(line))
          .join("\n")
          .trim();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(code);
        } else {
          const ta = document.createElement("textarea");
          ta.value = code;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          ta.remove();
        }
        const original = btn.textContent;
        btn.textContent = "✅ Copied";
        setTimeout(() => (btn.textContent = original), 1600);
      });
    });

    // Setup modal tabs (one-file launcher vs git clone).
    $$(".setup-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        $$(".setup-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        const which = tab.dataset.setup;
        $$(".setup-pane").forEach((pane) => {
          pane.hidden = pane.dataset.setupPane !== which;
        });
      });
    });
    // Arrow-key navigation between the analysis views.
    const viewTabs = $$(".view-tab");
    viewTabs.forEach((tab, index) => {
      tab.addEventListener("keydown", (event) => {
        const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
        if (!step) return;
        event.preventDefault();
        const next = viewTabs[(index + step + viewTabs.length) % viewTabs.length];
        activateView(next.dataset.view);
        next.focus();
      });
    });

    // Restore the previous result of this tab, if there is one.
    if (restorePayload()) {
      renderDashboard();
      const meta = $("#result-meta");
      if (meta) meta.textContent += " · restored from this tab (reload cleared nothing, no re-scan needed)";
    }

    // Ctrl/Cmd+Enter runs the analysis for whichever pane is active.
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        if ($("#pane-code").classList.contains("active")) analyzeCode();
        else analyzeUrl();
      }
    });
  }

  // Escape closes the setup dialog on every page.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closePrivacyModal();
  });

  document.addEventListener("DOMContentLoaded", init);
})();
