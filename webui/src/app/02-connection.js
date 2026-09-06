  function apiBase() {
    return (window.SCRIPTSENTRY_API || "").replace(/\/+$/, "");
  }

  function apiUrl(path) {
    return `${apiBase()}${path.startsWith("/") ? path : `/${path}`}`;
  }

  function apiToken() {
    return String(window.SCRIPTSENTRY_API_TOKEN || sessionStorage.getItem("scriptsentry_engine_token") || "").trim();
  }

  /* Hosted (GitHub Pages) vs local engine page.
   *
   * This distinction is the whole reason the setup dialog exists, and getting
   * it wrong is what made pairing look broken: a page served over HTTPS from
   * github.io CANNOT talk to `http://127.0.0.1:8000` at all.  Browsers block
   * the request as *mixed content* before it ever reaches the engine, so the
   * pairing token is never even presented — no token, however correct, can
   * make that fetch succeed.  The honest answer is to send the user to the
   * dashboard the engine itself serves, where the token is already applied.
   */
  function isLocalPage() {
    return /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)$/.test(window.location.hostname || "");
  }

  // True when this page is HTTPS but the configured engine is plain HTTP —
  // the exact combination browsers refuse to connect.
  function isMixedContentBlocked() {
    if (window.location.protocol !== "https:") return false;
    const base = apiBase();
    if (!base) return false; // same-origin: nothing to block
    return /^http:\/\//i.test(base);
  }

  // Where the user should actually be to run a scan.
  function localDashboardUrl() {
    const base = apiBase() || "http://127.0.0.1:8000";
    return base.replace(/\/+$/, "") + "/";
  }

  /* ---- Scan hand-off (hosted page → the engine's own dashboard) ----
   *
   * A github.io page physically cannot call http://127.0.0.1 (mixed content).
   * Until the request itself travelled with the user, "open the local
   * dashboard" meant re-typing the URL and re-setting every scan option there.
   * The pending request is now serialized into the link's #scan= fragment —
   * fragments stay in the browser and are never sent to any server — and the
   * local page picks it up, fills the form and starts the scan.
   */
  function toB64Url(text) {
    const bytes = new TextEncoder().encode(text);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64Url(text) {
    let normalized = text.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4) normalized += "=";
    const bin = atob(normalized);
    return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  }

  // Upper bound for a transferable request. Fragments of a few MB are fine in
  // every modern browser, but pasted code is capped by the engine at 5 MB and
  // uploads at 3 MB each — keep the link comfortably inside both limits.
  const HANDOFF_LIMIT = 2 * 1024 * 1024;

  function buildHandoffUrl() {
    const base = localDashboardUrl();
    if (!currentScanRequest) return base;
    try {
      const encoded = toB64Url(JSON.stringify(currentScanRequest));
      if (encoded.length > HANDOFF_LIMIT) {
        // Too big to carry (large upload): still hand off, minus the bodies.
        const slim = currentScanRequest.mode === "files"
          ? { mode: "files", files: [], tooLarge: true,
              names: (currentScanRequest.files || []).map((f) => f.filename) }
          : { mode: currentScanRequest.mode, tooLarge: true };
        return `${base}#scan=${toB64Url(JSON.stringify(slim))}`;
      }
      return `${base}#scan=${encoded}`;
    } catch {
      return base;
    }
  }

  function sanitizeScanRequest(req) {
    if (!req || typeof req !== "object") return null;
    const clamp = (value, lo, hi, dflt) => {
      const n = parseInt(value, 10);
      return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : dflt;
    };
    if (req.tooLarge) {
      // Bodies did not fit; just pre-select the right input mode.
      return { mode: req.mode, tooLarge: true, names: Array.isArray(req.names) ? req.names.map(String).slice(0, 50) : [] };
    }
    if (req.mode === "url") {
      if (!isValidHttpUrl(req.url)) return null;
      return {
        mode: "url",
        url: String(req.url),
        profile: ["fast", "balanced", "strict"].includes(req.profile) ? req.profile : "balanced",
        max_depth: clamp(req.max_depth, 1, 10, 5),
        max_files: clamp(req.max_files, 1, 1000, 50),
        max_workers: clamp(req.max_workers, 1, 32, 6),
      };
    }
    if (req.mode === "code" && typeof req.code === "string" && req.code.trim()) {
      if (req.code.length > HANDOFF_LIMIT) return null;
      const filename = String(req.filename || "inline.js").replace(/\x00/g, "").slice(0, 240) || "inline.js";
      return { mode: "code", code: req.code, filename };
    }
    if (req.mode === "files" && Array.isArray(req.files)) {
      const files = req.files
        .filter((f) => f && typeof f.filename === "string" && typeof f.code === "string" && f.code.trim())
        .slice(0, 50)
        .map((f) => ({ filename: String(f.filename).slice(0, 240), code: f.code }));
      if (!files.length) return null;
      return { mode: "files", files };
    }
    return null;
  }

  function parseScanTransfer() {
    if (!/^#scan=/.test(location.hash)) return null;
    try {
      return sanitizeScanRequest(JSON.parse(fromB64Url(location.hash.slice(6))));
    } catch {
      return null;
    }
  }

  function authHeaders() {
    const token = apiToken();
    return token ? { "X-ScriptSentry-Token": token } : {};
  }

  function setApiToken(value) {
    const token = String(value || "").trim();
    if (token) {
      sessionStorage.setItem("scriptsentry_engine_token", token);
      window.SCRIPTSENTRY_API_TOKEN = token;
    } else {
      sessionStorage.removeItem("scriptsentry_engine_token");
      window.SCRIPTSENTRY_API_TOKEN = "";
    }
    backendChecked = false;
  }

  /* Backend liveness + privacy gate
   *
   * The status is rendered in two places (the header pill and the setup
   * dialog).  The dot is a real animated element (pulsing core + expanding
   * ring) so an offline engine is obvious at a glance, and the state is also
   * carried by a class for colour/aria, never by a static emoji.
   */
  const ENGINE_STATE_CLASS = {
    offline: "is-offline",
    checking: "is-checking",
    online: "is-online",
  };

  function setEngineStatus(state, text) {
    const stateClass = ENGINE_STATE_CLASS[state] || "is-online";
    const label = text || "Local engine offline — view the setup guide";
    [
      ["#engine-dot", "#engine-status-text"],
      ["#engine-dot-modal", "#engine-status-text-modal"],
    ].forEach(([dotSel, labelSel]) => {
      const dot = $(dotSel);
      const textNode = $(labelSel);
      if (dot) dot.className = `pulse-dot ${stateClass}`;
      if (textNode) textNode.textContent = label;
    });
    const pill = $("#engine-status");
    if (pill) {
      pill.className = `engine-pill ${stateClass}`;
      pill.setAttribute("aria-label", `Local engine status: ${label}. Click to open the setup guide.`);
    }
    const aside = $("#engine-status-aside");
    if (aside) aside.className = `aside-status ${stateClass}`;
  }

  async function checkBackend() {
    // Don't pretend to "check" something the browser will never let us reach.
    if (isMixedContentBlocked()) {
      backendConnected = false;
      backendChecked = true;
      setEngineStatus("offline", "Open the engine's own dashboard — this hosted page can't reach it");
      showHostedHandoff();
      return false;
    }
    setEngineStatus("checking", "Checking local engine…");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const res = await fetch(apiUrl("/api/health"), { cache: "no-store", signal: controller.signal });
      if (res.ok) {
        const health = await res.json().catch(() => ({}));
        if (health.auth_required && !apiToken()) {
          backendConnected = false;
          backendChecked = true;
          setEngineStatus("checking", "Engine online · pairing token required");
          return false;
        }
        backendConnected = true;
        backendChecked = true;
        setEngineStatus("online", "Local engine connected · private analysis ready");
        // A scan handed off from the hosted page can start as soon as the
        // engine answers (a token stored in this tab counts as paired).
        maybeRunPendingTransfer();
        return true;
      }
      throw new Error("health not ok");
    } catch {
      backendConnected = false;
      backendChecked = true;
      setEngineStatus("offline", "Local engine offline — view the setup guide");
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  /* The engine is often started *after* this page is opened, so keep
   * re-checking while it is unreachable (and stop once it answers). */
  let enginePollTimer = null;

  function stopEnginePoll() {
    if (enginePollTimer) {
      clearInterval(enginePollTimer);
      enginePollTimer = null;
    }
  }

  function scheduleEnginePoll() {
    stopEnginePoll();
    if (backendConnected) return;
    // Polling a blocked origin only spams the console with mixed-content errors.
    if (isMixedContentBlocked()) return;
    enginePollTimer = setInterval(async () => {
      if (document.hidden || backendConnected) return;
      await checkBackend();
      if (backendConnected) stopEnginePoll();
    }, 8000);
  }

  async function ensureBackend() {
    if (backendChecked && backendConnected) return true;
    const ok = await checkBackend();
    if (!ok) openPrivacyModal();
    return ok;
  }

  /* Replace the "paste a token here" promise with the truth when this page
   * physically cannot reach the engine.  Pairing controls are hidden (they
   * cannot work) and the engine's own dashboard link takes their place —
   * carrying the pending scan request so nothing has to be re-entered. */
  function showHostedHandoff() {
    const aside = $(".modal-col-aside");
    if (!aside || aside.dataset.handoff === "1") return;
    aside.dataset.handoff = "1";

    const url = buildHandoffUrl();
    const title = $(".aside-title");
    if (title) title.textContent = "Open your local dashboard";

    // The pairing field/blurb can't do anything from here — remove the offer.
    aside.querySelectorAll(".field-label, .token-field, .js-pairing-copy").forEach((el) => {
      el.hidden = true;
    });

    // One honest sentence about pairing: the local dashboard asks for the
    // token once — it is printed in the terminal where the engine runs.
    const carriedNote = currentScanRequest
      ? `<p class="modal-note" style="margin:0 0 10px">✅ Your scan travels with that link — the local page fills in `
        + `${currentScanRequest.mode === "url" ? "the target URL and scan settings"
            : currentScanRequest.mode === "files" ? "your uploaded files"
            : "your pasted code"} automatically and starts right after pairing.</p>`
      : "";
    const note = document.createElement("div");
    note.className = "handoff-note";
    note.innerHTML =
      `<p class="modal-note" style="margin:0 0 10px">` +
      `Your browser blocks this <b>https://</b> page from calling the engine at ` +
      `<code>${escapeHtml(localDashboardUrl())}</code> (<b>mixed content</b>). That's a browser rule, ` +
      `not a token problem — pasting the pairing token here can't fix it.</p>` +
      carriedNote +
      `<p class="modal-note" style="margin:0 0 12px">The engine serves the <b>same dashboard</b> itself. `
      + `Open it, then paste the <b>pairing token</b> once when it asks — the token is printed in the `
      + `terminal where the engine is running:</p>` +
      `<a class="btn" id="open-local-dashboard" href="${escapeHtml(url)}" target="_blank" rel="noopener">` +
      `🚀 Open ${escapeHtml(localDashboardUrl())}</a>`;

    const status = $("#engine-status-aside");
    if (status) aside.insertBefore(note, status);
    else aside.appendChild(note);

    // "Retry Connection" would just re-fail; point it at the dashboard too.
    const retry = $("#retry-backend");
    if (retry) retry.hidden = true;
  }

  function openPrivacyModal() {
    const modal = $("#privacy-modal");
    if (!modal) return;
    modal.hidden = false;
    document.body.classList.add("modal-open");
    // Live storage facts, refreshed every time the dialog opens (no-op on
    // pages without the Data & storage panel).
    refreshStoragePanel();
    if (isMixedContentBlocked()) {
      showHostedHandoff();
      const link = $("#open-local-dashboard");
      if (link) setTimeout(() => link.focus({ preventScroll: true }), 40);
      return;
    }
    // Focus the least destructive control that is always useful here.
    const target = apiToken() ? $("#retry-backend") : $("#engine-token");
    if (target && typeof target.focus === "function") {
      setTimeout(() => target.focus({ preventScroll: true }), 40);
    }
  }

  function showConnectionError(error) {
    const node = $("#connection-error");
    if (node) {
      node.textContent = error && error.message ? error.message : "The engine request failed.";
      node.hidden = false;
    }
  }

  // Decide whether a failure is an engine connection/pairing problem (which
  // should open the setup modal) or an actual analysis rejection (invalid
  // target, private URL, scan error) which should surface inline instead.
  function isConnectionFailure(error) {
    const msg = String((error && error.message) || "").toLowerCase();
    if (msg.includes("unreadable response") || msg.includes("failed to fetch") ||
        msg.includes("networkerror") || msg.includes("load failed")) {
      return true;
    }
    // 401/403 pairing/origin issues are connection/setup problems.
    if (msg.includes("pairing") || msg.includes("token") || msg.includes("origin") ||
        msg.includes("401") || msg.includes("403")) {
      return true;
    }
    return false;
  }

  // Show an analysis failure inline (URL tab) or as a console error, and only
  // open the setup modal when the engine itself is unreachable/unpaired.
  async function handleAnalysisError(error, { urlMode } = {}) {
    const msg = (error && error.message) || "Analysis failed.";
    // A cancel is the user's own action, not a failure — report it without
    // error styling (and without painting the input red).
    const canceled = /cancel/i.test(msg);
    setEngineStatus("checking", msg);
    if (isConnectionFailure(error)) {
      showConnectionError(error);
      openPrivacyModal();
      return;
    }
    // The engine responded but rejected/failed the analysis — show inline.
    closePrivacyModal();
    if (urlMode) {
      setFieldError("#url-input", "#url-error", msg, { neutral: canceled });
    } else {
      setFieldError("#code-input", "#code-error", msg, { neutral: canceled });
    }
  }

  function closePrivacyModal() {
    const modal = $("#privacy-modal");
    if (modal) modal.hidden = true;
    document.body.classList.remove("modal-open");
    const node = $("#connection-error");
    if (node) node.hidden = true;
  }

  /* Force-download the one-file launcher.
   *
   * A plain `<a href="https://raw.githubusercontent.com/…" download>` does NOT
   * download: browsers ignore the `download` attribute for cross-origin
   * targets, so the file opens in a tab instead.  Fetching the text and saving
   * it through a same-origin blob URL is what actually produces a download.
   */