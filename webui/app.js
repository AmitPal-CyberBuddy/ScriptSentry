/* ScriptSentry Web dashboard */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const ICONS = {
    shield: "🛡️",
    key: "🔑",
    vial: "🧪",
    lock: "🔒",
    route: "🌐",
    bolt: "⚡",
    database: "💾",
    bug: "🐞",
    alert: "⚠️",
    gear: "⚙️",
    sparkles: "✨",
    layers: "🧰",
    star: "🌟",
    search: "🔎",
  };

  let payload = null;
  let lastQuery = null;
  let lastJobId = null;
  let backendConnected = false;
  let backendChecked = false;

  /* API base: same origin locally, or a hosted Python backend on Pages. */
  function apiBase() {
    return (window.SCRIPTSENTRY_API || "").replace(/\/+$/, "");
  }

  function apiUrl(path) {
    return `${apiBase()}${path.startsWith("/") ? path : `/${path}`}`;
  }

  function apiToken() {
    return String(window.SCRIPTSENTRY_API_TOKEN || sessionStorage.getItem("scriptsentry_engine_token") || "").trim();
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
    const label = text || "Local engine offline — run server.py";
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
        return true;
      }
      throw new Error("health not ok");
    } catch {
      backendConnected = false;
      backendChecked = true;
      setEngineStatus("offline", "Local engine offline — run server.py");
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

  function openPrivacyModal() {
    const modal = $("#privacy-modal");
    if (!modal) return;
    modal.hidden = false;
    document.body.classList.add("modal-open");
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
    setEngineStatus("checking", msg);
    if (isConnectionFailure(error)) {
      showConnectionError(error);
      openPrivacyModal();
      return;
    }
    // The engine responded but rejected/failed the analysis — show inline.
    closePrivacyModal();
    if (urlMode) {
      setFieldError("#url-input", "#url-error", msg);
    } else {
      setFieldError("#code-input", "#code-error", msg);
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
  function saveBlob(blob, filename) {
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    // Give the browser a moment to start the download before releasing it.
    setTimeout(() => URL.revokeObjectURL(href), 30000);
  }

  async function downloadLauncher(btn) {
    if (!btn || btn.disabled) return;
    const url = String(btn.getAttribute("data-download") || "").trim();
    const filename = String(btn.getAttribute("data-filename") || "scriptsentry.py").trim();
    const hint = btn.parentElement ? btn.parentElement.querySelector(".download-hint") : null;
    const original = btn.textContent;
    if (!url) return;

    btn.disabled = true;
    btn.textContent = "⏳ Downloading…";
    if (hint) hint.textContent = "";

    try {
      const res = await fetch(url, { mode: "cors", cache: "no-store", credentials: "omit" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      if (!text.trim()) throw new Error("empty file");
      saveBlob(new Blob([text], { type: "text/x-python;charset=utf-8" }), filename);
      if (hint) hint.textContent = `✅ Downloaded ${filename}`;
      btn.textContent = "✅ Downloaded";
    } catch {
      // Last resort: open it so the user can still save it manually.
      if (hint) hint.textContent = "⚠️ Couldn't save automatically — opened in a new tab.";
      window.open(url, "_blank", "noopener,noreferrer");
    } finally {
      setTimeout(() => {
        btn.textContent = original;
        btn.disabled = false;
      }, 1800);
    }
  }

  /* ---------------- Scroll experience ---------------- */

  const REVEAL_SELECTOR = [
    ".section-head",
    ".feature-card",
    ".step-card",
    ".notice-card",
    ".trust-row",
    ".setup-card",
    ".connect-card",
    ".console",
    ".tool-hero",
    ".footer-brand",
    ".footer-col",
  ].join(", ");

  // Reveal blocks as they scroll into view (once, then stop observing).
  function initReveal() {
    const nodes = $$(REVEAL_SELECTOR);
    if (!nodes.length) return;

    if (!("IntersectionObserver" in window) ||
        window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      nodes.forEach((el) => el.classList.add("is-visible"));
      return;
    }

    nodes.forEach((el) => {
      // Stagger siblings so a grid of cards cascades instead of popping.
      const siblings = Array.from(el.parentElement ? el.parentElement.children : []);
      const index = Math.max(0, siblings.indexOf(el));
      el.style.setProperty("--reveal-delay", `${Math.min(index, 7) * 70}ms`);
    });

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
    );

    nodes.forEach((el) => {
      // Anything already on screen at load reveals immediately.
      const box = el.getBoundingClientRect();
      if (box.top < window.innerHeight * 0.9) el.classList.add("is-visible");
      else observer.observe(el);
    });
  }

  // Thin progress bar under the sticky header.
  function initScrollProgress() {
    const bar = $("#scroll-progress");
    if (!bar) return;
    let queued = false;
    const update = () => {
      queued = false;
      const doc = document.documentElement;
      const max = doc.scrollHeight - window.innerHeight;
      const ratio = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
      bar.style.transform = `scaleX(${ratio})`;
    };
    window.addEventListener("scroll", () => {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(update);
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  // Highlight the nav link for whichever section is on screen.
  function initNavSpy() {
    const links = $$('.site-nav a[href^="#"]');
    if (!links.length || !("IntersectionObserver" in window)) return;
    const byId = new Map();
    links.forEach((link) => {
      const target = document.getElementById(link.getAttribute("href").slice(1));
      if (target) byId.set(target, link);
    });
    if (!byId.size) return;

    const current = $("#nav-current");
    const setActive = (link) => {
      links.forEach((l) => {
        const on = l === link;
        l.classList.toggle("is-active", on);
        if (on) l.setAttribute("aria-current", "true");
        else l.removeAttribute("aria-current");
      });
      // "You are here" label for narrow screens, where the nav is collapsed.
      if (current) current.textContent = link ? link.textContent.trim() : "Overview";
    };
    if (current) current.textContent = "Overview";

    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible && byId.has(visible.target)) setActive(byId.get(visible.target));
    }, { rootMargin: "-25% 0px -60% 0px", threshold: [0.01, 0.25, 0.6] });

    byId.forEach((_, section) => observer.observe(section));
  }

  /* Shared page chrome: setup modal, engine pill, launcher downloads. */
  function initChrome() {
    $$(".js-download-launcher").forEach((btn) => {
      btn.addEventListener("click", () => downloadLauncher(btn));
    });

    const pill = $("#engine-status");
    if (pill) pill.addEventListener("click", openPrivacyModal);

    const heroSetup = $("#hero-setup");
    if (heroSetup) heroSetup.addEventListener("click", openPrivacyModal);

    const closeX = $("#close-modal-x");
    if (closeX) closeX.addEventListener("click", closePrivacyModal);

    // Clicking the dimmed backdrop also closes the dialog.
    const modal = $("#privacy-modal");
    if (modal) {
      modal.addEventListener("mousedown", (event) => {
        if (event.target === modal) closePrivacyModal();
      });
    }

    // Smooth in-page scrolling for the header / footer navigation.
    $$('a[href^="#"]').forEach((link) => {
      link.addEventListener("click", (event) => {
        const id = link.getAttribute("href").slice(1);
        if (!id) return;
        const target = document.getElementById(id);
        if (!target) return;
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        if (history.replaceState) history.replaceState(null, "", `#${id}`);
      });
    });

    initReveal();
    initScrollProgress();
    initNavSpy();
    initMobileNav();
  }

  /* Below 1040px the section links collapse behind a menu button. Without
   * this a phone visitor could not reach any other part of the page. */
  function initMobileNav() {
    const header = $("#site-header");
    const toggle = $("#nav-toggle");
    const nav = $("#site-nav");
    if (!header || !toggle || !nav) return;

    const setOpen = (open) => {
      header.classList.toggle("nav-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Close Navigation Menu" : "Open Navigation Menu");
    };

    toggle.addEventListener("click", () => setOpen(!header.classList.contains("nav-open")));

    // Tapping a section link should navigate and get the menu out of the way.
    nav.addEventListener("click", (event) => {
      if (event.target.closest("a")) setOpen(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && header.classList.contains("nav-open")) {
        setOpen(false);
        toggle.focus();
      }
    });

    document.addEventListener("click", (event) => {
      if (!header.contains(event.target)) setOpen(false);
    });

    // Leaving the collapsed layout with the menu open would strand it open.
    window.addEventListener("resize", () => {
      if (window.innerWidth > 1040) setOpen(false);
    });
  }

  async function retryBackend() {
    const field = $("#engine-token");
    if (field && field.value.trim()) setApiToken(field.value);
    const ok = await checkBackend();
    if (ok) closePrivacyModal();
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

  function renderProgress(job) {
    const text = $("loading-text");
    const fill = $("#progress-fill");
    const stats = $("#progress-stats");
    if (!text || !fill || !stats) return;
    const pct = Math.max(0, Math.min(100, Number(job.percent || 0)));
    text.textContent = job.message || (job.phase || "Working…");
    fill.style.width = `${pct}%`;
    renderStages(job);
    // An ETA measured over a couple of seconds is a guess, not an estimate.
    // Say so instead of printing a number that looks authoritative.
    const confidence = Number(job.eta_confidence || 0);
    let eta = "—";
    if (job.eta_seconds != null) {
      eta = confidence < 0.5 ? "estimating…" : `~${formatDuration(job.eta_seconds * 1000)} left`;
    }
    // `total` is the engine's current work estimate, not the file cap.
    const files = job.total ? `${job.files_scanned || 0}/${job.total}` : `${job.files_scanned || 0}`;
    stats.innerHTML = [
      ["stage", job.stage || job.phase || "queued"],
      ["files", files],
      ["bytes", formatBytes(job.bytes_scanned)],
      ["pct", `${pct.toFixed(0)}%`],
      ["elapsed", formatDuration(job.elapsed_ms)],
      ["eta", eta],
    ].map(([k, v]) => `<b>${escapeHtml(k)}</b>: ${escapeHtml(String(v))}`).join(" · ");
  }

  function showLoading(text) {
    $("#loading").classList.add("show");
    $("#loading-text").textContent = text || "Analyzing…";
    $("#analyze-code").disabled = true;
    $("#analyze-url").disabled = true;
  }

  function hideLoading() {
    $("#loading").classList.remove("show");
    $("#analyze-code").disabled = false;
    $("#analyze-url").disabled = false;
    const fill = $("#progress-fill");
    const stats = $("#progress-stats");
    if (fill) fill.style.width = "0%";
    if (stats) stats.innerHTML = "";
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

  function initParticles() {
    const canvas = $("#particles");
    const ctx = canvas.getContext("2d");
    const colors = ["#22d3ee", "#38bdf8", "#a78bfa", "#f472b6"];
    let particles = [];
    let raf = 0;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const count = Math.min(90, Math.floor(window.innerWidth / 16));
      particles = Array.from({ length: count }, () => ({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.8 + 0.5,
        vx: (Math.random() - 0.5) * 0.28,
        vy: (Math.random() - 0.5) * 0.28,
        c: colors[Math.floor(Math.random() * colors.length)],
        a: Math.random() * 0.35 + 0.12,
      }));
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const p of particles) {
        ctx.beginPath();
        ctx.globalAlpha = p.a;
        ctx.fillStyle = p.c;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener("resize", resize);
    draw();
    window.addEventListener("beforeunload", () => cancelAnimationFrame(raf));
  }

  /* ---------------- Tabs ---------------- */

  function initTabs() {
    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        $$(".tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        const pane = tab.dataset.pane;
        $$(".pane").forEach((p) => p.classList.toggle("active", p.id === `pane-${pane}`));
      });
    });
  }

  /* ---------------- Analysis ---------------- */

  const SAMPLE = `// ScriptSentry sample bundle
const config = {
  apiUrl: "https://api.example.com/v1",
  apiKey: "AIzaSyB7X-Example-Key-12345678",
  secret: "sup3r-s3cr3t!!",
};

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature-here";

const key = EncryptionKey = "aVeryStrongEncryptionKey123!";
const iv = EncryptionIV = "1b2c3d4e5f6a7b8c";

async function loadProfile() {
  const resp = await fetch("/api/v1/profile", {
    headers: { Authorization: "Bearer " + token },
  });
  localStorage.setItem("auth", token);
  return resp.json();
}

function dangerous() {
  eval(userInput);
  document.getElementById("target").innerHTML = rawPayload;
}

CryptoJS.AES.encrypt(payload, key, { iv: iv, mode: CryptoJS.mode.CBC });
`;

  async function pollJob(jobId) {
    let latest = null;
    for (let i = 0; i < 1200; i++) {
      const status = await getJSON(`/api/status?job_id=${encodeURIComponent(jobId)}`);
      latest = status.job;
      renderProgress(latest);
      if (latest.status === "done") return latest;
      if (latest.status === "error") throw new Error(latest.error || "Analysis failed.");
      if (latest.status === "canceled") throw new Error("Analysis canceled.");
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("Analysis timed out while waiting for the local engine.");
  }

  async function cancelCurrentJob() {
    if (!lastJobId) return;
    try {
      await postJSON("/api/cancel", { job_id: lastJobId });
      $("#loading-text").textContent = "Canceling scan…";
    } catch (err) {
      showConnectionError(err);
    }
  }

  async function finishJob(jobId) {
    const data = await getJSON(`/api/result?job_id=${encodeURIComponent(jobId)}`);
    if (!data.ready) {
      throw new Error("The analysis is not ready yet.");
    }
    payload = data.payload;
    renderDashboard();
    $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setFieldError(inputId, errorId, message) {
    const err = $(errorId);
    const input = $(inputId);
    if (err) {
      err.textContent = message || "";
      err.hidden = !message;
    }
    if (input) input.classList.toggle("input-invalid", !!message);
    if (message && input) {
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
    if (!(await ensureBackend())) return;
    showLoading("Analyzing JavaScript…");
    try {
      const query = {
        mode: "code",
        code,
        filename: $("#filename-input").value || "inline.js",
      };
      lastQuery = query;
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
    if (!(await ensureBackend())) return;
    showLoading("Discovering and scanning JavaScript… this can take a moment.");
    try {
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
    if (!(await ensureBackend())) return;
    // Read files locally in the browser; only the text content is sent to the
    // local engine (same authenticated channel as paste — nothing is uploaded
    // to a cloud).
    const payloadFiles = [];
    for (const f of pendingFiles) {
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
    showLoading(`Analyzing ${payloadFiles.length} local file(s)…`);
    try {
      const query = { mode: "code", files: payloadFiles };
      lastQuery = query;
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
        const err = await res.text().catch(() => "");
        throw new Error(err || "Report generation failed.");
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
      showConnectionError(err);
      setEngineStatus("checking", err.message || "Analysis failed");
      openPrivacyModal();
    } finally {
      hideLoading();
    }
  }

  /* ---------------- Rendering ---------------- */

  function renderEngineNotes() {
    const node = $("#engine-notes");
    if (!node || !payload) return;
    const notes = [];
    const parser = (payload.meta || {}).ast_parser || {};
    if (parser.available === false) {
      notes.push(
        `<b>Reduced-depth analysis:</b> the optional JavaScript parser (<code>${escapeHtml(parser.name || "esprima")}</code>) `
        + "is not installed, so this scan used the line-based fallback. Install it for full AST taint analysis: "
        + `<code>${escapeHtml(parser.install_hint || "pip install esprima")}</code>.`,
      );
    }
    const warnings = new Set();
    (payload.files || []).forEach((f) => (f.analysis_warnings || []).forEach((w) => warnings.add(w)));
    warnings.forEach((w) => notes.push(escapeHtml(w)));
    node.innerHTML = notes.length
      ? notes.map((n) => `<div class="engine-note">⚠️ ${n}</div>`).join("")
      : "";
    node.hidden = !notes.length;
  }

  /* Keep the last result for the lifetime of this tab: a reload or an
   * accidental navigation should not cost you another scan. */
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
        <span style="color:#8ea2c1">${escapeHtml((s.evidence || []).slice(0, 2).join(" · "))}</span>
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
      ["Runtime Findings", findings.map((f) => `${f.severity || "MEDIUM"} · ${f.type || f.id} · ${(f.evidence || []).join(" · ")}`).slice(0, 20), "#ff4d6d"],
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
          return `<li style="animation-delay:${i * 0.03}s">
            <span class="risk-dot" style="color:${color}"></span>
            <span><b>${escapeHtml(f.type || f.id || "finding")}</b> · ${escapeHtml(f.severity || "")} · conf ${escapeHtml(CONF_LABEL[f.confidence] || f.confidence || "?")} · ${escapeHtml(f.file || "")}${f.line ? ` · L${f.line}` : ""}<br>
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
      group.style.display = group.dataset.view === view ? "" : "none";
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

  function renderSummary() {
    const summary = payload.summary;
    const score = summary.overall_score || 0;
    const riskLabel = summary.risk_label || "LOW";
    const riskColor = summary.risk_color || "#22d3ee";

    const circ = 2 * Math.PI * 50;
    // overall_score is now an explainable 0-100 evidence-weighted score.
    const pct = Math.max(2, Math.min(100, score));
    const gauge = $("#gauge");
    gauge.style.stroke = riskColor;
    gauge.setAttribute("stroke", riskColor);
    gauge.style.strokeDasharray = `${(pct / 100) * circ} ${circ}`;

    $("#risk-label").textContent = riskLabel;
    $("#risk-label").style.color = riskColor;
    $("#risk-score").textContent = `Risk ${score}/100`;
    const chip = $("#risk-chip");
    const actionCount = summary.total_findings || 0;
    const obsCount = summary.total_observations || 0;
    chip.textContent = `${actionCount} action${actionCount === 1 ? "" : "s"} · ${obsCount} observation${obsCount === 1 ? "" : "s"}`;
    chip.style.background = riskColor;
    chip.style.color = "#071019";

    const metrics = [
      { label: "Files Analyzed", value: summary.total_files || 0, color: "#22d3ee" },
      { label: "Actionable Findings", value: actionCount, color: "#fb7185" },
      { label: "Confirmed Effects", value: (summary.risk_counts || {}).confirmed || 0, color: "#ff4d6d" },
      { label: "Risk Score /100", value: score, color: riskColor },
    ];

    $("#metrics").innerHTML = metrics
      .map(
        (m, i) => `<div class="card metric fade-up" style="animation-delay:${i * 0.08}s">
          <div class="value" data-target="${m.value}" style="color:${m.color}">0</div>
          <div class="label">${escapeHtml(m.label)}</div>
          <div class="spark"><i style="background:${m.color}"></i></div>
        </div>`
      )
      .join("");

    $$("#metrics .value").forEach((el) => {
      animateNumber(el, parseInt(el.dataset.target, 10) || 0);
    });

    const bars = summary.categories
      .slice()
      .sort((a, b) => b.value - a.value)
      .slice(0, 12);
    $("#category-bars").innerHTML = bars
      .map((c) => {
        const width = Math.max(3, Math.min(100, c.value * 18));
        return `<div class="category">
          <div class="name"><span>${ICONS[c.icon] || "•"} ${escapeHtml(c.label)}</span><b>${c.value}</b></div>
          <div class="cat-bar"><i style="--cat:${c.color};width:${width}%"></i></div>
        </div>`;
      })
      .join("");
  }

  function renderCharts() {
    renderDonut();
    renderRadar();
  }

  function renderDonut() {
    const chart = $("#donut-chart");
    const legend = $("#donut-legend");
    const data = payload.donut;
    const labels = data.labels || [];
    const values = data.values || [];
    const colors = data.colors || [];
    const total = values.reduce((a, b) => a + b, 0) || 1;
    const r = 75;
    const circ = 2 * Math.PI * r;
    let offset = 0;

    chart.innerHTML = "";
    if (labels.length === 0) {
      chart.innerHTML = `<text x="110" y="112" fill="#8ea2c1" text-anchor="middle">No detections</text>`;
      legend.innerHTML = "";
      return;
    }

    labels.forEach((label, i) => {
      const value = values[i];
      const frac = Math.max(0.012, value / total);
      const len = frac * circ;
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", "110");
      circle.setAttribute("cy", "110");
      circle.setAttribute("r", String(r));
      circle.setAttribute("fill", "none");
      circle.setAttribute("stroke", colors[i] || "#22d3ee");
      circle.setAttribute("stroke-width", "15");
      circle.setAttribute("stroke-dasharray", `${len} ${circ - len}`);
      circle.setAttribute("stroke-dashoffset", String(-offset));
      circle.setAttribute("stroke-linecap", "butt");
      const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
      style.textContent = `@keyframes seg${i} { from { stroke-dashoffset: ${circ}; } to { stroke-dashoffset: ${-offset}; } }`;
      chart.appendChild(style);
      circle.style.animation = `seg${i} 1s ease both`;
      chart.appendChild(circle);
      offset += len;
    });

    legend.innerHTML = labels
      .map(
        (l, i) =>
          `<span><i style="background:${colors[i]}"></i>${escapeHtml(l)} · ${values[i]}</span>`
      )
      .join("");
  }

  function renderRadar() {
    const canvas = $("#radar-chart");
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 220;
    const height = canvas.clientHeight || 220;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const data = payload.radar;
    const labels = data.labels || [];
    const values = data.values || [];
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) / 2 - 30;
    const n = labels.length;
    if (!n) return;

    ctx.clearRect(0, 0, width, height);

    // grid rings
    for (let ring = 1; ring <= 4; ring++) {
      const rr = (radius * ring) / 4;
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const x = cx + Math.cos(angle) * rr;
        const y = cy + Math.sin(angle) * rr;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = "rgba(142,162,193,0.16)";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // axes
    for (let i = 0; i < n; i++) {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      const x = cx + Math.cos(angle) * radius;
      const y = cy + Math.sin(angle) * radius;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(x, y);
      ctx.strokeStyle = "rgba(142,162,193,0.16)";
      ctx.stroke();

      const lx = cx + Math.cos(angle) * (radius + 18);
      const ly = cy + Math.sin(angle) * (radius + 18);
      ctx.fillStyle = "#8ea2c1";
      ctx.font = "10px Inter, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(labels[i].slice(0, 14), lx, ly);
    }

    // polygon
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      const value = Math.min(100, values[i] || 0) / 100;
      const x = cx + Math.cos(angle) * radius * value;
      const y = cy + Math.sin(angle) * radius * value;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, width, height);
    grad.addColorStop(0, "rgba(34,211,238,0.22)");
    grad.addColorStop(1, "rgba(167,139,250,0.22)");
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = "#22d3ee";
    ctx.lineWidth = 2;
    ctx.shadowBlur = 16;
    ctx.shadowColor = "#22d3ee";
    ctx.stroke();
    ctx.shadowBlur = 0;

    for (let i = 0; i < n; i++) {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      const value = Math.min(100, values[i] || 0) / 100;
      const x = cx + Math.cos(angle) * radius * value;
      const y = cy + Math.sin(angle) * radius * value;
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = "#a5f3fc";
      ctx.fill();
    }
  }

  function renderTimeline() {
    const steps = payload.timeline || [];
    $("#timeline").innerHTML = steps
      .map(
        (s, i) => `
        <div class="step fade-up" style="animation-delay:${i * 0.1}s;color:${s.color}">
          <div class="step-ico" style="--step:${s.color}">${ICONS[s.icon] || "•"}</div>
          <div class="step-body">
            <div class="stage">${escapeHtml(s.stage)}</div>
            <div class="label">${escapeHtml(s.label)}</div>
            <div class="value" data-count="${s.value}" data-color="${s.color}">0</div>
          </div>
        </div>`
      )
      .join("");
    $$("#timeline .value").forEach((el) => animateNumber(el, parseInt(el.dataset.count, 10) || 0));
  }

  function renderScanSummary() {
    const panel = $("#scan-summary");
    if (!panel) return;
    const s = payload.scan_summary || {};
    const summary = payload.summary || {};
    const files = (payload.files || []).length;
    if (!Object.keys(s).length && summary.total_files != null) {
      panel.innerHTML = [
        ["Files analyzed", summary.total_files || files, "#22d3ee"],
        ["Bytes scanned", formatBytes(summary.bytes_scanned), "#38bdf8"],
        ["Runtime evidence", summary.runtime_status || "not_run", "#a78bfa"],
      ].map(([n, v, c]) => `<div class="finding-chip"><span class="chip-title" style="color:${c}">${escapeHtml(n)}</span><div>${escapeHtml(v)}</div></div>`).join("");
      return;
    }
    const skipped = Number(s.skipped_files || 0);
    const runtime = s.runtime_status || "not_run";
    const runtimeColor = s.runtime_captured ? "#34d399" : "#fbbf24";
    const chips = [
      ["Discovered links", s.total_discovered ?? files, "#22d3ee"],
      ["Files analyzed", s.total_files ?? files, "#38bdf8"],
      ["Skipped", skipped, skipped ? "#fb7185" : "#34d399"],
      ["Bytes scanned", formatBytes(s.bytes_scanned), "#a78bfa"],
      ["Bundle bytes", formatBytes(s.total_bytes), "#60a5fa"],
      ["Runtime", runtime, runtimeColor],
      ["Workers", s.max_workers || "-", "#60a5fa"],
      ["Hard cap hit", s.capped ? "yes" : "no", s.capped ? "#fb7185" : "#34d399"],
    ];
    const reasons = (s.skipped_reasons || []).slice(0, 6);
    panel.innerHTML = chips
      .map(([n, v, c]) => `<div class="finding-chip"><span class="chip-title" style="color:${c}">${escapeHtml(n)}</span><div>${escapeHtml(v)}</div></div>`)
      .join("") + (reasons.length ? `<div class="finding-chip" style="grid-column:1/-1"><span class="chip-title" style="color:#fb7185">Why some files were skipped</span><div>${reasons.map(escapeHtml).join(" · ")}</div></div>` : "");
  }

  function renderFiles() {
    const files = payload.files || [];
    const tabs = $("#file-tabs");
    const panel = $("#file-panel");

    if (files.length === 0) {
      tabs.innerHTML = "";
      panel.innerHTML = `<div class="finding-chip">No JavaScript discovered at this URL.</div>`;
      return;
    }

    tabs.innerHTML = files
      .map(
        (f, i) =>
          `<button class="file-tab ${i === 0 ? "active" : ""}" data-i="${i}" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</button>`
      )
      .join("");

    tabs.querySelectorAll(".file-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.querySelectorAll(".file-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        renderFilePanel(files[parseInt(tab.dataset.i, 10)]);
      });
    });

    renderFilePanel(files[0]);
  }

  function renderFilePanel(file) {
    const panel = $("#file-panel");
    const density = [
      ["Secrets", file.secrets, "#ff4d6d"],
      ["Crypto Keys", file.keys, "#ff9f43"],
      ["IV / Nonce", file.ivs, "#ffd166"],
      ["Endpoints", file.endpoints, "#22d3ee"],
      ["API Calls", file.api_calls, "#38bdf8"],
      ["Storage", file.storage, "#a78bfa"],
      ["DOM / XSS", file.dom_risks, "#fb7185"],
      ["Runtime", file.suspicious, "#f97316"],
      ["Config", file.configs, "#fbbf24"],
      ["Decoded", file.decoded, "#34d399"],
      ["Tech Stack", file.tech, "#60a5fa"],
      ["Features", file.features, "#c084fc"],
      ["Data Flow", file.data_flow, "#818cf8"],
      ["Auth", file.auth, "#22d3ee"],
      ["Obfuscation", file.obfuscation, "#f472b6"],
      ["Dependencies", file.deps, "#a78bfa"],
      ["Transport", file.transport, "#38bdf8"],
      ["Methods", file.methods, "#fb7185"],
      ["Risk Signals", (file.signals || []).map((s) => s.title), "#ff4d6d"],
      ["Source Map", file.source_map && file.source_map.present ? [`${file.source_map.sources?.length || 0} source(s) · ${file.source_map.available ? "metadata loaded" : "reference unresolved"}`] : [], "#60a5fa"],
      ["Analyzer Warnings", file.analysis_warnings || [], "#fbbf24"],
    ]
      .filter(([, items]) => items && items.length)
      .map(
        ([name, items, color]) => `
        <div class="finding-chip">
          <span class="chip-title" style="color:${color}">${escapeHtml(name)} · ${items.length}</span>
          ${items.map((it) => `<div>• ${escapeHtml(it)}</div>`).join("")}
        </div>`
      )
      .join("");

    const list = (file.findings || [])
      .map(
        (f, i) => `
        <li style="animation-delay:${i * 0.05}s">
          <span class="risk-dot" style="color:${file.color}"></span>
          <span>${escapeHtml(f)}</span>
        </li>`
      )
      .join("");

    const profile = [
      ["Size", `${file.size || 0} bytes`, "#22d3ee"],
      ["Lines", `${file.lines || 0}`, "#38bdf8"],
      ["Complexity", `${file.complexity || 0}`, "#a78bfa"],
      ["Imports", `${file.imports_count || 0}`, "#34d399"],
      ["Exports", `${file.exports_count || 0}`, "#60a5fa"],
      ["Functions", `${file.functions_count || 0}`, "#f472b6"],
      ["Classes", `${file.classes_count || 0}`, "#fbbf24"],
      ["Module", file.module_system || "unknown", "#818cf8"],
    ]
      .map(([n, v, c]) => `<div class="finding-chip"><span class="chip-title" style="color:${c}">${escapeHtml(n)}</span><div>${escapeHtml(v)}</div></div>`)
      .join("");

    panel.innerHTML = `
      <div class="finding-grid" style="margin-bottom:14px">${profile}</div>
      <div class="finding-grid">${density || `<div class="finding-chip">No structured findings for this file.</div>`}</div>
      <ul class="find-list">${list}</ul>
    `;
  }

  /* ---------------- Boot ---------------- */

  /* The dashboard is now two pages sharing one script: `index.html` is the
   * landing page, `tool.html` hosts the console.  Chrome (engine status, setup
   * dialog, scroll effects) runs on both; the analyzer wiring only runs where
   * the console markup actually exists. */
  function isToolPage() {
    return !!$("#code-input");
  }

  function init() {
    initParticles();
    initChrome();
    if (isToolPage()) initTool();
    checkBackend().then(scheduleEnginePoll);
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
    $("#load-sample").addEventListener("click", () => {
      $("#code-input").value = SAMPLE;
      $("#pane-code").scrollIntoView({ behavior: "smooth", block: "center" });
    });
    $("#close-modal").addEventListener("click", closePrivacyModal);
    $("#retry-backend").addEventListener("click", retryBackend);
    $("#cancel-scan").addEventListener("click", cancelCurrentJob);
    const tokenField = $("#engine-token");
    if (tokenField) tokenField.value = apiToken();
    // Copy buttons in the setup modal (generic, per data-copy target).
    $$("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-copy");
        const node = target ? document.getElementById(target) : null;
        const code = node ? node.textContent : "";
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
