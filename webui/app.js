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
  let backendConnected = false;
  let backendChecked = false;

  /* API base: same origin locally, or a hosted Python backend on Pages. */
  function apiBase() {
    return (window.SCRIPTSENTRY_API || "").replace(/\/+$/, "");
  }

  function apiUrl(path) {
    return `${apiBase()}${path.startsWith("/") ? path : `/${path}`}`;
  }

  /* Backend liveness + privacy gate */
  function setEngineStatus(state, text) {
    const dot = $("#engine-dot");
    const label = $("#engine-status-text");
    if (!dot || !label) return;
    dot.className = "dot" + (state === "offline" ? " offline" : state === "checking" ? " checking" : "");
    label.textContent = text || "Local engine offline — run server.py";
  }

  async function checkBackend() {
    const dot = $("#engine-dot");
    setEngineStatus("checking", "Checking local engine…");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const res = await fetch(apiUrl("/api/health"), { cache: "no-store", signal: controller.signal });
      if (res.ok) {
        backendConnected = true;
        backendChecked = true;
        setEngineStatus("", "🟢 Local engine connected · private analysis ready");
        return true;
      }
      throw new Error("health not ok");
    } catch {
      backendConnected = false;
      backendChecked = true;
      setEngineStatus("offline", "🔴 Local engine offline — run server.py");
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  async function ensureBackend() {
    if (backendChecked && backendConnected) return true;
    const ok = await checkBackend();
    if (!ok) openPrivacyModal();
    return ok;
  }

  function openPrivacyModal() {
    const modal = $("#privacy-modal");
    if (modal) modal.hidden = false;
  }

  function closePrivacyModal() {
    const modal = $("#privacy-modal");
    if (modal) modal.hidden = true;
  }

  async function retryBackend() {
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
      headers: { "Content-Type": "application/json" },
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

  async function analyzeCode() {
    const code = $("#code-input").value;
    if (!code.trim()) {
      alert("Paste some JavaScript first.");
      return;
    }
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
      payload = data.payload;
      renderDashboard();
      $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      setEngineStatus("offline");
      openPrivacyModal();
    } finally {
      hideLoading();
    }
  }

  async function analyzeUrl() {
    const url = $("#url-input").value.trim();
    if (!url) {
      alert("Enter a target URL.");
      return;
    }
    if (!(await ensureBackend())) return;
    showLoading("Discovering and scanning JavaScript… this can take a moment.");
    try {
      const query = {
        mode: "url",
        url,
        profile: $("#profile").value,
        max_depth: parseInt($("#max-depth").value, 10),
        max_files: parseInt($("#max-files").value, 10),
        timeout: 30,
      };
      lastQuery = query;
      const data = await postJSON("/api/analyze", query);
      payload = data.payload;
      renderDashboard();
      $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      setEngineStatus("offline");
      openPrivacyModal();
    } finally {
      hideLoading();
    }
  }

  /* ---------------- Report export ---------------- */

  async function exportReport(format) {
    if (!lastQuery) {
      alert("Analyze something before exporting a report.");
      return;
    }
    showLoading("Generating report…");
    if (!(await ensureBackend())) return;
    showLoading("Generating report…");
    try {
      const res = await fetch(apiUrl(`/api/report?format=${format}`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(lastQuery),
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw new Error(err || "Report generation failed.");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = format === "txt" ? "scriptsentry-report.txt" : "scriptsentry-report.html";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      setEngineStatus("offline");
      openPrivacyModal();
    } finally {
      hideLoading();
    }
  }

  /* ---------------- Rendering ---------------- */

  function renderDashboard() {
    if (!payload) return;
    const results = $("#results");
    results.classList.add("show");
    $("#result-meta").textContent = `${payload.meta.engine} · ${payload.meta.analysis_mode === "url" ? "Remote URL" : "Source snippet"} · ${payload.meta.generated_at || ""}`;
    renderSummary();
    renderSignals();
    renderDeps();
    renderCharts();
    renderTimeline();
    renderFiles();
  }

  function renderSignals() {
    const signals = payload.summary.signals || [];
    const sevColor = { CRITICAL: "#ff4d6d", HIGH: "#ff9f43", MEDIUM: "#ffd166", LOW: "#22d3ee", INFO: "#a78bfa" };
    $("#risk-signals").innerHTML = signals.length
      ? signals
          .slice(0, 12)
          .map(
            (s, i) => `<li style="animation-delay:${i * 0.05}s">
              <span class="risk-dot" style="color:${sevColor[s.severity] || "#22d3ee"}"></span>
              <span><b>${escapeHtml(s.title || s.id)}</b> · ${escapeHtml(s.file || "")}<br><span style="color:#8ea2c1">${escapeHtml((s.evidence || []).slice(0, 2).join(" · "))}</span></span>
            </li>`
          )
          .join("")
      : `<li><span class="risk-dot" style="color:#22d3ee"></span><span>No high-priority risk signals raised.</span></li>`;
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

  function renderSummary() {
    const summary = payload.summary;
    const score = summary.overall_score || 0;
    const riskLabel = summary.risk_label || "LOW";
    const riskColor = summary.risk_color || "#22d3ee";

    const circ = 2 * Math.PI * 50;
    const pct = Math.max(4, Math.min(100, score * 4));
    const gauge = $("#gauge");
    gauge.style.stroke = riskColor;
    gauge.setAttribute("stroke", riskColor);
    gauge.style.strokeDasharray = `${(pct / 100) * circ} ${circ}`;

    $("#risk-label").textContent = riskLabel;
    $("#risk-label").style.color = riskColor;
    $("#risk-score").textContent = `Score ${score}`;
    const chip = $("#risk-chip");
    chip.textContent = `${summary.total_findings || 0} signals`;
    chip.style.background = riskColor;
    chip.style.color = "#071019";

    const metrics = [
      { label: "Files Analyzed", value: summary.total_files || 0, color: "#22d3ee" },
      { label: "Detections", value: summary.total_findings || 0, color: "#a78bfa" },
      { label: "Crypto Flows", value: summary.crypto_flow_count || 0, color: "#f472b6" },
      { label: "Risk Score", value: score, color: riskColor },
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

  function init() {
    initParticles();
    initTabs();
    $("#code-input").value = SAMPLE;
    $("#analyze-code").addEventListener("click", analyzeCode);
    $("#analyze-url").addEventListener("click", analyzeUrl);
    $("#export-html").addEventListener("click", () => exportReport("html"));
    $("#export-txt").addEventListener("click", () => exportReport("txt"));
    $("#load-sample").addEventListener("click", () => {
      $("#code-input").value = SAMPLE;
      $("#pane-code").scrollIntoView({ behavior: "smooth", block: "center" });
    });
    $("#close-modal").addEventListener("click", closePrivacyModal);
    $("#retry-backend").addEventListener("click", retryBackend);
    $("#copy-setup").addEventListener("click", () => {
      const code = $("#setup-code").textContent;
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
      $("#copy-setup").textContent = "✅ Copied";
      setTimeout(() => ($("#copy-setup").textContent = "📋 Copy"), 1600);
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closePrivacyModal();
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        if ($("#pane-code").classList.contains("active")) analyzeCode();
        else analyzeUrl();
      }
    });
    checkBackend();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
