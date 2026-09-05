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

  /* The radar is a <canvas>: it has no intrinsic scaling, so its
   * backing store has to be rebuilt whenever its box changes. It used
   * to be drawn once and then stretched by CSS after a resize or a
   * rotation — the grid and labels drifted out of alignment with the
   * polygon. A ResizeObserver covers both cases that matter:
   *   - the viewport changing width
   *   - the Overview panel being hidden and re-shown by the view tabs
   *     (a display:none canvas measures 0 and must be redrawn)      */
  function initChartResponsiveness() {
    const canvas = $("#radar-chart");
    if (!canvas) return;

    const redraw = () => {
      if (canvas.clientWidth && payload && payload.radar) renderRadar();
    };

    if (typeof ResizeObserver !== "undefined") {
      let raf = 0;
      let lastWidth = 0;
      const observer = new ResizeObserver((entries) => {
        const width = Math.round(entries[0].contentRect.width);
        if (!width || width === lastWidth) return;
        lastWidth = width;
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(redraw);
      });
      observer.observe(canvas);
      return;
    }

    // Fallback for engines without ResizeObserver.
    let timer = 0;
    window.addEventListener("resize", () => {
      clearTimeout(timer);
      timer = setTimeout(redraw, 160);
    });
  }

  function renderRadar() {
    const canvas = $("#radar-chart");
    const ctx = canvas.getContext("2d");
    // Cap DPR: a 3x backing store on a phone costs memory and fill rate
    // for a chart that is 250px wide, with no visible gain.
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = canvas.clientWidth || 220;
    const height = canvas.clientHeight || 220;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const data = payload.radar;
    const labels = data.labels || [];
    const values = data.values || [];
    const n = labels.length;
    if (!n) return;

    /* The radius used to be min(w,h)/2 - 30: a constant that assumed a
     * roomy card. On a phone the labels are then drawn past the left
     * and right edges of the canvas and sliced in half.
     *
     * The reserve is now measured from the longest label at the real
     * font size, and it is budgeted per axis — a label at the top of
     * the chart only needs vertical room for one line of text, not
     * half its own width, so the plot does not shrink more than it
     * has to. */
    const labelFont = Math.max(9, Math.min(11, Math.round(Math.min(width, height) / 22)));
    const labelText = labels.map((label) => String(label).slice(0, 14));

    ctx.font = `${labelFont}px Inter, sans-serif`;
    let widest = 0;
    for (const text of labelText) widest = Math.max(widest, ctx.measureText(text).width);

    const gap = 12;
    const halfW = width / 2;
    const halfH = height / 2;
    const radius = Math.max(
      20,
      Math.min(halfW - widest / 2 - gap, halfH - labelFont - gap),
    );

    const cx = halfW;
    const cy = halfH;

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

      const lx = cx + Math.cos(angle) * (radius + gap);
      const ly = cy + Math.sin(angle) * (radius + gap);
      ctx.fillStyle = "#8ea2c1";
      ctx.font = `${labelFont}px Inter, sans-serif`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(labelText[i], lx, ly);
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
      ["Source Map", file.source_map && file.source_map.present ? [sourceMapChipText(file.source_map)] : [], "#60a5fa"],
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

  /* The dashboard is three pages sharing one script: `home/index.html` is the
   * landing page, `tool/index.html` hosts the console, and `changelog/index.html`
   * is generated from CHANGELOG.md.  Chrome (engine status, setup dialog,
   * scroll effects) runs on all of them; the analyzer wiring only runs where
   * the console markup actually exists. */