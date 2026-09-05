  function initParticles() {
    const canvas = $("#particles");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const colors = ["#22d3ee", "#38bdf8", "#a78bfa", "#f472b6"];
    let particles = [];
    let raf = 0;
    let w = 0;
    let h = 0;
    let dpr = 1;

    // Fewer, slower particles on a phone: a 90-particle animation loop
    // competes with the analyzer for the main thread on weak hardware.
    const budget = () => {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return 0;
      const narrow = window.innerWidth < 640;
      return narrow ? 28 : 90;
    };

    function build() {
      w = window.innerWidth;
      h = window.innerHeight;
      // Size the backing store in device pixels, or the field looks
      // soft on every HiDPI phone and laptop screen.
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const count = Math.min(budget(), Math.floor(w / 16));
      particles = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        r: Math.random() * 1.8 + 0.5,
        vx: (Math.random() - 0.5) * 0.28,
        vy: (Math.random() - 0.5) * 0.28,
        c: colors[Math.floor(Math.random() * colors.length)],
        a: Math.random() * 0.35 + 0.12,
      }));
    }

    function draw() {
      ctx.clearRect(0, 0, w, h);
      for (const p of particles) {
        ctx.beginPath();
        ctx.globalAlpha = p.a;
        ctx.fillStyle = p.c;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = w;
        if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = h;
        if (p.y > h) p.y = 0;
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    }

    build();

    /* Rebuilding the field on every resize event is both wasteful and
     * visibly wrong on mobile: showing/hiding the URL bar fires resize
     * continuously as the page scrolls, which used to scatter every
     * particle back to a new random position. Width changes are the
     * only ones that actually require a rebuild, and they are debounced
     * so a drag-resize or a rotate settles first. */
    let resizeTimer = 0;
    let lastWidth = window.innerWidth;
    window.addEventListener("resize", () => {
      if (window.innerWidth === lastWidth) return; // height-only: URL bar
      lastWidth = window.innerWidth;
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(build, 180);
    });

    // Rotating a phone changes both axes and must not be debounced away
    // into a stretched canvas.
    window.addEventListener("orientationchange", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(build, 260);
    });

    if (particles.length) draw();

    // Pause the loop when the tab is hidden.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf && particles.length) {
        draw();
      }
    });

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

  /* Poll /api/status until the job reaches a terminal state.
   *
   * The old loop threw "timed out while waiting for the local engine" after
   * 1200 polls (10 minutes flat) whether or not the engine was still making
   * progress — on a large target the dashboard declared failure while the
   * scan kept running. The rules now match reality:
   *   - No fixed wall-clock cap: a scan may take as long as the engine keeps
   *     answering and reporting. Real bundle-heavy sites need more than ten
   *     minutes; the engine, not the browser, decides when it is done.
   *   - Transient poll failures (a busy worker pool, laptop sleep, a dropped
   *     connection) are tolerated for a grace window before giving up.
   *   - A job id the engine no longer knows (server restarted) is reported
   *     as exactly that instead of a generic timeout.
   *   - Long silences are surfaced as "quiet since …" hints in the progress
   *     panel (see renderProgress), never as an error, because a silent
   *     minute while a large bundle is parsed is normal work. */
  const POLL_INTERVAL_MS = 500;
  const POLL_MAX_INTERVAL_MS = 4000;         // quiet-scan ceiling (visible tab)
  const POLL_MAX_HIDDEN_INTERVAL_MS = 10000; // hidden tab backs off further
  const POLL_FAILURE_GRACE_MS = 20000;   // tolerated loss of contact
  const QUIET_HINT_MS = 15000;           // no engine update → explain, don't panic
  const QUIET_STALL_MS = 2 * 60000;      // 2 min quiet → add elapsed/ETA context
  const QUIET_STUCK_MS = 6 * 60000;      // 6 min quiet → mention Cancel as an option
  const LONG_SCAN_NOTE_MS = 3 * 60000;   // gentle "big scans take a while" note

  /* Why a stage goes quiet, in one line each. Production JS is big: the
   * analyze stage is CPU-bound and one minified bundle can occupy a worker
   * for minutes without finishing, and the beautifier/verifier have their
   * own long, event-free stretches. The hint names the stage's cost *before*
   * it suggests anything is wrong — "cancel and retry with fewer workers"
   * after 90 seconds was advice for a problem that in most cases did not
   * exist, and "fewer workers" would not even speed up a single big file. */
  const STAGE_QUIET_NOTES = {
    recon: "Fetching the page (network-bound — slow sites, redirects or bot protection make this slower).",
    discover: "Resolving module and chunk references found inside the downloaded scripts.",
    download: "Downloading bundles from the target site (network-bound).",
    normalize: "Beautifying minified bundles — large production files take longer to reformat.",
    analyze: "Static-analysis passes (secrets, taint, AST, attack surface) run per script and stay quiet while one large bundle is processed — normal for production-size JS.",
    correlate: "De-duplicating and ranking findings across scripts.",
    verify: "A local headless browser is loading the page and recording runtime evidence.",
    report: "Assembling the report.",
  };

  async function pollJob(jobId) {
    const startedAt = performance.now();
    let lastGoodPoll = startedAt;
    let pollDelay = POLL_INTERVAL_MS;
    let lastSignature = "";
    while (true) {
      let status;
      try {
        status = await getJSON(`/api/status?job_id=${encodeURIComponent(jobId)}`);
        lastGoodPoll = performance.now();
      } catch (err) {
        const msg = String((err && err.message) || "");
        if (/unknown job/i.test(msg)) {
          throw new Error(
            "The engine no longer knows this scan job — server.py was probably restarted. Start the scan again.",
          );
        }
        if (performance.now() - lastGoodPoll > POLL_FAILURE_GRACE_MS) {
          throw new Error(
            `Lost contact with the local engine during the scan (${formatDuration(performance.now() - startedAt)} in). `
            + "Is server.py still running? Check its window for errors, then start the scan again.",
          );
        }
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        continue;
      }
      const job = status && status.job;
      if (!job) {
        throw new Error(
          "The engine sent a status response without a job record — server.py was probably restarted. Start the scan again.",
        );
      }
      renderProgress(job);
      if (job.status === "done") return job;
      if (job.status === "error") throw new Error(job.error || "Analysis failed.");
      if (job.status === "canceled") throw new Error("Analysis canceled.");
      // Adaptive cadence. Progress that is visibly moving is polled fast
      // (500 ms) so the bar and messages feel live; a stage that reports the
      // same snapshot (one big bundle being analyzed) backs off gradually to
      // a few seconds — the engine's answer cannot have changed, and the
      // client-side ticker keeps the clocks moving between polls. Any change
      // snaps the cadence straight back to fast.
      const signature = [
        job.status, job.stage, job.message, job.percent, job.current,
        job.total, job.files_scanned, job.bytes_scanned, job.canceling,
      ].join("\u0001");
      if (signature !== lastSignature) {
        lastSignature = signature;
        pollDelay = POLL_INTERVAL_MS;
      } else {
        const ceiling = document.hidden ? POLL_MAX_HIDDEN_INTERVAL_MS : POLL_MAX_INTERVAL_MS;
        pollDelay = Math.min(Math.round(pollDelay * 1.7) || POLL_INTERVAL_MS, ceiling);
      }
      await new Promise((r) => setTimeout(r, pollDelay));
    }
  }

  async function cancelCurrentJob() {
    if (!lastJobId) return;
    // Optimistic: flip to "Canceling…" immediately (before the engine replies)
    // so the button feels alive even if the next poll is a half-second away.
    // The engine sets job.canceling on the next status snapshot; renderProgress
    // keeps the "Canceling…" headline from then on and disables the button.
    cancelRequested = true;
    cancelRequestedAt = Date.now();
    if (lastJobSnapshot) drawProgress(lastJobSnapshot);
    try {
      await postJSON("/api/cancel", { job_id: lastJobId });
    } catch (err) {
      // The engine may have already finished (or never existed); the poll loop
      // still owns the terminal state. Undo the optimistic flag so a transient
      // failure doesn't leave the panel stuck on "Canceling…".
      cancelRequested = false;
      showConnectionError(err);
    }
  }

  async function finishJob(jobId) {
    const data = await getJSON(`/api/result?job_id=${encodeURIComponent(jobId)}`);
    if (!data.ready) {
      throw new Error("The analysis is not ready yet.");
    }
    payload = data.payload;
    viewedScanNote = "";
    renderDashboard();
    renderHistoryChip();
    refreshHistory().catch(() => {});
    $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---------------- Scan history (local SQLite) ----------------
