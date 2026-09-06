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
  // Latest /api/health payload: what the engine advertises (AST parser,
  // runtime evidence availability) is what the console capability chips show.
  let lastHealth = null;
  // The most recent analysis the user asked for. When the hosted page cannot
  // reach the engine (browsers block https → http://127.0.0.1), this travels
  // inside the handoff link so the local dashboard can fill in every setting
  // — URL/code/files, profile, depth, cap, workers — and start the scan.
  let currentScanRequest = null;
  let pendingScanTransfer = null;
  let transferPrompted = false;
  // Progress-display state shared by the poll loop and the client-side
  // ticker. The engine only advances `elapsed_ms` / `since_update_ms` when it
  // emits an event, so a long quiet stage (one big bundle being parsed) would
  // otherwise show a frozen clock — the exact "is it stuck?" moment. The
  // ticker extrapolates those two timestamps between polls so the clock and
  // the "last update … ago" readout keep moving even while the engine is
  // silent, and it stops the moment the engine re-reports.
  let lastJobSnapshot = null;
  let lastRenderAt = 0;
  let progressTicker = null;
  // Optimistic cancellation: set the instant the user clicks Cancel, before
  // (and regardless of) the engine acknowledging it, so the UI flips to
  // "Canceling…" immediately instead of waiting for the next poll.
  let cancelRequested = false;
  let cancelRequestedAt = 0;
  // The scan's recent events, in order, for the activity log.
  let activityLog = [];

  /* API base: same origin locally, or a hosted Python backend on Pages. */