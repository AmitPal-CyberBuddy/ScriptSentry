/* ScriptSentry Web dashboard */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // Icon set: small stroke SVGs (feather-style geometry, 24x24, currentColor)
  // replacing the emoji chrome. Emoji render differently on every platform
  // and read as decoration; these are crisp at any size and inherit the
  // text color. All UI icons live here so the set stays coherent.
  const ICON_PATHS = {
    shield: '<path d="M12 3l7 3v5c0 4.6-3 7.7-7 9.3C8 18.7 5 15.6 5 11V6z"/>',
    key: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    vial: '<path d="M10 2v6.3L4.6 17.9A2 2 0 0 0 6.4 21h11.2a2 2 0 0 0 1.8-3.1L14 8.3V2"/><path d="M8.5 2h7"/><path d="M7 15h10"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13.5 13.5 0 0 1 0 18 13.5 13.5 0 0 1 0-18z"/>',
    bolt: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    bug: '<path d="M8 6l-1-2M16 6l1-2"/><rect x="8" y="6" width="8" height="12" rx="4"/><path d="M8 12H3M21 12h-5M8 8L5 6M16 8l3-2M8 16l-3 2M16 16l3 2"/>',
    alert: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/>',
    sparkles: '<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M18.5 14.5l.8 1.9 1.9.8-1.9.8-.8 1.9-.8-1.9-1.9-.8 1.9-.8z"/>',
    layers: '<path d="M12 2l10 5-10 5L2 7z"/><path d="M2 12l10 5 10-5"/><path d="M2 17l10 5 10-5"/>',
    star: '<path d="M12 2.5l2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5L2.5 9.4l6.6-.9z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/>',
    scale: '<path d="M12 3v18M5 21h14M6 3h12"/><path d="M6 3L3 10a3.2 3.2 0 0 0 6 0z"/><path d="M18 3l-3 7a3.2 3.2 0 0 0 6 0z"/>',
    tool: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    check: '<path d="M20 6L9 17l-5-5"/>',
    x: '<path d="M18 6L6 18M6 6l12 12"/>',
    download: '<path d="M12 3v12"/><path d="M6 11l6 6 6-6"/><path d="M4 21h16"/>',
    palette: '<path d="M12 3a9 9 0 1 0 0 18h1.5a2.5 2.5 0 0 0 0-5H12a2 2 0 0 1 0-4h6.5A3.5 3.5 0 0 0 22 8.5C22 5.5 17.5 3 12 3z"/><path d="M7.5 10.5h.01M10.5 7h.01M15 7h.01"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5.5"/><circle cx="12" cy="12" r="2"/>',
    home: '<path d="M3 10.5L12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/><path d="M10 21v-6h4v6"/>',
    "git-branch": '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/><path d="M6 9v6"/>',
    container: '<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5"/><path d="M12 13v8"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    briefcase: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M3 13h18"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    file: '<path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6"/>',
    "file-text": '<path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>',
    chart: '<path d="M3 3v18h18"/><path d="M8 17v-5M13 17V7M18 17v-8"/>',
    clipboard: '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/>',
    pin: '<path d="M12 21s-7-5.8-7-11a7 7 0 0 1 14 0c0 5.2-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
    ruler: '<path d="M3 17.2L17.2 3 21 6.8 6.8 21z"/><path d="M8 16l1.5 1.5M11 13l1.5 1.5M14 10l1.5 1.5M17 7l1.5 1.5"/>',
    book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V2H6.5A2.5 2.5 0 0 0 4 4.5z"/><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/>',
    "book-open": '<path d="M2 4h6a4 4 0 0 1 4 4v13a3 3 0 0 0-3-3H2z"/><path d="M22 4h-6a4 4 0 0 0-4 4v13a3 3 0 0 1 3-3h7z"/>',
    edit: '<path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
    plug: '<path d="M9 7V2M15 7V2"/><path d="M6 7h12v4a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1-1"/>',
    flame: '<path d="M12 2c1 3-2 4.5-2 8a2.5 2.5 0 0 0 5 .5C17 12 19 13 19 16a7 7 0 0 1-14 0c0-5 4-6.5 7-14z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 15h10l1-15"/><path d="M10 11v6M14 11v6"/>',
    message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    launch: '<path d="M5 19L19 5"/><path d="M8 5h11v11"/>',
    signal: '<rect x="8" y="2" width="8" height="20" rx="4"/><circle cx="12" cy="7" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="12" cy="17" r="1.6"/>',
    blocked: '<circle cx="12" cy="12" r="9"/><path d="M5.5 5.5l13 13"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="10" y="10" width="4" height="4"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    compass: '<circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l-2 5-5 2 2-5z"/>',
    code: '<path d="M8 6L2 12l6 6M16 6l6 6-6 6"/>',
    save: '<path d="M5 3h11l3 3v15H5z"/><path d="M8 3v5h7V3"/><path d="M8 21v-7h8v7"/>',
  };

  function svgIcon(name, cls) {
    const body = ICON_PATHS[name];
    if (!body) return "";
    return `<svg class="icon${cls ? " " + cls : ""}" aria-hidden="true" focusable="false" `
      + `viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" `
      + `stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
  }

  // Legacy keyed lookups (ICONS[c.icon] in charts/steps) keep working.
  const ICONS = {};
  Object.keys(ICON_PATHS).forEach((name) => { ICONS[name] = svgIcon(name); });
  // The dashboard's category chips call the globe "route".
  ICONS.route = svgIcon("globe");

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