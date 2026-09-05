# webui/src — source of truth for `webui/app.js`

The shipped dashboard is a **single file**, `webui/app.js`: the pages load
`../app.js` directly (no bundler, no build step for users) and the Python
tests read it. Editing a 3,000-line IIFE, however, is miserable — so the
editable source is the numbered fragments in this directory and
`webui/app.js` is **generated** from them.

## Workflow

1. Edit the relevant fragment in `webui/src/app/NN-*.js`.
2. Rebuild: `python3 tools/build_webui.py`
3. Commit **both** the fragment and the regenerated `webui/app.js`.
   (`--check` fails if `app.js` is stale; CI runs it.)

All fragments are concatenated inside one `"use strict"` arrow IIFE
(`(() => { ... })();` — opened in `01-header.js`, closed in `12-boot.js`),
so every fragment sees the shared state and helpers of every other
fragment, exactly as before the split. Keep it that way: no fragment may
open or close a block that another fragment has to match.

## Fragment map

| Fragment | Contents |
| --- | --- |
| `01-header` | IIFE open, `"use strict"`, `$`/`$$`, ICONS, shared mutable state |
| `02-connection` | engine base URL/pairing, backend check, hosted→local handoff, privacy modal, connection errors |
| `03-page-chrome` | launcher download, reveal-on-scroll, sticky header, nav spy, help tips, mobile nav |
| `04-scan-io` | input-pane switching, transfer notes, `postJSON`/`getJSON`, formatters, stage rendering, activity log |
| `05-progress` | progress ticker/drawer, scan-busy state, loading overlay, number animation |
| `06-tabs-and-polling` | tabs, particles, job polling + backoff, cancel, quiet-scan notes |
| `07-history-and-analysis` | scan history chip/view, field validation, `analyzeCode`/`analyzeUrl` |
| `08-uploads-and-export` | upload queue, `analyzeFiles`, report export, engine notes |
| `09-dashboard-render` | payload store/restore, dashboard skeleton, priorities/risk/signals/scripts/deps/runtime/attack/flows |
| `10-findings` | finding status model, unified findings table, view switching |
| `11-charts` | summary, donut/radar charts, timeline, scan summary, per-file panels |
| `12-boot` | page detection (`isToolPage`), `init`/`initTool`, key handlers, `DOMContentLoaded` |
