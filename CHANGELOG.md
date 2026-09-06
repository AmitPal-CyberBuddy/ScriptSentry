# Changelog

All notable changes to ScriptSentry are listed here, newest first.

> 🚧 **Status: under active development.** ScriptSentry is still a pre-release
> tool: it is already useful for triage, but features and detection rules keep
> improving, and details may change between versions.

## [Unreleased] — 2.2.0-dev

The 2.2.0 accuracy & triage work below is in development and not a published
release yet.

### Data & storage: the local-first claim, now verifiable

- **A "⚙ Data & storage" trust surface lives in the setup dialog.** The
  aside column (the three-page architecture is unchanged) gains a section
  backed by `GET /api/storage`: history enabled/disabled, the SQLite DB and
  WAL file sizes, scan and finding counts, oldest/newest scan timestamps,
  the retention limit, stored report-payload bytes, the ETA-calibration
  file size, and which browser keys each piece uses (triage statuses in
  `localStorage`; last report and pairing token in `sessionStorage`). A
  small "where is this stored?" link next to the history diff chip after a
  scan opens the same section.
- **Deletion is a real wipe, not a row delete.** `DELETE
  /api/history/<scan_id>` removes one scan and its findings;
  `DELETE /api/history` closes the SQLite handle, deletes `history.db`,
  `-wal` and `-shm` (row deletes aren't enough in WAL mode — a stale open
  handle can resurrect deleted rows), and recreates an empty database from
  the shared schema. Anonymous ETA timing stats in `eta_calibration.json`
  are kept by default (they aren't user content) and only removed with the
  explicit `include_calibration=true` flag.
- **Destructive routes follow the same security model as analysis.**
  They are DELETE-only, require the pairing token, and reject untrusted
  origins; the UI confirms every destructive action and its controls are
  disabled while a scan runs (the existing `setScanBusy` pattern).
- **Your data can be browsed and downloaded.** The panel reuses the scan
  list already fetched for the history card, each row with a delete button,
  and `GET /api/history/export` downloads the entire history — scans,
  findings and diffs — as JSON in the same attachment style as the report
  exports, with stored report payloads included only behind
  `include=payload`.
- **The copy states the negatives.** Never stored: cookie values, request
  bodies, localStorage values, form inputs. Scan content never leaves the
  machine — AI notes come from the user's own local model and exist only
  inside the stored report; URL downloads/uploads use a temporary
  workspace deleted after the scan.

### Dashboard fixes: panels that would not show, and notices that read as errors

- **Findings / Scripts / Intelligence / Runtime panels now actually appear.**
  `activateView()` used to reveal the selected tab by setting
  `group.style.display = ""`, which removes the inline style and lets the
  panel fall back to the stylesheet's `display: none`; only the Overview
  panels ever surfaced, because they also carry `.grid` (which sets its own
  display later in the file). Tabs now toggle an `.is-active` class instead,
  with a stylesheet rule whose specificity wins over both `.view-group` and
  `.grid` (and keeps the Overview grid layout when active). A new
  source-contract test in `tests/test_responsive_ui.py` fails if inline-style
  revealing is reintroduced.
- **The AST fallback notice is honest instead of alarming.** When a file's
  dialect cannot be parsed, the engine note now names that file and explains
  that only that file fell back to conservative regex patterns while the rest
  used full AST analysis. Engine notes render with a neutral `ℹ️` marker
  (previously `⚠️`), so genuine warnings keep their warning signal and
  informational degradation is not mistaken for an error.
- **The analysis dashboard stops reading as one long card.** Findings,
  Scripts, Intelligence and Runtime panels used to stack full-width cards,
  leaving long empty bands below short panels. Each of those views is now a
  single two-column card grid (one column on narrow screens), so panels sit
  side by side, shorter panels are no longer stretched to fill gap, and a
  view with one panel (Runtime) still spans the full row. A layout
  source-contract test in `tests/test_responsive_ui.py` fails if a view
  regresses to stacked full-width cards.

### The interface, recomposed

- **The landing page is an editorial document now, not a stack of cards.**
  The hero is an asymmetric split — the statement on the left, a static
  "live signal" instrument card on the right that speaks the report's own
  language (verdict, severity bars, finding lines). The ten capabilities
  are a numbered index with hairline dividers instead of ten identical
  cards; the workflow is one full-width band with oversized numerals; the
  trust argument is set as type; the setup guide separates the one
  recommended path from the alternatives.
- **The analyzer page leads with the product.** The old hero billboard is
  a slim command strip, so the console sits above the fold; the results
  header is a proper band with the export cluster attached to it.
- **A calmer, flatter visual system underneath everything**: darker flat
  background, surfaces separated by hairlines instead of glows, tighter
  radii, one ambient light instead of three colored blobs, monospace
  micro-labels, and color reserved for data (severity, status, charts).
  All 434 tests — including the responsive-contract suite (grid hygiene,
  cascade order, touch targets, breakpoints) — pass unchanged.
- **The capability rail carries the engine facts** (AST engine, exports,
  history, AI notes, privacy) so the left column of the index is content,
  not empty space; the setup dialog gains the pip/pipx/Docker path as a
  third tab; the 404 page is rebuilt in the new design language; and the
  local server sends `Cache-Control: no-cache` so a stale cached page can
  never pair with a newer engine.

### Maintainability: the engine behind the tool

- **The 714-line `server.py` monolith is now a thin bootstrap over an `api/`
  package** (`settings`, `auth`, `cors`, `http`, `analysis_routes`,
  `report_routes`, `handlers`). Nothing moved for users: `python server.py`,
  `scriptsentry-server`, and every `from server import …` embedder import
  behave exactly as before.
- **`webui/app.js` is now edited as 12 focused fragments** in
  `webui/src/app/` and regenerated byte-for-byte by
  `python3 tools/build_webui.py` — no Node toolchain needed. The shipped
  single file is unchanged (pages still load `../app.js`); CI fails if
  `app.js` drifts from its fragments.
- **The lint gate widened** to ruff's bugbear (B) and simplify (SIM) rule
  families with the whole tree clean. Bugbear caught one real bug on the way
  in: the progress tracker's "banked stage progress" loop computed
  `max(done, 0.0)` — a no-op — so finished stages' progress was not actually
  banked; it now banks `fraction × weight` as documented.
- **Coverage reporting is configured** (`[tool.coverage]` in
  `pyproject.toml`): `python3 -m coverage run -m unittest discover -s tests`
  then `python3 -m coverage report`.
- **The landing page tells the truth about 2.2.0.** New feature cards for
  scan history & diffing and the local-AI triage notes; the secrets,
  attack-surface and dependencies cards now mention provider-format
  validation, SPA hash-route hints and known-vulnerability matching; the
  workflow lists the JSON/OpenAPI exports; the shipped "build-over-build
  diffing" teaser is replaced by the real feature; and the setup guide
  gained pip/pipx and Docker install paths beside the launcher and git
  clone.

### An ETA that knows what the scan costs — and a quieter, politer UI

- **Time remaining is now estimated from the discovered workload.** The old
  ETA extrapolated the progress bar's speed and nothing else — it froze
  during quiet stages and could show `eta ~2m left` beside `last update
  28m ago`. The new estimator (`core/eta.py`) blends two sources: a cost
  model built from what recon/discover/download actually found (file count,
  real bytes), the scan profile (timeouts, caps) and the worker count, with
  throughput constants calibrated on real hardware (tunable via
  `SCRIPTSENTRY_ETA_ANALYZE_*`); and the observed rate of real progress,
  which takes over as it proves itself (`eta_confidence`, `eta_basis` in
  `/api/status` say which half is currently trusted). A 6-script site no
  longer borrows the file cap as its workload, strict 500-file scans are no
  longer capped at a 15-minute ceiling, and the estimate stays live —
  recomputed on every status poll — while the engine is silent, with
  `elapsed` counting from the real start time instead of freezing with the
  last engine event.
- **Status polling adapts to the scan.** The dashboard polls fast (500 ms)
  while progress visibly moves and backs off — up to 4 s (10 s in a hidden
  tab) — when the engine reports the same snapshot, snapping back to fast on
  any change. Successful `/api/status` and `/api/health` polls are no longer
  printed by the engine, so its terminal stops drowning in
  `GET /api/status 200` lines during a scan (failures still log).
- **A running scan locks the conflicting actions.** "Analyze Files" (which
  used to stay enabled — a second scan could silently clobber the running
  one) and the four report-export buttons are disabled while a scan runs;
  exporting for a still-running job now surfaces the engine's real answer
  ("Analysis is still running…") in the status pill instead of opening the
  pairing/setup dialog.

### Source maps: analyze the original code behind the bundle

- **Original sources are now analyzed, not just detected.** When a bundle
  ships `//# sourceMappingURL=...` with embedded `sourcesContent` (inline
  data URIs or a fetchable `.map`), the engine analyzes those pre-build
  sources and attributes findings to their real file names
  (`./src/auth/config.ts`), marked `via: source_map` in findings, exports
  and the dashboard. Bounded by design: at most 12 sources per bundle
  (`SCRIPTSENTRY_SOURCES`... `SCRIPTSENTRY_SOURCEMAP_SOURCES`), 400 KB per
  source, a 3 MB total budget, content-hash dedup against the bundle, and a
  kill switch (`SCRIPTSENTRY_SOURCEMAP_ANALYSIS=0`). A per-file chip and an
  engine note show how many originals were analyzed and how many findings
  they produced; maps without embedded contents are reported honestly.
- **Two quadratic regexes fixed — minutes became seconds.** A production
  bundle carrying a large single-line base64 blob (exactly what an inline
  source map is) used to stall `extract_crypto_material` for *minutes*:
  `\w+(...)*{`-style patterns made every position of the run scan to
  end-of-line (O(n²)). The function-definition and service-trace patterns
  are now bounded (`\w{1,64}`, ≤200-char argument lists), and the taint
  fallback skips "statements" larger than 4 KB (a multi-hundred-KB
  non-delimited run is data, not code). A 521 KB inline-map bundle now
  analyzes in ~2 s instead of 240 s+, and the no-parser test suite dropped
  from timing out to ~10 s. This was very likely the dominant cost behind
  long silent analyze stages on production targets.

### Dependencies: known-vulnerability matching

- **Version banners are now fingerprints.** Bundled libraries carry their
  versions in banner comments and module metadata (`/*! jQuery v3.4.1 */`,
  `_.VERSION="4.17.15"`). A curated advisory table (jQuery, Lodash,
  Underscore, Moment, Axios, Bootstrap, AngularJS, CryptoJS — fix-version
  ranges with CVE ids) turns those into findings: "Vulnerable library:
  jQuery 3.4.1 (CVE-2020-11022)" with severity and summary, honest medium
  confidence (a fingerprint, not a probe). The contract is conservative:
  **no version extracted → no vulnerability claimed** — inventory stays
  inventory; patched versions are annotated but silent.

### Secrets: the value itself is now evidence

- **Credential validation tiers.** Candidates are checked against the
  providers whose token *shape* is proof: JWTs must base64url-decode into
  JSON with an `alg` header (`structure` tier), PEM blocks must carry a
  decodable body, and Slack/GitHub/Stripe/SendGrid/AWS/Twilio/npm tokens
  match their canonical documented formats (`format` tier). A validated
  candidate upgrades the hardcoded-secret finding to **high** confidence
  (carrying the provider verdicts); unvalidated entropy guesses stay at
  medium. Nothing else gains anything — ordinary strings validate to None.
- **The secret analyzer never produced a finding.** A `match.groups() > 1`
  tuple/int comparison raised TypeError on the first regex match — silently
  swallowed into `analyzer_errors` — so the `secret_analysis` section has
  been empty since it shipped. Fixed, with a regression test; findings now
  carry their validation verdict per candidate.

### Any local model, and a shippable package

- **Any OpenAI-compatible local model server.** `--ai openai` speaks the
  OpenAI chat-completions protocol against **local** servers — LM Studio
  (`http://localhost:1234/v1` by default), llama.cpp server, vLLM — with
  `--openai-base-url`, `--api-key` (for servers that want a token) and the
  same honest fallback (`openai_unavailable`) as the Ollama path when the
  server is down. Hosted cloud providers remain deliberately unsupported:
  the privacy contract ("code never leaves your machine") still holds.
- **Packaging.** `pyproject.toml` makes the engine pip/pipx-installable
  (`pip install .` → `scriptsentry` and `scriptsentry-server` console
  commands, version read from `core.version`, dashboard shipped as package
  data with a `SCRIPTSENTRY_WEBUI_DIR` override and a share-dir fallback);
  a Dockerfile builds an image with the Playwright Chromium preinstalled
  for headless/CI runtime evidence; and the dashboard gains a raw **JSON**
  export button (the shared `generate_json_report` shape the CLI writes).

### Deeper discovery & a politer crawler

- **Sitemap/robots.txt discovery.** Recon now reads `robots.txt` for
  `Sitemap:` lines and `/sitemap.xml`, and follows up to 10 declared
  same-origin *pages* (never assets or cross-origin URLs) through the same
  script extraction as the landing page — lazy chunks that only a sitemap
  page loads are analyzed too, and the report notes where they came from.
  `SCRIPTSENTRY_SITEMAP_DISCOVERY=0` disables it.
- **OpenAPI-shaped API-surface export.** The endpoint inventory the engine
  already extracts now exports as an OpenAPI 3.1 document (`🧭 API map`
  button in the dashboard, `--format openapi` on the CLI, written as
  `api-surface.openapi.json` with `--format all`): real paths, methods,
  query parameters and header/auth hints, with websockets/SSE/GraphQL under
  `x-` extensions. It is explicitly an *observation* export — descriptions
  say the operations were seen in shipped JavaScript, not documented.
- **SPA hash-route hints.** Client-side routes hidden in quoted hash
  fragments (`#/admin/users`, `#/settings/profile` — router tables, redirects,
  `href`s) are now reported as attack-surface hints: a dashboard panel, a
  report section, and an `x-spa-hash-routes` extension in the OpenAPI export.
  They are marked `⚠ internal` when they match the internal/hidden hints and
  are deliberately *not* listed as API paths — the server answers a hash
  route with the same document as any other.
- **Crawl politeness.** `SCRIPTSENTRY_CRAWL_DELAY_MS=<ms>` serializes every
  network request per host (pages, scripts, source maps — one choke point
  in `safe_get`), for scanning sites you own without bursting. Default off.

### Test-suite guard fix

- The SSRF guard tests (`tests/test_hardening.py`) now pin
  `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS` off for themselves, so the whole
  suite passes whether or not the process-wide override (which CI sets for
  the loopback pipeline tests) is present — a latent conflict the sitemap
  tests flushed out before CI ever ran these commits.

### Scan history: "3 new, 2 resolved since your last scan"

- **Local scan history with cross-scan diffing.** Every completed dashboard
  scan is now recorded (SQLite, WAL, one file under the shared state
  directory — `core/history.py`) with a fingerprint per finding that is
  stable across scans (finding id + document + sink/title; deliberately not
  line numbers, which shift with unrelated edits). The dashboard shows the
  diff against the previous scan of the same target as soon as a scan
  finishes, and a history panel lists recent scans (files, findings,
  duration, +new/−resolved) with a View button that re-renders a past scan
  through the same dashboard code path. Retention keeps the newest 200
  scans (`SCRIPTSENTRY_HISTORY_MAX`); oversized reports store summary-only;
  `SCRIPTSENTRY_HISTORY=0` turns recording off; canceled/failed scans record
  nothing and history failures can never fail a finished scan. Local-only,
  like everything else.

### The ETA learns your machine

- **Self-tuning calibration.** The workload cost model shipped with constants
  measured on one laptop; on a faster box (or with the new process engine) it
  started every scan with the same systematic error. Now each successful URL
  scan reports the measured wall-clock seconds of the CPU-bound stages
  (analyze, normalize); the correction folds into a bounded EWMA
  (`core/eta_calibration.py`, clamped to 0.25–4.0, ~3 scans to converge) and
  persists to `$SCRIPTSENTRY_STATE_DIR/eta_calibration.json` (default
  `~/.cache/scriptsentry/`), keyed per analyze engine since the process pool
  legitimately changes the math. Network-bound stages are never tuned, junk
  samples (no files, tiny bytes, absurd durations) are rejected, and
  `SCRIPTSENTRY_ETA_SELF_TUNING=0` switches the whole loop off. Canceled or
  failed scans record nothing; bookkeeping can never break a finished scan.

### Performance: measure first, then cut

- **The scan pipeline was profiled end-to-end and the real bottlenecks cut.**
  On a 440 KB minified bundle a single-file scan dropped from ~10.3s to
  ~5.2s. The big rocks were not where the roadmap guessed: not the ten
  sub-analyzers (~330ms combined) but the taint analyzer re-descending the
  whole AST six times (now flattened once per document, ~5.3s → ~1.8s),
  line-number computation that sliced and re-counted the entire document per
  regex match (`content[:pos].count("\n")` — attack-surface GraphQL/URL
  sweeps, the taint regex fallback; now a shared bisected line index,
  `core/text_index.py`), the crypto extractor re-scanning the full content
  once per candidate string via `content.find` (now `finditer` + a bisected
  proximity window, ~1.7s → ~0.2s — and candidate positions are now the real
  match positions, not the first occurrence of a repeated string), an
  O(matches × endpoints) dedupe scan, ~40 full-content `str.lower()` copies
  in the dependency scan, and a redundant full-tree conversion pass in the
  new tree-sitter converter (estree `range`s are now emitted eagerly per
  node). Finding order and all detection outcomes are preserved; 349 tests
  pin both modes.
- **The analyze stage now uses all cores.** Per-document analysis is
  CPU-bound (parsing + Python AST walks), so a thread pool serialized every
  worker onto one core under the GIL. URL scans now run the analysis in a
  process pool (`ProcessPoolExecutor`, spawn context) — parsing and walks in
  workers, all I/O (reads, dedupe, chunk downloads, source-map fetches) and
  all progress reporting in the parent; worker heartbeats for large bundles
  travel back through a queue so the dashboard keeps moving mid-file. A
  broken/unavailable pool degrades to the thread engine automatically, and
  `SCRIPTSENTRY_ANALYZE_ENGINE=thread` opts out entirely. On a 2-core
  machine the 4-file benchmark improves ~17%; the gap grows with core count
  and bundle count. Uploaded snippets/analyze one file in place unchanged.

### Modern JavaScript parsing

- **tree-sitter is now the primary AST engine.** The analyzer parses with
  tree-sitter (JavaScript grammar, TypeScript grammars for `.ts`-shaped
  input) and keeps `esprima` as an automatic fallback. Esprima predates
  optional chaining, nullish coalescing and class fields, so every modern
  bundle used to silently drop to the capped-confidence regex fallback; those
  files now get the full AST pipeline — taint flows, attack surface, import
  discovery — on syntax written after 2020. A ~350 KB minified bundle parses
  and converts in under a second, and the parse-once cache still guarantees
  one parse per document no matter how many analyzers need the tree.
- **Partial trees instead of hard failures.** tree-sitter recovers from
  syntax errors, so a bundle with a corrupted region still yields an AST for
  everything else; the unparseable regions are counted and surfaced as an
  honest "AST parse note" in the report instead of discarding the file.
- **Estree compatibility preserved.** The converter emits estree-shaped
  dictionaries — including `range` offsets in character positions, dynamic
  `import()` modelled as `ImportExpression`, and `?.`/`??` mapped onto
  `MemberExpression`/`BinaryExpression` with their `optional`/operator
  markers — so taint evidence, source/sink labels and module discovery
  behave exactly as they did under esprima. Byte-to-character translation
  keeps ranges correct in sources that contain non-ASCII text.

### Development infrastructure

- **CI is here.** A GitHub Actions workflow now runs the whole test suite on
  Python 3.10–3.12 *and* on a second matrix entry with the optional AST
  AST stack removed — pinning the documented regex-fallback degradation so the
  fallback mode can never silently regress. Loopback URL-scan pipeline tests
  run in CI too, the shipped web UI is syntax-checked with Node, and ruff
  (`ruff.toml`, pyflakes + pycodestyle errors) guards the Python correctness
  floor. The suite went from "268 tests, 10 fail without optional deps" to
  283 tests that pass in **both** modes: tests needing an AST engine or the
  `requests` package now skip with an honest reason instead of failing. Falling out of the new lint gate: dead code and unused imports
  removed across `core/`, two bare `except:` blocks made explicit, and a
  duplicated `file_size`/`line_count` pair dropped from the report model.
  See the new `ROADMAP.md` for what comes next.

### Honest scan progress — no more "is it stuck?" spinner
- **The dashboard no longer declares a false timeout.** The browser poll loop
  used to give up after exactly 10 minutes with *"Analysis timed out while
  waiting for the local engine"* — while the engine was still scanning a large
  target. The poll now waits as long as the engine keeps answering and
  reporting: transient contact losses are tolerated for a 20-second grace
  window, a restarted engine is reported as exactly that ("server.py was
  probably restarted"), and long scans simply keep the live progress panel
  open. Polling backs off while the tab is hidden.
- **Every silent stretch now explains itself.** The engine reports a
  heartbeat (`since_update_ms`) with each status poll, and — for large
  documents — from *inside* a single-file analysis: heavy passes (secrets,
  AST, each sub-analyzer, taint, attack surface) now emit *"Analyzing
  app.min.js — taint flows"*-style events, so a production bundle that
  occupies one worker for minutes no longer looks like a dead engine (the
  old dashboard could sit at "last update 28m ago" while a 2 MB bundle was
  still being worked). When a stage does stay quiet, the progress panel
  first names that stage's cost (*"Static-analysis passes … stay quiet while
  one large bundle is processed — normal for production-size JS"*), adds
  elapsed/ETA context after 2 minutes, and only after 6 minutes of total
  silence mentions Cancel — pointing at the engine terminal first, without
  blaming the file-cap/worker settings.
- **Work is announced before it happens.** Files in flight are reported as
  *"Scanning app.min.js…"* (the old UI could only say "Analyzed …" after the
  fact, so a 30–60s bundle looked frozen), beautifying reports per-file
  *"Normalizing … (3/12)"*, and runtime-evidence capture emits a heartbeat
  while the headless browser runs.
- **The progress bar can no longer jump to 100% and snap back.** Download
  events used to bypass the weighted stage model, so the job derived
  `percent = files_done/files_total` mid-download. All download and normalize
  events now flow through the same weighted, monotonic percent.
- **An unfetchable target is an error, not an empty report.** A page that
  cannot be downloaded (wrong URL, network down, bot protection) fails the
  scan with an actionable message instead of "completing" in seconds with a
  blank dashboard; a page that loads but genuinely has no JavaScript explains
  that in the report notes.
- **Cancelling is no longer styled as an error.** A user-initiated cancel
  shows a neutral inline note instead of painting the input red.
- **URL scans are ~2x faster.** The same document was previously parsed by
  esprima once per consumer (taint, attack surface, module discovery, AST
  summary) — up to four full parse + AST-conversion passes per file, which is
  where scans silently spent most of their time. A bounded, content-hash-keyed
  parse cache (`core/js_parser.py`) now parses each unique document exactly
  once and shares the read-only tree; one measured 335 KB bundle went from
  142s to 26s (5.5x), and a full mock-site scan from 129s to 68s. The cache is
  bounded by source bytes (256 KB/entry, 512 KB total) so large bundles can
  never pin unbounded memory. `token_count` is now 0 because the token stream
  is no longer collected (nothing consumed it; collecting it made conversion
  ~2.5x slower).

### The hosted page now hands your scan over — and honest setup steps
- **No more re-entering the scan on the local dashboard.** The hosted page
  (GitHub Pages) can never call `http://127.0.0.1:8000` — browsers block the
  mixed-content request. Instead of sending you there empty-handed, the
  pending analysis now travels **inside the hand-off link** (`#scan=`
  fragment, which browsers never send to any server): target URL, profile,
  depth, file cap, workers, pasted code, and even uploaded files (up to a
  2 MB link budget; larger uploads are named and re-picked on the local
  page). The engine's dashboard fills the console in and starts the scan
  automatically once it is paired.
- **The setup guide no longer claims the local dashboard is "already
  paired".** It is not: the dashboard asks for the pairing token once, and
  every setup path now says exactly where that token comes from (printed in
  the engine's terminal, right under the dashboard address). The guide also
  states plainly that `scriptsentry.py` and `server.py` start the *same*
  engine — run one, not both.
- **The 📋 Copy button copies commands only.** The `#` comment lines shown
  next to the commands ("# downloads & starts the engine on first run") no
  longer end up in your terminal.
- **Hover tooltips no longer clip their first words.** The viewport nudge for
  the floating `?` tips ran only for click/keyboard opens, so hovering the
  left-column fields (Profile, Max files) could cut the tip off-screen; hover
  and focus now nudge it back into view too.
- **Direct `.js`/`.mjs` targets actually scan.** The URL field suggests
  `https://example.com/app.js`, but the engine treated every target as an
  HTML page — a direct script returned an empty "no JavaScript found"
  report. A direct script target is now downloaded and analyzed itself
  (bounded to the 2 MB per-file limit), its `import()`/chunk references are
  followed recursively, and provenance keeps the real URL. A `.js` URL that
  actually serves HTML (soft 404 wrapper) falls back to normal page
  discovery, and an unreachable target fails with an actionable error.
- Suite grown to **267 tests**: hand-off contracts (fragment-only transfer,
  comment-free copy, token wording) and direct-target scans against a live
  loopback site.

### End-to-end review hardening — risk chips, taint precision & transport
- **Per-file risk chips now match the overall score.** A file's chip comes from
  the same evidence-weighted 0–100 model as the report score
  (`core.risk_model.file_risk`), so a file can no longer read CRITICAL next to
  an overall MEDIUM. The legacy sum-based `signal_score` is replaced by the
  worst-file score; observation-only files stay below CRITICAL.
- **No directory listings.** `server.py` returns **404** for directories
  without an `index.html` (e.g. `/assets/`), so the local engine cannot leak a
  directory tree.
- **Bounded fallback reads.** The exception fallback in
  `core/url_policy.read_response_text` reads at most `max_bytes + 1` bytes from
  `response.raw` instead of letting `response.text` materialize an unbounded
  body.
- **Dead code removed**: unused `config` blocks (origin allow-list, noise
  words, scan/performance/confidence constants), `ai/prompts.py`, and the
  never-written `derived_keys` crypto result key.
- **Taint precision.** Identifiers bound to statically-known values (literals,
  constant templates, literal arrays/objects, constant unary expressions) no
  longer trigger the by-name heuristic; **reassignment to a static value clears
  prior taint** in both the AST and regex paths. Unresolved names (parameters,
  globals) keep their conservative medium-confidence treatment.
- **DNS-rebinding hardening.** Each target is syntax-checked and resolved in a
  single step, then every connection is pinned to the validated public address
  literals (all address families), so an attacker-controlled name server cannot
  swap the answer mid-request; each redirect hop is re-validated and re-pinned.
  `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1` opts out for explicitly authorized
  local/private targets.
- **Local-first AI summary.** `--ai ollama` sends only structured findings
  (never raw source) to a **local** Ollama server and falls back to the built-in
  rule-based summary when Ollama is offline or misbehaves. Cloud LLM providers
  and the `--api-key` placeholder were removed — shipping scanned code to a
  cloud would contradict the \"nothing leaves your computer\" design. The
  deterministic summary stays the default and is never mandatory.
- Suite grown to **227 tests + 5 subtests**, covering the AI contract, DNS
  pinning, per-file risk consistency, and the accuracy-regression cases.

### Accuracy & triage model
- Severity, **confidence**, triage **status**, and **analysis quality** are now
  independent axes. Confidence is derived from the *evidence* (regex → low,
  framework/behavioral → medium, source-to-sink/runtime → high, demonstrated
  runtime effect → confirmed) and is never inferred from severity.
- New triage vocabulary: **Open · Needs review · Confirmed · False positive ·
  Informational**. Static source→sink flows are high confidence but stay
  **Open**; **Confirmed** is reserved for deterministic proof, a demonstrated
  unsafe runtime effect (e.g. live `eval`), or explicit analyst confirmation.
- Runtime DOM-sink execution is high confidence / Open (exploitability not
  proven); WebSocket/API inventory and string timers are observations.
- Findings now carry an **analysis quality** (`high` / `medium` / `heuristic`)
  plus explicit **limitations** (dynamic property access, unmodeled call,
  inter-procedural depth bound, regex fallback).

### Findings vs observations
- Results are split into **Actionable Findings** (investigate/remediate) and
  **Security Observations** (interesting behavior that is not a proven
  vulnerability), surfaced as separate sections in the dashboard and reports.
- Stronger finding identity (type + canonical source + sink + file + line +
  normalized flow signature) so two distinct untrusted sources reaching the
  same sink are no longer collapsed into one record.

### Risk score
- New evidence-weighted **0–100 risk score** (`core/risk_model.py`) with a
  transparent `+points` contributor breakdown and an investigate-first
  **priority list**, replacing the previous unbounded category count.

### Script discovery
- New layered discovery (`core/module_discovery.py`): AST
  import/require/dynamic-`import()` first, bundler adapters (Webpack chunk
  maps, Vite/Rollup/Next.js/Parcel hashed assets) second, regex fallback third.
  Non-script references (API paths, JSON/CSS/font imports) are filtered out.

### Dashboard UX
- Primary navigation reduced from nine views to five: **Overview · Findings ·
  Scripts · Intelligence · Runtime** (Assets lives under Scripts; Attack
  Surface / Data Flows / Secrets / Dependencies live under Intelligence).
- Overview leads with "is it risky → why → what to investigate first"
  (priorities and score breakdown) above the charts.
- Findings show confidence, analysis-quality chips, and analysis limits.

### False-positive discipline
- Tightened credible-secret filtering (placeholders such as
  `YOUR_API_TOKEN_HERE`, template markers, and zeroed values are not credible).
- Formal **accuracy regression suite** (`tests/test_accuracy_regression.py`)
  with TP / TN / known-FP / framework-edge / minified / obfuscated fixtures.

### Onboarding & UX
- **Local file upload**: the Paste Code tab now has a "📁 Upload files" mode —
  drag & drop or browse multiple `.js` / `.mjs` / `.cjs` / `.jsx` / `.ts` files
  and analyze them in one scan with per-file attribution. Files are read in the
  browser and sent only to the paired local engine (nothing goes to a cloud);
  the server enforces an extension allow-list, a 20-file cap and a 3 MB/file
  limit. Content duplicates are deduped and path-like names sanitized.
- Scan controls (profile, max depth, max files, workers) now have inline **?**
  tooltips explaining what each one does.
- New one-file launcher `scriptsentry.py`: download a single file and run it;
  on first run it downloads the pinned engine from the official GitHub repo,
  installs dependencies and starts the dashboard (cached for later runs).
- Setup modal now offers a **Download scriptsentry.py** button alongside the
  git-clone path. Native `alert()` popups are replaced with inline field
  validation and error messages (invalid/non-URL targets, rejected scans).
- Added an **authorized-testing-only** notice to the page, the setup modal and
  the README.

### Brand, landing page & front-end fixes
- **Separate pages for overview and console**: `home/index.html` is the
  overview/landing page (hero, what it finds, how it works, trust, setup,
  connect) and `tool/index.html` hosts the analysis console. Both share
  `app.js`, `styles.css` and `config.js`; the script detects which page it is
  on and only wires the analyzer when the console markup is present. `server.py`
  serves `/` → `tool/index.html` so a locally started engine opens the console,
  while GitHub Pages serves the overview at `/home/`.
- **Scroll animations**: sections, cards, steps and footer columns reveal as
  they enter the viewport (`IntersectionObserver`, staggered, unobserve after
  the first reveal), plus a scroll-progress bar under the sticky header and
  active-section highlighting in the nav. All of it is disabled under
  `prefers-reduced-motion`, and the hidden state is scoped to a `js-reveal`
  class set in `config.js` so a failed script can never blank the page.
- **Proper headings**: one `h1` per page ("Watch every line…" on the overview,
  "JavaScript analysis console" on the console page), `h2` per section, `h3` per
  card, plus a skip-to-content link and `aria-current` on the active nav link.
- **Connect section is about ScriptSentry, not CyberBuddy.** It now reads
  "Building ScriptSentry for analysts, with analysts" with a ScriptSentry
  roadmap item (build-over-build diffing and a CI gate) instead of the
  CyberBuddy / HAR Analyzer copy.
- **Proper identity**: real SVG logo (shield + `</>` mark) rendered inline in the
  header and footer, plus `webui/assets/favicon.svg`, `favicon-32.png`,
  `icon-192.png`, `icon-512.png`, `apple-touch-icon.png`, a 1200×630
  `og-card.png` and a `site.webmanifest`. The page now ships full favicon,
  Open Graph and Twitter card metadata instead of a bare title.
- **Landing page**: the dashboard is now a single scrollable site with a sticky
  header (nav + **⚡ Go to tool** button), hero with dual CTAs, "What it finds",
  "How it works", "Why it's trustworthy", "Run your own engine" and
  "Connect with me" sections, and a multi-column footer with legal notice.
- **Fixed the launcher download.** The setup dialog used
  `<a href="raw.githubusercontent.com/…" download>`, which browsers ignore for
  cross-origin targets — the file opened in a tab instead of downloading. The
  launcher is now fetched and saved through a same-origin blob URL, with a
  new-tab fallback and an inline status hint.
- **Engine status is now an animated indicator.** The header pill uses a
  pulsing core + expanding ring (green / amber / red) instead of a static 🟢/🔴
  emoji, is clickable to open the setup guide, and is mirrored inside the
  setup dialog.
- **Setup dialog**: wider two-column layout on large screens (900 px), a proper
  **× close button** in the top-right, backdrop-click and Escape to dismiss,
  scroll lock, focus handling, and a dedicated "Pair the engine" column with
  the live engine state.
- **Target URL input was unstyled** (only `textarea` and `input[type=text]`
  were). All text/url/email/password inputs now share the themed field style,
  with a 🌐 prefixed URL field, a 🔑 prefixed token field, focus/hover states,
  placeholder colouring and a dark-mode autofill fix.
- `server.py` redirects the browser's automatic `/favicon.ico` probe to the real
  SVG asset instead of returning 404.

### Maintenance
- Engine version centralized in `core/version.py`; added `release.json` and
  this changelog. TXT report no longer iterates string evidence
  character-by-character; CSV/SARIF export quality/limitation fields.
- Test count: **227+ passing** (plus 5 subtests).


### Audit follow-ups — detection quality
- **One pattern catalogue.** `core/js_patterns.py` is now the single source of
  truth for sources, sinks, crypto markers and transport calls; `core/taint.py`
  and the `analyzers/*` modules import from it instead of keeping private
  copies that could disagree.
- **Secrets.** Deduped by longest credential token (one Firebase key is now one
  finding, not three); public-by-design client keys (Firebase `apiKey`,
  Google/Stripe/Recaptcha publishable keys) are reported as inventory under
  `public_client_keys` instead of as secrets; real provider credentials
  (`sk_live_`, `ghp_`, `xox*-`, `AKIA…`, Slack/Discord webhooks) are matched by
  value shape rather than by a minimum length.
- **Sensitivity.** `sensitive_storage` no longer fires on any mention of
  `document.cookie` or on `sessionStorage` at large — it requires a sensitive
  key name or value, so ordinary theme/analytics storage is MEDIUM again.
- **Secret context.** `content.find()` is checked for `-1` before slicing, so a
  reconstructed value can no longer quote the top of the file as its context.
- **Crypto.** Word-bounded, shared markers replace the old substring test that
  found "DES" inside "desktopTheme" and "Hex" inside "hexagon".
- **Taint.** New sources (`document.baseURI`, `history.state`, `window.name`)
  and sinks (element `href`/`src` assignment, `setAttribute('href'|'src'|'srcdoc')`,
  jQuery `.html()/.append()/.prepend()/.attr()`) on both the AST and the
  line-fallback path; source markers are matched case-insensitively, which
  previously hid every camelCase source from the AST path.
- **Risk floor.** A single HIGH/CRITICAL severity forces at least MEDIUM
  regardless of how much low-tier evidence a scan produced.
- **Parser visibility.** `/api/health` and the dashboard payload now report
  `ast_parser` (name / available / mode / install hint), the server prints the
  parser state at startup, and the console warns when a scan ran in fallback
  mode. Tests that require the AST layer skip cleanly when esprima is absent.

### Navigation and content cleanup
- **The footer's "Project" column implied pages that do not exist.**
  Separate "Changelog", "Documentation" and "Report an Issue" entries all
  pointed at the same GitHub repo, each labelled as though it were its own
  destination. They are now a single entry — "GitHub · source, docs &
  changelog" — which is honest about where it goes.
- **"Report an Issue" moved into Connect.** It no longer sits as its own
  footer entry. The Connect section now leads with it: what to send, plus
  the issue tracker alongside email and LinkedIn.
- **Removed the "Next: Bundle Diffing" footer link.** It looked like a
  roadmap page but only scrolled to the contact section. The roadmap is
  real content and stays in the Connect card, clearly labelled as what is
  next on the bench — it is not navigation.
- **Removed the duplicated "Feedback & Ideas" footer link,** which the
  header already covers.
- **Footers are three columns** (Brand / Product / Connect) instead of
  four, on both pages.
- **Removed repeated copy.** The footer brand paragraph restated the hero
  paragraph almost verbatim; it is now a single line. The Connect card's
  heading repeated its own section introduction. And "authorized testing
  only" appeared three times on the landing page — the setup dialog's copy
  is gone, since the hero notice and the persistent footer already carry
  it. The console page keeps its dialog notice because it has no hero
  notice to rely on.
- **Tests.** 11 new link-integrity tests: internal links resolve, in-page
  and cross-page anchors have targets, assets exist, `target="_blank"`
  carries `rel="noopener"`, no placeholder hrefs, and three guardrails on
  footer quality (no dead-end links, no repeating one destination, no
  sitemap-length footers). All mutation-tested.

### Responsive QA pass -- composition, not just fit
- **Stat tiles were 360px boxes on a tablet.** The generic `.grid-4`
  ladder dropped the four metric tiles to two tracks between 640 and
  1000px, leaving a 42px number adrift in a huge card. They now hold
  four across down to 640px (170px tracks, which still fit "Actionable
  Findings" on one line) and drop to two on a phone. Never three: eight
  would not be the issue, but four tiles on three tracks leaves an
  orphan.
- **The console container was over-widened.** It had been set to
  1440-1680 on the theory that a dense tool wants more room, but the
  console's density is vertical (long finding and script lists), not
  horizontal. Widening only stretched the two-up overview cards into
  750-830px letterboxes. It now tracks the landing measure.
- **The gauge card left a third of itself empty.** The dial was a fixed
  150px while its card grew past 600px, so the gauge and its caption
  huddled against the left edge. The dial now scales with the space and
  the pair is centred.
- **The donut chart letterboxed.** A square viewBox with `width: 100%`
  and a fixed height renders as a centred square no wider than that
  height, so the donut sat in 240px with hundreds of pixels of dead
  space either side. Its width is now capped to its height, and where
  the card is wide enough the legend sits beside it rather than below.
  That depends on the *card's* width, not the viewport's -- at a 620px
  viewport the charts are already two-up and the card is only ~272px --
  so it is a container query, degrading to stacked where unsupported.
- **Two orphan-row defects.** Eight feature cards on `auto-fit` reached
  five tracks on a wide monitor and left a lopsided 5 + 3; four step
  cards reached three tracks between ~880 and ~1170px and stranded one
  alone. Both now use explicit ladders whose counts divide the item
  count evenly.
- **Phone composition.** Four export buttons plus a status line
  free-wrapped into ragged rows; they are now a 2x2 group with the
  status spanning above. Five view tabs wrap to two columns with the
  fifth spanning the full width, rather than leaving a short last line.
  The Copy button no longer squeezes a code snippet into a ~110px
  column, which forced horizontal scrolling for a single long URL.
- **Spacing moved onto the fluid scale** for cards, the setup card, the
  console head and body, the tool hero and the dropzone, so density
  stays proportional instead of being tuned at each breakpoint. Fixed
  26px and 20px paddings were proportionally heavy inside a 292px phone
  card.
- **Tests.** 6 new composition tests (grid ladders, stat density,
  console containment, card-width ceiling), mutation-tested.

### Responsive design system
- **Mobile navigation was unreachable.** `.nav-toggle` is `display: none`
  by default, and the override that reveals it below 1040px sat ~370 lines
  *earlier* in the stylesheet. A media query is not a specificity bump, so
  the base rule won and the menu button never rendered — below 1040px the
  nav links were set to `opacity: 0` with nothing able to reveal them. The
  collapsed-nav block now sits at the end of the file, where it belongs.
- **A fluid design-token layer.** Gutters, vertical rhythm, radii,
  container widths and a full type scale are now `clamp()`-based custom
  properties, so 600px and 1200px are designed widths rather than sizes
  the layout merely survives. Breakpoints now only appear where the
  *architecture* changes (column counts, nav mode, modal → sheet).
- **Grids can shrink.** Every `1fr` track is now `minmax(0, 1fr)`. A bare
  `1fr` resolves to `minmax(auto, 1fr)` and refuses to shrink below its
  content, which is what pushed the page into horizontal scroll.
  `auto-fit` minimums are wrapped in `min(100%, Npx)` so a grid can never
  demand a track wider than its container.
- **Tooltips work on touch.** The `?` hints were 15×15px, hover-only, and
  opened a fixed 230px popover centred on the dot — untappable, and
  clipped off the right edge at any narrow width. They now have a 44px
  hit area, open on tap / click / Enter / Space, are nudged back into the
  viewport when a trigger sits near an edge, and on touch or narrow
  screens expand inline under their label instead of floating.
- **Charts follow their container.** The radar canvas was sized once from
  `clientWidth` and never redrawn, so it stretched after a resize or a
  rotation. A `ResizeObserver` now redraws it, which also covers the
  Overview panel being hidden and re-shown by the view tabs. Its label
  reserve is measured from the longest label instead of a fixed 30px, so
  labels no longer slice off at phone widths.
- **The particle field no longer thrashes.** It rebuilt every particle on
  every resize event, and mobile browsers fire resize continuously as the
  URL bar hides while scrolling. Width-only changes now matter, they are
  debounced, and the canvas is DPR-aware.
- **Modals become bottom sheets** on phones: full-width, thumb-reachable,
  `dvh`-capped (with a `vh` fallback) so content is not hidden behind
  browser chrome, with a 44px close button and safe-area padding.
- **Touch targets.** On coarse pointers every tab, button, pill, select
  and row control gets a 44px minimum, rather than asking a thumb to hit
  a 31px target.
- **Type is readable.** 23 declarations below 11.5px were raised onto the
  fluid scale — the clamps lift small screens the most and move desktop by
  at most ~1.5px. The base size moved from `<html>` to `<body>`: setting
  it on the root redefines `rem`, which made every `clamp()` scale twice
  over and overrode the visitor's own browser font size.
- **Text no longer clipped.** 33 sub-12px labels raised onto the scale.
- **Tests.** 15 new contract tests lock in the invariants above (grid
  tracks, cascade order, viewport units, type floor, touch targets,
  breakpoints), each verified by mutation testing.

### Scan pipeline, progress and reporting accuracy
- **Explicit pipeline stages.** A scan is now modelled as Recon → Discover →
  Download → Normalize → Analyze → Correlate → Verify → Report
  (`core/pipeline.py`). Each stage carries a cost weight, so the progress bar
  reflects where the time actually goes instead of crawling to 3% and then
  jumping. The console renders the stages with pending/active/done state; the
  fine-grained `phase` values existing consumers rely on are unchanged.
- **Honest ETA.** The old estimate was `elapsed x (100 - percent) / percent`
  over a percentage computed as "files done / file cap", which reported absurd
  numbers for small sites and swung wildly between polls. The ETA now measures
  the progress rate over a sliding window, smooths it with an EMA, damps
  upward jumps so a stall cannot explode the estimate, and reports a
  confidence value — the UI shows "estimating…" until it is meaningful.
- **Provenance in every export.** Findings now carry the URL the script came
  from. Previously a URL scan reported the temporary workspace path, which is
  deleted when the scan ends, so no finding could be traced back to an asset.
  CSV gained an `origin` column and SARIF points `artifactLocation` at it.
- **SARIF accuracy.** `rank` now carries confidence (25/50/75/100), `kind`
  carries the result state, `security-severity` is emitted for GitHub, and
  observations / false positives export as `note` + `informational` instead of
  `error` — they used to fail CI gates on findings the engine itself calls
  unproven.
- **CSV accuracy.** List-valued evidence (keys, IVs, secret candidates) is
  joined instead of written as a Python repr such as `['a', 'b']`.
- **Coverage & reliability block.** TXT and HTML reports now state what was
  and was not analyzed: coverage, skipped assets and why, file-cap and depth
  limits, whether the AST parser or the line fallback ran, the runtime
  verification status, and the confidence mix. Reports that hide their own
  blind spots invite over-trust.

### Audit follow-ups — web UI
- Sticky header links are page sections with scroll-spy; below 1040px the nav
  collapses into a real menu (it used to disappear entirely) and shows a
  "you are here" label.
- Findings gained severity chips with counts, a search box and a
  "showing 80 of N" notice when a long list is truncated.
- The engine is polled while unreachable, so starting it after the page is open
  no longer needs a manual refresh. A scan result survives a reload of the tab.
- Accessibility: real tab semantics on the analysis views with arrow-key
  navigation, a skip link, visible focus rings and `prefers-reduced-motion`
  support.
- Copy is ScriptSentry's own voice, headings and tags are Title Case, and the
  pre-release badge is gone from the hosted pages (it stays in the local engine
  banner, the HTML/TXT report footer and `/api/health`).

### Changelog page, docs metadata and navigation cleanup
- **The changelog is a real page now.** `Changelog` used to link into the
  repository, which on a static site means a visitor lands on a file listing
  instead of a page. `webui/changelog/index.html` is now generated from this
  file by `tools/build_changelog.py`, so the hosted page cannot drift from the
  changelog a person edits. The page reuses the overview page's head, header and
  footer, so navigation and metadata changes land on it automatically.
- **Two guards keep that honest.** `tests/test_docs.py` fails when the
  committed page is out of date (verified by mutation testing), and the Pages
  workflow regenerates it on every deploy as a safety net. The generated file
  carries a "do not edit by hand" banner.
- **The changelog page is styled as a document, not a dashboard**: one reading
  column at the 72ch prose measure, a rule between releases instead of a card
  per entry, and no new colours or type sizes. Responsiveness comes from the
  measure itself — a phone, a tablet and a 2560px display all get the same
  readable line — with a single width rule for the two back-links.
- **The footer is a wayfinding list again, not a sitemap.** It had grown to
  nine links, three of which repeated sections the header nav already reaches.
  The Product column now carries only the two destinations the header does not
  route to (the analyzer and the changelog) alongside Connect.
- **`README.md` is visitor-facing.** It now leads with what ScriptSentry is and
  how to use it, rather than reading as developer notes; internal detail moved
  to the docs it belongs in.

## [2.1.0] — earlier release
- Modular `webui` / `server.py` / `core` / `analyzers` architecture.
- Script inventory & behavior intelligence, first/third-party attribution,
  risk scoring, and static/runtime data-exfiltration correlation.
- Local authenticated dashboard with pairing token, bounded jobs, Playwright
  runtime evidence, source-map awareness, and TXT/HTML/CSV/SARIF exports.
