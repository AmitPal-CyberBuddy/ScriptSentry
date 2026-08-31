# ScriptSentry implementation audit

**Audit scope:** repository architecture, local API, discovery/download boundaries, static and runtime analysis, evidence correlation, script intelligence, reporting, frontend UX, performance/recovery, and tests.

## Product direction

ScriptSentry is kept as a JavaScript/client-side behavior intelligence tool rather than a generic web vulnerability scanner. Its primary output is an attributable script inventory and a manually verifiable account of capabilities, data flows, contacted destinations, dependencies, and security-relevant behavior.

A dangerous API or DOM call without a source, reachability context, or impact is an **observation**, not an automatically confirmed vulnerability. Severity (impact), confidence (evidence certainty), triage status, and analysis quality are independent axes. Coarse static/regex patterns are low-confidence observations; framework patterns and behavioral correlations are medium; a static source→sink path or a browser-runtime observation is high but stays **Open** for triage. The **Confirmed** status is reserved for deterministic proof, a *demonstrated* unsafe runtime effect (e.g. live `eval`), or explicit analyst confirmation. Findings carry an `analysis_quality` (high/medium/heuristic) plus explicit `limitations` rather than overclaiming.

## Architecture reviewed and improved

- `core.analyzer_service` is the shared URL/code orchestration path for the CLI and HTTP dashboard. URL scans use isolated temporary workspaces, bounded file sizes, URL-scoped filenames, content-hash deduplication, bounded worker pools, recursive module/chunk traversal, progress events, cancellation checks, runtime response rescanning, and cleanup.
- `core.discovery`, `core.downloader`, and `core.url_policy` distinguish script assets from API strings and enforce an HTTP(S), no-credentials, public-network boundary. Redirects are validated hop by hop, responses are size bounded, HTML soft-404s are rejected, and local/reserved targets are refused unless the explicit development override is set.
- Discovery covers inline scripts, external scripts, modulepreload/preload/prefetch, static and dynamic imports, CommonJS requires, bundler chunk naming, and runtime-loaded script bodies. A normal page scan performs one page fetch through the combined discovery API.
- Runtime evidence captures network/request metadata without bodies, dynamic script bodies only transiently for local rescanning, console/page/request errors, DOM sinks, string evaluation/timers, WebSockets, storage reads/writes/removals, cookie access, forms, frames, and messaging. Values are bounded; cookie and storage values are not persisted.
- `core.source_maps` records bounded source-map provenance metadata and availability without exposing source-map bodies in runtime evidence.
- `core.taint` covers URL, messaging, storage, cookie, and form sources; aliases, object/array properties, awaited/transform expressions, function parameters, network sinks, and sanitizer state. `core.analysis_model` provides consistent severity, confidence, evidence type, status, and deduplication semantics.
- Script intelligence maps first/third-party/inline/dynamic assets, hashes, loading edges, contacted domains, capabilities, sensitive reads, changes/inventory metadata, and risk factors. Reporting and dashboard payloads preserve evidence, source maps, warnings, attack surface, runtime state, and remediation context.
- `server.py` is a local, authenticated job API. Health is intentionally public for pairing discovery; analysis, status, results, cancel, and exports require a process-scoped pairing token. Exact origin checks, CORS response rules, no-store responses, body/URL/parameter bounds, job caps/retention, and safe static response headers are enforced.
- The frontend now uses relative assets (Pages subpaths work), a restrictive CSP, token session storage, authenticated calls, retry/error UX, progress/ETA, cancellation, and runtime/source-map evidence views. Dynamic render paths use HTML escaping for untrusted report values.

## Findings fixed during the audit

1. Duplicate / divergent CLI scan behavior was removed; the CLI delegates to the same analyzer service as the dashboard.
2. Global output artifacts could cross-contaminate same-named bundles across targets; scans now use isolated workspaces and URL-unique paths.
3. Recursive discovery could treat arbitrary API paths as JavaScript; followable script references are now constrained.
4. Blind redirect handling could make the local engine an SSRF primitive; redirects and DNS-resolved destinations are checked.
5. Static regex observations were being treated as confirmed findings; evidence-aware normalization now downgrades them.
6. Runtime evidence was too narrow; bounded dynamic scripts, storage reads, cookies, messaging, and page/request errors are retained.
7. Runtime-only bundles were inventoried but not analyzed; their bounded response bodies are rescanned locally.
8. Source-map references were absent; bounded provenance metadata is now attached to files.
9. HTTP work was synchronous and unbounded from the dashboard; jobs now expose progress, ETA, cancellation, cleanup, and retention.
10. Frontend/backend pairing was implicit; authenticated API calls and token retry UX now protect the local engine.
11. The progress job runner had a missing successful return path, which left completed work permanently reported as `running`; this is covered by API smoke tests.
12. Documentation had unauthenticated export examples and stale deployment claims; setup and security requirements now match the implementation.

## Verification performed

- `python -m unittest discover -s tests -v` — **77 tests passed**.
- `python -m py_compile core/*.py ai/*.py main.py server.py tests/*.py` — passed.
- `node --check webui/app.js` and `node --check webui/config.js` — passed.
- Live local server smoke: static UI headers/assets, health, unauthenticated rejection, disallowed-origin rejection, authenticated code job, polling, result payload, and SARIF export — passed.
- Analysis tests cover AST/profile, endpoint/attack-surface extraction, source-to-sink taint, sanitizer handling, framework/dependency signals, script inventory, runtime finding normalization, dashboard sections, report exports, the layered module/bundler discovery, the explainable risk model, and the accuracy regression suite (TP/TN/known-FP/edge/minified/obfuscated).

## Code map (for contributors)

The user-facing overview lives in `README.md`; this is where the pieces sit:

```
webui/            single-page dashboard (index.html, app.js, styles.css, config.js)
server.py         stdlib loopback HTTP server + /api (auth, routing, jobs, reports)
core/
  version.py            single source of engine version (mirrored in release.json)
  analyzer_service.py   shared URL/code orchestration (CLI + dashboard)
  scanner.py            regex/feature signal detection + risk-signal assembly
  analysis_model.py     severity/confidence/status vocab, normalization, dedupe,
                        finding identity, findings-vs-observations split
  risk_model.py         evidence-weighted 0-100 score, contributors, priorities
  module_discovery.py   layered AST + bundler-aware script/module reference discovery
  taint.py              AST source→sink taint analysis + analysis quality/limitations
  js_parser.py / ast_analyzer.py   optional esprima wrapper + AST profile
  attack_surface.py     endpoint/API/realtime surface extraction
  framework_rules.py    React/Angular/Vue/jQuery sink rules
  script_intel.py       script inventory, behavior profiles, risk scoring, exfil correlation
  runtime_evidence.py   optional Playwright capture + runtime finding builder
  discovery.py / downloader.py / beautifier.py / source_maps.py / url_policy.py / jobs.py
  reporter.py           report model + TXT/HTML/CSV/SARIF + dashboard payload
analyzers/        additive analysis modules (secret, crypto, api, auth, storage, ...)
ai/               optional AI summary
config.py         profiles and detection/scan configuration
tests/            unit tests + corpus/ accuracy fixtures
release.json      machine-readable release metadata ; CHANGELOG.md is the history
```

### Data-count / scan-summary fields

URL scans report explicit accounting (never silently drop assets):
`total_discovered` (page entry points), `total_files` (unique files analyzed,
including recursively found chunks), `skipped_files` + `skipped_reasons`,
`bytes_scanned`, `total_bytes`, `runtime_status`, and the hard-cap flag. These
feed both the dashboard **Scripts → Assets** detail and the JSON/dashboard
payload under `__scan_summary__`.

## Follow-up review actions

The external review correctly emphasized false-positive discipline, first-class behavior profiles, third-party intelligence, and script-to-network attribution. The current branch already had the modular `webui`/`server`/`core`/`analyzers` split, evidence-aware findings, and behavior inventory, so a disruptive directory rename was not necessary. This follow-up adds the useful missing pieces:

- `tests/corpus/` now contains representative categorized JavaScript fixtures and contract tests, including the reachable-versus-sanitized DOM case and fixture-secret filtering.
- Script inventory entries now retain `loaded_by`, `pages_present`, and runtime requests attributed to a script where Chromium/CDP exposes an initiator stack.
- Runtime network records now preserve bounded `initiated_by` script URLs, while messaging and storage-read evidence is exposed consistently to the dashboard.

## v2.2 accuracy & triage follow-up

Building on the review, the engine now:

- Derives confidence from **evidence type** rather than severity; adds an
  independent triage vocabulary (Open / Needs review / Confirmed / False
  positive / Informational) and reserves Confirmed for deterministic proof or
  a demonstrated runtime effect.
- Reports **analysis quality + limitations** per flow (dynamic property
  access, unmodeled calls, inter-procedural depth bound, regex fallback) and
  fixes a latent `content_low` reference in the taint engine.
- Splits findings into **actionable findings** vs **security observations** and
  uses a stronger finding identity so distinct untrusted sources reaching one
  sink stay distinguishable.
- Adds an explainable evidence-weighted **0–100 risk score** with a contributor
  breakdown and an investigate-first priority list (`core/risk_model.py`).
- Adds **layered script discovery** — AST import/require/`import()` first,
  bundler adapters (Webpack/Vite/Next/Parcel) second, regex fallback third
  (`core/module_discovery.py`).
- Reduces dashboard navigation from nine views to five and leads the Overview
  with priorities and the score breakdown.
- Adds a formal **accuracy regression suite** and tightens credible-secret
  filtering (placeholders such as `YOUR_API_TOKEN_HERE` are not secrets).
- Centralizes the engine version in `core/version.py` and adds `release.json`
  and `CHANGELOG.md`.

## End-to-end review hardening — risk chips, taint precision & transport

An end-to-end review of the shipped dashboard and CLI closed the remaining gaps:

- **Per-file risk chips are consistent with the overall score.** `core.risk_model.file_risk`
  reuses the evidence-weighted 0–100 model, so a file can no longer display CRITICAL beside an
  overall MEDIUM report; `signal_score` is now the worst-file score, and observation-only files
  stay below CRITICAL.
- **Taint precision.** `core.taint.known_static`/`_is_static_value` suppress the by-name heuristic
  for identifiers bound to statically-known values (literals, constant templates, literal
  arrays/objects, constant unary expressions); reassignment to a static value clears prior taint in
  both the AST and regex paths. Unresolved names (parameters, globals) keep conservative
  medium-confidence treatment.
- **DNS-rebinding TOCTOU closed.** `core.url_policy` validates and resolves each URL in one step
  (`_validate_and_pin`), then pins the connection by overriding `socket.getaddrinfo` for the exact
  host with **all** validated public address literals (all address families, so IPv6-only targets
  still work), restoring the real resolver afterwards; `safe_get` re-pins every redirect hop.
  `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1` opts out for explicitly authorized local/private targets.
  Per-connection pinning is used because urllib3's connection-level hooks no longer separate
  `host` from `_dns_host` (urllib3 2.7).
- **Server hygiene.** Directories without an index file 404 instead of listing; the
  `read_response_text` fallback reads at most `max_bytes + 1` from `response.raw`; unused config
  blocks, `ai/prompts.py`, and the never-written `derived_keys` key were removed.
- **AI decision — local Ollama only.** `--ai ollama` sends structured findings (never raw source,
  ≤6000 chars) to a local Ollama server (`/api/generate`, non-streaming, temperature 0.2, 60 s
  timeout) and falls back to the deterministic rule-based summary on any failure
  (`ollama_unavailable` + reason). Cloud LLM providers and the `--api-key` flag were removed:
  shipping scanned code to a cloud contradicts the privacy-first design. The deterministic summary
  is the default and nothing AI-related is mandatory.

## Deliberate limitations

- Playwright is optional. When Chromium is unavailable ScriptSentry reports
  `missing_dependency` and continues with static analysis; the
  disabled/missing-dependency path is tested.
- Static JavaScript parsing remains intentionally conservative when the
  optional esprima parser cannot handle a bundle. Unsupported/unmodeled
  constructs are surfaced as **limitations** and lower analysis quality rather
  than being upgraded to a high-confidence vulnerability.
- Cancellation is cooperative. An in-flight network request may finish at its
  bounded timeout before the analyzer observes cancellation; completed/canceled
  result state is not exposed as a successful report.
- The pairing token is process-scoped. A publicly hosted backend still needs
  TLS, firewall/platform access controls, and a private deployment; the token
  must not be committed to `config.js` or a public repository.
- `server.py` deliberately stays a dependency-free stdlib file. When the API
  surface grows further it is planned to split into a small `api/` package
  (`auth.py`, `cors.py`, `handlers.py`, `analysis_routes.py`, `report_routes.py`);
  the handlers are already factored into discrete methods to make that mechanical.
- Findings are deterministic triage signals, not proof of exploitation; always
  validate with server-side behavior and manual review.
