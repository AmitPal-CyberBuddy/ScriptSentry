# ScriptSentry implementation audit

**Audit scope:** repository architecture, local API, discovery/download boundaries, static and runtime analysis, evidence correlation, script intelligence, reporting, frontend UX, performance/recovery, and tests.

## Product direction

ScriptSentry is kept as a JavaScript/client-side behavior intelligence tool rather than a generic web vulnerability scanner. Its primary output is an attributable script inventory and a manually verifiable account of capabilities, data flows, contacted destinations, dependencies, and security-relevant behavior.

A dangerous API or DOM call without a source, reachability context, or impact is an observation. It is not automatically a confirmed vulnerability. Confirmed statuses are reserved for stronger source-to-sink, runtime, or equivalent evidence; coarse static patterns are marked `potential` or `needs_review`.

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

- `python -m unittest discover -s tests -v` — **42 tests passed**.
- `python -m py_compile core/*.py ai/*.py main.py server.py tests/*.py` — passed.
- `node --check webui/app.js` and `node --check webui/config.js` — passed.
- Live local server smoke: static UI headers/assets, health, unauthenticated rejection, disallowed-origin rejection, authenticated code job, polling, result payload, and SARIF export — passed.
- Existing analysis tests cover AST/profile, endpoint/attack-surface extraction, source-to-sink taint, sanitizer handling, framework/dependency signals, script inventory, runtime finding normalization, dashboard sections, and report exports.

## Deliberate limitations

- Playwright is optional and Chromium is not installed in the current execution environment, so a real browser execution pass was not available during this audit. The disabled/missing-dependency path is tested; installing Chromium enables the runtime capture path described above.
- Static JavaScript parsing remains intentionally conservative when the optional parser cannot handle a bundle. Unsupported syntax is retained as a warning rather than upgraded to a high-confidence vulnerability.
- Cancellation is cooperative. An in-flight network request may finish at its bounded timeout before the analyzer observes cancellation; completed/canceled result state is not exposed as a successful report.
- The pairing token is process-scoped. A publicly hosted backend still needs TLS, firewall/platform access controls, and a private deployment; the token must not be committed to `config.js` or a public repository.
