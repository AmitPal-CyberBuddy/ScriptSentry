# ScriptSentry Roadmap

A phase-wise plan for making the engine more accurate on real production
bundles, faster, and easier to trust. Phases are ordered by dependency: the
trust work first (so every later change is verified), then detection quality
(the core value), then performance, then product depth. Items move between
phases as evidence accumulates — benchmarks and false-positive reports beat
opinions.

## Phase 1 — Trust & CI foundation ✅

*GitHub Actions CI, honest test modes, lint gate.*

- [x] CI workflow (`.github/workflows/ci.yml`): the full suite on Python
  3.10–3.12 **plus** a `no-ast-parser` matrix entry that pins the documented
  regex-fallback degradation (AST-precision contracts skip, never fail).
- [x] Loopback URL-scan pipeline tests enabled in CI
  (`SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1`).
- [x] Web UI syntax job (`node --check` on the shipped scripts) and a ruff
  correctness floor (`ruff.toml`: pyflakes + pycodestyle errors) — plus the
  dead code and duplicate-dict-key cleanup that fell out of it.
- [x] Mode-aware test contracts: tests that require the optional `esprima`
  parser or `requests` package skip with a reason instead of failing, so
  "green" means the same thing in every environment.

## Phase 2 — Detection quality

*The biggest accuracy levers for minified production bundles, in order.*

- [x] **Source-map ingestion**: when a bundle references `.map`, analyze the
  *original* sources — real names in reports, unmangled taint flows,
  `via: source_map` attribution in findings/exports/UI. (Two quadratic
  regexes surfaced by this work — crypto extractor + taint fallback on
  large single-line base64 blobs — were fixed on the way: minutes → ~2s.)
- [ ] **Modern parser**: add tree-sitter (+ JavaScript/TS grammars) as the
  primary AST source, keeping esprima as a fallback. Esprima predates
  optional chaining, nullish coalescing and class fields, so modern bundles
  silently drop to the capped-confidence fallback today.
- [ ] **Source-map ingestion**: when a bundle references `.map`, fetch it and
  analyze the *original* sources — real names in reports, unmangled taint
  flows. Remap line numbers back to the bundle for verification.
- [ ] **Data-driven dependency intelligence**: replace the hardcoded
  `dep_entity` dict with a shipped dataset (RetireJS-style) that extracts
  versions and emits known-vulnerability findings with references.
- [ ] **Validator-tiered secrets**: checksum validation for AWS/Slack/Google/
  JWT-shaped candidates, upgrading confidence from "candidate" to
  "validated format" (and killing residual false positives).

## Phase 3 — Performance at production scale

*The analyze stage is the O(n^1.7) bottleneck; measuring first.*

- [ ] Profile `scan_file` end-to-end and cut duplicate full-content passes
  (secret regexes + endpoint/api/storage/header scans + 10 sub-analyzers
  each rescanning the same text) into a shared single-pass context.
- [ ] Move the CPU-bound analyze stage to a `ProcessPoolExecutor` (I/O
  stages stay on threads) — near-linear multi-core gains under the GIL.
- [ ] Self-tuning ETA: persist observed stage durations (bytes × workers →
  seconds) locally and adapt `core/eta.py`'s calibration per machine.

## Phase 4 — Product depth

- [ ] Local scan history + diffing (SQLite): "3 new, 2 resolved since your
  last scan" — turns one-shot scans into monitoring.
- [ ] Deeper discovery: sitemap.xml/robots.txt, SPA hash-route hints, and an
  API-surface map (optional OpenAPI-shaped export) built from the endpoint
  inventory the engine already extracts.
- [ ] Crawl politeness: optional per-host rate limiting for the download
  stage (good citizenship for scanning sites you own).
- [ ] Local LLM flexibility: accept any OpenAI-compatible endpoint (LM
  Studio, llama.cpp) alongside Ollama.
- [ ] Packaging: `pyproject.toml` (pipx-installable) + a Dockerfile with
  Chromium preinstalled for headless/CI use; expose JSON report export in
  the web UI (the CLI already supports it).

## Phase 5 — Code health (continuous)

- [ ] Split `server.py` into the planned `api/` package (the docstring
  already sketches it).
- [ ] Modularize `webui/app.js` (3k+ lines) behind a simple build or ES
  modules.
- [ ] Widen the ruff selection (bugbear, simplicity) and add coverage
  reporting once Phase 1's gate has bedded in.
