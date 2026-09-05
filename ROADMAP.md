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
- [x] **Modern parser**: tree-sitter (+ JavaScript/TypeScript grammars) is
  now the primary AST source; esprima remains the fallback. Optional
  chaining, nullish coalescing, class fields and dynamic `import()` parse
  natively (no more confidence-capped fallback for post-2020 syntax).
  Converter emits estree-shaped dicts with `range` character offsets so
  taint evidence keeps slicing exact source text; garbage input yields a
  partial tree plus a surfaced "parse note" instead of a hard failure.
- [x] **Source-map ingestion**: when a bundle references `.map`, fetch it and
  analyze the *original* sources — real names in reports, unmangled taint
  flows. Remap line numbers back to the bundle for verification.
- [x] **Data-driven dependency intelligence** (v1): curated advisory table
  (`core/dependency_intel.py`) extracts bundle versions from banners and
  emits known-vulnerability findings with CVE references — never claiming a
  CVE without an extracted version. (Widen the table over time; a full
  RetireJS import can replace it later.)
- [x] **Validator-tiered secrets**: JWT/PEM structural validation and
  canonical-format matching for Slack/GitHub/Stripe/AWS/SendGrid/Twilio/npm
  upgrade validated candidates to high confidence (`validated` verdicts ride
  along on findings). (Also fixed on the way: the secret analyzer had never
  emitted a finding — a tuple/int TypeError was swallowed per match.)

## Phase 3 — Performance at production scale

*The analyze stage is the O(n^1.7) bottleneck; measuring first.*

- [x] Profile `scan_file` end-to-end and cut the duplicate full-content
  passes: the profile said the ten sub-analyzers were cheap and the real
  rocks were taint's six full AST re-descents (now one flattening pass with
  per-statement node buckets), per-match `content[:pos].count("\n")` line
  numbering (shared bisected line index), crypto's per-candidate
  `content.find` re-scans (`finditer` + bisect), an O(matches × endpoints)
  dedupe, ~40 redundant `content.lower()` copies, and the converter's
  post-hoc range pass (ranges now emitted eagerly). 440KB bundle:
  ~10.3s → ~5.2s per file.
- [x] Move the CPU-bound analyze stage to a `ProcessPoolExecutor` (I/O
  stages stay in the parent; worker heartbeats via queue; automatic thread
  fallback; `SCRIPTSENTRY_ANALYZE_ENGINE=thread` opt-out). Multi-core gains
  scale with bundle count.
- [x] Self-tuning ETA: each completed URL scan records measured analyze /
  normalize durations and folds them into a persisted, clamped EWMA
  (`core/eta_calibration.py`, `$SCRIPTSENTRY_STATE_DIR`, per-engine keys,
  `SCRIPTSENTRY_ETA_SELF_TUNING=0` kill switch) that `core/eta.py` applies
  on top of its shipped constants.

## Phase 4 — Product depth

- [x] Local scan history + diffing (SQLite): `core/history.py` records each
  completed dashboard scan with stable per-finding fingerprints and the
  dashboard answers "3 new, 2 resolved since your last scan" (plus a
  history panel that re-renders past reports).
- [x] Deeper discovery: robots.txt/`Sitemap:`/sitemap.xml pages feed recon
  (bounded to 10 same-origin pages, kill switch
  `SCRIPTSENTRY_SITEMAP_DISCOVERY=0`); the endpoint inventory now exports
  as an OpenAPI 3.1 document (`🧭 API map` / `--format openapi`).
- [x] Crawl politeness: `SCRIPTSENTRY_CRAWL_DELAY_MS` enforces a per-host
  minimum interval at the single fetch choke point (`safe_get`).
- [x] Local LLM flexibility: `--ai openai` calls any OpenAI-compatible
  local server (LM Studio/llama.cpp/vLLM) via `--openai-base-url` and an
  optional `--api-key`, with the same honest fallback as Ollama.
- [x] Packaging: `pyproject.toml` (console scripts, pipx-installable,
  wheel verified) + a Dockerfile with the Playwright Chromium preinstalled;
  the web UI exports the raw JSON report alongside HTML/TXT/CSV/SARIF.

## Phase 5 — Code health (continuous)

- [x] Split `server.py` into the planned `api/` package (the docstring
  already sketches it).
- [x] Modularize `webui/app.js` (3k+ lines) behind a simple build or ES
  modules.
- [x] Widen the ruff selection (bugbear, simplicity) and add coverage
  reporting once Phase 1's gate has bedded in.
