# ScriptSentry — End-to-End Review

**Reviewed:** commit `851b67a` → working tree on `arena/01a05639-scriptsentry`
**Date:** 2026-08-31
**Method:** full source read of every module (~14k LOC Python + ~2.2k LOC JS), full test suite run (`197 passed, 5 subtests passed`), and live end-to-end exercising of the server API, CLI, uploads, reports, cancellation, security boundaries, and a URL scan against a local fixture site.

---

## Verdict

**Strong, unusually mature codebase for a pre-release tool.** The accuracy-first triage model (severity / confidence / status / analysis quality as independent axes, `confirmed` reserved for demonstrated proof, findings vs. observations) is coherent and consistently enforced across scanner, taint engine, risk model, reporters, and UI. The crawler is SSRF-aware, the local engine is properly authenticated, and the test suite actually guards the accuracy contracts it claims. I found **3 real bugs** (all fixed) and a handful of **design-level issues** (documented below, not fixed).

---

## What was verified live

| Check | Result |
|---|---|
| `pip install -r requirements.txt` + test suite | ✅ 196 → 197 tests pass |
| Engine startup, token print, dev-build warning | ✅ |
| `/api/health` public, analysis endpoints token-gated (401) | ✅ |
| Evil `Origin` rejected (403) | ✅ |
| DOM-XSS flow `location.search → innerHTML` | ✅ HIGH / high / **open** (not auto-confirmed) |
| Exfil flow `document.cookie → fetch` | ✅ HIGH / high / open |
| `sk_live_...` secret detected; `AIza...` Google key correctly classified as **public** (not a secret) | ✅ |
| Sanitized flows (`DOMPurify.sanitize`, `escapeHtml`) → LOW / informational | ✅ |
| Private/reserved URL targets rejected; credential-URLs rejected | ✅ |
| URL scan: page → `app.js` → `chunk.js` (`import` edge), inline scripts, per-file origin attribution | ✅ (after fix #1) |
| Uploads (incl. `../../evil.js` filename sanitized), cancel, job status/result | ✅ |
| TXT / CSV / SARIF / HTML exports (SARIF 2.1.0 valid, rank/kind/level semantics correct) | ✅ |
| Malformed JSON, wrong Content-Type, bad mode → clean 4xx errors | ✅ |
| Runtime (Playwright) capture | ⚠️ Could not run live — Chromium download blocked in sandbox; graceful `browser_failed` degradation verified (see issue #8) |

---

## Bugs found and fixed (commit `7e1cf89`)

### 1. `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS` was a silent no-op — private-target scans always returned 0 files
The override was only consulted at the top-level call sites (`analyze_url`, `server.py`), but **every actual HTTP request re-validates through `safe_get` → `validate_public_url`**, which rejects private/reserved destinations unconditionally. Result: with the override set (the documented way to scan authorized internal/localhost apps), the page fetch always failed and the scan came back with `page_fetch: failed` and zero files — no error surfaced anywhere.
**Fix:** `core/url_policy.py` now honors the override inside the crawler boundary (every request and redirect hop). Scheme, hostname, and credential-in-URL rules still apply with the override set. Regression test added; the override is now documented in `DEPLOYMENT.md`.

### 2. CLI/API report exports lost the scan source ("Source: inline snippet" after a URL scan)
`generate_report` / `generate_html_report` / `generate_csv_report` / `generate_sarif_report` never received `metadata`, so the TXT/HTML/CSV/SARIF files written by `main.py` (and by sync `/api/report` calls) reported `Source: inline snippet` even when scanning a URL, while `report.json` had the correct source. The dashboard was unaffected (it passes metadata), which is why tests missed it.
**Fix:** all four generators accept `metadata` and pass it to `build_report_model`; `main.py` and `server.py` now pass it.

### 3. Progress/reliability lied about the runtime pass
`_attach_runtime` always emitted `"Runtime evidence captured"` even when Playwright was missing or the browser failed to launch, and `scan_reliability` mapped unknown statuses like `browser_failed` to `"not run"`.
**Fix:** the verify-stage message now reflects the real outcome (`captured` / `skipped (disabled|missing_dependency)` / `unavailable (browser_failed|error)`), and the reliability table maps `browser_failed` and `missing_dependency` accurately.

---

## Design-level issues (recommendations and their status)

1. **`--ai openai|azure|ollama` is cosmetic.** `ai/llm_engine.py` never calls any provider — `build_ai_summary` returns the same deterministic rule-based text for every provider and ignores `api_key`/`model`. The flag promises an LLM summary that doesn't exist. Either wire a real provider call or rename the option (e.g. `--summary`) and stop implying external AI is used. **Status: pending — see the AI flag decision below.**
2. **Per-file risk labels used the legacy additive score.** ✅ **FIXED (commit `043057e`)** — per-file chips now come from the same evidence-weighted 0–100 model (`risk_model.file_risk`); the contradictory "CRITICAL (13) next to HIGH (58)" is gone.
3. **DNS-rebinding TOCTOU.** ✅ **FIXED (commit below)** — `safe_get` now validates and resolves each hop exactly once (`_validate_and_pin`) and pins the request to the validated public IP literals via a scoped `socket.getaddrinfo` override, so the check and the connection cannot see two different answers. All validated addresses are chained so IPv4/IPv6 fallback still works; the `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS` override disables pinning (it exists to reach private targets).
4. **`read_response_text` fallback can buffer an unbounded body.** ✅ **FIXED (commit `043057e`)** — the exception fallback now reads at most `max_bytes + 1` from `response.raw` instead of letting `response.text` materialise the whole body.
5. **Dead code / cruft.** ✅ **FIXED (commit `043057e`)** — removed `config.ALLOWED_ORIGINS` / `SCAN_CONFIG` / `PERFORMANCE` / `CONFIDENCE` / `NOISE_WORDS` (all zero imports), `ai/prompts.py`, and the crypto result key `derived_keys` (never assigned or read). `_walk_imports` turned out to still be live — kept. `decoded_secrets` is also still used internally for crypto confidence — kept.
6. **Conservative taint identifiers can FP.** ✅ **IMPROVED (commit `22e1360`)** — identifiers bound to statically-known values (`const input = 'welcome'`) are no longer tainted by name; reassignment clears taint in both the AST and line-fallback paths. The conservative by-name treatment remains for unresolved names (function parameters, globals). Corpus fixture `false-positive-cases/chat-widget.js` added to keep it honest.
7. **Static directory listing.** ✅ **FIXED (commit `043057e`)** — directories without an `index.html` (e.g. `/assets/`) return 404 instead of a listing.
8. **Runtime evidence not exercised live in this environment** (Playwright CDN blocked). The degradation path is verified and unit-tested; before shipping, run `python -m playwright install chromium` and do one live URL scan to confirm capture, instrumentation, and the `runtime://` rescan path.

### AI flag decision

The `--ai` flag is cosmetic today. Options: (a) rename to `--summary` — honest, zero maintenance, no privacy impact; (b) wire a real provider — only **local Ollama** is compatible with the privacy-first design (OpenAI/Azure send code to a third party, contradicting "no code ever leaves your computer"); it would be strictly opt-in (`--ai ollama --ollama-url http://localhost:11434`), with the deterministic summary as the always-available fallback when Ollama is offline. Wiring a provider is not mandatory for correctness — the deterministic summary is already useful — so it should only be done if a maintainer actually wants LLM summaries. **Recommended: (a) now, (b) optional later.**

---

## What is genuinely good

- **One shared scan lifecycle** — CLI and dashboard call the same `analyzer_service`; no silent divergence.
- **Evidence honesty** — confidence derives from evidence type, never severity; static source→sink stays `open`, only demonstrated runtime effects reach `confirmed`; findings carry `analysis_quality` + explicit `limitations`; SARIF maps observations to `note`/`informational` so CI isn't gated on unproven signals.
- **SSRF-aware crawler** — per-hop redirect validation, private/reserved IP + DNS checks, credential-URL rejection, size bounds, soft-404 rejection, isolated temp workspaces, URL-hashed filenames, content-hash dedup, capped worker pools, cooperative cancellation.
- **Layered discovery** — AST imports → bundler signatures (Webpack/Vite/Next/Parcel) → regex fallback; `fetch('/api/...')` strings are never treated as crawl targets.
- **Taint engine** — AST-first with a conservative line-based fallback; tracks aliases, object properties, sanitizers, inter-procedural calls (depth-bounded), and records what it couldn't model.
- **Privacy-first runtime instrumentation** — key names only, no cookie/storage values, script bodies transient and dropped before serialization.
- **Explainable risk model** — bounded 0–100 with per-contributor breakdown, observation cap, and an investigate-first priority list.
- **Server hardening** — loopback default, process-scoped pairing token with `hmac.compare_digest`, exact-origin allowlist, CORS with `Access-Control-Allow-Private-Network`, body/URL/upload bounds, job caps/retention, security headers on every response.
- **Frontend discipline** — `escapeHtml`/`textContent` for all dynamic rendering, CSP, token in `sessionStorage` only, retry/error UX, per-option tooltips.
- **Documentation & tests** — `AUDIT.md` honestly narrates past bugs and design decisions; `CHANGELOG.md` ↔ `changelog.html` drift is CI-guarded; 16 test modules including an accuracy-regression corpus of true positives/negatives and known false positives.

---

## Files changed in this review

```
core/url_policy.py        — honor SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS at the crawler boundary
core/analyzer_service.py  — honest verify-stage progress messages
core/reporter.py          — metadata threading into all report generators; runtime status labels
main.py                   — pass metadata to report exports
server.py                 — pass metadata to sync /api/report exports
DEPLOYMENT.md             — document the private-target override
tests/test_hardening.py   — regression test for the override boundary
```

**Final status:** `197 passed, 5 subtests passed` after the changes. The tool is a credible, well-scoped triage engine; the fixes above remove three silent-failure/misreporting defects that would have eroded trust in exactly the way this codebase otherwise works hard to avoid.

---

## Follow-up: hosted-page onboarding & one-file launcher (`scriptsentry.py`) — verified live (commit `a5059fb`)

The hosted page (GitHub Pages) and the launcher flow were exercised end to end, including a real first-run bootstrap that downloaded the engine archive from GitHub.

### Your assumptions about the hosted page — confirmed correct
- The hosted UI is the **interface only**; analysis runs on your machine. When you open the GitHub Pages site and hit **Analyze**, the setup modal explains exactly that: *download `scriptsentry.py` → `python3 scriptsentry.py --port 8000` → paste the pairing token it prints* (there's also a "Clone the Repo" tab). The modal even has a working ⬇️ **Download scriptsentry.py** button pointing at the raw file on GitHub.
- The page then polls `http://127.0.0.1:8000/api/health` (auto-retrying every 8 s while the engine is offline) and, once paired, sends everything to your local engine over CORS (`github.io` origins are explicitly allowed; the pairing token is required for analysis). The GUI's URL is the GitHub Pages link — you stay on it; the engine runs locally.

### Launcher bootstrap — verified working, with 2 real bugs found and fixed
Live test: copied `scriptsentry.py` alone into a fresh directory (no repo), ran it → it downloaded the engine tarball from GitHub, unpacked into `~/.scriptsentry/bootstrap/`, installed deps, printed the token, and served a fully working engine (health check + DOM-XSS analysis passed through it). Second run reuses the cached engine.

Two bugs broke the "checks requirements and runs properly" promise:
1. **`pip install` was missing `-r`** — the command was `pip install /path/requirements.txt`, which is invalid; auto-install could never succeed on a machine with missing deps (it only looked like it worked when deps were already present).
2. **PEP 668 / non-root Pythons** (Debian 12+, Ubuntu 23.04+) refused the install, and the launcher then started a degraded engine (URL scanning dead, AST fallback) with only a confusing pip traceback — plus its manual-install hint pointed at a nonexistent `requirements.txt` in the user's cwd.

Fixes in `scriptsentry.py`: `-r` flag corrected; PEP 668 retries with `--break-system-packages` (with a clear message and a venv alternative; `SCRIPTSENTRY_BREAK_SYSTEM_PACKAGES=1` opts in silently); if the batched install still fails, each package is installed individually so one broken package (e.g. esprima's root-only header install) can't block the rest; the manual-install hint now points at the real requirements file; and the engine still starts with its degradation honestly reported (`AST parser: UNAVAILABLE — running in regex_fallback mode`, plus a note that URL scanning needs `requests`/`beautifulsoup4`).

Verified scenarios: fresh venv with no deps (full install + full analysis), PEP 668 retry (simulated `externally-managed` marker → retry succeeds), fully blocked index (all installs fail → clear warning, server still starts degraded, paste/upload analysis works), and cached-engine second run.
