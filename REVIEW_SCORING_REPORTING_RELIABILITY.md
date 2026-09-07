# ScriptSentry — Risk Scoring, Reporting, Accuracy & Reliability Review

**Reviewed:** working tree on `arena/01a07bc5-scriptsentry` (base `26d4780`, engine `2.2.0-dev`)
**Date:** 2026-09-07
**Method:** full read of the scoring/reporting/correlation core (`risk_model`, `reporter`, `analysis_model`, `jobs`, `api/http`, `api/report_routes`, `api/analysis_routes`), targeted read of `scanner`/`taint`/`analyzer_service`, live adversarial probing of the running dashboard (empty/binary/non-JS inputs, invalid and private URLs, formula-laden payloads, malformed findings, export of every format), and the full test suite (491 tests, all green).

---

## Verdict

The scoring and reporting architecture is **unusually honest for a security tool**: severity / confidence / status / analysis-quality as independent axes, `confirmed` reserved for demonstrated proof, observations capped so inventory volume cannot outrank findings, and a reliability block in every export that says what was *not* analyzed. Three real defects were found and fixed during this review (all verified with end-to-end PoCs before and after); the remaining items are calibration choices and robustness polish, not correctness breaks.

---

## Bugs found and fixed (this pass)

### 1. CSV formula injection — every text cell was executable in Excel/Sheets
Evidence, sources, sinks and file names are strings from the **scanned (untrusted) code**. A paste could name its file `=HYPERLINK("http://evil","Report")-1.js` (the API only stripped nulls and capped length), and a bundle can ship values like `=SUM(9+9)*cmd|/C calc`. Verified live: 4 cells in a real export started with `=` / formula characters, which Excel and Google Sheets execute when the CSV is opened (phishing link and DDE payload classes).

**Fix:** `reporter._csv_safe` prefixes any cell starting with `= + - @ \t \r` with an apostrophe (OWASP mitigation); content stays readable. Re-verified live: 0 injectable cells, guarded cells render as text. Caller-supplied filenames additionally get control characters stripped at the API boundary (`api.analysis_routes._clean_display_filename`).

### 2. One malformed `line` value killed every export *and* the dashboard payload
`analysis_model.normalize_finding` did `int(out.get("line") or 0)`. A finding whose `line` was a non-numeric string (possible from runtime evidence, hand-edited or legacy restored payloads) raised `ValueError` inside `split_findings` → `build_report_model` → **CSV, SARIF, HTML, TXT and `build_dashboard_payload` all 500**. Verified by direct call before the fix.

**Fix:** `coerce_line()` — ints pass through, numeric strings parse, anything else salvages digits or reports 0. Applied at all three `analysis_model` sites plus the SARIF `startLine` cast. One bad finding can now never take the pipeline down; the finding itself survives with `line: 0`.

### 3. Real secrets silently dropped when a neighboring token matched a fixture marker
`_credible_secret` checked fixture markers ("example", "sample", "your_", …) against the **whole candidate line**, not the secret value. Verified: a real 26-char high-entropy key on a line adjacent to `https://api.example.com` produced **zero findings** (the word "example" in the domain killed it); the same key without the domain was flagged HIGH. Any scanned file mentioning "example.com", a `sample_rate` field, or a "your plan" label could hide a real credential with no diagnostic.

**Fix:** markers now apply to the extracted secret **value** only. The whole accuracy corpus (including every fixture/placeholder false-positive case — which all carry markers in the value) still passes, and the previously-missed case is now detected end-to-end.

New regression suite: `tests/test_export_hardening.py` (13 tests) pins all three contracts.

---

## What was verified as solid

| Area | Check | Result |
|---|---|---|
| Input validation | Empty code, binary garbage, plain English, invalid URL, private IP target | ✅ specific 4xx JSON errors, no crashes, no empty 200s |
| Report exports | txt/csv/sarif/html/json/openapi from a live job | ✅ all render; SARIF level/kind/rank semantics correct (observations = `note`/`informational`, not CI-failing `error`) |
| HTML report | Escaping of untrusted values | ✅ all interpolations via `esc()`; attribute slots use canonicalized values only |
| Secret validation | Network calls to "validate" keys | ✅ none — format/structure checks only, purely offline (privacy claim holds) |
| Job lifecycle | Locking, cooperative cancel, ETA blending, calibration, job caps | ✅ sound; cancel keeps heartbeats but never overwrites user state |
| SSRF / downloader | Private/reserved targets refused with clear errors | ✅ live-verified |
| `scan_reliability` | Coverage/skips/engine/confidence mix in every export | ✅ genuinely good anti-overtrust design |

---

## Open findings & improvement areas (prioritized, not fixed)

### P1 — Accuracy

1. **Value-pattern credential discovery is missing.** `core/secret_validation.py` knows the canonical shapes of Slack (`xox…`), GitHub, Stripe, AWS, JWT, PEM… but is only used to *upgrade* candidates found by **name-based** regexes (`api_key =`, `password =` …). A bare `AKIA…`, `ghp_…` or `sk_live_…` in an object property, array or string concatenation is never discovered. Fix: run `PROVIDER_PATTERNS` over string literals as a second discovery pass (tiered as `format` confidence by the existing validator).
2. **No string-concatenation constant folding.** `"AKIA" + "IOSFODNN7EXAMPLE"` is invisible. Minified and defensive bundles really do split keys. An AST pass folding `Literal + Literal` before secret detection would close it (tree-sitter is already the preferred engine).
3. **Secret findings carry no line number** (`line: 0` in every export; SARIF locations point at the file top). The scanner knows the match offset — plumb `content.count("\n", 0, idx) + 1` through.

### P2 — Risk-model calibration (design review recommended)

4. **A single runtime-proven CRITICAL scores 30/100.** `overall_risk` gives a confirmed critical `base(20)+10 = 30`; the label compensates (confirmed ≥ 1 → HIGH, ≥ 2 → CRITICAL) but the *number* next to "CRITICAL severity, confirmed, runtime_effect" reads as modest. Meanwhile the third-party behavioral bucket is **uncapped**: 12 third-party scripts that read sensitive data and send externally → 100/CRITICAL (each adds up to 18). Observations are capped at 15 for exactly this reason; consider (a) a score floor/boost when `counts["confirmed"] ≥ 1` on a HIGH/CRITICAL finding, and (b) a cap (or diminishing returns) on the third-party bucket. Current behavior is pinned by tests, so this is a deliberate-choice review, not a bug.

### P3 — Reliability / robustness polish

5. **Mixed time units in job snapshots.** `created_at` is an ISO-8601 string; `started_at`/`finished_at`/`cancel_requested_at` are epoch floats. Any consumer must handle both. Pick one (epoch floats + a derived ISO field, or all ISO).
6. **Job retention only prunes on `create`.** A completed job's full result (potentially tens of MB for a 500-file scan) stays in memory until the *next* job is created. A periodic sweep (or pruning in `status`/`result` too) would bound memory for long-lived engines.
7. **79 broad `except Exception` swallows** (of 92 total handlers) — most are legitimately best-effort bookkeeping (history, calibration, heartbeats) with comments saying so, but a few convert real signals into silence (e.g. `_fetch_target_script` → `None` on any error). A pass adding a one-line `print`/debug-log to the quiet ones would make field debugging much easier.
8. **Query parsing duplicated.** `api/report_routes` hand-parses `?a=b` without URL-decoding while `BaseHandler._query_param` uses `parse_qsl`. Harmless today (`format` is plain ASCII) but a second parameter would silently misparse.
9. **Hash inconsistency:** `_merge_into` dedups content by MD5 while everything else uses SHA-256. Harmless (dedup only) — align for hygiene.

---

## Reproducing the fixed bugs (pre-fix PoCs)

```bash
# 1. CSV injection (pre-fix: 4 injectable cells; post-fix: 0)
curl -X POST $API/api/analyze -H "$H" -d \
  '{"mode":"code","filename":"=HYPERLINK(\"http://evil.example\",\"Report\")-1.js","code":"var apiKey=\"kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5\";var u=\"https://api.example.com\";document.getElementById(\"x\").innerHTML=location.hash;"}'
# then POST /api/report?format=csv {"job_id": ...}

# 2. Export crash (pre-fix): findings with "line": "not-a-number" -> ValueError in
#    build_report_model / build_dashboard_payload (all formats 500)

# 3. False negative (pre-fix): the apiKey above was NOT detected while
#    api.example.com was on a nearby line; post-fix it is a HIGH hardcoded_secret.
```

## Verification

- `python3 -m unittest discover -s tests` → **491 tests, OK (65 skipped)** — includes the 13 new hardening tests and the full TP/TN/FP accuracy corpus.
- `ruff check` on every touched module → clean.
- Live dashboard re-tested post-fix: injection PoC now yields 0 injectable cells; the missed secret is detected.
