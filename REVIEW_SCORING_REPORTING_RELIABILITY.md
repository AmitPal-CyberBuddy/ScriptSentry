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

New regression suite: `tests/test_export_hardening.py` (13 tests) pins all three contracts. The P1 accuracy items are pinned by `tests/test_credential_discovery.py` (13 tests): canonical-format discovery, concat folding, line numbers into CSV/SARIF, and the public-key/placeholder exclusions.

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

### P1 — Accuracy — ✅ implemented 2026-09-07 (see below)

1. ~~**Value-pattern credential discovery is missing.**~~ **Fixed.** `_credible_secret` now consults `secret_validation.validate()`: a value matching a canonical provider shape (AWS `AKIA/ASIA/ABIA/ACCA`, GitHub, Slack, Stripe, SendGrid, Twilio, npm — or a JWT/PEM that decodes) bypasses the fixture-marker/entropy heuristics, because a documented credential shape is stronger evidence than any heuristic (a real key can legitimately contain "example"/"xxx" substrings). The scanner's discovery regexes were extended with the providers that had drifted (SendGrid, Twilio, npm, AWS temp-key prefixes). Public-by-design client keys (`AIza…`, `pk_live_…`, `GOCSPX…`) are still excluded — deliberately checked *before* the format bypass.
2. ~~**No string-concatenation constant folding.**~~ **Fixed.** `_folded_concat_candidates` folds `"AKIA" + "IOSFODNN7EXAMPLE"` chains (single-line, ≥8 folded chars, capped at 200/file) into synthetic candidates that flow through the exact same dedup/credibility pipeline; an assignment target left of the chain is preserved so name-based credibility applies too. The chain's line number is carried through to the finding. Verified fast on pathological inputs (100k `a+` runs: 0.02s) and 300KB single-line minified bundles.
3. ~~**Secret findings carry no line number.**~~ **Fixed.** The `hardcoded_secret` signal now carries the line of the first credible secret (literal match, or the concat-chain map for folded values); `_signal` grew a `line` parameter. CSV/SARIF/dashboard all point at real positions (SARIF 0-indexed).
4. **(Remaining) deeper constant propagation** — folding covers literal chains, not `Buffer.concat`, `[...].join("")`, `atob("…")` before the secret check, or cross-statement propagation. The decoded-strings pass already covers some `atob` shapes; generalizing it is the natural next step.

### P2 — Risk-model calibration — ✅ implemented 2026-09-08 (see below)

4. ~~**A single runtime-proven CRITICAL scores 30/100 while uncapped third-party correlations saturate to 100.**~~ **Rebalanced.**
   - **Demonstrated-severity floor (`CONFIRMED_SEVERITY_FLOOR`):** a confirmed/runtime-proven CRITICAL finding now puts the score in the CRITICAL band at minimum (≥ 75; HIGH ≥ 50). The lift is added as an explicit *contributor* ("Demonstrated CRITICAL effect (severity floor)"), never a silent clamp, so contributor points still sum exactly to the score — the explainability contract the dashboard and `test_end_to_end_score_is_explained_in_report_model` pin. A confirmed MEDIUM gets no floor; several confirmed findings that already out-earn the floor get no lift.
   - **Third-party bucket cap (`THIRD_PARTY_CAP = 30`):** the combined contribution of third-party behavioral correlations (sensitive-reads + external-destinations, or high per-script risk) is capped like the observation bucket. 20 trackers reading cookies and beaconing externally now score 30/MEDIUM instead of 100/CRITICAL; every script still counts in `counts["third_party_exfil"]`, and `counts` exposes `third_party_points`/`third_party_cap` for transparency.
   - Net effect: one demonstrated CRITICAL (75) now outranks twenty unproven trackers (30), the number agrees with the label, and mixed cases stay fully explainable. Pinned by 8 new `CalibrationTest` cases in `tests/test_risk_model.py`.

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
