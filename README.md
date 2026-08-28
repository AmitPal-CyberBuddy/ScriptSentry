# ScriptSentry

**Watch every line. Detect every risk.**

ScriptSentry is a visual JavaScript security and script-behavior intelligence platform. It finds hardcoded
secrets, crypto material, endpoints, API calls, storage usage, DOM/XSS patterns, obfuscation,
technology stacks and data flows — then explains *which script* does what, where its data can go,
and how risky that behavior is, all in a modern, animated dashboard.

## ✨ Features

- **Visual Web Dashboard** with animated risk gauge, count-up metrics, radar + donut charts and
  a motion-rich analysis journey.
- **Paste-code analysis** — drop any JS snippet and get instant structured results.
- **Live URL scanning** — discover, download, beautify and recursively analyze JavaScript assets.
- **Optional local runtime evidence** — Playwright-driven headless-browser pass that captures dynamic
  chunks, console errors, DOM sink writes, network/WebSocket activity and storage-key usage visible
  only when the page actually executes. Cookies: names only; request bodies/localStorage values are
  never stored.
- **Script inventory & behavior intelligence** — first/third-party attribution, inline/external/
  dynamic loading method, script hashes, sensitive reads (URL/cookies/storage/forms), DOM/network
  writes, browser API map, external destinations, script risk score, and static/runtime
  data-exfiltration correlation.
- **20+ detection modules**:
  - Secrets & credentials (JWT, API keys, auth headers, private keys)
  - Crypto routines, keys and IV/nonce extraction
  - API inventory, endpoints, HTTP methods, fetch/axios/XHR/WebSocket/SSE
  - Client storage, DOM/XSS indicators, unsafe runtime calls
  - Hardcoded configs, decoded/obfuscated strings
  - Technology stack, dependency ecosystem, notable features, data-flow summary
  - **AST profile** — imports/exports, functions, classes, call graph, complexity
  - **Source→sink taint analysis** — URL/query/hash, postMessage, storage, cookies, form
    values → innerHTML / eval / redirect / prototype pollution, with sanitizer awareness,
    function-argument propagation and object-property tracking
  - **Context-aware attack surface** — fetch/axios/XHR, WebSocket/SSE, GraphQL, query params,
    headers, JSON body fields, auth and internal-endpoint hints
  - **Framework-aware rules** — React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`,
    Vue `v-html`, jQuery DOM sinks
- **Report suite**:
  - Animated web export (HTML), plain text, CSV and SARIF from the dashboard
  - CLI TXT / JSON / HTML / CSV / SARIF reports
  - Structured risk signals, unified triage findings, remediation plan, attack surface summary
- **Deterministic rule + AST engine** — no external LLM required, with an optional AI-style summary.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Optional: enable the local headless-browser runtime evidence pass.
# If you skip this, URL scans still work with static analysis only.
python -m playwright install chromium

python3 server.py
```

Open the dashboard URL printed by the server, paste JavaScript, or enter a target URL.
The dashboard can **Export HTML Report** and **Export Text Report** after any analysis.

### 🌐 GitHub Pages / hosted UI (free & private)

You can host the dashboard UI on GitHub Pages. The backend stays **entirely local**:

1. Publish `webui/` to Pages (see `deployment/deploy-pages.yml`).
2. A visitor opens the hosted page and gets a **privacy-first setup guide** if `server.py` isn't
   running locally.
3. They run `pip install -r requirements.txt && python3 server.py --port 8000` on their machine.
4. The hosted page connects to the local engine (`http://127.0.0.1:8000`) and runs fully private —
   no code ever uploads to the cloud.

The local engine only accepts API calls from localhost/loopback origins and GitHub Pages
origins (plus `SCRIPTSENTRY_ALLOWED_ORIGINS` if you host the UI on a custom domain). Other
websites cannot drive it.

See `DEPLOYMENT.md` for the full guide.

Launch the dashboard directly from the CLI too:

```bash
python3 main.py --serve --port 8000
```

## 📤 Dashboard Report Export

From the web UI press one of the header buttons after analysis:

- **Export HTML Report** — polished shareable report (executive summary, risk signals,
  category bars, per-file detail, remediation plan)
- **Export Text Report** — triage-friendly CLI-style report
- **Export CSV Report** — spreadsheet-friendly unified findings (id, severity, file, line,
  source → sink, flow, status)
- **Export SARIF Report** — SARIF 2.1.0 for GitHub code scanning / CI tooling

The dashboard has an analyst **Findings** tab where you can triage each signal as
*Confirmed / False positive / Informational / Needs review* (stored only in your browser).

Equivalent API endpoints (used by the UI, also callable directly):

```bash
curl -X POST localhost:8000/api/report?format=html \
  -H 'Content-Type: application/json' \
  -d '{"mode":"code","code":"const key=EncryptionKey=\"abc\";"}'

curl -X POST "localhost:8000/api/report?format=csv" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"code","code":"const q=location.search;innerHTML=q;"}'
```

## 🧪 CLI Scan

```bash
python3 main.py https://example.com --profile balanced --format all
python3 main.py "https://example.com/static/js/app.js"
python3 main.py https://example.com --max-depth 5 --profile strict --format html
```

Output is written to `output/` (`report.txt`, `report.json`, `report.html`,
`report.csv`, `report.sarif`).

Optional AI-style summary:

```bash
python3 main.py https://example.com --ai openai --api-key YOUR_KEY --model gpt-4o-mini
```

## 🗂 Architecture

```
╭──────────────────────────────────────────────╮
│  webui/  — modern animated single-page GUI   │
│  server.py — stdlib HTTP dashboard + /api    │
│                                              │
│  core/                                       │
│   analyzer_service.py — orchestration        │
│   scanner.py — regex signal detection        │
│   analysis_model.py — finding vocab/correlation│
│   ast_analyzer.py — AST intelligence         │
│   js_parser.py — optional esprima wrapper    │
│   taint.py — AST source→sink taint analysis  │
│   attack_surface.py — endpoint/API surface   │
│   framework_rules.py — React/Angular/Vue/jQ  │
│   crypto.py — key / IV / crypto extraction   │
│   decoder.py — base64 + hex decoding         │
│   discovery.py — JS asset discovery          │
│   downloader.py — parallel downloads         │
│   beautifier.py — JSON/JS beautify           │
│   reporter.py — report model, TXT/HTML/GUI   │
│   runtime_evidence.py — optional Playwright  │
│   runtime DOM/network/storage capture        │
│   script_intel.py — script inventory,        │
│   behavior profiles, risk scoring, exfil     │
│                                              │
│  analyzers/ — additive analysis modules      │
│  ai/ — optional AI summary                   │
│  config.py — profiles and detection config   │
╰──────────────────────────────────────────────╯
```

## 🧠 Engine Notes

The dashboard uses a deterministic rule-based engine. Every detection is independently scored
and normalized into a single dashboard payload, so the same JavaScript always produces the same
risk picture. URL scanning requires `requests` + `beautifulsoup4`; snippet analysis only needs
Python's standard library. The optional runtime pass additionally requires `playwright` and a
local Chromium install; when those are absent ScriptSentry reports `missing_dependency` and
continues with static analysis.
