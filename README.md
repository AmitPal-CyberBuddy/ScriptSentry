# ScriptSentry

**Watch every line. Detect every risk.**

ScriptSentry is a visual JavaScript intelligence and security analyzer. It finds hardcoded
secrets, crypto material, endpoints, API calls, storage usage, DOM/XSS patterns, obfuscation,
technology stacks and data flows — then presents everything in a modern, animated dashboard.

## ✨ Features

- **Visual Web Dashboard** with animated risk gauge, count-up metrics, radar + donut charts and
  a motion-rich analysis journey.
- **Paste-code analysis** — drop any JS snippet and get instant structured results.
- **Live URL scanning** — discover, download, beautify and recursively analyze JavaScript assets.
- **20+ detection modules**:
  - Secrets & credentials (JWT, API keys, auth headers, private keys)
  - Crypto routines, keys and IV/nonce extraction
  - API inventory, endpoints, HTTP methods, fetch/axios/XHR/WebSocket/SSE
  - Client storage, DOM/XSS indicators, unsafe runtime calls
  - Hardcoded configs, decoded/obfuscated strings
  - Technology stack, dependency ecosystem, notable features, data-flow summary
  - **AST profile** — imports/exports, functions, classes, call graph, complexity
- **Report suite**:
  - Animated web export (HTML) and plain text export from the dashboard
  - CLI TXT / JSON / HTML reports
  - Structured risk signals, remediation plan, attack surface summary
- **Deterministic rule + AST engine** — no external LLM required, with an optional AI-style summary.

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python3 server.py
```

Open the dashboard URL printed by the server, paste JavaScript, or enter a target URL.
The dashboard can **Export HTML Report** and **Export Text Report** after any analysis.

Launch the dashboard directly from the CLI too:

```bash
python3 main.py --serve --port 8000
```

## 📤 Dashboard Report Export

From the web UI press one of the header buttons after analysis:

- **Export HTML Report** — polished shareable report (executive summary, risk signals,
  category bars, per-file detail, remediation plan)
- **Export Text Report** — triage-friendly CLI-style report

Equivalent API endpoints (used by the UI, also callable directly):

```bash
curl -X POST localhost:8000/api/report?format=html \
  -H 'Content-Type: application/json' \
  -d '{"mode":"code","code":"const key=EncryptionKey=\"abc\";"}'
```

## 🧪 CLI Scan

```bash
python3 main.py https://example.com --profile balanced --format all
python3 main.py "https://example.com/static/js/app.js"
python3 main.py https://example.com --max-depth 5 --profile strict --format html
```

Output is written to `output/` (`report.txt`, `report.json`, `report.html`).

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
│   ast_analyzer.py — AST intelligence         │
│   js_parser.py — optional esprima wrapper    │
│   crypto.py — key / IV / crypto extraction   │
│   decoder.py — base64 + hex decoding         │
│   discovery.py — JS asset discovery          │
│   downloader.py — parallel downloads         │
│   beautifier.py — JSON/JS beautify           │
│   reporter.py — report model, TXT/HTML/GUI   │
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
Python's standard library.
