# 🛡️ ScriptSentry

[![CI](https://github.com/AmitPal-CyberBuddy/ScriptSentry/actions/workflows/ci.yml/badge.svg)](https://github.com/AmitPal-CyberBuddy/ScriptSentry/actions/workflows/ci.yml)

**Watch every line. Detect every risk.**

ScriptSentry is a **privacy-first JavaScript security & script-behavior
intelligence tool**. Point it at a URL or paste any JavaScript, and it tells
you not just *what dangerous strings appear* but what the scripts actually
**do**: what data they read, where that data can go, which third parties are
involved, and how risky that behavior is — presented in a clear, visual
dashboard.

Everything runs **locally on your machine**. Your code is never uploaded to a
cloud; there are no accounts and no API keys required for core analysis.

> ⚖️ **Authorized testing only.** Only scan applications and systems you own or
> have explicit written permission to test. You are responsible for complying
> with all applicable laws and the target's terms of service. ScriptSentry
> produces triage signals, not proof of exploitation — verify every finding and
> never use the tool to access systems without authorization.

---

## What it finds

- 🔐 **Secrets & credentials** — JWTs, API keys, auth headers, crypto keys/IVs
- 🕳️ **Real DOM-XSS & open-redirect flows** — source→sink taint analysis
  (`location`/`postMessage`/storage/cookies/forms → `innerHTML`/`eval`/redirect)
- 🚚 **Data exfiltration** — sensitive reads correlated with external/third-party
  destinations
- 🌐 **Attack surface** — endpoints, HTTP methods, WebSockets, SSE, GraphQL,
  params, headers, body fields, internal/hidden routes
- 📦 **Dependencies & tech stack** — frameworks and libraries, including
  framework-specific risky APIs (React `dangerouslySetInnerHTML`, Angular
  `bypassSecurityTrust*`, Vue `v-html`, jQuery sinks)
- 💾 **Client storage & crypto use** — localStorage/sessionStorage/cookies,
  client-side crypto routines
- 🧩 **Obfuscation** — encoded/hidden strings and suspicious runtime calls
- 🖥️ **Runtime evidence** *(optional)* — a local headless browser that watches
  the live page: network traffic, DOM sinks, `eval`, storage, cookies, and
  scripts loaded only after execution

Every finding id, its plain-language meaning and the usual fix are documented
in the **[rule reference](docs/RULES.md)** (same page, hosted:
`https://<site>/rules/`) — generated from the engine's own rule registry, so
the docs and the reports always agree.

## Why the results are trustworthy

ScriptSentry is built to **avoid crying wolf**. It separates three things many
scanners mix together:

| Question | Answer |
|----------|--------|
| **How bad would it be *if real*?** | Severity — Info → Critical |
| **How certain is the *evidence*?** | Confidence — low → high → confirmed |
| **What's the analyst state?** | Open · Needs review · Confirmed · False positive · Informational |

A regex hit is **not** treated as proof. A static source→sink path is reported
as high confidence but stays **Open** — encoding, framework sanitizers, or
unreachable code may still neutralize it. **Confirmed** is reserved for
demonstrated/deterministic proof (for example, `eval` actually executing in the
captured page) or your own manual verification.

The dashboard therefore splits results into:

- **🚦 Actionable Findings** — things that warrant investigation or remediation.
- **👁️ Security Observations** — interesting behavior that is *not* a proven
  vulnerability (API surface, obfuscation, inventory, patterns without a flow).

Each finding also shows an **analysis quality** rating and any **limitations**
(e.g. "dynamic property access unresolved"), so the tool never pretends to
understand JavaScript constructs it didn't fully model. The risk score is a
bounded **0–100** with an itemized breakdown of exactly what contributes to it,
plus an **investigate-first** priority list.

---

## How it works

1. **Discover.** Point ScriptSentry at a URL and it walks the page like a
   browser would: inline scripts, `<script src>` and module tags, preloads,
   dynamic `import()` / `require()` edges, and bundler chunk references
   (Webpack, Vite, Next, Parcel). Direct `.js`/`.mjs` links are analyzed as
   the target themselves. Paste or upload code and you skip straight to step 2.
2. **Parse every script with the best engine available.** A real JavaScript
   AST (tree-sitter, falling back to esprima, then conservative line-based
   patterns) turns each file into a behavior model — no string-only guessing.
3. **Model behavior, not just suspicious strings.** Taint analysis follows
   data from sources (`location`, `postMessage`, storage, cookies, forms,
   network responses) to sinks (`innerHTML`, `eval`, redirects, `fetch`),
   with alias/property tracking and sanitizer awareness. Secrets, crypto
   misuse, dependencies, API surface and obfuscation become evidence the
   model can reason about.
4. **Verify what's provable.** Optionally rerun the page in a local headless
   Chromium: live network calls, DOM sinks, `eval`, storage and cookie access,
   and scripts that only load after execution. Each finding carries severity,
   confidence, triage status and analysis quality — never an overclaim.
5. **Explain and triage.** The dashboard renders an itemized 0–100 risk score,
   an investigate-first priority list, Actionable Findings vs. Security
   Observations, per-script inventory, and exports (HTML/TXT/CSV/SARIF/JSON).

Everything above runs on your machine. The hosted page is only the interface.

---

## Quick start

Requires Python 3.10+.

### Option A — one file (no clone needed)

Download just [`scriptsentry.py`](scriptsentry.py) and run it. On first run it
fetches the engine from the official GitHub repo, installs dependencies, and
starts — everything stays local:

```bash
python3 scriptsentry.py --port 8000
```

The engine is cached under `~/.scriptsentry/bootstrap/` and reused on every
later run — the launcher never re-downloads it on its own. After fixes land in
the repository, refresh your local copy with:

```bash
python3 scriptsentry.py --update
```

You can also grab it straight from the hosted dashboard: the setup modal (shown
when the local engine isn't running) has a **⬇️ Download scriptsentry.py**
button.

### Option B — install with pip (or pipx)

```bash
# Installs the engine and the `scriptsentry-server`/`scriptsentry` commands
pip install .
scriptsentry-server --port 8000
```

`pipx install .` works too and keeps the tool in its own isolated
environment. The same package is what the Docker image runs.

### Option C — clone the repo

```bash
# 1. Get the project and install dependencies
git clone https://github.com/AmitPal-CyberBuddy/ScriptSentry.git
cd ScriptSentry
pip install -r requirements.txt

# 2. (Optional) enable the local headless-browser runtime pass.
#    Skip this and URL scans still work with static analysis only.
python -m playwright install chromium

# 3. Start the dashboard
python3 server.py
```

### Option D — Docker

```bash
docker build -t scriptsentry .
docker run --rm -p 8000:8000 scriptsentry
```

The image preinstalls Playwright's Chromium, so the optional runtime-evidence
pass works out of the box.

### Pairing the dashboard

Open the URL the server prints (default `http://127.0.0.1:8000`). Locally, `/`
serves the **analysis console** (`webui/tool/index.html`) directly; the
overview/landing page lives at `/home/`. On startup the server prints a
one-time **engine pairing token** — paste it into the page's setup dialog when
prompted (the header's animated engine pill opens it). The token stays in that
browser tab only and is sent as an `X-ScriptSentry-Token` header.

### Three ways to analyze

- **Paste JavaScript** into the editor and hit **Analyze Code**.
- **Upload files** — switch the editor to **📁 Upload files** and drag & drop one
  or more local `.js` / `.mjs` / `.cjs` / `.jsx` / `.ts` files; they're analyzed
  together with per-file attribution. Files are read in your browser and sent
  only to the local engine over the paired channel — nothing is uploaded to a
  cloud.
- **Enter a target URL** and choose a profile (Fast / Balanced / Strict),
  recursion depth, file cap, and worker count, then hit **Analyze Target**.
  Hover the **?** next to each option for a one-line explanation of what it
  controls.

### Command line

```bash
# Scan a live site (discovers & recursively analyzes every script)
python3 main.py https://example.com --profile balanced --format all

# Scan local files or a whole directory (same engine as the dashboard;
# walks .js/.mjs/.cjs/.jsx/.ts/.tsx, skips node_modules and .git)
python3 main.py ./dist bundle.js --format sarif txt

# Reports are written to output/ by default, or wherever --output points:
# report.txt / .json / .html / .csv / .sarif / api-surface.openapi.json
```

Mix URLs and local paths in one command; a dead URL never discards the
results of the other targets.

**CI gate:** `--fail-on {critical,high,medium,low,none}` exits `1` when any
*actionable* finding (observations excluded) reaches that severity — the hook
a pipeline gates on. Exit `2` means an operational error (nothing was
scanned), so a broken target never silently passes a gate:

```bash
python3 main.py ./dist --format sarif txt --fail-on high --output ci-report
```

**Baselines: fail only on what is new.** `--fail-on` alone answers "are there
findings?" — the wrong question for a codebase that already has accepted
ones. A baseline answers the question CI actually needs ("is this run worse
than the accepted state?"):

```bash
# Once (e.g. on main, or locally): snapshot the current findings…
python3 main.py ./dist --fail-on low --save-baseline scriptsentry-baseline.json

# …commit the file, then gate every future run on what changed:
python3 main.py ./dist --fail-on low --baseline scriptsentry-baseline.json
```

With `--baseline`, only findings that are **new** or **worsened** (severity
raised, or an observation that came back actionable) count against the exit
code; known findings stay in every report — the report never lies, only the
gate narrows. Baselines are deterministic (sorted fingerprints, no
timestamps), so they diff cleanly in review, and a missing baseline file
behaves like an empty one: everything counts as new, the safe direction.
Findings are identified by the same line-independent fingerprint the history
diff uses, so an unrelated edit above a finding does not flip it to "new".
Updating a baseline — accepting a finding — is a visible, reviewable act:
commit the file.

**Watch mode:** `--watch SECONDS` re-scans the target(s) on an interval and
prints what changed between cycles — new, worse, improved and
no-longer-detected findings, identified line-independently (the same
fingerprint as baselines and the history diff), so cosmetic edits don't
noise the diff:

```bash
python3 main.py https://example.com --watch 60 --fail-on high
```

Ctrl+C stops the watch (exit 0). With `--fail-on`, the first failing cycle
exits 1 — watch mode is monitoring, and a gate that keeps running after
turning red is a gate nobody watches.

Launch the dashboard directly from the CLI:

```bash
python3 main.py --serve --port 8000
```

Optional AI-style summary (not required for any core analysis). By default
`--ai` is `disabled` — no model is called at all. `--ai ollama` calls a
**local** Ollama server, and `--ai openai` calls any **local**
OpenAI-compatible server (LM Studio, llama.cpp server, vLLM). Both are
privacy-first — code never leaves your machine — and both fall back to the
built-in rule-based summary if the model server is offline:

```bash
# Ollama (default endpoint http://localhost:11434)
python3 main.py https://example.com --ai ollama --model llama3.2

# LM Studio (default endpoint http://localhost:1234/v1) or any
# OpenAI-compatible local server (llama.cpp: http://localhost:8080/v1)
python3 main.py https://example.com --ai openai --model your-model-name
```

Flags: `--ai {disabled,ollama,openai}` (default `disabled` — no summary at all),
`--model NAME` (default `llama3.2`), `--ollama-url URL` (default
`http://localhost:11434`), `--openai-base-url URL` (default
`http://localhost:1234/v1`, i.e. LM Studio), `--api-key TOKEN` (only for local
servers that request one). Only structured findings — never raw source code —
are sent to the model, and the summary is written into the CLI reports
(TXT/HTML/JSON/CSV/SARIF); the dashboard itself stays model-free. Hosted cloud
providers are deliberately unsupported.

---

## Reading the dashboard

The interface is organized into five focused views:

1. **📊 Overview** — answers three questions up front: *is this app risky?*,
   *why?* (itemized risk-score breakdown), and *what should I investigate
   first?* (priority list). Charts and the detection snapshot sit below.
2. **🚦 Findings** — Actionable Findings to triage, and Security Observations.
   Click a finding's status chip to cycle it through Open → Needs review →
   Confirmed → False positive → Informational (stored only in your browser).
3. **📚 Scripts** — the script inventory: every discovered script with
   first/third-party attribution, sensitive reads, DOM/network writes, browser
   APIs, external destinations, load relationships, and a per-script risk
   score. Also includes the per-asset file details.
4. **🧠 Intelligence** — source→sink data flows, attack surface, secrets, and
   dependencies/transport.
5. **🖥️ Runtime** — the optional headless-browser evidence (network, console,
   DOM sinks, eval, storage/cookies, WebSockets, dynamically loaded scripts).

### Export a report

After any analysis, use the header buttons (or the API/CLI) to export:

- **HTML** — polished, shareable report
- **TXT** — triage-friendly text report
- **CSV** — spreadsheet of findings (severity, confidence, status, source→sink,
  flow, quality, limitations)
- **SARIF** — SARIF 2.1.0 for GitHub code scanning / CI

---

### Use it in CI (GitHub Actions)

The repo ships a composite action that installs the engine on the runner and
scans your checkout — the scanned code never leaves the runner:

```yaml
name: ScriptSentry
on: [push]
permissions:
  security-events: write   # for the SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan the JavaScript in this repository
        uses: AmitPal-CyberBuddy/ScriptSentry/.github/actions/scan@main
        with:
          targets: .              # files, directories or URLs (space-separated)
          fail-on: high           # critical|high|medium|low|none
          format: sarif txt
          output: scriptsentry-report
          # baseline: scriptsentry-baseline.json   # gate only on new/worsened
      - name: Upload findings to code scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scriptsentry-report/report.sarif
          category: scriptsentry
```

Local targets are reported with repository-relative paths, so SARIF findings
map straight onto your files in the code scanning UI. This repository runs
the same action on itself (`.github/workflows/self-scan.yml`) as a live
example.

## Host the UI, keep the engine local

You can host the dashboard front-end (for example on **GitHub Pages**) while the
analysis engine stays entirely on your own machine:

1. Publish the `webui/` folder (a ready-made workflow is in
   `.github/workflows/deploy-pages.yml`). It is a handful of static pages —
   `home/index.html` (overview, what it finds, how it works, setup, connect),
   `tool/index.html` (the console) and `changelog/index.html` (what's new) —
   plus `assets/` (favicons, app icons, web manifest, social card). GitHub
   Pages serves them at `/home/`, `/tool/` and `/changelog/`.
2. On your machine run `pip install -r requirements.txt && python3 server.py`.
3. Open the hosted page and enter the pairing token. It talks directly to your
   local `127.0.0.1` engine — **no code ever leaves your computer**.

The local engine only accepts loopback/GitHub-Pages origins, requires the
pairing token for analysis, rejects credential-bearing or private/loopback
target URLs, and pins each outbound hop to the public IPs it validated at scan
time (DNS-rebinding resistant) so it can't be abused as an open proxy.
Full hosting details are in [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

---

## Your data: history, inspection & deletion

ScriptSentry has **no accounts, no profiles, no cloud sync** — everything it
keeps stays on the machine where the engine runs. Here is the full story:

- **Scan history lives in a local SQLite database** (`history.db`, WAL mode) in
  the engine's state directory
  (`~/.cache/scriptsentry`, or `$SCRIPTSENTRY_STATE_DIR`). Each entry keeps
  the target, when it was scanned, file/finding counts, a summary diff against
  the previous scan of the same target, and the full report payload (capped at
  16 MB per scan). Only the newest **200** scans are retained by default
  (`SCRIPTSENTRY_HISTORY_MAX` overrides it; `SCRIPTSENTRY_HISTORY=0` disables
  recording entirely).
- **Anonymous timing stats** (`eta_calibration.json`) help the engine estimate
  progress; they contain no scan content.
- **In your browser:** triage status changes go to `localStorage`; the most
  recent report and the pairing token for that tab go to `sessionStorage`
  (cleared when the tab closes). Only keys are ever described — never values.
- **Everything is inspectable and deletable.** The **💾 Data & storage** button
  in the dashboard header opens the trust panel inside the setup dialog. It
  shows live facts (history enabled/disabled, database and WAL sizes, scan and
  finding counts, oldest/newest scan, retention, stored report bytes) and lists
  your scans:
  - **View** any stored scan to reopen its full report;
  - **Delete** a single scan — or **🗑 Delete all history** (scans, findings,
    stored reports; anonymous ETA stats stay unless you wipe them too);
  - **🧹 Clear this browser's data** (triage statuses + last report, with an
    opt-in checkbox to also remove the pairing token and log the tab out);
  - **⬇️ Download all data** as one JSON export (scans, findings, diffs and
    stored report payloads) — useful before deleting anything.
- **Never stored at all:** cookie values, request bodies, localStorage values,
  form inputs, or the source of code you paste/upload outside the scan that
  uses it. Scan content never leaves your machine. The optional **Local AI
  triage notes** exist only in the CLI reports (`--ai`) — a local model reads
  structured findings, never your source, and the dashboard itself never
  calls a model.

---

## Privacy & security model

- **100% local analysis.** The hosted page is just the interface; all scanning
  happens against `localhost` via `server.py`.
- The runtime pass records URL/console text, DOM-sink values, and storage/cookie
  **key names only** — never cookie values, request bodies, or localStorage
  values. Dynamic script bodies are rescanned locally and then dropped from
  serialized evidence.
- The server binds to loopback by default, uses a process-scoped pairing token
  with `hmac.compare_digest`, enforces origin checks, and bounds request body
  and URL sizes.
- **DNS-rebinding resistant scans.** Each target is validated and resolved in a
  single step, then every connection is pinned to the validated public address
  literals (all address families); redirect hops are re-validated and re-pinned.
  Set `SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1` only when you are explicitly
  authorized to scan local/private targets.

---

## Project status

ScriptSentry is under active development and has not shipped its first stable
release yet. The analysis is already useful for triage, but the interface and
the detection rules are still being refined — treat findings as signals to
investigate rather than a final verdict, and expect things to keep improving.

Every change is recorded in the [changelog](webui/changelog/index.html), and
the technical notes behind the design decisions live in [`docs/AUDIT.md`](docs/AUDIT.md).

---

## Getting help

- 🐛 **Found a bug — or a finding that's wrong?** Open an
  [issue](https://github.com/AmitPal-CyberBuddy/ScriptSentry/issues/new/choose)
  (a free GitHub account is required). For a wrong finding, the most useful
  thing to send is the snippet plus what the tool reported.
- 🔐 **Found a vulnerability *in ScriptSentry itself*?** Please don't open a
  public issue. Use
  [private vulnerability reporting](https://github.com/AmitPal-CyberBuddy/ScriptSentry/security/advisories/new)
  so it can be fixed before it is disclosed. See [`SECURITY.md`](SECURITY.md).
- 💼 **Connect on [LinkedIn](https://www.linkedin.com/in/amitpal-wb/)**.
- 🐙 **Browse the source** on
  [GitHub](https://github.com/AmitPal-CyberBuddy/ScriptSentry).

---

> ScriptSentry produces deterministic signals for triage — it is not proof of
> exploitation. Always validate findings with server-side behavior and manual
> review.
