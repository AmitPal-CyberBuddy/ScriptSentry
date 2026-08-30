# 🛡️ ScriptSentry

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

## Quick start

Requires Python 3.8+.

### Option A — one file (no clone needed)

Download just [`scriptsentry.py`](scriptsentry.py) and run it. On first run it
fetches the engine from the official GitHub repo, installs dependencies, and
starts — everything stays local:

```bash
python3 scriptsentry.py --port 8000
```

You can also grab it straight from the hosted dashboard: the setup modal (shown
when the local engine isn't running) has a **⬇️ Download scriptsentry.py**
button.

### Option B — clone the repo

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

Open the URL the server prints (default `http://127.0.0.1:8000`). Locally, `/`
serves the **analysis console** (`tool.html`) directly; the overview/landing page
lives at `/index.html`. On startup the server prints a one-time **engine pairing
token** — paste it into the page's setup dialog when prompted (the header's
animated engine pill opens it). The token stays in that browser tab only and is
sent as an `X-ScriptSentry-Token` header.

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

# Reports are written to output/ : report.txt / .json / .html / .csv / .sarif
```

Launch the dashboard directly from the CLI:

```bash
python3 main.py --serve --port 8000
```

Optional AI-style summary (not required for any core analysis):

```bash
python3 main.py https://example.com --ai openai --api-key YOUR_KEY --model gpt-4o-mini
```

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

## Host the UI, keep the engine local

You can host the dashboard front-end (for example on **GitHub Pages**) while the
analysis engine stays entirely on your own machine:

1. Publish the `webui/` folder (a ready-made workflow is in
   `deployment/deploy-pages.yml`). It is a handful of static pages —
   `index.html` (overview, what it finds, how it works, setup, connect),
   `tool.html` (the console) and `changelog.html` (what's new) — plus `assets/`
   (favicons, app icons, web manifest, social card). GitHub Pages serves
   `index.html` at `/`.
2. On your machine run `pip install -r requirements.txt && python3 server.py`.
3. Open the hosted page and enter the pairing token. It talks directly to your
   local `127.0.0.1` engine — **no code ever leaves your computer**.

The local engine only accepts loopback/GitHub-Pages origins, requires the
pairing token for analysis, rejects credential-bearing or private/loopback
target URLs, and validates redirects so it can't be abused as an open proxy.
Full hosting details are in [`DEPLOYMENT.md`](DEPLOYMENT.md).

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

---

## Project status

ScriptSentry is under active development and has not shipped its first stable
release yet. The analysis is already useful for triage, but the interface and
the detection rules are still being refined — treat findings as signals to
investigate rather than a final verdict, and expect things to keep improving.

Every change is recorded in the [changelog](webui/changelog.html), and the
technical notes behind the design decisions live in [`AUDIT.md`](AUDIT.md).

---

## Getting help

- 🐛 **Found a bug — or a finding that's wrong?** Open an
  [issue](https://github.com/AmitPal-CyberBuddy/ScriptSentry/issues) or
  [email me](mailto:amitpal.secure@gmail.com?subject=ScriptSentry%20feedback).
  For a wrong finding, the most useful thing to send is the snippet plus what
  the tool reported.
- 💼 **Connect on [LinkedIn](https://www.linkedin.com/in/amitpal-wb/)**.
- 🐙 **Browse the source** on
  [GitHub](https://github.com/AmitPal-CyberBuddy/ScriptSentry).

---

> ScriptSentry produces deterministic signals for triage — it is not proof of
> exploitation. Always validate findings with server-side behavior and manual
> review.
