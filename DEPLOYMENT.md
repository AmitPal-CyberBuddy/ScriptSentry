# 🚀 Deployment Guide

## 🔒 Privacy-first static UI + local engine (recommended)

This is the **free, privacy-first** setup:

- GitHub Pages hosts the UI (`webui/index.html`, `app.js`, `styles.css`, `config.js`).
- The analyzer runs **only on the visitor's machine** via `python3 server.py`.
- No JavaScript ever uploads to a cloud. The page is just chrome; `server.py` does the work locally.

### How it works
1. A visitor opens the hosted page.
2. If `server.py` is not running, the UI shows an engine-status badge:
   `🔴 Local engine offline — run server.py`.
3. When they press Analyze / Scan / Export, a **privacy modal** opens with a short setup guide.
4. They run `python3 server.py --port 8000` locally.
5. The hosted page connects to `http://127.0.0.1:8000` and the tool runs from the hosted UI.
6. Copy the pairing token printed by `server.py` into the UI's pairing field. It is kept only in
   this tab's session storage and is sent in an auth header, never in a URL or report.

### Wiring
- `webui/config.js` auto-selects the API base:
  - served from localhost → same origin
  - hosted on GitHub Pages → `http://127.0.0.1:8000`
- `server.py` exposes `/api/health`, `/api/analyze`, `/api/report` with CORS +
  `Access-Control-Allow-Private-Network: true` so a public page can talk to the loopback engine.
- The API validates the browser `Origin` and only allows loopback/localhost, `*.github.io`,
  and origins listed in `SCRIPTSENTRY_ALLOWED_ORIGINS` (comma separated). Other websites are
  rejected with HTTP 403, so the local engine cannot be used as an open proxy by an arbitrary page.
- For a **custom** hosted domain, set `SCRIPTSENTRY_ALLOWED_ORIGINS=https://my.example.com`
  before starting `server.py`.
- If a visitor changes the port, they update `webui/config.js` to the matching port.

### Optional: local runtime evidence (Playwright)

URL scans can additionally execute the target page in a local headless Chromium to capture
dynamic scripts, console errors, DOM sink writes, network/WebSocket activity and storage-key usage.

```bash
pip install -r requirements.txt
python -m playwright install chromium        # once, on the machine running server.py
python3 server.py --port 8000
```

Privacy invariants for this pass:

- The browser runs on the same machine as the local engine; nothing is uploaded.
- Only URLs, console text, DOM sink values, storage **key names** and cookie **names** are kept.
- Cookie values, request bodies and localStorage values are not persisted.
- Disable it on a shared/hosted backend with `SCRIPTSENTRY_RUNTIME_EVIDENCE=0` if browser
  dependencies are unwanted. When Playwright/Chromium is missing, scans degrade gracefully to
  static analysis and the dashboard shows `missing_dependency` on the Runtime view.

### Set it up
1. Copy `deployment/deploy-pages.yml` to `.github/workflows/deploy-pages.yml`.
2. Enable **Settings → Pages → Source → GitHub Actions**.
3. Publish `webui/` (the workflow copies `webui/*` into `_site/`).

---

## Hosted backend alternative

ScriptSentry has two parts:

| Part | Files | Can it run on GitHub Pages? |
|------|-------|------------------------------|
| **Web UI** (static) | `webui/` | ✅ Yes |
| **Analyzer backend** (Python) | `server.py`, `core/`, `analyzers/`, `ai/` | ❌ No (GitHub Pages is static-only) |

GitHub Pages only serves static files, so the Python analysis engine **cannot run there**.
For the most comprehensive and accurate result, keep the Python engine running on a real
runtime and deploy the UI as a static frontend pointing to it.

---

## ✅ Recommended: GitHub Pages frontend + hosted Python backend

This keeps the **full accurate engine** (regex + AST + crypto + dependency scanner),
while the dashboard lives on GitHub Pages. Runtime browser evidence is optional in this mode:
either install a headless Chromium on the host or set `SCRIPTSENTRY_RUNTIME_EVIDENCE=0`.

### 1. Host the Python backend

Any Python 3.11+ host works. Free options:

- **Render** — free Web Service, deploy from this repo, start command `python3 server.py --port $PORT`
- **Railway** — `python3 server.py --port $PORT`
- **HuggingFace Spaces** — `python3 server.py --port 7860`
- **Any VPS** — `nohup python3 server.py --port 8000 &`

The backend should be protected behind the platform's TLS/auth boundary when deployed publicly.
It allows exact GitHub Pages origins (and exact values in `SCRIPTSENTRY_ALLOWED_ORIGINS`) and
requires the process pairing token for analysis, status, results, cancellation, and reports.
Do not put that token in a public repository or `config.js`; enter it in the dashboard session.

### 2. Point the frontend at the backend

Edit `webui/config.js`:

```js
window.SCRIPTSENTRY_API = "https://your-backend.onrender.com";
```

`app.js` automatically prefixes all `/api/...` calls with this URL.

If the value stays empty, the dashboard works only when served from the same origin
as `server.py` (local dev mode).

### 3. Publish the UI to GitHub Pages

Use the included Actions workflow (below), or manually publish the `webui/` folder.

---

## ⚙️ GitHub Pages workflow (static UI only)

A ready-to-use template lives at `deployment/deploy-pages.yml`. Copy it into
`.github/workflows/deploy-pages.yml`, then set the repo **Pages → Source → GitHub Actions**:

```bash
cp deployment/deploy-pages.yml .github/workflows/deploy-pages.yml
```

> Note: hosted GitHub Apps without `workflows` permission cannot create or update
> `.github/workflows/` files automatically. Copy the template into place from a
> token/context that has `workflows` scope.

```yaml
name: Deploy dashboard to GitHub Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - name: Prepare static site
        run: |
          mkdir -p _site
          cp -r webui/* _site/
      - uses: actions/upload-pages-artifact@v3
        with:
          path: _site
      - id: deployment
        uses: actions/deploy-pages@v4
```

> If you use a custom URL path (e.g. `https://user.github.io/repo/`), set asset
> paths in `webui/index.html` to relative (`styles.css`, `app.js`, `config.js`)
> rather than `/styles.css`. The included UI already uses relative asset paths.

---

## ❌ Why “full client-side” is not the most accurate option

A pure browser port would:

- lose the Python AST + crypto + network scanning capabilities,
- degrade detection quality,
- be unable to scan remote URLs without a CORS proxy.

Keep the backend for accuracy. The static frontend approach keeps **100% of the
analysis engine** and still gives you a shareable GitHub Pages dashboard.

---

## Alternative: Precomputed reports via GitHub Actions

If you only want read-only results on Pages:

1. Create a scheduled/on-push workflow that runs the Python CLI.
2. Write `output/report.json` + `output/report.html` into `gh-pages` or `_site/`.
3. Publish as a static result page.

This is **not interactive**, but it requires no always-on backend.
