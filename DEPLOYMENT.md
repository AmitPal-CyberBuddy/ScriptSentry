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

### Wiring
- `webui/config.js` auto-selects the API base:
  - served from localhost → same origin
  - hosted on GitHub Pages → `http://127.0.0.1:8000`
- `server.py` exposes `/api/health`, `/api/analyze`, `/api/report` with CORS +
  `Access-Control-Allow-Private-Network: true` so a public page can talk to the loopback engine.
- If a visitor changes the port, they update `webui/config.js` to the matching port.

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
while the dashboard lives on GitHub Pages.

### 1. Host the Python backend

Any Python 3.11+ host works. Free options:

- **Render** — free Web Service, deploy from this repo, start command `python3 server.py --port $PORT`
- **Railway** — `python3 server.py --port $PORT`
- **HuggingFace Spaces** — `python3 server.py --port 7860`
- **Any VPS** — `nohup python3 server.py --port 8000 &`

The backend listens on `0.0.0.0` and already returns `Access-Control-Allow-Origin: *`
on API responses, so it accepts requests from any GitHub Pages origin.

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
> rather than `/styles.css`. The included workflow uses absolute paths by default;
> update the `link`/`script` tags if needed.

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
