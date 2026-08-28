# 🚀 Deployment Guide

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

Add `.github/workflows/deploy-pages.yml` and set the repo **Pages → Source → GitHub Actions**.

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
