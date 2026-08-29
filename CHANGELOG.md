# Changelog

All notable changes to ScriptSentry are documented here. The version number is
defined in one place (`core/version.py`) and mirrored in `release.json`.

> 🚧 **Status: under active development — not yet published.** The project is
> marked as a pre-release (`DEV_BUILD = True`, version suffix `-dev`) until the
> first stable release.

## [Unreleased] — 2.2.0-dev

The 2.2.0 accuracy & triage work below is in development and not a published
release yet.

### Accuracy & triage model
- Severity, **confidence**, triage **status**, and **analysis quality** are now
  independent axes. Confidence is derived from the *evidence* (regex → low,
  framework/behavioral → medium, source-to-sink/runtime → high, demonstrated
  runtime effect → confirmed) and is never inferred from severity.
- New triage vocabulary: **Open · Needs review · Confirmed · False positive ·
  Informational**. Static source→sink flows are high confidence but stay
  **Open**; **Confirmed** is reserved for deterministic proof, a demonstrated
  unsafe runtime effect (e.g. live `eval`), or explicit analyst confirmation.
- Runtime DOM-sink execution is high confidence / Open (exploitability not
  proven); WebSocket/API inventory and string timers are observations.
- Findings now carry an **analysis quality** (`high` / `medium` / `heuristic`)
  plus explicit **limitations** (dynamic property access, unmodeled call,
  inter-procedural depth bound, regex fallback).

### Findings vs observations
- Results are split into **Actionable Findings** (investigate/remediate) and
  **Security Observations** (interesting behavior that is not a proven
  vulnerability), surfaced as separate sections in the dashboard and reports.
- Stronger finding identity (type + canonical source + sink + file + line +
  normalized flow signature) so two distinct untrusted sources reaching the
  same sink are no longer collapsed into one record.

### Risk score
- New evidence-weighted **0–100 risk score** (`core/risk_model.py`) with a
  transparent `+points` contributor breakdown and an investigate-first
  **priority list**, replacing the previous unbounded category count.

### Script discovery
- New layered discovery (`core/module_discovery.py`): AST
  import/require/dynamic-`import()` first, bundler adapters (Webpack chunk
  maps, Vite/Rollup/Next.js/Parcel hashed assets) second, regex fallback third.
  Non-script references (API paths, JSON/CSS/font imports) are filtered out.

### Dashboard UX
- Primary navigation reduced from nine views to five: **Overview · Findings ·
  Scripts · Intelligence · Runtime** (Assets lives under Scripts; Attack
  Surface / Data Flows / Secrets / Dependencies live under Intelligence).
- Overview leads with "is it risky → why → what to investigate first"
  (priorities and score breakdown) above the charts.
- Findings show confidence, analysis-quality chips, and analysis limits.

### False-positive discipline
- Tightened credible-secret filtering (placeholders such as
  `YOUR_API_TOKEN_HERE`, template markers, and zeroed values are not credible).
- Formal **accuracy regression suite** (`tests/test_accuracy_regression.py`)
  with TP / TN / known-FP / framework-edge / minified / obfuscated fixtures.

### Onboarding & UX
- **Local file upload**: the Paste Code tab now has a "📁 Upload files" mode —
  drag & drop or browse multiple `.js` / `.mjs` / `.cjs` / `.jsx` / `.ts` files
  and analyze them in one scan with per-file attribution. Files are read in the
  browser and sent only to the paired local engine (nothing goes to a cloud);
  the server enforces an extension allow-list, a 20-file cap and a 3 MB/file
  limit. Content duplicates are deduped and path-like names sanitized.
- Scan controls (profile, max depth, max files, workers) now have inline **?**
  tooltips explaining what each one does.
- New one-file launcher `scriptsentry.py`: download a single file and run it;
  on first run it downloads the pinned engine from the official GitHub repo,
  installs dependencies and starts the dashboard (cached for later runs).
- Setup modal now offers a **Download scriptsentry.py** button alongside the
  git-clone path. Native `alert()` popups are replaced with inline field
  validation and error messages (invalid/non-URL targets, rejected scans).
- Added an **authorized-testing-only** notice to the page, the setup modal and
  the README.

### Brand, landing page & front-end fixes
- **Proper identity**: real SVG logo (shield + `</>` mark) rendered inline in the
  header and footer, plus `webui/assets/favicon.svg`, `favicon-32.png`,
  `icon-192.png`, `icon-512.png`, `apple-touch-icon.png`, a 1200×630
  `og-card.png` and a `site.webmanifest`. The page now ships full favicon,
  Open Graph and Twitter card metadata instead of a bare title.
- **Landing page**: the dashboard is now a single scrollable site with a sticky
  header (nav + **⚡ Go to tool** button), hero with dual CTAs, "What it finds",
  "How it works", "Why it's trustworthy", "Run your own engine" and
  "Connect with me" sections, and a multi-column footer with legal notice.
- **Fixed the launcher download.** The setup dialog used
  `<a href="raw.githubusercontent.com/…" download>`, which browsers ignore for
  cross-origin targets — the file opened in a tab instead of downloading. The
  launcher is now fetched and saved through a same-origin blob URL, with a
  new-tab fallback and an inline status hint.
- **Engine status is now an animated indicator.** The header pill uses a
  pulsing core + expanding ring (green / amber / red) instead of a static 🟢/🔴
  emoji, is clickable to open the setup guide, and is mirrored inside the
  setup dialog.
- **Setup dialog**: wider two-column layout on large screens (900 px), a proper
  **× close button** in the top-right, backdrop-click and Escape to dismiss,
  scroll lock, focus handling, and a dedicated "Pair the engine" column with
  the live engine state.
- **Target URL input was unstyled** (only `textarea` and `input[type=text]`
  were). All text/url/email/password inputs now share the themed field style,
  with a 🌐 prefixed URL field, a 🔑 prefixed token field, focus/hover states,
  placeholder colouring and a dark-mode autofill fix.
- `server.py` redirects the browser's automatic `/favicon.ico` probe to the real
  SVG asset instead of returning 404.

### Maintenance
- Engine version centralized in `core/version.py`; added `release.json` and
  this changelog. TXT report no longer iterates string evidence
  character-by-character; CSV/SARIF export quality/limitation fields.
- Test count: **77+ passing**.

## [2.1.0] — earlier release
- Modular `webui` / `server.py` / `core` / `analyzers` architecture.
- Script inventory & behavior intelligence, first/third-party attribution,
  risk scoring, and static/runtime data-exfiltration correlation.
- Local authenticated dashboard with pairing token, bounded jobs, Playwright
  runtime evidence, source-map awareness, and TXT/HTML/CSV/SARIF exports.
