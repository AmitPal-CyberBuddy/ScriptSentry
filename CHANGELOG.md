# Changelog

All notable changes to ScriptSentry are listed here, newest first.

> 🚧 **Status: under active development.** ScriptSentry is still a pre-release
> tool: it is already useful for triage, but features and detection rules keep
> improving, and details may change between versions.

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
- **Separate pages for overview and console**: `home/index.html` is the
  overview/landing page (hero, what it finds, how it works, trust, setup,
  connect) and `tool/index.html` hosts the analysis console. Both share
  `app.js`, `styles.css` and `config.js`; the script detects which page it is
  on and only wires the analyzer when the console markup is present. `server.py`
  serves `/` → `tool/index.html` so a locally started engine opens the console,
  while GitHub Pages serves the overview at `/home/`.
- **Scroll animations**: sections, cards, steps and footer columns reveal as
  they enter the viewport (`IntersectionObserver`, staggered, unobserve after
  the first reveal), plus a scroll-progress bar under the sticky header and
  active-section highlighting in the nav. All of it is disabled under
  `prefers-reduced-motion`, and the hidden state is scoped to a `js-reveal`
  class set in `config.js` so a failed script can never blank the page.
- **Proper headings**: one `h1` per page ("Watch every line…" on the overview,
  "JavaScript analysis console" on the console page), `h2` per section, `h3` per
  card, plus a skip-to-content link and `aria-current` on the active nav link.
- **Connect section is about ScriptSentry, not CyberBuddy.** It now reads
  "Building ScriptSentry for analysts, with analysts" with a ScriptSentry
  roadmap item (build-over-build diffing and a CI gate) instead of the
  CyberBuddy / HAR Analyzer copy.
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


### Audit follow-ups — detection quality
- **One pattern catalogue.** `core/js_patterns.py` is now the single source of
  truth for sources, sinks, crypto markers and transport calls; `core/taint.py`
  and the `analyzers/*` modules import from it instead of keeping private
  copies that could disagree.
- **Secrets.** Deduped by longest credential token (one Firebase key is now one
  finding, not three); public-by-design client keys (Firebase `apiKey`,
  Google/Stripe/Recaptcha publishable keys) are reported as inventory under
  `public_client_keys` instead of as secrets; real provider credentials
  (`sk_live_`, `ghp_`, `xox*-`, `AKIA…`, Slack/Discord webhooks) are matched by
  value shape rather than by a minimum length.
- **Sensitivity.** `sensitive_storage` no longer fires on any mention of
  `document.cookie` or on `sessionStorage` at large — it requires a sensitive
  key name or value, so ordinary theme/analytics storage is MEDIUM again.
- **Secret context.** `content.find()` is checked for `-1` before slicing, so a
  reconstructed value can no longer quote the top of the file as its context.
- **Crypto.** Word-bounded, shared markers replace the old substring test that
  found "DES" inside "desktopTheme" and "Hex" inside "hexagon".
- **Taint.** New sources (`document.baseURI`, `history.state`, `window.name`)
  and sinks (element `href`/`src` assignment, `setAttribute('href'|'src'|'srcdoc')`,
  jQuery `.html()/.append()/.prepend()/.attr()`) on both the AST and the
  line-fallback path; source markers are matched case-insensitively, which
  previously hid every camelCase source from the AST path.
- **Risk floor.** A single HIGH/CRITICAL severity forces at least MEDIUM
  regardless of how much low-tier evidence a scan produced.
- **Parser visibility.** `/api/health` and the dashboard payload now report
  `ast_parser` (name / available / mode / install hint), the server prints the
  parser state at startup, and the console warns when a scan ran in fallback
  mode. Tests that require the AST layer skip cleanly when esprima is absent.

### Navigation and content cleanup
- **The footer's "Project" column implied pages that do not exist.**
  Separate "Changelog", "Documentation" and "Report an Issue" entries all
  pointed at the same GitHub repo, each labelled as though it were its own
  destination. They are now a single entry — "GitHub · source, docs &
  changelog" — which is honest about where it goes.
- **"Report an Issue" moved into Connect.** It no longer sits as its own
  footer entry. The Connect section now leads with it: what to send, plus
  the issue tracker alongside email and LinkedIn.
- **Removed the "Next: Bundle Diffing" footer link.** It looked like a
  roadmap page but only scrolled to the contact section. The roadmap is
  real content and stays in the Connect card, clearly labelled as what is
  next on the bench — it is not navigation.
- **Removed the duplicated "Feedback & Ideas" footer link,** which the
  header already covers.
- **Footers are three columns** (Brand / Product / Connect) instead of
  four, on both pages.
- **Removed repeated copy.** The footer brand paragraph restated the hero
  paragraph almost verbatim; it is now a single line. The Connect card's
  heading repeated its own section introduction. And "authorized testing
  only" appeared three times on the landing page — the setup dialog's copy
  is gone, since the hero notice and the persistent footer already carry
  it. The console page keeps its dialog notice because it has no hero
  notice to rely on.
- **Tests.** 11 new link-integrity tests: internal links resolve, in-page
  and cross-page anchors have targets, assets exist, `target="_blank"`
  carries `rel="noopener"`, no placeholder hrefs, and three guardrails on
  footer quality (no dead-end links, no repeating one destination, no
  sitemap-length footers). All mutation-tested.

### Responsive QA pass -- composition, not just fit
- **Stat tiles were 360px boxes on a tablet.** The generic `.grid-4`
  ladder dropped the four metric tiles to two tracks between 640 and
  1000px, leaving a 42px number adrift in a huge card. They now hold
  four across down to 640px (170px tracks, which still fit "Actionable
  Findings" on one line) and drop to two on a phone. Never three: eight
  would not be the issue, but four tiles on three tracks leaves an
  orphan.
- **The console container was over-widened.** It had been set to
  1440-1680 on the theory that a dense tool wants more room, but the
  console's density is vertical (long finding and script lists), not
  horizontal. Widening only stretched the two-up overview cards into
  750-830px letterboxes. It now tracks the landing measure.
- **The gauge card left a third of itself empty.** The dial was a fixed
  150px while its card grew past 600px, so the gauge and its caption
  huddled against the left edge. The dial now scales with the space and
  the pair is centred.
- **The donut chart letterboxed.** A square viewBox with `width: 100%`
  and a fixed height renders as a centred square no wider than that
  height, so the donut sat in 240px with hundreds of pixels of dead
  space either side. Its width is now capped to its height, and where
  the card is wide enough the legend sits beside it rather than below.
  That depends on the *card's* width, not the viewport's -- at a 620px
  viewport the charts are already two-up and the card is only ~272px --
  so it is a container query, degrading to stacked where unsupported.
- **Two orphan-row defects.** Eight feature cards on `auto-fit` reached
  five tracks on a wide monitor and left a lopsided 5 + 3; four step
  cards reached three tracks between ~880 and ~1170px and stranded one
  alone. Both now use explicit ladders whose counts divide the item
  count evenly.
- **Phone composition.** Four export buttons plus a status line
  free-wrapped into ragged rows; they are now a 2x2 group with the
  status spanning above. Five view tabs wrap to two columns with the
  fifth spanning the full width, rather than leaving a short last line.
  The Copy button no longer squeezes a code snippet into a ~110px
  column, which forced horizontal scrolling for a single long URL.
- **Spacing moved onto the fluid scale** for cards, the setup card, the
  console head and body, the tool hero and the dropzone, so density
  stays proportional instead of being tuned at each breakpoint. Fixed
  26px and 20px paddings were proportionally heavy inside a 292px phone
  card.
- **Tests.** 6 new composition tests (grid ladders, stat density,
  console containment, card-width ceiling), mutation-tested.

### Responsive design system
- **Mobile navigation was unreachable.** `.nav-toggle` is `display: none`
  by default, and the override that reveals it below 1040px sat ~370 lines
  *earlier* in the stylesheet. A media query is not a specificity bump, so
  the base rule won and the menu button never rendered — below 1040px the
  nav links were set to `opacity: 0` with nothing able to reveal them. The
  collapsed-nav block now sits at the end of the file, where it belongs.
- **A fluid design-token layer.** Gutters, vertical rhythm, radii,
  container widths and a full type scale are now `clamp()`-based custom
  properties, so 600px and 1200px are designed widths rather than sizes
  the layout merely survives. Breakpoints now only appear where the
  *architecture* changes (column counts, nav mode, modal → sheet).
- **Grids can shrink.** Every `1fr` track is now `minmax(0, 1fr)`. A bare
  `1fr` resolves to `minmax(auto, 1fr)` and refuses to shrink below its
  content, which is what pushed the page into horizontal scroll.
  `auto-fit` minimums are wrapped in `min(100%, Npx)` so a grid can never
  demand a track wider than its container.
- **Tooltips work on touch.** The `?` hints were 15×15px, hover-only, and
  opened a fixed 230px popover centred on the dot — untappable, and
  clipped off the right edge at any narrow width. They now have a 44px
  hit area, open on tap / click / Enter / Space, are nudged back into the
  viewport when a trigger sits near an edge, and on touch or narrow
  screens expand inline under their label instead of floating.
- **Charts follow their container.** The radar canvas was sized once from
  `clientWidth` and never redrawn, so it stretched after a resize or a
  rotation. A `ResizeObserver` now redraws it, which also covers the
  Overview panel being hidden and re-shown by the view tabs. Its label
  reserve is measured from the longest label instead of a fixed 30px, so
  labels no longer slice off at phone widths.
- **The particle field no longer thrashes.** It rebuilt every particle on
  every resize event, and mobile browsers fire resize continuously as the
  URL bar hides while scrolling. Width-only changes now matter, they are
  debounced, and the canvas is DPR-aware.
- **Modals become bottom sheets** on phones: full-width, thumb-reachable,
  `dvh`-capped (with a `vh` fallback) so content is not hidden behind
  browser chrome, with a 44px close button and safe-area padding.
- **Touch targets.** On coarse pointers every tab, button, pill, select
  and row control gets a 44px minimum, rather than asking a thumb to hit
  a 31px target.
- **Type is readable.** 23 declarations below 11.5px were raised onto the
  fluid scale — the clamps lift small screens the most and move desktop by
  at most ~1.5px. The base size moved from `<html>` to `<body>`: setting
  it on the root redefines `rem`, which made every `clamp()` scale twice
  over and overrode the visitor's own browser font size.
- **Text no longer clipped.** 33 sub-12px labels raised onto the scale.
- **Tests.** 15 new contract tests lock in the invariants above (grid
  tracks, cascade order, viewport units, type floor, touch targets,
  breakpoints), each verified by mutation testing.

### Scan pipeline, progress and reporting accuracy
- **Explicit pipeline stages.** A scan is now modelled as Recon → Discover →
  Download → Normalize → Analyze → Correlate → Verify → Report
  (`core/pipeline.py`). Each stage carries a cost weight, so the progress bar
  reflects where the time actually goes instead of crawling to 3% and then
  jumping. The console renders the stages with pending/active/done state; the
  fine-grained `phase` values existing consumers rely on are unchanged.
- **Honest ETA.** The old estimate was `elapsed x (100 - percent) / percent`
  over a percentage computed as "files done / file cap", which reported absurd
  numbers for small sites and swung wildly between polls. The ETA now measures
  the progress rate over a sliding window, smooths it with an EMA, damps
  upward jumps so a stall cannot explode the estimate, and reports a
  confidence value — the UI shows "estimating…" until it is meaningful.
- **Provenance in every export.** Findings now carry the URL the script came
  from. Previously a URL scan reported the temporary workspace path, which is
  deleted when the scan ends, so no finding could be traced back to an asset.
  CSV gained an `origin` column and SARIF points `artifactLocation` at it.
- **SARIF accuracy.** `rank` now carries confidence (25/50/75/100), `kind`
  carries the result state, `security-severity` is emitted for GitHub, and
  observations / false positives export as `note` + `informational` instead of
  `error` — they used to fail CI gates on findings the engine itself calls
  unproven.
- **CSV accuracy.** List-valued evidence (keys, IVs, secret candidates) is
  joined instead of written as a Python repr such as `['a', 'b']`.
- **Coverage & reliability block.** TXT and HTML reports now state what was
  and was not analyzed: coverage, skipped assets and why, file-cap and depth
  limits, whether the AST parser or the line fallback ran, the runtime
  verification status, and the confidence mix. Reports that hide their own
  blind spots invite over-trust.

### Audit follow-ups — web UI
- Sticky header links are page sections with scroll-spy; below 1040px the nav
  collapses into a real menu (it used to disappear entirely) and shows a
  "you are here" label.
- Findings gained severity chips with counts, a search box and a
  "showing 80 of N" notice when a long list is truncated.
- The engine is polled while unreachable, so starting it after the page is open
  no longer needs a manual refresh. A scan result survives a reload of the tab.
- Accessibility: real tab semantics on the analysis views with arrow-key
  navigation, a skip link, visible focus rings and `prefers-reduced-motion`
  support.
- Copy is ScriptSentry's own voice, headings and tags are Title Case, and the
  pre-release badge is gone from the hosted pages (it stays in the local engine
  banner, the HTML/TXT report footer and `/api/health`).

### Changelog page, docs metadata and navigation cleanup
- **The changelog is a real page now.** `Changelog` used to link into the
  repository, which on a static site means a visitor lands on a file listing
  instead of a page. `webui/changelog/index.html` is now generated from this
  file by `tools/build_changelog.py`, so the hosted page cannot drift from the
  changelog a person edits. The page reuses the overview page's head, header and
  footer, so navigation and metadata changes land on it automatically.
- **Two guards keep that honest.** `tests/test_docs.py` fails when the
  committed page is out of date (verified by mutation testing), and the Pages
  workflow regenerates it on every deploy as a safety net. The generated file
  carries a "do not edit by hand" banner.
- **The changelog page is styled as a document, not a dashboard**: one reading
  column at the 72ch prose measure, a rule between releases instead of a card
  per entry, and no new colours or type sizes. Responsiveness comes from the
  measure itself — a phone, a tablet and a 2560px display all get the same
  readable line — with a single width rule for the two back-links.
- **The footer is a wayfinding list again, not a sitemap.** It had grown to
  nine links, three of which repeated sections the header nav already reaches.
  The Product column now carries only the two destinations the header does not
  route to (the analyzer and the changelog) alongside Connect.
- **`README.md` is visitor-facing.** It now leads with what ScriptSentry is and
  how to use it, rather than reading as developer notes; internal detail moved
  to the docs it belongs in.

## [2.1.0] — earlier release
- Modular `webui` / `server.py` / `core` / `analyzers` architecture.
- Script inventory & behavior intelligence, first/third-party attribution,
  risk scoring, and static/runtime data-exfiltration correlation.
- Local authenticated dashboard with pairing token, bounded jobs, Playwright
  runtime evidence, source-map awareness, and TXT/HTML/CSV/SARIF exports.
