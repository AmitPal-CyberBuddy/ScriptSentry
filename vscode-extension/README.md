# ScriptSentry for VS Code

Client-side JavaScript security findings from the [ScriptSentry](https://github.com/AmitPal-CyberBuddy/ScriptSentry)
engine, right in the Problems panel. The extension never bundles the engine
and never uploads anything: it runs the engine locally, reads the SARIF it
writes, and maps results to diagnostics.

## What you get

- **Problems-panel diagnostics** for DOM injection, hardcoded secrets,
  open redirects, unsafe dynamic code, and the rest of the engine's rule
  set — each with the rule id, evidence, and a "Learn more" link into the
  hosted rule reference.
- **CWE on every mapped finding** (dom_injection arrives as
  `dom_injection: ... [CWE-79]`).
- **Respect for your triage.** Findings you marked as false positives in
  the dashboard arrive as SARIF suppressions and are hidden here too
  (opt back in with `scriptsentry.showSuppressed`).
- **Local-only.** No telemetry, no network calls of its own; the engine
  itself is a local Python process.

## Requirements

- Python 3.10+ with the ScriptSentry engine available one of these ways:
  1. **Any engine checkout** — set `scriptsentry.engineCommand` to
     e.g. `python3 /path/to/ScriptSentry/main.py`.
  2. **The one-file launcher** — running
     `python3 scriptsentry.py` once bootstraps the engine to
     `~/.scriptsentry/bootstrap/`; the extension finds it automatically.
  3. **A ScriptSentry checkout open in the workspace** — the extension
     detects `main.py` + `core/reporter.py` and uses it (the self-scan
     setup).

## Commands

| Command | What it does |
| --- | --- |
| `ScriptSentry: Scan Workspace` | Scans every JS/TS file in the first workspace folder |
| `ScriptSentry: Scan Current File` | Scans the file in the active editor |
| `ScriptSentry: Clear Findings` | Clears the diagnostics |
| `ScriptSentry: Show Engine Output` | Opens the engine log (last scan, errors) |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `scriptsentry.engineCommand` | `""` | Command that runs the engine CLI. String split on whitespace, or an array for paths with spaces: `["python3", "/opt/My Scripts/main.py"]`. Empty = auto-detect. |
| `scriptsentry.scanOnSave` | `false` | Re-scan the saved file automatically (JavaScript/TypeScript). |
| `scriptsentry.profile` | `"balanced"` | Engine profile: `balanced` \| `fast` \| `strict`. |
| `scriptsentry.showSuppressed` | `false` | Show findings triaged as false positives (as hints, prefixed `[false positive]`). |
| `scriptsentry.engineTimeoutSeconds` | `180` | Kill the engine after this many seconds. |

## How findings are placed

The engine reports file names relative to the scan root (often just
basenames). The extension resolves them against the workspace: exact
relative path first, then a unique basename match, then a suffix match.
When two files are equally plausible the finding is **not** placed
silently on the wrong one — it's logged to the engine output instead.

## Packaging (maintainers)

```bash
npm install -g @vscode/vsce
cd vscode-extension
vsce package          # produces scriptsentry-0.1.0.vsix
```

Tests (no npm dependencies; Node 18+ built-in runner):

```bash
node --test
```

## License

MIT, same as the engine.
