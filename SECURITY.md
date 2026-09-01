# Security Policy

## Reporting a vulnerability in ScriptSentry

**Please do not open a public issue for a security vulnerability.** A public
issue discloses the problem to everyone before there is a fix.

Use GitHub's **[private vulnerability reporting][report]** instead. It creates
a private advisory that only the maintainer can see, and it works without
exchanging email addresses.

[report]: https://github.com/AmitPal-CyberBuddy/ScriptSentry/security/advisories/new

What helps most in a report:

- what an attacker can achieve, and what access they need to start,
- the smallest input or steps that reproduce it,
- the version or commit you tested (`release.json` carries the engine version),
- anything you already know about a fix.

You will get an acknowledgement as soon as the report is read. ScriptSentry is
maintained by one person in their own time, so please allow a reasonable window
for a fix before disclosing publicly.

## What counts as a vulnerability here

ScriptSentry runs locally and is deliberately narrow in what it trusts, so the
issues worth reporting privately are the ones that break those boundaries:

- **Escaping the local-only boundary** — anything that causes analyzed code,
  file contents or scan results to leave the machine.
- **Bypassing the engine pairing token or the origin allowlist**, or otherwise
  letting an untrusted web page drive the local engine.
- **Code execution from analyzed input.** ScriptSentry parses hostile
  JavaScript by design; it must never *run* it. Anything that turns analysis
  into execution is the highest-severity class of bug here.
- **Path traversal or arbitrary file reads** through the upload or URL-scan
  paths.
- **Cross-site scripting in the dashboard**, e.g. a crafted script whose
  filename or finding text executes when the report renders it.

## What is not a vulnerability

These are ordinary bugs — please open a **[regular issue][issues]** for them:

- **A missed finding (false negative) or a wrong finding (false positive).**
  These matter a lot and are very welcome, but they are accuracy bugs, not
  security holes. There is an issue template for them.
- **Findings ScriptSentry reports about *your* code.** The tool telling you
  about a secret or a DOM-XSS flow in a bundle you scanned is it working. Fix
  it in that project.
- **The engine binding to a non-loopback address** when you explicitly pass
  `--host 0.0.0.0`. That is documented, and the server prints a warning; it is
  your firewall's job from there.
- Missing hardening on a page served only over loopback, with no attacker path.

[issues]: https://github.com/AmitPal-CyberBuddy/ScriptSentry/issues/new/choose

## Supported versions

This is a young, single-maintainer project: fixes land on `main` and go out in
the next release. Please test against `main` before reporting.

## Scope reminder

ScriptSentry is a tool for **authorized testing only**. Reports built from
scanning systems you do not own or have written permission to test will not be
accepted.
