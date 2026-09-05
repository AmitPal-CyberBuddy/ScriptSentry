#!/usr/bin/env python3
"""Regenerate webui/app.js from the webui/src/app/ fragments.

The shipped dashboard must stay a single file (the pages load
``../app.js`` directly and tests read it), but a 3,000-line IIFE is not a
place anyone wants to edit.  So the source of truth is the numbered
fragments in ``webui/src/app/`` and this script concatenates them -- in
filename order, byte-for-byte -- into ``webui/app.js``.  No Node toolchain
is required to build or develop.

Usage:
    python3 tools/build_webui.py            # rebuild webui/app.js
    python3 tools/build_webui.py --check    # exit 1 if app.js is stale

Run --check after editing a fragment; if it fails, rerun without --check
and commit the regenerated app.js together with the fragment edit.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "webui", "src", "app")
OUT_PATH = os.path.join(ROOT, "webui", "app.js")


def build():
    fragments = sorted(
        f for f in os.listdir(SRC_DIR) if f.endswith(".js")
    )
    if not fragments:
        raise SystemExit(f"no fragments found in {SRC_DIR}")
    parts = []
    for name in fragments:
        with open(os.path.join(SRC_DIR, name), encoding="utf-8") as fh:
            parts.append(fh.read())
    return "\n".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify webui/app.js is up to date; exit 1 if not")
    args = parser.parse_args(argv)

    generated = build()
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, encoding="utf-8") as fh:
            current = fh.read()
        if current == generated:
            print("webui/app.js is up to date.")
            return 0
        if args.check:
            sys.stderr.write(
                "webui/app.js is stale: it differs from webui/src/app/.\n"
                "Run: python3 tools/build_webui.py  (then commit both)\n"
            )
            return 1

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write(generated)
    print(f"rebuilt {os.path.relpath(OUT_PATH, ROOT)} "
          f"({generated.count(chr(10)) + 1} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
