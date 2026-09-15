#!/usr/bin/env python3
"""ScriptSentry one-file launcher & bootstrapper.

You don't need to clone the whole repository to use ScriptSentry. Download just
this file and run it:

    python3 scriptsentry.py
    python3 scriptsentry.py --port 8000          # options are passed to the server
    python3 scriptsentry.py --update             # discard the cached engine, fetch the latest
    python3 scriptsentry.py --help

How it works
------------
1. If the full engine already sits next to this file (you cloned the repo or ran
   it inside the project), it starts the dashboard immediately.
2. Otherwise it downloads the pinned ScriptSentry engine from the official
   GitHub repository over HTTPS, unpacks it into a local cache
   (``~/.scriptsentry/bootstrap/``), installs the small set of Python
   dependencies into your environment, and then starts the local server.

The cached engine is reused on every later run — the launcher never
re-downloads it on its own. After fixes land in the repository, refresh with
``python3 scriptsentry.py --update`` (or delete
``~/.scriptsentry/bootstrap/`` and run again).

Nothing is uploaded anywhere; the download only ever fetches the engine from
the official repository, and all analysis stays on your machine.

Environment overrides (optional)
--------------------------------
SCRIPTSENTRY_REF      git ref to fetch (default: main; set to a tag for release)
SCRIPTSENTRY_REPO     "owner/name" of the GitHub repo to bootstrap from
SCRIPTSENTRY_NO_INSTALL  set to "1" to skip the pip dependency install step
SCRIPTSENTRY_BREAK_SYSTEM_PACKAGES  set to "1" to pass --break-system-packages to pip
                        (PEP 668 externally-managed Pythons retry with this automatically)

Authorized use
--------------
Only scan applications you own or are explicitly authorized to test.
"""

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = os.environ.get("SCRIPTSENTRY_REPO", "AmitPal-CyberBuddy/ScriptSentry")
REF = os.environ.get("SCRIPTSENTRY_REF", "main")
CACHE_DIR = Path(os.environ.get("SCRIPTSENTRY_HOME", str(Path.home() / ".scriptsentry")))
BOOTSTRAP_DIR = CACHE_DIR / "bootstrap"

# The launcher's minimal footprint. tree-sitter is included because it is the
# engine's *preferred* AST parser (pip wheel, no compiler needed); esprima
# stays as the portable second engine. Playwright is deliberately NOT here:
# the module alone is useless without its ~350MB Chromium download, and the
# engine honestly reports runtime evidence as unavailable instead.
REQUIRED_PACKAGES = [
    "requests",
    "beautifulsoup4",
    "jsbeautifier",
    "tree-sitter",
    "tree-sitter-javascript",
    "tree-sitter-typescript",
    "esprima",
    "tqdm",
    "colorama",
]

# Distribution name -> importable module name.
IMPORT_NAMES = {
    "beautifulsoup4": "bs4",
    "tree-sitter-javascript": "tree_sitter_javascript",
    "tree-sitter-typescript": "tree_sitter_typescript",
}


def _safe_archive_path(path: str) -> bool:
    """True when a stripped archive path cannot escape the extraction dir."""
    if not path or path.startswith(("/", "\\")) or "\x00" in path:
        return False
    parts = path.replace("\\", "/").split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _safe_link_target(linkname: str) -> bool:
    """True when a symlink/hardlink target stays inside the archive tree."""
    if not linkname or linkname.startswith(("/", "\\")) or "\x00" in linkname:
        return False
    parts = linkname.replace("\\", "/").split("/")
    return all(part not in ("", ".", "..") for part in parts)


def engine_present(here: Path) -> bool:
    """True when the full project (core/ + webui/ + server.py) is available."""
    return (here / "core" / "analyzer_service.py").is_file() and (here / "server.py").is_file()


# Informational marker written into the cached engine so "which build am I
# running?" always has an answer (the GitHub tarball itself carries no VCS data).
META_NAME = ".launcher-meta.json"


def _write_download_meta(engine_dir: Path) -> None:
    """Record when and from where the engine was fetched. Best-effort."""
    payload = {
        "repo": REPO,
        "ref": REF,
        "url": _archive_url(),
        "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # Purely informational; never block the bootstrap on a meta-file failure.
    with contextlib.suppress(OSError):
        (engine_dir / META_NAME).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _downloaded_at(engine_dir: Path) -> str:
    """The cached engine's download timestamp ('unknown' when not recorded)."""
    try:
        meta = json.loads((engine_dir / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unknown"
    return str(meta.get("downloaded_at", "unknown"))


def _info(msg: str) -> None:
    print(f"  {msg}", flush=True)


def _archive_url() -> str:
    """GitHub tarball URL for the configured repo/ref."""
    if REF in ("main", "master"):
        return f"https://github.com/{REPO}/archive/refs/heads/{REF}.tar.gz"
    # Tags/commits use the 'tags' (or raw ref) archive endpoint.
    return f"https://github.com/{REPO}/archive/{REF}.tar.gz"


def download_archive() -> bytes:
    url = _archive_url()
    print(f"⬇  Downloading ScriptSentry engine from:\n   {url}", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "ScriptSentry-Launcher"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (official https URL)
        if resp.status != 200:
            raise RuntimeError(f"download failed with HTTP {resp.status}")
        data = resp.read()
    if not data:
        raise RuntimeError("downloaded an empty archive")
    return data


def extract_engine(data: bytes) -> Path:
    """Unpack the GitHub archive into the cache and return the project root."""
    BOOTSTRAP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scriptsentry-dl-") as tmp:
        tmp_path = Path(tmp)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            members = []
            for m in tar.getmembers():
                # Strip the top-level "ScriptSentry-<ref>/" prefix for a clean cache.
                parts = m.name.split("/", 1)
                if len(parts) != 2 or not parts[1]:
                    continue
                stripped = parts[1]
                # This is our own GitHub archive, but the launcher must stay
                # safe even if the tag/ref is swapped in env or a compromised
                # mirror is pointed at: never let a member path (or link
                # target) escape the extraction directory.
                if not _safe_archive_path(stripped) or (m.issym() or m.islnk()) and not _safe_link_target(m.linkname):
                    raise RuntimeError(f"archive member has an unsafe path: {m.name!r}")
                m.name = stripped
                members.append(m)
            # Python 3.12+ applies a safe extraction filter as a second layer
            # (also blocks symlink escapes); 3.10/3.11 rely on the checks above.
            extract_kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
            tar.extractall(tmp_path, members=members, **extract_kwargs)  # noqa: S202 (validated above)

        if not engine_present(tmp_path):
            raise RuntimeError("downloaded archive did not contain the expected engine files")

        target = BOOTSTRAP_DIR / REF
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        shutil.move(str(tmp_path), str(target))
    _write_download_meta(target)
    return target


def _pip_install(packages) -> bool:
    """Run pip once; retry with --break-system-packages on PEP 668.

    Returns True when pip reported success.  On failure pip's own stderr is
    surfaced so the reason is never mysterious.
    """
    base = [sys.executable, "-m", "pip", "install", "--quiet"]
    if os.environ.get("SCRIPTSENTRY_BREAK_SYSTEM_PACKAGES", "").strip().lower() in ("1", "true", "yes", "on"):
        base.append("--break-system-packages")

    def _run(command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return result.returncode == 0

    if _run(base + list(packages)):
        return True
    if "--break-system-packages" not in base:
        # PEP 668 (Debian 12+ / Ubuntu 23.04+): the distro python refuses
        # site-packages writes. The tool is a local, user-launched utility, so
        # retry with the documented escape hatch and say exactly that; a venv
        # remains the cleaner alternative.
        print(
            "⚠  This Python is 'externally managed' (PEP 668); retrying the install "
            "with --break-system-packages.\n"
            "    Prefer isolation? Create a venv and run the launcher with it:\n"
            f"      {sys.executable} -m venv ~/.scriptsentry/venv && ~/.scriptsentry/venv/bin/python scriptsentry.py\n"
            "    (or set SCRIPTSENTRY_BREAK_SYSTEM_PACKAGES=1 to skip the message)",
            flush=True,
        )
        return _run(base + ["--break-system-packages"] + list(packages))
    return False


def install_dependencies(engine_dir: Path) -> None:
    if os.environ.get("SCRIPTSENTRY_NO_INSTALL") == "1":
        _info("Skipping dependency install (SCRIPTSENTRY_NO_INSTALL set).")
        return
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(IMPORT_NAMES.get(pkg, pkg))
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    print(f"📦 Installing Python dependencies: {', '.join(missing)}", flush=True)
    req = engine_dir / "requirements.txt"
    installed_all = False
    if req.is_file():
        # `pip install -r path` (the bare path is not a valid requirement
        # string). Fast path: one pip run for the whole file.
        installed_all = _pip_install(["-r", str(req)])
    if not installed_all:
        # Fall back to installing each missing package on its own so a single
        # package with a broken/root-only build cannot block the rest (e.g.
        # esprima's sdist writes headers to /usr/include, which fails for
        # non-root users). Everything that installs still gets used; the
        # engine degrades gracefully for the ones that do not.
        failed = []
        for pkg in list(missing):
            print(f"  installing {pkg}…", flush=True)
            if _pip_install([pkg]):
                missing.remove(pkg)
            else:
                failed.append(pkg)
        if failed:
            print(f"⚠  Could not install: {', '.join(failed)}", flush=True)
            print(
                f"   You can install them manually with:\n"
                f"     {sys.executable} -m pip install -r {req}\n",
                flush=True,
            )
            # Be specific about what each missing package actually costs.
            # A generic "some packages failed" line led people to run scans
            # that silently used the weaker analyzer and then wonder why
            # findings looked thin.
            ast_pkgs = {"tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript", "esprima"}
            if ast_pkgs & set(failed):
                print(
                    "   ⚠  Some AST parsers could not be installed. Without both tree-sitter and "
                    "esprima every scan falls back to line-based matching: source-to-sink flows "
                    "are reported at 'medium' confidence instead of 'high', and some are missed "
                    "entirely. Installing tree-sitter is the single biggest accuracy win:\n"
                    f"     {sys.executable} -m pip install tree-sitter tree-sitter-javascript tree-sitter-typescript",
                    flush=True,
                )
            if {"requests", "beautifulsoup4"} & set(failed):
                print(
                    "   Note: without 'requests' and 'beautifulsoup4', URL scanning is unavailable; "
                    "pasted/uploaded code analysis still works.",
                    flush=True,
                )


def run_server(engine_dir: Path, server_args) -> None:
    # Make the engine importable and serve its bundled webui/.
    os.chdir(str(engine_dir))
    sys.path.insert(0, str(engine_dir))
    sys.argv = ["server.py"] + list(server_args or [])
    import runpy
    runpy.run_path(str(engine_dir / "server.py"), run_name="__main__")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ScriptSentry launcher (downloads the engine on first run, then starts it).",
        add_help=False,
    )
    parser.add_argument("--help", "-h", action="store_true", help="Show this help and exit")
    parser.add_argument(
        "--update",
        action="store_true",
        help="Discard the cached engine and download the latest from GitHub before starting",
    )
    args, server_args = parser.parse_known_args()
    if args.help:
        parser.print_help()
        print("\nAll other options are forwarded to the dashboard server (e.g. --port, --host).")
        return 0

    here = Path(__file__).resolve().parent
    print("🛡️  ScriptSentry — local JavaScript security analyzer", flush=True)

    if engine_present(here):
        _info("Engine found next to the launcher — starting directly.")
        if args.update:
            _info("--update refreshes the downloaded cache, but this launcher sits inside a")
            _info("project checkout — get the latest fixes with:  git pull")
        engine_dir = here
    else:
        cached = BOOTSTRAP_DIR / REF
        if args.update and cached.exists():
            print(f"♻️  --update: discarding the cached engine ({cached})…", flush=True)
            try:
                # Loud failure beats silently rescanning stale code, so no
                # ignore_errors here (a Windows lock or permission problem must
                # surface, not quietly keep the old engine).
                shutil.rmtree(cached)
            except OSError as exc:
                print(f"❌ Could not remove the cached engine: {exc}", flush=True)
                print("   Stop the running dashboard first (Ctrl+C in its terminal), then retry.", flush=True)
                return 1
        if engine_present(cached):
            _info(f"Using cached engine ({cached}).")
            _info(f"Downloaded at: {_downloaded_at(cached)} UTC — run with --update to fetch the latest code.")
            engine_dir = cached
        else:
            print("🚀 First run: the engine isn't present locally.", flush=True)
            print(f"   It will be downloaded from the official GitHub repo '{REPO}' (ref '{REF}').", flush=True)
            try:
                data = download_archive()
                engine_dir = extract_engine(data)
            except Exception as exc:  # noqa: BLE001
                print(f"\n❌ Could not bootstrap the engine: {exc}", flush=True)
                print("   You can instead clone the full project and run `python3 server.py`:\n"
                      f"     git clone https://github.com/{REPO}.git\n", flush=True)
                return 1
            _info(f"Engine ready at {engine_dir}.")

    install_dependencies(engine_dir)
    print("\nStarting the local dashboard…\n", flush=True)
    try:
        run_server(engine_dir, server_args)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
