#!/usr/bin/env python3
"""ScriptSentry one-file launcher & bootstrapper.

You don't need to clone the whole repository to use ScriptSentry. Download just
this file and run it:

    python3 scriptsentry.py
    python3 scriptsentry.py --port 8000          # options are passed to the server
    python3 scriptsentry.py --help

How it works
------------
1. If the full engine already sits next to this file (you cloned the repo or ran
   it inside the project), it starts the dashboard immediately.
2. Otherwise it downloads the pinned ScriptSentry engine from the official
   GitHub repository over HTTPS, unpacks it into a local cache
   (``~/.scriptsentry/bootstrap/``), installs the small set of Python
   dependencies into your environment, and then starts the local server.

Nothing is uploaded anywhere; the download only ever fetches the engine from
the official repository, and all analysis stays on your machine.

Environment overrides (optional)
--------------------------------
SCRIPTSENTRY_REF      git ref to fetch (default: main; set to a tag for release)
SCRIPTSENTRY_REPO     "owner/name" of the GitHub repo to bootstrap from
SCRIPTSENTRY_NO_INSTALL  set to "1" to skip the pip dependency install step

Authorized use
--------------
Only scan applications you own or are explicitly authorized to test.
"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = os.environ.get("SCRIPTSENTRY_REPO", "AmitPal-CyberBuddy/ScriptSentry")
REF = os.environ.get("SCRIPTSENTRY_REF", "main")
CACHE_DIR = Path(os.environ.get("SCRIPTSENTRY_HOME", str(Path.home() / ".scriptsentry")))
BOOTSTRAP_DIR = CACHE_DIR / "bootstrap"

REQUIRED_PACKAGES = ["requests", "beautifulsoup4", "jsbeautifier", "esprima", "tqdm", "colorama"]


def engine_present(here: Path) -> bool:
    """True when the full project (core/ + webui/ + server.py) is available."""
    return (here / "core" / "analyzer_service.py").is_file() and (here / "server.py").is_file()


def _info(msg: str) -> None:
    print(f"  {msg}", flush=True)


def download_archive() -> bytes:
    url = f"https://github.com/{REPO}/archive/refs/heads/{REF}.tar.gz"
    if REF not in ("main", "master"):
        # Tags/commits use the 'tags' (or raw ref) archive endpoint.
        url = f"https://github.com/{REPO}/archive/{REF}.tar.gz"
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
                m.name = parts[1]
                members.append(m)
            tar.extractall(tmp_path, members=members)  # noqa: S202 (our own GitHub archive)

        if not engine_present(tmp_path):
            raise RuntimeError("downloaded archive did not contain the expected engine files")

        target = BOOTSTRAP_DIR / REF
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        shutil.move(str(tmp_path), str(target))
    return target


def install_dependencies(engine_dir: Path) -> None:
    if os.environ.get("SCRIPTSENTRY_NO_INSTALL") == "1":
        _info("Skipping dependency install (SCRIPTSENTRY_NO_INSTALL set).")
        return
    missing = []
    for pkg in REQUIRED_PACKAGES:
        mod = "bs4" if pkg == "beautifulsoup4" else pkg
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    print(f"📦 Installing Python dependencies: {', '.join(missing)}", flush=True)
    req = engine_dir / "requirements.txt"
    cmd = [sys.executable, "-m", "pip", "install", "--quiet"]
    cmd += [str(req)] if req.is_file() else missing
    try:
        subprocess.check_call(cmd)
    except Exception as exc:  # noqa: BLE001
        print(f"⚠  Automatic dependency install failed ({exc}).", flush=True)
        print("   You can install them manually with:\n"
              f"     {sys.executable} -m pip install -r requirements.txt\n", flush=True)


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
    args, server_args = parser.parse_known_args()
    if args.help:
        parser.print_help()
        print("\nAll other options are forwarded to the dashboard server (e.g. --port, --host).")
        return 0

    here = Path(__file__).resolve().parent
    print("🛡️  ScriptSentry — local JavaScript security analyzer", flush=True)

    if engine_present(here):
        _info("Engine found next to the launcher — starting directly.")
        engine_dir = here
    else:
        cached = BOOTSTRAP_DIR / REF
        if engine_present(cached):
            _info(f"Using cached engine ({cached}).")
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
