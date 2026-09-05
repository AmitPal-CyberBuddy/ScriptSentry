"""Process-scoped server settings: web root, request limits, pairing token.

Everything here is fixed when the process starts and never mutates: the
dashboard is local-only software, so there is deliberately no runtime
configuration surface beyond environment variables.
"""
import os
import secrets

MAX_BODY = 16 * 1024 * 1024  # 16 MB (local, authenticated; uploads included)
MAX_URL_LENGTH = 2048
MAX_UPLOAD_FILES = 20
MAX_FILE_BYTES = 3 * 1024 * 1024  # per uploaded document
ALLOWED_UPLOAD_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".map", ".json", ".txt")


def _resolve_web_root():
    """Locate the shipped dashboard, wherever the engine runs from.

    A repository checkout keeps ``webui/`` next to the engine. A pip/pipx
    install finds the data-files copy under ``sys.prefix/share`` (or the
    provided override) so the console scripts serve the same dashboard.
    """
    override = os.environ.get("SCRIPTSENTRY_WEBUI_DIR")
    if override and os.path.isdir(override):
        return override
    import sys

    engine_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    local = os.path.join(engine_dir, "webui")
    if os.path.isdir(local):
        return local
    for base in {sys.prefix, getattr(sys, "base_prefix", sys.prefix)}:
        candidate = os.path.join(base, "share", "scriptsentry", "webui")
        if os.path.isdir(candidate):
            return candidate
    return local


WEB_ROOT = _resolve_web_root()

# A pairing token is deliberately process-scoped.  It is printed once at
# startup and never returned by health or included in a report response.
API_TOKEN = os.environ.get("SCRIPTSENTRY_API_TOKEN", "").strip() or secrets.token_urlsafe(32)
