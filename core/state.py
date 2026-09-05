"""A tiny shared helper for where ScriptSentry keeps its local state.

The dashboard is local-only, so all persistent state lives in one user-level
directory: ``$SCRIPTSENTRY_STATE_DIR`` if set, else
``$XDG_CACHE_HOME/scriptsentry`` (default ``~/.cache/scriptsentry``).
"""
import os

__all__ = ["state_dir"]


def state_dir():
    override = os.environ.get("SCRIPTSENTRY_STATE_DIR")
    if override:
        return override
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "scriptsentry")
