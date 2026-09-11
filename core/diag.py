"""Env-gated diagnostics for best-effort code paths.

Most ``except Exception`` blocks in the engine are *deliberately* silent:
bookkeeping (history, ETA calibration, heartbeats) must never fail a scan,
and fallback layers (regex when the AST layer is unavailable) are by design.
The cost is that a real problem in one of those paths is invisible in the
field -- "why was this file skipped?" had no answer unless you attached a
debugger.

Set ``SCRIPTSENTRY_DEBUG=1`` and every suppressed failure also prints one
line to stderr, scoped, with the exception. Off by default: engine output
stays exactly as quiet as before.

    SCRIPTSENTRY_DEBUG=1 python3 server.py
"""
import contextlib
import os
import sys

__all__ = ["note", "debug_enabled"]

_TRUTHY = {"1", "true", "yes", "on"}


def debug_enabled() -> bool:
    """True when SCRIPTSENTRY_DEBUG requests diagnostic output."""
    return os.environ.get("SCRIPTSENTRY_DEBUG", "").strip().lower() in _TRUTHY


def note(scope: str, message: str) -> None:
    """Print a scoped diagnostic line when SCRIPTSENTRY_DEBUG is set.

    Always returns; a diagnostics call must never become a new failure mode.
    """
    if not debug_enabled():
        return
    # Diagnostics are best-effort by contract: a broken stderr must never
    # become a new failure mode in the code path being diagnosed.
    with contextlib.suppress(Exception):
        print(f"[scriptsentry:{scope}] {message}", file=sys.stderr, flush=True)
