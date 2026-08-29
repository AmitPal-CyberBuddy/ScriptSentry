"""Single source of truth for the ScriptSentry engine/release version.

Every place that reports an engine or tool version (the loopback server
``Server`` header, the ``/api/health`` payload, the report model, HTML/SARIF
exports, the dashboard badge) imports from here, so a release only ever needs
the number changed in one place. See ``release.json`` for machine-readable
release metadata and ``CHANGELOG.md`` for the human history.

Release status
--------------
ScriptSentry is currently **under active development** and is not published as
a stable release. Keep ``DEV_BUILD = True`` (and the ``-dev`` pre-release
suffix) until the project is ready to ship. Cutting a release is then a
one-line change: set ``DEV_BUILD = False`` and drop the suffix.
"""

# Bump the number for a release; the ``-dev`` suffix marks a pre-release build.
__version__ = "2.2.0-dev"

# Master switch. False + a version without a suffix = a published release.
DEV_BUILD = True

RELEASE_STATUS = "under development" if DEV_BUILD else "stable"

# Short marketing/tool name reused by reports and the API.
ENGINE_NAME = "ScriptSentry Analyzer"

# SARIF producer version tracks the engine version.
SARIF_TOOL_VERSION = __version__


def engine_version() -> str:
    """Return the current engine version string (with pre-release suffix)."""
    return __version__


def is_dev_build() -> bool:
    """True while the project is unpublished / under active development."""
    return bool(DEV_BUILD)
