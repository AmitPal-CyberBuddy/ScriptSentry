"""Small, bounded source-map helpers for script provenance.

Minified production bundles ship a ``//# sourceMappingURL=...`` reference
pointing at a map that (usually) embeds the *original* pre-build sources in
``sourcesContent``. Analyzing those originals instead of the mangled bundle
is the single biggest accuracy lever for production targets: findings carry
real file names (``src/auth/config.ts``), taint flows read like the code the
authors wrote, and secrets survive minification faithfully.

Everything here is bounded: the map itself is size-capped, only a limited
number of sources are returned, and network fetches go through the same
SSRF-safe ``safe_get`` used for page/script downloads.
"""
import base64
import json
import re
from urllib.parse import urljoin

from core.url_policy import read_response_text, safe_get


def source_map_reference(content, base_url=""):
    """Return a source-map URL (or inline marker) from a JS document."""
    matches = re.findall(r"(?:#|@)\s*sourceMappingURL\s*=\s*([^\s]+)", content or "")
    if not matches:
        return ""
    ref = matches[-1].strip().strip("\"'")
    if ref.startswith("data:application/json;base64,"):
        return "inline:data"
    return urljoin(base_url, ref) if base_url else ref


def _decode_inline_map(content, max_bytes):
    """Decode an inline ``data:application/json;base64,...`` source map."""
    match = re.search(r"base64,([^\s]+)", content or "")
    if not match:
        return None
    try:
        raw = base64.b64decode(match.group(1), validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None
    return raw if len(raw) <= max_bytes else None


def _fetch_remote_map(ref, timeout, max_bytes, cancel_check=None):
    """Fetch a remote ``.map`` through the SSRF-safe, cancel-aware getter."""
    try:
        response = safe_get(ref, timeout=timeout, cancel_check=cancel_check)
        return read_response_text(response, max_bytes=max_bytes)
    except Exception:
        return None


def clean_source_name(name, source_root=""):
    """A readable display name for a map entry.

    Bundler maps use pseudo-URLs (``webpack://app/./src/App.tsx``), loader
    prefixes (``...!babel-loader!src/App.tsx``) and sometimes a ``sourceRoot``.
    Reports should show something that looks like the file the authors wrote.
    """
    text = str(name or "").strip()
    if not text:
        return ""
    # Loader chains: keep the segment after the last "!".
    if "!" in text:
        text = text.split("!")[-1]
    # Bundler pseudo-schemes: webpack://<project>/./src/x.ts -> ./src/x.ts.
    # Only a scheme marks the following segment as a project name -- a plain
    # "src/App.tsx" is already the real path and must survive untouched.
    for prefix in ("webpack://", "webpack:", "ng://", "vite://", "rollup://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            if "/" in text:
                rest = text.split("/", 1)[1]
                if rest:
                    text = rest
            break
    if text and not text.startswith((".", "/", "http://", "https://")):
        text = "./" + text
    root = str(source_root or "").strip()
    if root and not text.startswith(("webpack://", "http://", "https://")):
        text = root.rstrip("/") + "/" + text.lstrip("./")
    return text or str(name or "")


def load_source_map(content, base_url="", timeout=10, max_bytes=8_000_000, cancel_check=None):
    """Load and parse a document's source map.

    Returns ``(metadata, contents)`` where ``metadata`` is the provenance
    block the reports already render and ``contents`` is a bounded list of
    ``(display_name, source_text)`` pairs for every entry that embeds its
    original code. ``contents`` is empty when the map lacks ``sourcesContent``
    (servers strip it surprisingly often) or the map is unreachable/corrupt;
    ``metadata`` explains which in its ``note`` field.
    """
    ref = source_map_reference(content, base_url)
    metadata = {
        "present": bool(ref),
        "url": ref,
        "sources": [],
        "sources_content_count": 0,
        "available": False,
    }
    if not ref:
        return metadata, []

    raw = None
    if ref.startswith("inline:data"):
        raw = _decode_inline_map(content, max_bytes)
        if raw is None:
            metadata["note"] = "Inline source map could not be decoded or exceeds the size cap."
    elif ref.startswith(("http://", "https://")):
        raw = _fetch_remote_map(ref, timeout, max_bytes, cancel_check=cancel_check)
        if raw is None:
            metadata["note"] = "Source map could not be downloaded (missing, blocked, or over the size cap)."
    else:
        metadata["note"] = "Source map reference is relative and could not be resolved."

    if not raw:
        return metadata, []
    try:
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("map root is not an object")
    except (TypeError, ValueError):
        metadata["note"] = "Source map is not valid JSON."
        return metadata, []

    sources = [str(value) for value in (document.get("sources") or []) if value][:120]
    raw_contents = document.get("sourcesContent") or []
    metadata.update({
        "available": True,
        "version": document.get("version"),
        "sources": sources,
        "sources_content_count": sum(1 for value in raw_contents if value),
        "sources_content_bytes": sum(
            len(str(value).encode("utf-8", errors="ignore")) for value in raw_contents if value),
    })

    source_root = str(document.get("sourceRoot") or "")
    contents = []
    for index, source in enumerate(sources):
        if index >= len(raw_contents):
            break
        body = raw_contents[index]
        if not body:
            continue
        display = clean_source_name(source, source_root) or f"source-{index + 1}"
        contents.append((display, str(body)))
    return metadata, contents


def inspect_source_map(content, base_url="", timeout=10, max_bytes=2_000_000):
    """Return safe source-map metadata without exposing source contents."""
    metadata, _ = load_source_map(content, base_url=base_url, timeout=timeout, max_bytes=max_bytes)
    return metadata
