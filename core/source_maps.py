"""Small, bounded source-map helpers for script provenance."""
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
    ref = matches[-1].strip().strip('"\'')
    if ref.startswith("data:application/json;base64,"):
        return "inline:data"
    return urljoin(base_url, ref) if base_url else ref


def inspect_source_map(content, base_url="", timeout=10, max_bytes=2_000_000):
    """Return safe source-map metadata without exposing source contents."""
    ref = source_map_reference(content, base_url)
    if not ref:
        return {"present": False, "url": "", "sources": [], "sources_content_count": 0}
    raw = None
    if ref.startswith("inline:data"):
        match = re.search(r"base64,([^\s]+)", content or "")
        if match:
            try:
                raw = base64.b64decode(match.group(1), validate=True).decode("utf-8", errors="replace")
            except Exception:
                raw = None
    elif ref.startswith(("http://", "https://")):
        try:
            response = safe_get(ref, timeout=timeout)
            raw = read_response_text(response, max_bytes=max_bytes)
        except Exception:
            raw = None
    result = {"present": True, "url": ref, "sources": [], "sources_content_count": 0, "available": False}
    if not raw:
        return result
    try:
        document = json.loads(raw)
    except (TypeError, ValueError):
        return result
    sources = [str(value) for value in document.get("sources", []) if value][:120]
    contents = document.get("sourcesContent") or []
    result.update({
        "available": True,
        "version": document.get("version"),
        "sources": sources,
        "sources_content_count": sum(1 for value in contents if value is not None),
        "sources_content_bytes": sum(len(str(value).encode("utf-8", errors="ignore")) for value in contents if value is not None),
    })
    return result
