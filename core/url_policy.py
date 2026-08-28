"""URL and response-safety helpers for ScriptSentry's local crawler.

The engine deliberately fetches attacker-controlled web applications.  That is
useful for a script inventory, but it also makes the local process an attractive
SSRF primitive if it blindly follows redirects or downloads arbitrary embedded
URLs.  This module keeps the crawler's network boundary in one place.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:  # pragma: no cover - paste-only installations
    requests = None


MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 5
_UNSAFE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
}


def _unsafe_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolved_addresses(hostname: str) -> Iterable[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return ()
    return {info[4][0] for info in infos if info and info[4]}


def validate_public_url(url: str, *, resolve: bool = True, allowed_schemes=("http", "https")) -> tuple[bool, str]:
    """Validate a crawler URL and reject local/reserved network destinations.

    Host names are resolved before a request when possible.  A DNS lookup
    failure is not treated as a private address (the HTTP client will report a
    useful connection error); IP literals and known local names are always
    rejected.  Redirects are checked again by :func:`safe_get`.
    """
    try:
        parsed = urlparse(str(url or ""))
    except Exception:
        return False, "Malformed URL"
    if parsed.scheme.lower() not in allowed_schemes:
        return False, "Only http(s) URLs are supported"
    if not parsed.hostname:
        return False, "URL must include a hostname"
    if parsed.username or parsed.password:
        return False, "URLs containing credentials are not allowed"
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in _UNSAFE_HOSTNAMES or _unsafe_ip(hostname):
        return False, "Local and reserved network destinations are not allowed"
    if resolve:
        addresses = _resolved_addresses(hostname)
        if any(_unsafe_ip(address) for address in addresses):
            return False, "The target resolves to a local or reserved network"
    return True, ""


def safe_get(url: str, *, timeout=15, headers=None, max_redirects=MAX_REDIRECTS, **kwargs):
    """GET a public URL without following an unsafe redirect.

    The returned object is a normal ``requests.Response``.  Callers decide how
    much of the body to read; this function only enforces the URL boundary.
    """
    if requests is None:
        return None
    current = str(url)
    session = requests.Session()
    try:
        for _ in range(max(0, int(max_redirects)) + 1):
            valid, reason = validate_public_url(current, resolve=True)
            if not valid:
                raise ValueError(reason)
            response = session.get(
                current,
                timeout=timeout,
                headers=headers,
                allow_redirects=False,
                **kwargs,
            )
            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return response
                current = urljoin(current, location)
                continue
            return response
    finally:
        session.close()
    raise ValueError("Too many redirects")


def read_response_text(response, *, max_bytes=MAX_PAGE_BYTES) -> Optional[str]:
    """Read at most ``max_bytes`` from a response and decode it safely."""
    if response is None:
        return None
    try:
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        raw = b"".join(chunks)
        encoding = getattr(response, "encoding", None) or "utf-8"
        return raw.decode(encoding, errors="replace")
    except Exception:
        # Small mocked responses and a few custom transports only expose text.
        try:
            text = str(response.text)
            return text if len(text.encode("utf-8", errors="ignore")) <= max_bytes else None
        except Exception:
            return None
    finally:
        try:
            response.close()
        except Exception:
            pass
