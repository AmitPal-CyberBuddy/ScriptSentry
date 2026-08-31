"""URL and response-safety helpers for ScriptSentry's local crawler.

The engine deliberately fetches attacker-controlled web applications.  That is
useful for a script inventory, but it also makes the local process an attractive
SSRF primitive if it blindly follows redirects or downloads arbitrary embedded
URLs.  This module keeps the crawler's network boundary in one place.
"""
from __future__ import annotations

import ipaddress
import os
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


def _private_targets_allowed() -> bool:
    """True when the explicit development override is set.

    ``SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1`` exists so authorized testers can
    point the crawler at applications on a local network or a localhost
    service.  The top-level call sites (``analyzer_service``, ``server``)
    consult it, but the crawler itself re-validates every URL (including each
    redirect hop) inside ``safe_get``/``validate_public_url`` -- so the
    override must be honored here too, or private-target scans silently fail
    with zero files and a ``page_fetch: failed`` summary.
    """
    value = os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS", "").strip().lower()
    return value in ("1", "true", "yes", "on")


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
    # The explicit development override relaxes only the *destination* checks
    # (private/reserved IPs and local hostnames).  Scheme, hostname and
    # credential rules stay enforced so the override cannot turn the crawler
    # into a credential-swallowing or non-http open proxy.
    if _private_targets_allowed():
        return True, ""
    if hostname in _UNSAFE_HOSTNAMES or _unsafe_ip(hostname):
        return False, "Local and reserved network destinations are not allowed"
    if resolve:
        addresses = _resolved_addresses(hostname)
        if any(_unsafe_ip(address) for address in addresses):
            return False, "The target resolves to a local or reserved network"
    return True, ""


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host or "")
        return True
    except ValueError:
        return False


def _pin_getaddrinfo(hostname: str, ips) -> callable:
    """Temporarily resolve ``hostname`` to the validated literals ``ips``.

    Returns the original ``socket.getaddrinfo`` for the caller to restore.
    The pin is scoped to the duration of one request (try/finally), and only
    rewrites lookups for this exact hostname, so other threads resolving
    other hosts are unaffected.

    Every validated address is chained into the result so the HTTP client
    keeps its usual try-in-order behaviour (e.g. IPv6 first, IPv4 fallback)
    without ever consulting DNS again for this host.
    """
    hostname = (hostname or "").rstrip(".").lower()
    ips = tuple(ips or ())
    original = socket.getaddrinfo

    def pinned(host, *args, **kwargs):
        if host and host.rstrip(".").lower() == hostname:
            records = []
            for ip in ips:
                records.extend(original(ip, *args, **kwargs))
            return records
        return original(host, *args, **kwargs)

    socket.getaddrinfo = pinned
    return original


def _validate_and_pin(url: str):
    """Validate ``url`` and resolve it exactly once; return ``(ok, reason, ips)``.

    ``ips`` is the tuple of public IP literals the request is allowed to
    connect to, or None for IP-literal targets (nothing to rebind) and for
    unresolvable hostnames (the HTTP client will surface the connection
    error).  Using one resolution for both the safety check and the
    connection closes the DNS-rebinding window: the check and the socket
    can no longer see two different answers.
    """
    ok, reason = validate_public_url(url, resolve=False)
    if not ok:
        return False, reason, None
    if _private_targets_allowed():
        # The development override also disables pinning: private-target
        # scans connect to loopback/private IPs that pinning would reject.
        return True, "", None
    hostname = (urlparse(url).hostname or "").rstrip(".").lower()
    if not hostname or _is_ip_literal(hostname):
        return True, "", None
    addresses = sorted(_resolved_addresses(hostname))
    if not addresses:
        return True, "", None
    if any(_unsafe_ip(address) for address in addresses):
        return False, "The target resolves to a local or reserved network", None
    return True, "", tuple(addresses)


def safe_get(url: str, *, timeout=15, headers=None, max_redirects=MAX_REDIRECTS, **kwargs):
    """GET a public URL without following an unsafe redirect.

    The returned object is a normal ``requests.Response``.  Callers decide how
    much of the body to read; this function only enforces the URL boundary.

    Each hop is validated and resolved *once*; the request is pinned to the
    validated IP so the destination cannot change between the check and the
    connection (DNS rebinding).
    """
    if requests is None:
        return None
    current = str(url)
    session = requests.Session()
    try:
        for _ in range(max(0, int(max_redirects)) + 1):
            valid, reason, pinned_ips = _validate_and_pin(current)
            if not valid:
                raise ValueError(reason)
            if pinned_ips is None:
                response = session.get(
                    current,
                    timeout=timeout,
                    headers=headers,
                    allow_redirects=False,
                    **kwargs,
                )
            else:
                hostname = (urlparse(current).hostname or "").rstrip(".").lower()
                original = _pin_getaddrinfo(hostname, pinned_ips)
                try:
                    response = session.get(
                        current,
                        timeout=timeout,
                        headers=headers,
                        allow_redirects=False,
                        **kwargs,
                    )
                finally:
                    socket.getaddrinfo = original
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
        # Bound the fallback too: read at most max_bytes+1 from the raw stream
        # instead of letting response.text materialise an unbounded body.
        try:
            raw = getattr(response, "raw", None)
            if raw is not None and hasattr(raw, "read"):
                chunk = raw.read(max_bytes + 1)
                if chunk is None or len(chunk) > max_bytes:
                    return None
                encoding = getattr(response, "encoding", None) or "utf-8"
                return chunk.decode(encoding, errors="replace")
            text = str(response.text)
            return text if len(text.encode("utf-8", errors="ignore")) <= max_bytes else None
        except Exception:
            return None
    finally:
        try:
            response.close()
        except Exception:
            pass
