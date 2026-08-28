"""Optional local browser (Playwright) evidence capture.

This module is deliberately privacy-first and optional:

* It only runs when the user asks ScriptSentry to scan a URL.
* It never uploads anything. The browser runs on the same machine as the
  local engine.
* It captures URLs, console messages, DOM sink values, storage *key names*
  and cookie *names only* --- it never stores cookie values, request bodies
  or localStorage values.

If Playwright is not installed (or ``SCRIPTSENTRY_RUNTIME_EVIDENCE=0``), the
analyzer degrades back to pure static analysis and reports the reason in the
runtime evidence block.
"""
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import RUNTIME_EVIDENCE, REQUEST_HEADERS

try:
    from playwright.sync_api import sync_playwright

    _PLAYWRIGHT_IMPORTED = True
except Exception:  # pragma: no cover - exercised when dependency is optional
    sync_playwright = None
    _PLAYWRIGHT_IMPORTED = False


INSTRUMENTATION_JS = r"""
(() => {
  const w = window;
  if (w.__SS_RUNTIME__) return;
  const r = w.__SS_RUNTIME__ = {
    evals: [], timers: [], dom: [], storage: [], writes: [], errors: []
  };

  const push = (arr, item) => {
    if (arr && arr.length < 120) arr.push(item);
  };
  const trunc = (v) => {
    try {
      const s = typeof v === "string" ? v : String(v);
      return s.slice(0, 600);
    } catch (e) {
      return "";
    }
  };

  const nativeEval = w.eval;
  w.eval = function (code) {
    push(r.evals, { kind: "eval", code: trunc(code), url: location.href });
    return nativeEval.apply(this, arguments);
  };

  const nativeSetTimeout = w.setTimeout;
  w.setTimeout = function (fn, delay, ...args) {
    if (typeof fn === "string") {
      push(r.timers, { kind: "setTimeout", code: trunc(fn), url: location.href });
    }
    return nativeSetTimeout.call(w, fn, delay, ...args);
  };

  const nativeSetInterval = w.setInterval;
  w.setInterval = function (fn, delay, ...args) {
    if (typeof fn === "string") {
      push(r.timers, { kind: "setInterval", code: trunc(fn), url: location.href });
    }
    return nativeSetInterval.call(w, fn, delay, ...args);
  };

  try {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    if (desc && desc.set) {
      Object.defineProperty(Element.prototype, "innerHTML", {
        configurable: desc.configurable,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          push(r.dom, { sink: "innerHTML", value: trunc(v), url: location.href });
          return desc.set.call(this, v);
        },
      });
    }
  } catch (e) {}

  try {
    const originalInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (position, text) {
      push(r.dom, {
        sink: "insertAdjacentHTML",
        value: trunc(text),
        url: location.href,
      });
      return originalInsert.apply(this, arguments);
    };
  } catch (e) {}

  try {
    const originalWrite = Document.prototype.write;
    Document.prototype.write = function (...args) {
      push(r.dom, {
        sink: "document.write",
        value: trunc(args.join(",")),
        url: location.href,
      });
      return originalWrite.apply(this, arguments);
    };
  } catch (e) {}

  const trackStorage = (storage, name) => {
    try {
      const originalSet = storage.setItem;
      storage.setItem = function (key, value) {
        push(r.storage, {
          storage: name,
          key: String(key),
          valueLength: String(value).length,
          url: location.href,
        });
        return originalSet.call(storage, key, value);
      };
      const originalRemove = storage.removeItem;
      storage.removeItem = function (key) {
        push(r.writes, {
          storage: name,
          operation: "removeItem",
          key: String(key),
          url: location.href,
        });
        return originalRemove.call(storage, key);
      };
    } catch (e) {}
  };

  try { trackStorage(w.localStorage, "localStorage"); } catch (e) {}
  try { trackStorage(w.sessionStorage, "sessionStorage"); } catch (e) {}
})();
"""


EXTRACT_INSTRUMENTED_STATE_JS = r"""
() => {
  const r = window.__SS_RUNTIME__ || { evals: [], timers: [], dom: [], storage: [], writes: [] };
  const safe = (obj) => {
    try {
      return Object.keys(obj || {});
    } catch (e) {
      return [];
    }
  };
  return {
    url: location.href,
    title: document.title || "",
    readyState: document.readyState || "",
    scripts: Array.from(document.querySelectorAll("script[src]")).map((s) => s.getAttribute("src") || "").filter(Boolean).slice(0, 80),
    frames: Array.from(document.querySelectorAll("iframe[src]")).map((f) => f.getAttribute("src") || "").filter(Boolean).slice(0, 40),
    forms: Array.from(document.querySelectorAll("form[action]")).map((f) => f.getAttribute("action") || "").filter(Boolean).slice(0, 40),
    local_storage_keys: safe(window.localStorage).slice(0, 80),
    session_storage_keys: safe(window.sessionStorage).slice(0, 80),
    eval_calls: r.evals || [],
    string_timers: r.timers || [],
    dom_sinks: r.dom || [],
    storage_writes: r.storage || [],
    storage_removals: r.writes || [],
  };
}
"""


def runtime_evidence_enabled():
    """Return whether runtime evidence should be attempted.

    The feature is on when Playwright is installed and the user has not
    explicitly disabled it with ``SCRIPTSENTRY_RUNTIME_EVIDENCE=0``.
    """
    env = os.environ.get("SCRIPTSENTRY_RUNTIME_EVIDENCE", "").strip().lower()
    if env in ("0", "false", "off", "no", "disabled"):
        return False
    if env in ("1", "true", "on", "yes", "enabled"):
        return True
    return bool(RUNTIME_EVIDENCE.get("enabled", True))


def playwright_available():
    """Return True when the Playwright package can be imported."""
    return _PLAYWRIGHT_IMPORTED and sync_playwright is not None


def _limit(items, limit):
    return list(items or [])[: max(0, int(limit))]


def _record_request(request, store, limit):
    try:
        item = {
            "method": request.method,
            "url": request.url,
            "resource_type": request.resource_type,
            "post_data_length": len(request.post_data or ""),
            "from_service_worker": bool(getattr(request, "service_worker", None)),
        }
        if len(store) < limit:
            store.append(item)
    except Exception:
        pass


def _record_response(response, store, limit):
    try:
        item = {
            "method": getattr(response.request, "method", "GET"),
            "url": response.url,
            "status": response.status,
        }
        # Keep the response map keyed by URL+method so merge is deterministic.
        key = (item["method"], item["url"])
        if len(store) < limit:
            store[key] = item
    except Exception:
        pass


def _record_script(response, store, limit):
    try:
        resource_type = getattr(getattr(response, "request", None), "resource_type", None)
        if resource_type == "script" and len(store) < limit:
            store.add(response.url)
    except Exception:
        pass


def _merge_requests_and_responses(requests, responses):
    """Merge request/response snapshots into one compact ordered list."""
    by_url = {}
    for request in requests:
        by_url[(request.get("method"), request.get("url"))] = request
    for (method, url), response in responses.items():
        by_url[(method, url)] = {**by_url.get((method, url), {}), **response}
    return list(by_url.values())[:300]


def capture_runtime_evidence(
    url,
    timeout_ms=None,
    wait_after_load_ms=None,
    max_requests=300,
    max_console=120,
    max_pages=3,
):
    """Load ``url`` in a local headless Chromium and capture runtime evidence.

    Returns a dict that is always JSON-safe. It is safe to call this when
    Playwright is missing or disabled; the returned block carries a ``status``
    field so callers can explain why runtime evidence is unavailable.
    """
    started = time.time()
    start_iso = datetime.now(timezone.utc).isoformat()
    parsed = urlparse(url)
    identity = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    if not runtime_evidence_enabled():
        return {
            "enabled": False,
            "available": False,
            "captured": False,
            "status": "disabled",
            "reason": "Runtime evidence is disabled. Set SCRIPTSENTRY_RUNTIME_EVIDENCE=1 to enable it.",
            "url": url,
            "identity": identity,
            "started_at": start_iso,
            "duration_ms": 0,
        }
    if not playwright_available():
        return {
            "enabled": True,
            "available": False,
            "captured": False,
            "status": "missing_dependency",
            "reason": "Playwright is not installed. Run 'pip install playwright' and 'python -m playwright install chromium' to enable browser evidence.",
            "url": url,
            "identity": identity,
            "started_at": start_iso,
            "duration_ms": 0,
        }

    timeout_ms = int(timeout_ms or RUNTIME_EVIDENCE.get("timeout_ms", 15000))
    wait_after_load_ms = int(
        wait_after_load_ms if wait_after_load_ms is not None else RUNTIME_EVIDENCE.get("wait_after_load_ms", 1500)
    )
    max_requests = int(max_requests or RUNTIME_EVIDENCE.get("max_requests", 300))
    max_console = int(max_console or RUNTIME_EVIDENCE.get("max_console", 120))

    browser = None
    context = None
    requests = []
    responses = {}
    console_entries = []
    page_errors = []
    websockets = []
    failed_requests = []
    frame_urls = set()
    all_scripts = set()

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu", "--disable-notifications"],
                )
            except Exception as exc:
                return {
                    "enabled": True,
                    "available": True,
                    "captured": False,
                    "status": "browser_failed",
                    "reason": f"Chromium launch failed: {exc}",
                    "url": url,
                    "identity": identity,
                    "started_at": start_iso,
                    "duration_ms": int((time.time() - started) * 1000),
                }

            context = browser.new_context(
                user_agent=REQUEST_HEADERS.get("User-Agent", "Mozilla/5.0 (compatible; ScriptSentry)"),
                viewport={"width": 1365, "height": 768},
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.add_init_script(INSTRUMENTATION_JS)

            page.on("request", lambda req: _record_request(req, requests, max_requests))
            page.on("response", lambda res: _record_response(res, responses, max_requests))
            page.on(
                "console",
                lambda msg: console_entries.append(
                    {
                        "type": msg.type,
                        "text": (msg.text or "")[:600],
                        "url": getattr(getattr(msg, "location", None), "url", "") or "",
                        "line": getattr(getattr(msg, "location", None), "line", 0) or 0,
                    }
                )
                if len(console_entries) < max_console
                else None,
            )
            page.on("pageerror", lambda err: page_errors.append(str(err)[:600]))
            page.on("websocket", lambda ws: websockets.append(ws.url))
            page.on("requestfailed", lambda req: failed_requests.append({"url": req.url, "failure": str(getattr(req, "failure", ""))[:240]}))
            page.on("framenavigated", lambda frame: frame_urls.add(frame.url) if frame and frame.url and len(frame_urls) < max_pages * 12 else None)
            page.on("response", lambda res: _record_script(res, all_scripts, 120))

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:
                page_errors.append(f"page.goto failed: {exc}")

            try:
                page.wait_for_timeout(wait_after_load_ms)
            except Exception:
                pass

            # Let already-expired async chunks settle for the strict profile.
            try:
                page.wait_for_load_state("networkidle", timeout=min(3000, max(500, timeout_ms // 4)))
            except Exception:
                pass

            try:
                state = page.evaluate(EXTRACT_INSTRUMENTED_STATE_JS)
            except Exception:
                state = {}

            try:
                cookies = context.cookies()
            except Exception:
                cookies = []

            browser.close()
            browser = None
            context = None

        request_list = _merge_requests_and_responses(requests, responses)
        return {
            "enabled": True,
            "available": True,
            "captured": True,
            "status": "captured",
            "reason": "",
            "url": url,
            "identity": identity,
            "final_url": state.get("url") or "",
            "title": state.get("title") or "",
            "ready_state": state.get("readyState") or "",
            "started_at": start_iso,
            "duration_ms": int((time.time() - started) * 1000),
            "requests": _limit(request_list, max_requests),
            "console": _limit(console_entries, max_console),
            "page_errors": _limit(page_errors, 40),
            "failed_requests": _limit(failed_requests, 40),
            "websockets": _limit(websockets, 40),
            "frames": _limit(state.get("frames", []), 40),
            "forms": _limit(state.get("forms", []), 40),
            "scripts": sorted(set(_limit(state.get("scripts", []), 80) + _limit(all_scripts, 80)))[:80],
            "frame_urls": sorted(frame_urls)[:40],
            "local_storage_keys": _limit(state.get("local_storage_keys", []), 80),
            "session_storage_keys": _limit(state.get("session_storage_keys", []), 80),
            "cookie_names": [c.get("name") for c in cookies if c.get("name")][:80],
            "cookies": [
                {
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "path": c.get("path"),
                    "secure": bool(c.get("secure")),
                    "http_only": bool(c.get("httpOnly")),
                    "same_site": c.get("sameSite"),
                }
                for c in cookies[:80]
            ],
            "eval_calls": _limit(state.get("eval_calls", []), 120),
            "string_timers": _limit(state.get("string_timers", []), 120),
            "dom_sinks": _limit(state.get("dom_sinks", []), 120),
            "storage_writes": _limit(state.get("storage_writes", []), 120),
            "storage_removals": _limit(state.get("storage_removals", []), 80),
        }
    except Exception as exc:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        return {
            "enabled": True,
            "available": True,
            "captured": False,
            "status": "error",
            "reason": str(exc)[:500],
            "url": url,
            "identity": identity,
            "started_at": start_iso,
            "duration_ms": int((time.time() - started) * 1000),
        }


def _evidence_text(items, limit=4):
    out = []
    for item in items or []:
        if isinstance(item, dict):
            text = item.get("code") or item.get("value") or item.get("key") or item.get("url") or item.get("text") or ""
            if item.get("sink"):
                text = f"{item['sink']}: {text}"
        else:
            text = str(item)
        text = str(text).strip()
        if text and text not in out:
            out.append(text[:300])
        if len(out) >= limit:
            break
    return out


def _sensitive_key(key):
    lower = str(key or "").lower()
    return any(term in lower for term in ("token", "secret", "password", "auth", "session", "credential", "api_key", "jwt", "private", "key"))


def build_runtime_findings(runtime, target_url=""):
    """Convert captured browser evidence into normalized finding dicts.

    These findings share the same shape as static findings and are merged into
    CSV/SARIF/dashboard exports through ``core.analysis_model``.
    """
    runtime = runtime or {}
    if not runtime.get("captured"):
        return []

    target_url = target_url or runtime.get("url") or runtime.get("identity") or "runtime://browser"
    findings = []

    # 1) Dynamic code execution (eval / new Function / string timers).
    eval_calls = _evidence_text(runtime.get("eval_calls", []), 4)
    string_timers = _evidence_text(runtime.get("string_timers", []), 3)
    if eval_calls:
        findings.append({
            "id": "runtime_eval",
            "type": "Dynamic code execution observed",
            "severity": "HIGH",
            "confidence": "high",
            "status": "confirmed",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "eval / new Function",
            "flow": ["runtime eval", "synchronous code injection"],
            "evidence": eval_calls,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })
    elif string_timers:
        findings.append({
            "id": "runtime_string_timer",
            "type": "String-based timer execution",
            "severity": "MEDIUM",
            "confidence": "medium",
            "status": "needs_review",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "setTimeout / setInterval with string",
            "flow": ["string timer scheduled"],
            "evidence": string_timers,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 2) DOM sinks observed at runtime.
    dom_sinks = _evidence_text(runtime.get("dom_sinks", []), 6)
    if dom_sinks:
        findings.append({
            "id": "runtime_dom_sink",
            "type": "DOM sink executed at runtime",
            "severity": "HIGH",
            "confidence": "high",
            "status": "confirmed",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "innerHTML / insertAdjacentHTML / document.write",
            "flow": ["runtime DOM mutation", "DOM sink write"],
            "evidence": dom_sinks,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 3) Sensitive client storage writes / visible keys.
    storage_keys = [
        w.get("key")
        for w in (runtime.get("storage_writes") or [])
        if isinstance(w, dict) and _sensitive_key(w.get("key"))
    ]
    storage_keys += [k for k in (runtime.get("local_storage_keys") or []) if _sensitive_key(k)]
    storage_keys += [k for k in (runtime.get("session_storage_keys") or []) if _sensitive_key(k)]
    storage_keys += [n for n in (runtime.get("cookie_names") or []) if _sensitive_key(n)]
    storage_keys = list(dict.fromkeys(storage_keys))[:6]
    if storage_keys:
        findings.append({
            "id": "runtime_sensitive_storage",
            "type": "Sensitive client storage used at runtime",
            "severity": "HIGH",
            "confidence": "medium",
            "status": "needs_review",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "localStorage / sessionStorage / cookie",
            "flow": ["storage key written by live page"],
            "evidence": [f"storage key: {k}" for k in storage_keys],
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 4) Console errors / page exceptions.
    console_errors = []
    for entry in runtime.get("console", []):
        if isinstance(entry, dict) and str(entry.get("type", "")).lower() in ("error", "assert", "warning"):
            console_errors.append(f"{entry.get('type')}: {entry.get('text')}")
    page_errors = runtime.get("page_errors", []) or []
    if console_errors or page_errors:
        findings.append({
            "id": "runtime_console_errors",
            "type": "Browser console errors during execution",
            "severity": "MEDIUM",
            "confidence": "medium",
            "status": "needs_review",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "console.error / page error",
            "flow": ["runtime exception or console failure"],
            "evidence": (_evidence_text(console_errors, 4) + _evidence_text(page_errors, 4))[:6],
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 5) Failed requests are useful for mapping unreachable endpoints.
    failed = _evidence_text(runtime.get("failed_requests", []), 5)
    if failed:
        findings.append({
            "id": "runtime_failed_requests",
            "type": "Runtime requests failed",
            "severity": "LOW",
            "confidence": "medium",
            "status": "needs_review",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "network request failure",
            "flow": ["runtime request failed"],
            "evidence": failed,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 6) WebSocket endpoints only observable at runtime.
    websockets = _evidence_text(runtime.get("websockets", []), 5)
    if websockets:
        findings.append({
            "id": "runtime_websocket",
            "type": "Live WebSocket channel observed",
            "severity": "MEDIUM",
            "confidence": "high",
            "status": "confirmed",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "WebSocket",
            "flow": ["runtime WebSocket connected"],
            "evidence": websockets,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    # 7) Dynamic network / API surface that static analysis could not see.
    requests = runtime.get("requests", []) or []
    seen_urls = []
    for request in requests:
        url = request.get("url", "") if isinstance(request, dict) else ""
        method = request.get("method", "GET") if isinstance(request, dict) else "GET"
        if url and url not in seen_urls:
            seen_urls.append(f"{method} {url}")
        if len(seen_urls) >= 6:
            break
    if seen_urls:
        findings.append({
            "id": "runtime_api_calls",
            "type": "Runtime network/API activity",
            "severity": "LOW",
            "confidence": "medium",
            "status": "informational",
            "file": target_url,
            "line": 0,
            "source": "browser runtime",
            "sink": "fetch / XHR / resource request",
            "flow": ["runtime request observed"],
            "evidence": seen_urls,
            "sanitization_detected": False,
            "framework": "Playwright runtime",
            "evidence_type": "runtime_browser",
        })

    return findings


def attach_runtime_evidence(results, runtime, target_url=""):
    """Attach runtime evidence + findings to an analyzer result dict.

    Special ``__`` keys are not treated as files by the reporters; they supply
    global browser evidence for the dashboard and structured exports.
    """
    runtime = runtime or {}
    results["__runtime_evidence__"] = runtime
    results["__runtime_findings__"] = (
        build_runtime_findings(runtime, target_url) if runtime.get("captured") else []
    )
    return results
