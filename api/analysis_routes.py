"""Analysis routes: /api/health, /api/status, /api/result, /api/history*,
/api/storage, /api/cancel and /api/analyze.

Every API route (health included) answers JSON. Routes other than health
require the pairing token and are dispatched from :mod:`api.handlers`.
Destructive history routes arrive as DELETE and are dispatched from
``do_DELETE`` after the same origin/token gates.
"""
import json
import os
from datetime import datetime, timezone

from api.settings import (
    ALLOWED_UPLOAD_EXT,
    MAX_FILE_BYTES,
    MAX_UPLOAD_FILES,
    MAX_URL_LENGTH,
)
from config import DEFAULT_PROFILE, SCAN_MAX_WORKERS, SCAN_PROFILES
from core.analyzer_service import analyze_content, analyze_files, analyze_url
from core.history import delete_scan as history_delete_scan
from core.history import export_history as history_export
from core.history import get_scan as history_get
from core.history import list_scans as history_list
from core.history import storage_info as history_storage_info
from core.history import wipe_history as history_wipe
from core.jobs import jobs
from core.js_parser import parser_status
from core.runtime_evidence import playwright_available, runtime_evidence_enabled
from core.url_policy import validate_public_url
from core.version import ENGINE_NAME, RELEASE_STATUS, is_dev_build


def _clean_display_filename(name):
    """Strip control characters and cap a caller-supplied display filename.

    Returns possibly-empty text; callers apply their own default. The name
    flows into reports (TXT line structure, CSV cells, SARIF URIs), so a
    newline or tab smuggled in via ``filename`` corrupts exports, and control
    characters are part of the spreadsheet-formula smuggling family.
    Formula-leading characters themselves are neutralized at the export
    boundary (``reporter._csv_safe``); names stay human-readable here.
    """
    cleaned = "".join(ch for ch in str(name).replace("\\x00", "") if ch.isprintable())
    return cleaned.strip()[:240]


class AnalysisRoutesMixin:
    """Job-oriented API endpoints mixed into the dashboard handler."""

    def _payload(self, results, metadata=None):
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            meta.update(metadata)
        from core.reporter import build_dashboard_payload

        return build_dashboard_payload(results, metadata=meta)

    def _handle_health(self):
        self._send_json({
            "ok": True,
            "engine": ENGINE_NAME,
            "version": _engine_version(),
            "release_status": RELEASE_STATUS,
            "dev_build": is_dev_build(),
            "privacy": "local-only",
            "auth_required": True,
            "pairing": "Set X-ScriptSentry-Token to use analysis endpoints.",
            "runtime_evidence": {
                "enabled": runtime_evidence_enabled(),
                "playwright": playwright_available(),
            },
            "ast_parser": parser_status(),
        })

    def _handle_api_get(self, parsed):
        """Serve every GET-able API route; True when the request was handled."""
        if not self._require_api_auth():
            return True
        if parsed.path == "/api/status":
            job_id = self._query_param(parsed, "job_id", "")
            status = jobs.status(job_id)
            if status is None:
                self._send_error_json("Unknown job_id", 404)
                return True
            self._send_json({"ok": True, "job": status})
            return True
        if parsed.path == "/api/result":
            job_id = self._query_param(parsed, "job_id", "")
            job = jobs.get(job_id)
            if job is None:
                self._send_error_json("Unknown job_id", 404)
                return True
            if job.status != "done":
                self._send_json({"ok": True, "job": job.snapshot(), "ready": False})
                return True
            raw = jobs.result(job_id)
            payload = self._payload(raw, metadata={"mode": job.mode, "source": job.source})
            self._send_json({"ok": True, "job": job.snapshot(), "ready": True, "payload": payload})
            return True
        if parsed.path == "/api/storage":
            info = history_storage_info()
            # The browser half of the inventory: what this page keeps where.
            info["browser_notes"] = {
                "triage": "localStorage",
                "last_result": "sessionStorage",
                "token": "sessionStorage",
            }
            self._send_json({"ok": True, "storage": info})
            return True
        if parsed.path == "/api/history":
            limit = self._query_param(parsed, "limit", "50")
            target = self._query_param(parsed, "target", "")
            self._send_json({"ok": True,
                             "scans": history_list(limit=int(limit) if limit.isdigit() else 50,
                                                   target=target or None)})
            return True
        if parsed.path.startswith("/api/history/diff"):
            from_id = self._query_param(parsed, "from", "")
            to_id = self._query_param(parsed, "to", "")
            if not (from_id and to_id):
                self._send_error_json("Provide from= and to= scan ids", 400)
                return True
            # Finding-level revalidation (verdicts, severity transitions,
            # coverage honesty, plain-language summary) with the legacy
            # count keys kept for existing consumers.
            from core.revalidation import revalidate_scans
            reval = revalidate_scans(from_id, to_id)
            if reval is None:
                self._send_error_json("Provide from= and to= scan ids", 400)
                return True
            self._send_json({"ok": True, "diff": reval, "revalidation": reval})
            return True
        if parsed.path == "/api/history/export":
            # Must be checked before the generic /api/history/<scan_id> branch
            # below, which would otherwise read "export" as a scan id.
            include_payload = self._query_param(parsed, "include", "") == "payload"
            data = history_export(include_payload=include_payload)
            self._send_download(
                json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"),
                "application/json; charset=utf-8",
                "scriptsentry-history-export.json",
            )
            return True
        if parsed.path.startswith("/api/history/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            include_payload = self._query_param(parsed, "include", "") == "payload"
            scan = history_get(scan_id, include_report=include_payload)
            if scan is None:
                self._send_error_json("Unknown scan id", 404)
                return True
            if include_payload:
                report = scan.pop("report", None)
                if report is None:
                    self._send_error_json("This scan's full report was not retained", 410)
                    return True
                meta = {"mode": scan.get("mode"), "source": scan.get("target")}
                scan["payload"] = self._payload(report, metadata=meta)
            self._send_json({"ok": True, "scan": scan})
            return True
        return False

    def _handle_api_post(self, parsed, body):
        """Serve every POST-able API route; True when the request was handled."""
        if parsed.path == "/api/cancel":
            job_id = str(body.get("job_id", "")).strip()
            job = jobs.get(job_id)
            if job is None:
                self._send_error_json("Unknown job_id", 404)
                return True
            if job.status in ("done", "error", "canceled"):
                self._send_json({"ok": True, "job": job.snapshot()})
                return True
            jobs.cancel(job_id)
            self._send_json({"ok": True, "job": job.snapshot()})
            return True
        if parsed.path != "/api/analyze":
            return False

        mode = str(body.get("mode", "code")).strip().lower()
        if mode not in ("url", "code"):
            self._send_error_json("mode must be 'code' or 'url'", 400)
            return True
        self._handle_async_analysis(body, mode)
        return True

    def _handle_api_delete(self, parsed):
        """Serve every DELETE-able API route (destructive history ops).

        Called after the origin and pairing-token gates in ``do_DELETE``:
        a destructive route must never be reachable without an explicit token
        or from an origin the engine does not trust.
        """
        if parsed.path == "/api/history":
            include_calibration = (
                self._query_param(parsed, "include_calibration", "").lower() == "true"
            )
            wiped = history_wipe(include_calibration=include_calibration)
            self._send_json({"ok": True, **wiped})
            return True
        if parsed.path.startswith("/api/history/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            if not history_delete_scan(scan_id):
                self._send_error_json("Unknown scan id", 404)
                return True
            self._send_json({"ok": True, "deleted": True, "scan_id": int(scan_id)})
            return True
        return False

    @staticmethod
    def _extract_uploads(body):
        """Validate the optional local file-upload list (read in the browser).

        Returns a list of {"filename", "code"} or raises ValueError. Files are
        supplied as text by the hosted/local UI and analyzed entirely by the
        local engine; nothing is sent to a cloud.
        """
        files = body.get("files")
        if files is None:
            return None
        if not isinstance(files, list) or not files:
            raise ValueError("No files were provided")
        if len(files) > MAX_UPLOAD_FILES:
            raise ValueError(f"Too many files (limit {MAX_UPLOAD_FILES})")
        cleaned = []
        for item in files:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if not isinstance(code, str) or not code.strip():
                continue
            name = str(item.get("filename", "")).strip()
            if len(code.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
                raise ValueError(f"File {name or '(unnamed)'} exceeds the {MAX_FILE_BYTES // (1024*1024)}-MB per-file limit")
            # Keep a JS-ish extension; unknown uploads are still analyzed as JS.
            if name and not name.lower().endswith(ALLOWED_UPLOAD_EXT):
                raise ValueError(f"Unsupported file type: {name}")
            name = _clean_display_filename(name)
            cleaned.append({"filename": name or f"upload-{len(cleaned)+1}.js", "code": code})
        if not cleaned:
            raise ValueError("Uploaded files were empty")
        return cleaned

    def _run_analysis(self, body):
        mode = str(body.get("mode", "code")).strip().lower()
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if len(url) > MAX_URL_LENGTH or not url.startswith(("http://", "https://")):
                raise ValueError("Enter a valid http(s) URL")
            if not os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"):
                valid, reason = validate_public_url(url)
                if not valid:
                    raise ValueError(reason)
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = self._bounded_int(body.get("max_depth", profile_cfg["max_depth"]), profile_cfg["max_depth"], 1, 10)
            timeout = self._bounded_int(body.get("timeout", profile_cfg["timeout"]), profile_cfg["timeout"], 2, 60)
            max_files = self._bounded_int(body.get("max_files", profile_cfg["max_files"]), profile_cfg["max_files"], 1, 1000)
            max_workers = self._bounded_int(body.get("max_workers", SCAN_MAX_WORKERS), SCAN_MAX_WORKERS, 1, 32)
            return analyze_url(
                url, max_depth=max_depth, timeout=timeout,
                max_files=max_files, max_workers=max_workers,
            )
        uploads = self._extract_uploads(body)
        if uploads:
            return analyze_files(uploads)
        code = body.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Paste some JavaScript to analyze")
        filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
        return analyze_content(code, filename=_clean_display_filename(filename) or "inline.js")

    def _handle_async_analysis(self, body, mode):
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if len(url) > MAX_URL_LENGTH or not url.startswith(("http://", "https://")):
                self._send_error_json("Enter a valid http(s) URL", 400)
                return
            if not os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"):
                valid, reason = validate_public_url(url)
                if not valid:
                    self._send_error_json(reason, 400)
                    return
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = self._bounded_int(body.get("max_depth", profile_cfg["max_depth"]), profile_cfg["max_depth"], 1, 10)
            timeout = self._bounded_int(body.get("timeout", profile_cfg["timeout"]), profile_cfg["timeout"], 2, 60)
            max_files = self._bounded_int(body.get("max_files", profile_cfg["max_files"]), profile_cfg["max_files"], 1, 1000)
            max_workers = self._bounded_int(body.get("max_workers", SCAN_MAX_WORKERS), SCAN_MAX_WORKERS, 1, 32)
            try:
                job = jobs.create(
                    mode="url", source=url, profile=profile,
                    max_files=max_files, max_depth=max_depth, timeout=timeout,
                    max_workers=max_workers,
                )
            except RuntimeError as exc:
                self._send_error_json(str(exc), 429)
                return
            jobs.start(
                job.id,
                analyze_url,
                url,
                max_depth=max_depth,
                timeout=timeout,
                max_files=max_files,
                max_workers=max_workers,
                progress_callback=lambda **kw: job.update(**kw),
                cancel_check=job.cancel_event.is_set,
            )
        else:
            try:
                uploads = self._extract_uploads(body)
            except ValueError as exc:
                uploads = None
                upload_error = str(exc)
            else:
                upload_error = ""
            if uploads:
                try:
                    job = jobs.create(mode="code", source=f"{len(uploads)} file(s)", max_files=len(uploads),
                                      max_workers=SCAN_MAX_WORKERS)
                except RuntimeError as exc:
                    self._send_error_json(str(exc), 429)
                    return
                jobs.start(
                    job.id,
                    analyze_files,
                    uploads,
                    progress_callback=lambda **kw: job.update(**kw),
                    cancel_check=job.cancel_event.is_set,
                )
            else:
                code = body.get("code")
                if not isinstance(code, str) or not code.strip():
                    self._send_error_json(upload_error or "Paste some JavaScript to analyze", 400)
                    return
                if len(code.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
                    self._send_error_json(f"JavaScript input is limited to {MAX_FILE_BYTES // (1024*1024)} MB", 413)
                    return
                filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
                filename = _clean_display_filename(filename) or "inline.js"
                try:
                    job = jobs.create(mode="code", source=filename, max_files=1,
                                      max_workers=SCAN_MAX_WORKERS)
                except RuntimeError as exc:
                    self._send_error_json(str(exc), 429)
                    return
                jobs.start(
                    job.id,
                    analyze_content,
                    code,
                    filename=filename,
                    progress_callback=lambda **kw: job.update(**kw),
                    cancel_check=job.cancel_event.is_set,
                )

        self._send_json({"ok": True, "job_id": job.id, "job": job.snapshot()})


def _engine_version():
    # Imported lazily to keep this module's import surface small at startup.
    from core.version import __version__

    return __version__
