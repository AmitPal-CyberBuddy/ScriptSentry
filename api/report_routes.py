"""Report export route: /api/report?format=(html|txt|csv|sarif|json|openapi).

Either re-exports a finished job's results (``job_id``) or runs a fresh
synchronous analysis for ad-hoc CLI/hosted use. Every format is written
straight to the response as a download attachment.
"""
from core.jobs import jobs
from core.reporter import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_openapi_report,
    generate_report,
    generate_sarif_report,
)

_REPORT_FORMATS = ("html", "txt", "csv", "sarif", "openapi", "json")


class ReportRoutesMixin:
    """The /api/report endpoint mixed into the dashboard handler."""

    def _send_download(self, data, content_type, filename):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(data)

    def _handle_report(self, parsed, body):
        query = {}
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    query[k] = v
        report_format = query.get("format", "html").lower()
        if report_format not in _REPORT_FORMATS:
            self._send_error_json(
                "format must be " + ", ".join(_REPORT_FORMATS[:-1]) + ", or " + _REPORT_FORMATS[-1],
                400,
            )
            return
        try:
            job_id = str(body.get("job_id", "")).strip()
            if job_id:
                job = jobs.get(job_id)
                if job is None:
                    self._send_error_json("Unknown job_id", 404)
                    return
                if job.status == "done":
                    results = jobs.result(job_id) or {}
                elif job.status in ("queued", "running"):
                    self._send_error_json("Analysis is still running; wait for completion before exporting.", 409)
                    return
                else:
                    self._send_error_json(job.error or "Analysis failed.", 500)
                    return
            else:
                results = self._run_analysis(body)
        except Exception as exc:
            self._send_error_json(f"Analysis failed: {exc}", 500)
            return

        source = str(body.get("url", body.get("filename", "")))
        if not source and isinstance(body.get("files"), list) and body["files"]:
            source = f"{len(body['files'])} uploaded file(s)"
        metadata = {"mode": str(body.get("mode", "code")), "source": source}

        if report_format == "txt":
            self._send_download(
                generate_report(results, metadata=metadata).encode("utf-8"),
                "text/plain; charset=utf-8",
                "scriptsentry-report.txt",
            )
            return
        if report_format == "csv":
            self._send_download(
                generate_csv_report(results, metadata=metadata).encode("utf-8"),
                "text/csv; charset=utf-8",
                "scriptsentry-report.csv",
            )
            return
        if report_format == "sarif":
            self._send_download(
                generate_sarif_report(results, metadata=metadata).encode("utf-8"),
                "application/sarif+json; charset=utf-8",
                "scriptsentry-report.sarif",
            )
            return
        if report_format == "json":
            self._send_download(
                generate_json_report(results, metadata=metadata).encode("utf-8"),
                "application/json; charset=utf-8",
                "scriptsentry-report.json",
            )
            return
        if report_format == "openapi":
            self._send_download(
                generate_openapi_report(results, metadata=metadata).encode("utf-8"),
                "application/json; charset=utf-8",
                "scriptsentry-api-surface.openapi.json",
            )
            return

        self._send_download(
            generate_html_report(results, metadata=metadata).encode("utf-8"),
            "text/html; charset=utf-8",
            "scriptsentry-report.html",
        )
