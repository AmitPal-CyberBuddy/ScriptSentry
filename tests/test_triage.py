"""Server-side triage: a decision follows a finding across scans and exports.

Covers the storage layer (core.triage over the history DB), the payload/
export integration (fingerprint join, CSV columns, SARIF suppressions,
plain-language markers), and the honest-data contract (storage panel count,
export inclusion, wipe coverage).
"""
import json
import os
import tempfile
import unittest
from unittest import mock

import main as cli


def _finding(fid, severity="HIGH", line=3, observation=False):
    return {"id": fid, "type": fid, "severity": severity, "title": fid,
            "file": "app.js", "sink": "el.innerHTML = q", "line": line,
            "observation": observation, "evidence": ["src -> el.innerHTML = q"],
            "confidence": "high", "status": "open"}


def _results(*findings):
    return {"app.js": {"findings": list(findings), "name": "app.js"},
            "__scan_summary__": {"files": 1}}


class _TriageEnv:
    """Isolated state dir + reloaded history/triage modules; a mixin."""

    def setUp(self):
        import core.history as history
        self._tmp = tempfile.TemporaryDirectory(prefix="ss-triage-")
        self.addCleanup(self._tmp.cleanup)
        self._old = os.environ.get("SCRIPTSENTRY_STATE_DIR")
        os.environ["SCRIPTSENTRY_STATE_DIR"] = self._tmp.name
        self.addCleanup(self._restore)
        import importlib
        importlib.reload(history)
        import core.triage as triage
        importlib.reload(triage)
        self.history = history
        self.triage = triage

    def _restore(self):
        if self._old is None:
            os.environ.pop("SCRIPTSENTRY_STATE_DIR", None)
        else:
            os.environ["SCRIPTSENTRY_STATE_DIR"] = self._old
        import importlib
        importlib.reload(self.history)
        import core.triage as triage
        importlib.reload(triage)

    def test_set_get_clear_round_trip(self):
        t = self.triage
        fp = self.history.fingerprint(_finding("dom_injection"))
        self.assertEqual(t.triage_map(), {})
        entry = t.set_triage(fp, "false_positive", note="sanitized upstream")
        self.assertEqual(entry["status"], "false_positive")
        self.assertEqual(t.triage_map()[fp]["status"], "false_positive")
        self.assertEqual(t.triage_map()[fp]["note"], "sanitized upstream")
        self.assertEqual(t.triage_count(), 1)
        self.assertTrue(t.clear_triage(fp))
        self.assertEqual(t.triage_map(), {})
        self.assertFalse(t.clear_triage(fp))  # already gone

    def test_status_vocabulary_is_enforced(self):
        t = self.triage
        for bad in ("bogus", "", None, "FALSE-POSITIVE"):
            with self.assertRaises(ValueError):
                t.set_triage("f" * 40, bad)
        for good in t.TRIAGE_STATUSES:
            t.set_triage("f" * 40, good)
        self.assertEqual(t.triage_count(), 1)  # same fingerprint = one row

    def test_fingerprint_is_required_and_bounded(self):
        t = self.triage
        with self.assertRaises(ValueError):
            t.set_triage("", "open")
        with self.assertRaises(ValueError):
            t.set_triage("x" * 200, "open")

    def test_history_disabled_refuses_to_store(self):
        os.environ["SCRIPTSENTRY_HISTORY"] = "0"
        self.addCleanup(os.environ.pop, "SCRIPTSENTRY_HISTORY", None)
        import importlib
        importlib.reload(self.history)
        import core.triage as triage
        importlib.reload(triage)
        with self.assertRaises(ValueError):
            triage.set_triage("f" * 40, "open")
        self.assertEqual(triage.triage_map(), {})

    def test_wipe_deletes_triage_too(self):
        t = self.triage
        t.set_triage(self.history.fingerprint(_finding("x")), "confirmed")
        self.assertEqual(t.triage_count(), 1)
        self.history.wipe_history()
        self.assertEqual(t.triage_count(), 0)
        # storage_info reports the count after wipe
        self.assertEqual(self.history.storage_info()["triage_count"], 0)

    def test_export_history_includes_decisions(self):
        t = self.triage
        fp = self.history.fingerprint(_finding("secret"))
        t.set_triage(fp, "false_positive", note="test fixture")
        data = self.history.export_history()
        self.assertEqual(data["triage"][0]["fingerprint"], fp)
        self.assertEqual(data["triage"][0]["status"], "false_positive")


class TriageStoreTest(_TriageEnv, unittest.TestCase):
    """The storage layer, on an isolated state dir."""


class TriageAnnotationTest(_TriageEnv, unittest.TestCase):
    """The fingerprint join: decisions follow findings, lines do not matter."""

    def test_annotate_stamps_fingerprint_and_state(self):
        t = self.triage
        fp = self.history.fingerprint(_finding("dom_injection"))
        t.set_triage(fp, "confirmed")
        findings = [_finding("dom_injection"), _finding("other")]
        t.annotate_findings(findings, t.triage_map())
        self.assertEqual(findings[0]["triage_status"], "confirmed")
        self.assertEqual(findings[0]["triage_fp"], fp)
        self.assertNotIn("triage_status", findings[1])
        self.assertIn("triage_fp", findings[1])

    def test_annotate_with_empty_map_still_stamps_fingerprints(self):
        t = self.triage
        findings = [_finding("dom_injection")]
        t.annotate_findings(findings, {})
        self.assertIn("triage_fp", findings[0])
        self.assertNotIn("triage_status", findings[0])


class TriageExportsTest(_TriageEnv, unittest.TestCase):
    """Reports carry the decisions: CSV columns, SARIF suppressions, markers."""

    def _triaged_results(self, status="false_positive", note="known fixture"):
        t = self.triage
        from core.reporter import build_report_model
        finding = _finding("dom_injection")
        triage = {t.history.fingerprint(finding): {"status": status, "note": note,
                                                   "updated_at": 0}}
        results = _results(finding)
        model = build_report_model(results, triage=triage)
        annotated = [f for f in model["summary"]["findings"] if f.get("triage_status")]
        self.assertTrue(annotated, "the finding must carry its triage state")
        return results, triage

    def test_csv_carries_triage_columns(self):
        from core.reporter import generate_csv_report
        results, triage = self._triaged_results()
        csv = generate_csv_report(results, triage=triage)
        header = csv.splitlines()[0]
        self.assertIn("triage_status", header)
        self.assertIn("triage_note", header)
        row = next(line for line in csv.splitlines() if "dom_injection" in line)
        self.assertIn("false_positive", row)
        self.assertIn("known fixture", row)

    def test_sarif_suppresses_false_positives(self):
        from core.reporter import generate_sarif_report
        results, triage = self._triaged_results(status="false_positive")
        sarif = json.loads(generate_sarif_report(results, triage=triage))
        result = next(r for r in sarif["runs"][0]["results"]
                      if r.get("properties", {}).get("triage"))
        self.assertEqual(result["properties"]["triage"], "false_positive")
        self.assertEqual(result["suppressions"][0]["status"], "rejected")
        self.assertEqual(result["suppressions"][0]["kind"], "external")
        self.assertIn("known fixture", result["suppressions"][0]["justification"])

    def test_sarif_confirmed_is_a_property_not_a_suppression(self):
        from core.reporter import generate_sarif_report
        results, triage = self._triaged_results(status="confirmed")
        sarif = json.loads(generate_sarif_report(results, triage=triage))
        result = next(r for r in sarif["runs"][0]["results"]
                      if r.get("properties", {}).get("triage"))
        self.assertEqual(result["properties"]["triage"], "confirmed")
        self.assertNotIn("suppressions", result)

    def test_txt_marks_triaged_findings(self):
        from core.reporter import generate_report
        results, triage = self._triaged_results(status="confirmed", note="reviewed by sec")
        text = generate_report(results, triage=triage)
        self.assertIn("[triaged: confirmed]", text)
        self.assertIn("reviewed by sec", text)

    def test_dashboard_payload_always_stamps_fingerprints(self):
        from core.reporter import build_dashboard_payload
        results, _ = self._triaged_results()
        payload = build_dashboard_payload(results)  # no triage: fp still needed
        stamped = [f for f in payload["summary"]["findings"] if f.get("triage_fp")]
        self.assertTrue(stamped, "the UI needs triage_fp to address decisions")

    def test_cli_triage_flag_flows_into_reports(self):
        from unittest import mock
        t = self.triage
        finding = _finding("dom_injection")
        t.set_triage(t.history.fingerprint(finding), "false_positive", note="cli flag")
        results = _results(finding)
        with tempfile.TemporaryDirectory(prefix="ss-cli-triage-") as tmp:
            out = os.path.join(tmp, "reports")
            path = os.path.join(tmp, "app.js")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("var x = 1;\n")
            with mock.patch("main.analyze_files", return_value=results):
                code = cli.main([path, "--format", "csv", "--output", out, "--triage"])
            self.assertEqual(code, 0)
            with open(os.path.join(out, "report.csv"), encoding="utf-8") as fh:
                csv = fh.read()
        self.assertIn("false_positive", csv)
        self.assertIn("cli flag", csv)


class TriageUiContractTest(unittest.TestCase):
    """The UI wires decisions to the engine, not to localStorage."""

    def test_app_js_wires_server_triage(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "webui", "app.js"),
                  encoding="utf-8") as fh:
            app = fh.read()
        self.assertIn('postJSON("/api/triage"', app)
        self.assertIn("migrateLegacyTriage", app)
        # Server state wins; localStorage is only the legacy fallback.
        self.assertIn("if (f.triage_status) return f.triage_status;", app)
        self.assertIn("triage_fp", app)  # payload findings are addressable by fingerprint

    def test_storage_panel_lists_triage_count(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "webui", "src", "app",
                               "07-history-and-analysis.js"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("Triage decisions", src)


if __name__ == "__main__":
    unittest.main()


class TriageEndpointTest(unittest.TestCase):
    """Live-server checks: /api/triage routes + triage riding on payloads."""

    @classmethod
    def setUpClass(cls):
        import server
        import threading
        cls.server_module = server
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="scriptsentry-triage-api-")
        cls._env = mock.patch.dict(os.environ, {
            "SCRIPTSENTRY_STATE_DIR": cls._tmpdir.name,
            "SCRIPTSENTRY_HISTORY": "1",
        })
        cls._env.start()
        cls.httpd = server.make_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"
        import time

        cls._time = time
        cls._token = server.API_TOKEN

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls._env.stop()
        cls._tmpdir.cleanup()

    def request(self, path, method="GET", body=None, token=None, origin=None):
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-ScriptSentry-Token"] = token
        if origin:
            headers["Origin"] = origin
        request = Request(
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers, method=method,
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def _analyze_and_get_payload(self, code):
        """Run a synchronous code scan through the job API; return payload."""
        status, body = self.request("/api/analyze", method="POST", token=self._token,
                                    body={"mode": "code", "code": code,
                                          "filename": "triage-e2e.js"})
        self.assertEqual(status, 200, body)
        job_id = body["job_id"]
        for _ in range(80):
            code_, result = self.request(f"/api/result?job_id={job_id}",
                                         token=self._token)
            if code_ == 200 and result.get("ready"):
                return result["payload"]
            self._time.sleep(0.1)
        self.fail("scan job never finished")

    def test_triage_round_trip_over_api(self):
        fp = "a" * 40
        # No token -> 401; untrusted origin -> 403.
        status, _ = self.request("/api/triage", method="POST",
                                 body={"fingerprint": fp, "status": "confirmed"})
        self.assertEqual(status, 401)
        status, _ = self.request("/api/triage", method="POST", token=self._token,
                                 origin="https://evil.example",
                                 body={"fingerprint": fp, "status": "confirmed"})
        self.assertEqual(status, 403)
        # Store, read back, clear.
        status, body = self.request("/api/triage", method="POST", token=self._token,
                                    body={"fingerprint": fp, "status": "confirmed",
                                          "note": "reviewed"})
        self.assertEqual(status, 200)
        status, body = self.request("/api/triage", token=self._token)
        self.assertEqual(body["triage"][fp]["status"], "confirmed")
        status, body = self.request(f"/api/triage/{fp}", method="DELETE",
                                    token=self._token)
        self.assertEqual((status, body["deleted"]), (200, True))
        status, body = self.request("/api/triage", token=self._token)
        self.assertNotIn(fp, body["triage"])

    def test_invalid_status_is_rejected(self):
        status, body = self.request("/api/triage", method="POST", token=self._token,
                                    body={"fingerprint": "b" * 40, "status": "bogus"})
        self.assertEqual(status, 400)

    def test_storage_reports_triage_count(self):
        self.request("/api/triage", method="POST", token=self._token,
                     body={"fingerprint": "c" * 40, "status": "open"})
        status, body = self.request("/api/storage", token=self._token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["storage"]["triage_count"], 1)

    def test_decision_follows_finding_across_scans(self):
        """End-to-end: triage a finding, re-scan, the payload carries it."""
        code_v1 = ('document.getElementById("x").innerHTML ='
                   ' new URLSearchParams(location.search).get("q");\n')
        payload = self._analyze_and_get_payload(code_v1)
        findings = [f for f in payload["summary"]["findings"]
                    if f.get("id") == "dom_injection"]
        self.assertTrue(findings, "the snippet must raise dom_injection")
        finding = findings[0]
        self.assertIn("triage_fp", finding, "payload findings must be addressable")
        # Triage it as a false positive...
        status, _ = self.request("/api/triage", method="POST", token=self._token,
                                 body={"fingerprint": finding["triage_fp"],
                                       "status": "false_positive", "note": "safe by CSP"})
        self.assertEqual(status, 200)
        # ...re-scan the same code: the decision rides on the new payload.
        payload2 = self._analyze_and_get_payload(code_v1)
        again = [f for f in payload2["summary"]["findings"]
                 if f.get("id") == "dom_injection"][0]
        self.assertEqual(again.get("triage_status"), "false_positive")
        self.assertEqual(again.get("triage_note"), "safe by CSP")

    def test_export_carries_triage_over_api(self):
        code = 'var apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
        payload = self._analyze_and_get_payload(code)
        secrets = [f for f in payload["summary"]["findings"]
                   if "secret" in str(f.get("id", ""))]
        if not secrets:
            self.skipTest("snippet raised no secret finding on this engine")
        status, _ = self.request("/api/triage", method="POST", token=self._token,
                                 body={"fingerprint": secrets[0]["triage_fp"],
                                       "status": "false_positive"})
        self.assertEqual(status, 200)
        # The SARIF export of a fresh scan must carry the suppression.
        request_body = {"mode": "code", "code": code, "filename": "triage-e2e.js",
                        "format": "sarif"}
        from urllib.request import Request, urlopen
        req = Request(self.base + "/api/report?format=sarif",
                      data=json.dumps(request_body).encode(),
                      headers={"Content-Type": "application/json",
                               "X-ScriptSentry-Token": self._token},
                      method="POST")
        with urlopen(req, timeout=20) as response:
            sarif = json.loads(response.read())
        suppressed = [r for r in sarif["runs"][0]["results"]
                      if r.get("suppressions")]
        self.assertTrue(suppressed, "the false positive must be suppressed in SARIF")


if __name__ == "__main__":
    unittest.main()
