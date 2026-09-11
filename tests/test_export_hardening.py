"""Export and detection hardening: findings that must survive bad input.

Three classes of failure are pinned here, each found by review:

1.  **CSV formula injection** -- evidence, sources, sinks and file names come
    from the scanned (untrusted) code. A cell that starts with ``=``, ``+``,
    ``-``, ``@`` or a tab/CR is executed as a formula by Excel / Google
    Sheets when the export is opened. The export must neutralize it.
2.  **A malformed ``line`` must not kill every export** -- one finding with a
    non-numeric line used to raise ``ValueError`` inside the shared
    correlation layer, taking CSV, SARIF, HTML, TXT *and* the dashboard
    payload down with it. A line that cannot be read is simply unknown (0).
3.  **Fixture markers apply to the secret value, not the whole line** -- a
    real credential on a line that merely mentions ``example.com`` (or a
    ``sample_rate`` field) used to be silently dropped by the
    ``_credible_secret`` fixture filter.
"""
import csv
import io
import unittest

from core.analysis_model import coerce_line
from core.reporter import (
    build_dashboard_payload,
    build_report_model,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)
from core.scanner import scan_content


FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_rows(text):
    return list(csv.DictReader(io.StringIO(text)))


class CoerceLineTest(unittest.TestCase):
    def test_int_passthrough(self):
        self.assertEqual(coerce_line(7), 7)
        self.assertEqual(coerce_line(0), 0)

    def test_numeric_string(self):
        self.assertEqual(coerce_line("12"), 12)
        self.assertEqual(coerce_line(" 34 "), 34)

    def test_malformed_shapes_fall_back_to_digits_or_zero(self):
        self.assertEqual(coerce_line("not-a-number"), 0)
        self.assertEqual(coerce_line("line 42!"), 42)  # salvage the digits
        self.assertEqual(coerce_line(None), 0)
        self.assertEqual(coerce_line(True), 0)  # bools are not line numbers
        self.assertEqual(coerce_line(""), 0)
        self.assertEqual(coerce_line(-5), 0)  # lines are never negative


class MalformedLineExportTest(unittest.TestCase):
    """One bad finding must never take the whole export pipeline down."""

    RESULTS = {
        "weird.js": {
            "findings": [
                {"id": "good", "type": "Good", "severity": "HIGH", "confidence": "high",
                 "line": 3, "source": "location.hash", "sink": "eval",
                 "evidence_type": "source_to_sink", "status": "open"},
                {"id": "bad_line", "type": "Bad", "severity": "HIGH", "confidence": "high",
                 "line": "not-a-number", "source": "a", "sink": "b",
                 "evidence_type": "static_pattern", "status": "open"},
                {"id": "str_line", "type": "Str", "severity": "LOW", "confidence": "low",
                 "line": "12", "source": "a", "sink": "b",
                 "evidence_type": "static_pattern", "status": "open"},
            ],
        },
    }

    def test_model_builds_and_keeps_all_findings(self):
        model = build_report_model(self.RESULTS)
        ids = {f["id"] for f in model["summary"]["findings"]}
        self.assertEqual(ids, {"good", "bad_line", "str_line"})

    def test_every_export_format_survives(self):
        for name, fn in (
            ("txt", generate_report),
            ("csv", generate_csv_report),
            ("sarif", generate_sarif_report),
            ("html", generate_html_report),
        ):
            with self.subTest(export=name):
                out = fn(self.RESULTS)
                self.assertTrue(out, f"{name} export came back empty")

    def test_dashboard_payload_survives(self):
        payload = build_dashboard_payload(self.RESULTS)
        self.assertIn("summary", payload)

    def test_sarif_coerces_lines(self):
        import json

        sarif = json.loads(generate_sarif_report(self.RESULTS))
        lines = [
            r["locations"][0]["physicalLocation"]["region"]["startLine"]
            for r in sarif["runs"][0]["results"]
        ]
        self.assertEqual(sorted(lines), [0, 2, 11])  # 3->2, junk->0, "12"->11

    def test_csv_keeps_all_rows(self):
        rows = _csv_rows(generate_csv_report(self.RESULTS))
        self.assertEqual(len(rows), 3)


class CsvFormulaInjectionTest(unittest.TestCase):
    """The scanned code is untrusted; its strings must not become formulas."""

    def _injectable_results(self):
        # A pasted file whose *name* is a formula, plus a finding whose
        # evidence is a formula -- both reach CSV cells verbatim today.
        return {
            '=HYPERLINK("http://evil.example","Report")-1.js': {
                "findings": [
                    {"id": "hardcoded_secret", "type": "Hardcoded secret candidate",
                     "severity": "HIGH", "confidence": "medium", "status": "needs_review",
                     "file": '=HYPERLINK("http://evil.example","Report")-1.js',
                     "line": 1, "source": "",
                     "sink": 'apiKey = "=SUM(9+9)*cmd|/C calc"',
                     "evidence": 'apiKey = "=SUM(9+9)*cmd|/C calc"',
                     "evidence_type": "static_pattern"},
                    {"id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
                     "confidence": "medium", "status": "needs_review",
                     "file": '=HYPERLINK("http://evil.example","Report")-1.js',
                     "line": 2, "source": "=cmd|' /C calc'!A0", "sink": "innerHTML",
                     "evidence_type": "source_to_sink"},
                ],
            },
        }

    def test_no_cell_executes_as_a_spreadsheet_formula(self):
        rows = _csv_rows(generate_csv_report(self._injectable_results()))
        self.assertEqual(len(rows), 2)
        for i, row in enumerate(rows):
            for col, value in row.items():
                if col in ("line", "sanitization_detected", "observation"):
                    continue  # numeric/boolean, never formula-shaped
                self.assertFalse(
                    str(value)[:1] in FORMULA_PREFIXES,
                    f"row {i} column {col} starts with a formula character: {value!r}",
                )

    def test_neutralized_cells_stay_readable(self):
        rows = _csv_rows(generate_csv_report(self._injectable_results()))
        file_cell = rows[0]["file"]
        self.assertTrue(file_cell.startswith("'="), "guard prefix missing")
        self.assertIn("HYPERLINK", file_cell)  # content preserved for the analyst

    def test_normal_values_are_not_mangled(self):
        results = {"app.js": {"findings": [
            {"id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
             "confidence": "high", "status": "open", "file": "app.js", "line": 4,
             "source": "location.search", "sink": "innerHTML = q",
             "evidence_type": "source_to_sink"},
        ]}}
        rows = _csv_rows(generate_csv_report(results))
        self.assertEqual(rows[0]["file"], "app.js")
        self.assertEqual(rows[0]["source"], "location.search")


class FixtureMarkerScopeTest(unittest.TestCase):
    """A real secret survives a line that merely mentions 'example'."""

    def test_real_secret_next_to_example_domain_is_detected(self):
        code = (
            'var apiEndpoint = "https://api.example.com/v1/log";\n'
            'var apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
            "send(apiEndpoint, apiKey);\n"
        )
        findings = scan_content(code).get("findings") or []
        ids = {f["id"] for f in findings}
        self.assertIn("hardcoded_secret", ids,
                      "a real high-entropy key was dropped because the neighboring "
                      "line mentions example.com (whole-line fixture marker)")

    def test_placeholder_values_are_still_filtered(self):
        code = 'const token = "sample-placeholder-token";\nconst k = "YOUR_API_TOKEN_HERE";\n'
        findings = scan_content(code).get("findings") or []
        ids = {f["id"] for f in findings}
        self.assertNotIn("hardcoded_secret", ids)


if __name__ == "__main__":
    unittest.main()
