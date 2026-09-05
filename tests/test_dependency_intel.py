"""Known-vulnerability intelligence for bundled libraries.

A version banner in a minified bundle is a fingerprint: ``jQuery v3.4.1``
means CVE-2020-11022 applies, and a tester should see that without cross-
referencing NVD by hand. The contract here is conservative in the direction
that matters: **no version extracted, no vulnerability claimed** -- inventory
never becomes a CVE finding by accident.
"""
import unittest

from core.dependency_intel import (
    LIBRARY_INTEL,
    check_dependencies,
    extract_version,
    match_vulnerabilities,
    version_in_ranges,
)
from core.scanner import scan_content


class VersionRangeTest(unittest.TestCase):
    def test_comparison_operators(self):
        self.assertTrue(version_in_ranges("3.4.1", "<3.5.0"))
        self.assertFalse(version_in_ranges("3.5.0", "<3.5.0"))
        self.assertTrue(version_in_ranges("3.5.0", "<=3.5.0"))
        self.assertTrue(version_in_ranges("0.21.0", ">=0.21.0"))
        self.assertTrue(version_in_ranges("1.2.3", "=1.2.3"))
        self.assertTrue(version_in_ranges("1.2", "=1.2.0"), "short versions pad with zeros")

    def test_compound_ranges_require_every_constraint(self):
        self.assertTrue(version_in_ranges("1.2.3", ">=1.2.0,<3.4.0"))
        self.assertFalse(version_in_ranges("3.4.0", ">=1.2.0,<3.4.0"))
        self.assertFalse(version_in_ranges("1.0.0", ">=1.2.0,<3.4.0"))

    def test_garbage_never_counts_as_vulnerable(self):
        self.assertFalse(version_in_ranges(None, "<3.5.0"))
        self.assertFalse(version_in_ranges("banana", "<3.5.0"))
        self.assertFalse(version_in_ranges("3.4.1", "not a range"))


class VersionExtractionTest(unittest.TestCase):
    def test_realistic_banner_shapes(self):
        self.assertEqual(extract_version("jquery", "/*! jQuery v3.4.1 | (c) JS Foundation */"), "3.4.1")
        self.assertEqual(extract_version("jquery", "jQuery JavaScript Library v1.12.4"), "1.12.4")
        self.assertEqual(extract_version("lodash", '_.VERSION="4.17.15";'), "4.17.15")
        self.assertEqual(extract_version("axios", "axios v0.21.1"), "0.21.1")
        self.assertEqual(extract_version("bootstrap", "Bootstrap v4.1.3"), "4.1.3")
        self.assertEqual(extract_version("underscore", "//     Underscore.js 1.9.1"), "1.9.1")

    def test_no_version_is_none(self):
        self.assertIsNone(extract_version("jquery", "el.html(x);"))
        self.assertIsNone(extract_version("not-a-library", "jQuery v3.4.1"))


class VulnerabilityMatchTest(unittest.TestCase):
    def test_vulnerable_and_patched_versions(self):
        self.assertTrue(match_vulnerabilities("jquery", "3.4.1"))
        self.assertEqual(match_vulnerabilities("jquery", "3.5.0"), [])
        self.assertEqual(match_vulnerabilities("lodash", "4.17.21"), [])
        self.assertTrue(any(v["cve"] == "CVE-2020-8203"
                            for v in match_vulnerabilities("lodash", "4.17.15")))

    def test_no_version_no_claim(self):
        self.assertEqual(match_vulnerabilities("jquery", None), [])

    def test_every_advisory_carries_a_cve_and_severity(self):
        for lib in LIBRARY_INTEL.values():
            for vuln in lib["vulnerabilities"]:
                self.assertTrue(vuln["cve"].startswith("CVE-"))
                self.assertIn(vuln["severity"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
                self.assertTrue(vuln["summary"])


class ScanIntegrationTest(unittest.TestCase):
    def test_vulnerable_bundle_produces_attributed_finding(self):
        code = (
            "/*! jQuery v3.4.1 | (c) JS Foundation */\n"
            "var x = window.jQuery;\n"
        )
        results = scan_content(code, filename="app.js")
        dep = next(d for d in results["dependency_scan"] if d.get("source") == "jquery")
        self.assertEqual(dep.get("version"), "3.4.1")
        self.assertTrue(dep.get("vulnerabilities"))

        finding = next(f for f in results["findings"]
                       if str(f.get("id", "")).startswith("vulnerable_dependency"))
        self.assertIn("CVE-2020-11022", finding.get("type", ""))
        self.assertEqual(finding["confidence"], "medium", "version fingerprints are honest, not proof")
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_patched_version_annotates_without_finding(self):
        # The inventory detector keys on the "lodash" marker; `_.VERSION`
        # alone is an API alias it deliberately does not guess from.
        code = '_.VERSION = "4.17.21";\n/* lodash 4.17.21 */ var x = _.map([1,2], function(v){return v;});\n'
        results = scan_content(code, filename="app.js")
        dep = next(d for d in results["dependency_scan"] if d.get("source") == "lodash")
        self.assertEqual(dep.get("version"), "4.17.21")
        self.assertEqual(dep.get("vulnerabilities"), [])
        self.assertFalse(any(str(f.get("id", "")).startswith("vulnerable_dependency")
                             for f in results["findings"]))

    def test_unversioned_library_stays_inventory(self):
        code = "var crypto = require('crypto-js');\n"
        results = scan_content(code, filename="app.js")
        dep = next(d for d in results["dependency_scan"] if d.get("source") == "crypto-js")
        self.assertNotIn("version", dep)
        self.assertEqual(dep.get("vulnerabilities"), [])

    def test_check_dependencies_leaves_unknown_libraries_alone(self):
        entries = [{"name": "React", "source": "react", "kind": "framework"}]
        signals = check_dependencies(entries, "React.createElement()")
        self.assertEqual(signals, [])
        self.assertNotIn("version", entries[0])


if __name__ == "__main__":
    unittest.main()
