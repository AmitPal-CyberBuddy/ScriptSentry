"""Release-metadata consistency checks.

These guard the habit of keeping project metadata in sync on a significant
change: the single version source (`core/version.py`), `release.json`, the
change history (`CHANGELOG.md`), and every place that advertises the engine
version to users (health API, report payload, SARIF export).
"""
import json
import re
import unittest
from pathlib import Path

from core.reporter import build_dashboard_payload, generate_sarif_report
from core.version import ENGINE_NAME, RELEASE_STATUS, __version__, is_dev_build

ROOT = Path(__file__).resolve().parent.parent


class ReleaseMetadataTest(unittest.TestCase):
    def test_version_is_semver_like(self):
        # Pre-release builds may carry a suffix (e.g. "2.2.0-dev").
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$")

    def test_project_is_marked_under_development(self):
        # Until the first stable ship, the project must be explicitly a dev build.
        self.assertTrue(is_dev_build())
        self.assertEqual(RELEASE_STATUS, "under development")

    def test_release_json_matches_version_module(self):
        data = json.loads((ROOT / "release.json").read_text(encoding="utf-8"))
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["engine"], ENGINE_NAME)
        self.assertEqual(data["status"], RELEASE_STATUS)
        self.assertFalse(data.get("published"))
        self.assertTrue(data.get("highlights"))

    def test_changelog_has_entry_for_current_version(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(__version__, text, "CHANGELOG.md must mention the current version")

    def test_health_and_report_advertise_current_version(self):
        # Dashboard payload engine version.
        payload = build_dashboard_payload({})
        self.assertEqual(payload["meta"]["engine_version"], __version__)
        self.assertEqual(payload["meta"]["engine"], ENGINE_NAME)
        # SARIF tool version.
        sarif = json.loads(generate_sarif_report({"a.js": {"secrets": [], "keys": [], "ivs": [],
            "crypto": [], "endpoints": [], "headers": [], "storage": [], "dom_risks": [],
            "suspicious_calls": [], "hardcoded_configs": [], "decoded_strings": [],
            "risk_signals": [], "dataflows": [], "framework_findings": [], "findings": [],
            "finding_statuses": {}, "dependency_scan": [], "technology_stack": [],
            "attack_surface": {}, "ast_analysis": {}, "obfuscation_analysis": {},
            "notable_features": [], "file_size": 1}}))
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], __version__)

    def test_no_hardcoded_old_version_in_server(self):
        server_src = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertNotIn('"version": "2.1"', server_src)
        self.assertIn("ENGINE_VERSION", server_src)


if __name__ == "__main__":
    unittest.main()
