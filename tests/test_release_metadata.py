"""Release-metadata consistency checks.

These guard the habit of keeping project metadata in sync on a significant
change: the single version source (`core/version.py`), `release.json`, the
change history (`CHANGELOG.md`), and every place that advertises the engine
version to users (health API, report payload, SARIF export).
"""
import collections
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

    def test_wheel_data_files_ship_a_servable_dashboard(self):
        """``pip install .`` must ship a servable dashboard.

        ``api.settings._resolve_web_root`` serves from
        ``share/scriptsentry/webui`` inside the installed tree. setuptools
        data-files does NOT preserve source subdirectories: each source file
        lands directly in its *destination* directory. So the mapping must
        use one destination per UI subdirectory — otherwise
        ``webui/home/index.html``, ``webui/tool/index.html`` and
        ``webui/changelog/index.html`` collapse into the top-level
        ``index.html`` (last one wins) and an installed server serves the
        wrong page at "/". This test reconstructs the installed layout from
        pyproject.toml and compares it to the shipped directory tree.
        """
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        # Parse the simple `"dest" = [ ... ]` structure without tomllib
        # (this suite also runs on the 3.10 CI leg).
        entries = {}
        current = None
        for raw_line in pyproject.splitlines():
            m = re.match(r'^\s*"([^"]+)"\s*=\s*\[$', raw_line)
            if m:
                current = m.group(1)
                entries[current] = []
                continue
            if current is None:
                continue
            m = re.match(r'^\s*"([^"]+)",?$', raw_line)
            if m:
                entries[current].append(m.group(1))
            elif raw_line.strip() == "]":
                current = None

        self.assertTrue(entries, "could not parse [tool.setuptools.data-files]")

        # Reconstruct the installed tree: dest dir + source basename.
        installed = set()
        seen_per_dest = collections.defaultdict(set)
        for dest, sources in entries.items():
            for src in sources:
                base = src.rsplit("/", 1)[-1]
                installed.add(f"{dest}/{base}")
                norm_dest = re.sub(r"^share/scriptsentry/", "", dest).rstrip("/")
                if base in seen_per_dest[norm_dest]:
                    self.fail(f"duplicate basename {base!r} in the same destination "
                              f"({norm_dest}) — setuptools flattens it, the wrong "
                              "file wins in the wheel")
                seen_per_dest[norm_dest].add(base)

        # Every runtime UI file must be shipped exactly as the server expects it.
        expected = {
            "webui/app.js",
            "webui/styles.css",
            "webui/config.js",
            "webui/index.html",
            "webui/404.html",
            "webui/home/index.html",
            "webui/tool/index.html",
            "webui/changelog/index.html",
            "webui/assets/favicon.svg",
            "webui/assets/favicon-32.png",
            "webui/assets/apple-touch-icon.png",
            "webui/assets/icon-192.png",
            "webui/assets/icon-512.png",
            "webui/assets/og-card.png",
            "webui/assets/site.webmanifest",
        }
        self.assertEqual(
            installed,
            {f"share/scriptsentry/{p}" for p in expected},
            "installed webui layout must match the served tree exactly",
        )

    def test_wheel_ships_every_runtime_python_package(self):
        """The installed ``scriptsentry-server`` must be importable.

        ``api`` was once left out of ``[tool.setuptools.packages.find]``: the
        wheel installed fine but the console script died immediately on
        ``from api import …``. Every first-party package the server imports
        must be covered.
        """
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        include = re.search(r'packages\s*=\s*\{ find = \{ include = \[([^\]]*)\]', pyproject)
        self.assertIsNotNone(include, "packages.find.include must be declared")
        patterns = re.findall(r'"([^"]+)"', include.group(1))
        runtime_packages = ["ai", "analyzers", "api", "core"]
        for pkg in runtime_packages:
            self.assertTrue(
                any(pkg in pattern for pattern in patterns),
                f"packages.find.include must cover '{pkg}' so the installed "
                "wheel can import it",
            )
            self.assertTrue(
                any((ROOT / pkg).glob("*.py")),
                f"repo package {pkg}/ must contain modules",
            )

    def test_python_version_claims_are_consistent(self):
        """pyproject is authoritative; every other place that advertises a
        supported Python floor must agree with it."""
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'requires-python\s*=\s*"([^"]+)"', pyproject)
        self.assertIsNotNone(m, "pyproject.toml must declare requires-python")
        floor = m.group(1)

        release = json.loads((ROOT / "release.json").read_text(encoding="utf-8"))
        self.assertEqual(release["compatibility"]["python"], floor,
                         "release.json compatibility.python must match pyproject requires-python")

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"Requires Python {floor.removeprefix('>=')}+.", readme,
                      "README Quick start must quote the same Python floor")
        deployment = (ROOT / "DEPLOYMENT.md").read_text(encoding="utf-8")
        self.assertIn(f"Python {floor.removeprefix('>=')}", deployment,
                      "DEPLOYMENT.md must quote the same Python floor")

        ruff = (ROOT / "ruff.toml").read_text(encoding="utf-8")
        self.assertIn(f'target-version = "py{floor.removeprefix(">=").replace(".", "")}"', ruff,
                      "ruff target-version must match the supported floor")

    def test_no_hardcoded_old_version_in_server(self):
        server_src = (ROOT / "server.py").read_text(encoding="utf-8")
        handler_src = (ROOT / "api" / "handlers.py").read_text(encoding="utf-8")
        self.assertNotIn('"version": "2.1"', server_src)
        self.assertNotIn('"version": "2.1"', handler_src)
        # The handler's Server header is built from the real version, which
        # lives in core.version (imported under its engine alias).
        self.assertIn("_engine_version", handler_src)


if __name__ == "__main__":
    unittest.main()
