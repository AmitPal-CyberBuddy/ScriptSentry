"""CLI local-target and CI gate contracts.

The CLI accepts local files/directories alongside URLs (same
``analyze_files`` pipeline as the dashboard), writes every report format to a
configurable ``--output`` directory, and gates CI on ``--fail-on``:
exit 0 = clean (or below threshold), 1 = actionable findings at/above the
threshold, 2 = operational error (nothing scanned). Observations never fail
a build.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

import main as cli


SECRET_JS = (
    'const apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
    "const q = new URLSearchParams(location.search).get('q');\n"
    "document.getElementById('x').innerHTML = q;\n"
)
CLEAN_JS = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));\n"


class TrustedNamesTest(unittest.TestCase):
    """CLI scans keep repo-relative paths (SARIF mapping); uploads don't."""

    def test_uploads_still_strip_to_basename(self):
        from core.analyzer_service import _safe_local_filename
        self.assertEqual(_safe_local_filename("../../etc/evil.js", 0), "evil.js")
        self.assertEqual(_safe_local_filename("a\\b.js", 0), "b.js")

    def test_trusted_names_keep_relative_paths_without_escapes(self):
        from core.analyzer_service import _safe_local_filename

        def keep(name):
            return _safe_local_filename(name, 0, keep_path=True)

        self.assertEqual(keep("webui/src/app/x.js"), "webui/src/app/x.js")
        self.assertEqual(keep("/abs/path/y.js"), "abs/path/y.js")
        self.assertEqual(keep("../escape/z.js"), "escape/z.js")
        self.assertEqual(keep("a\\b\\c.js"), "a/b/c.js")

    def test_cli_scan_keys_are_repo_relative(self):
        with tempfile.TemporaryDirectory(prefix="ss-cli-rel-") as root:
            os.makedirs(os.path.join(root, "src", "lib"))
            with open(os.path.join(root, "src", "lib", "app.js"), "w", encoding="utf-8") as fh:
                fh.write(SECRET_JS)
            with tempfile.TemporaryDirectory(prefix="ss-cli-out-") as out:
                results = cli.run([os.path.join(root, "src")],
                                  output_formats=["txt"], output_dir=out)
            self.assertIn(os.path.join("lib", "app.js"), results,
                          "results keys must be relative to the scanned target")


class ParserTest(unittest.TestCase):
    def test_targets_are_positional_and_fail_on_has_choices(self):
        args = cli.build_parser().parse_args(["./dist", "bundle.js", "--fail-on", "high"])
        self.assertEqual(args.targets, ["./dist", "bundle.js"])
        self.assertEqual(args.fail_on, "high")
        self.assertEqual(args.output, "output")

    def test_fail_on_defaults_to_none(self):
        args = cli.build_parser().parse_args(["https://x.test/"])
        self.assertEqual(args.fail_on, "none")


class TargetClassificationTest(unittest.TestCase):
    def test_is_url(self):
        self.assertTrue(cli.is_url("https://example.com"))
        self.assertTrue(cli.is_url("http://example.com"))
        self.assertFalse(cli.is_url("./dist"))
        self.assertFalse(cli.is_url("bundle.js"))


class CollectLocalFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ss-cli-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def _write(self, rel, content):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_single_file_is_read_with_relative_name(self):
        path = self._write("app.js", SECRET_JS)
        files, errors = cli.collect_local_files([path])
        self.assertEqual(errors, [])
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["filename"], "app.js")
        self.assertIn("apiKey", files[0]["code"])

    def test_directory_walk_finds_js_and_skips_vendored_dirs(self):
        self._write("src/a.js", SECRET_JS)
        self._write("src/b.ts", "const x: number = 1;\n")
        self._write("src/node_modules/vendored/c.js", SECRET_JS)
        self._write("src/README.md", "not javascript")
        files, errors = cli.collect_local_files([os.path.join(self.root, "src")])
        self.assertEqual(errors, [])
        names = sorted(f["filename"].replace("\\", "/").split("/")[-1] for f in files)
        self.assertEqual(names, ["a.js", "b.ts"])

    def test_missing_path_is_reported_not_raised(self):
        files, errors = cli.collect_local_files([os.path.join(self.root, "nope.js")])
        self.assertEqual(files, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("no such file", errors[0])

    def test_empty_files_are_skipped(self):
        self._write("empty.js", "   \n")
        files, errors = cli.collect_local_files([os.path.join(self.root, "empty.js")])
        self.assertEqual(files, [])
        self.assertEqual(errors, [])

    def test_file_cap_is_enforced(self):
        self._write("a.js", SECRET_JS)
        files, _ = cli.collect_local_files([self.root], max_files=1)
        self.assertEqual(len(files), 1)


class FailOnGateTest(unittest.TestCase):
    def _results(self, severity, observation=False):
        return {"app.js": {"findings": [
            {"id": "x", "severity": severity, "observation": observation},
        ]}}

    def test_observations_never_fail_the_build(self):
        rank, count = cli.worst_actionable_severity(self._results("CRITICAL", observation=True))
        self.assertEqual((rank, count), (-1, 0))

    def test_worst_severity_and_count(self):
        results = {"a.js": {"findings": [
            {"id": "x", "severity": "LOW", "observation": False},
            {"id": "y", "severity": "HIGH", "observation": False},
        ]}, "b.js": {"findings": [
            {"id": "z", "severity": "HIGH", "observation": False},
        ]}}
        self.assertEqual(cli.worst_actionable_severity(results), (cli.SEVERITY_RANK["HIGH"], 2))

    def test_unknown_severity_is_ignored(self):
        rank, count = cli.worst_actionable_severity(self._results("WEIRD"))
        self.assertEqual((rank, count), (-1, 0))

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory(prefix="ss-cli-run-") as out:
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
                fh.write(SECRET_JS)
                path = fh.name
            self.addCleanup(os.unlink, path)
            # The snippet has HIGH findings (secret + DOM injection): fail-on
            # high must exit 1, fail-on critical exits 0, none exits 0.
            for threshold, expected in (("high", 1), ("critical", 0), ("none", 0)):
                with self.subTest(threshold=threshold):
                    code = cli.main([path, "--format", "json", "--output", out,
                                     "--fail-on", threshold])
                    self.assertEqual(code, expected, f"--fail-on {threshold}")
            # Reports land in the requested directory.
            self.assertTrue(os.path.exists(os.path.join(out, "report.json")))
            with open(os.path.join(out, "report.json"), encoding="utf-8") as handle:
                payload = json.load(handle)
            # A directly-loadable document (not a double-encoded JSON string).
            self.assertIsInstance(payload, dict)
            self.assertTrue(payload["executive_summary"]["verdict"])

    def test_main_operational_error_exits_two(self):
        code = cli.main(["/definitely/not/a/real/path.js", "--format", "txt"])
        self.assertEqual(code, 2)


class MixedTargetsTest(unittest.TestCase):
    def test_dead_url_does_not_kill_local_results(self):
        with tempfile.TemporaryDirectory(prefix="ss-cli-run-") as out:
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
                fh.write(SECRET_JS)
                path = fh.name
            self.addCleanup(os.unlink, path)
            basename = os.path.basename(path)
            with mock.patch("main.analyze_url", side_effect=RuntimeError("boom")):
                results = cli.run([path, "https://dead.example/x.js"],
                                  output_formats=["txt"], output_dir=out)
            file_keys = [k for k in results if not str(k).startswith("__")]
            self.assertTrue(any(k == basename for k in file_keys),
                            "local results must survive a dead URL")
            self.assertTrue(results[basename].get("findings"),
                            "the local scan must produce findings")

    def test_all_targets_dead_raises_value_error(self):
        with mock.patch("main.analyze_url", side_effect=RuntimeError("boom")), \
                self.assertRaises(ValueError):
            cli.run(["https://dead.example/x.js"], output_formats=["txt"])


if __name__ == "__main__":
    unittest.main()
