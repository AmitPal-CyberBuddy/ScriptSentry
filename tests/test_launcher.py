"""One-file launcher (scriptsentry.py) safety and dependency checks.

The launcher downloads a tarball from GitHub and unpacks it into the user
cache. Its archive handling must never let a crafted (or swapped) archive
escape the extraction directory, and its dependency list must actually cover
the importable modules it checks for.
"""
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scriptsentry


def _tar_gz(members):
    """Build an in-memory .tar.gz from (name, type, payload, linkname) tuples."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, kind, payload, linkname in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = linkname
                tar.addfile(info)
                continue
            data = payload.encode("utf-8")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class SafePathTest(unittest.TestCase):
    def test_safe_paths_pass(self):
        for path in ("server.py", "webui/tool/index.html", "core/tree_sitter_ast.py",
                     "ai/llm_engine.py", "tests/corpus/x y.js"):
            self.assertTrue(scriptsentry._safe_archive_path(path), path)

    def test_traversal_paths_are_rejected(self):
        for path in ("../evil.py", "core/../../evil.py", "a/../b", "../../../tmp/evil",
                     "/etc/passwd", "core//x.py", "./x.py", "", "a\x00b.py", ".."):
            self.assertFalse(scriptsentry._safe_archive_path(path), path)

    def test_link_targets_are_rejected_when_outside(self):
        self.assertTrue(scriptsentry._safe_link_target("core/module.py"))
        self.assertTrue(scriptsentry._safe_link_target("assets/icon.png"))
        for target in ("../../etc/passwd", "/etc/passwd", "", "../x", ".."):
            self.assertFalse(scriptsentry._safe_link_target(target), target)


class ExtractEngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scriptsentry-test-")
        self.addCleanup(self._tmp.cleanup)
        self.cache = Path(self._tmp.name) / "cache"

    def _extract(self, archive):
        with mock.patch.object(scriptsentry, "BOOTSTRAP_DIR", self.cache):
            return scriptsentry.extract_engine(archive)

    def test_benign_archive_extracts(self):
        archive = _tar_gz([
            ("ScriptSentry-main/core/analyzer_service.py", tarfile.REGTYPE, "print('hi')", ""),
            ("ScriptSentry-main/server.py", tarfile.REGTYPE, "print('server')", ""),
            ("ScriptSentry-main/webui/index.html", tarfile.REGTYPE, "<!doctype html>", ""),
        ])
        target = self._extract(archive)
        self.assertTrue((target / "core" / "analyzer_service.py").is_file())
        self.assertTrue((target / "server.py").is_file())
        self.assertTrue((target / "webui" / "index.html").is_file())

    def test_dotdot_member_is_rejected(self):
        archive = _tar_gz([
            ("ScriptSentry-main/../../tmp/scriptsentry-evil.txt", tarfile.REGTYPE, "pwn", ""),
        ])
        with self.assertRaises(RuntimeError):
            self._extract(archive)

    def test_absolute_member_is_rejected(self):
        archive = _tar_gz([
            ("ScriptSentry-main//etc/cron.d/evil", tarfile.REGTYPE, "pwn", ""),
        ])
        with self.assertRaises(RuntimeError):
            self._extract(archive)

    def test_subdirectory_escape_is_rejected(self):
        archive = _tar_gz([
            ("ScriptSentry-main/core/../evil.txt", tarfile.REGTYPE, "pwn", ""),
        ])
        with self.assertRaises(RuntimeError):
            self._extract(archive)

    def test_escaping_symlink_is_rejected(self):
        archive = _tar_gz([
            ("ScriptSentry-main/server.py", tarfile.REGTYPE, "print('server')", ""),
            ("ScriptSentry-main/evil", tarfile.SYMTYPE, "", "../../../etc/passwd"),
        ])
        with self.assertRaises(RuntimeError):
            self._extract(archive)

    def test_archive_without_engine_files_is_rejected(self):
        archive = _tar_gz([
            ("ScriptSentry-main/README.txt", tarfile.REGTYPE, "not the engine", ""),
        ])
        with self.assertRaises(RuntimeError):
            self._extract(archive)


class UpdateFlagTest(unittest.TestCase):
    """The launcher's cache contract.

    A plain run reuses a previously downloaded engine forever and never hits
    the network again — which is exactly why 'my fix never arrived' looked
    like the fix not working. ``--update`` is the explicit way out, and the
    startup banner must say which build is being served.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="scriptsentry-upd-")
        self.addCleanup(self._tmp.cleanup)
        self.cache = Path(self._tmp.name) / "cache"
        # A launcher location that has no engine next to it, so main() takes
        # the bootstrap/cache path instead of "engine found next to launcher".
        self.launcher_dir = Path(self._tmp.name) / "elsewhere"
        self.launcher_dir.mkdir()

    def _seed_cache(self, marker: str) -> Path:
        cached = self.cache / "bootstrap" / "main"
        (cached / "core").mkdir(parents=True)
        (cached / "server.py").write_text(marker, encoding="utf-8")
        (cached / "core" / "analyzer_service.py").write_text(marker, encoding="utf-8")
        return cached

    def _run_main(self, argv):
        engine_dirs = []
        archive = _tar_gz([
            ("ScriptSentry-main/server.py", tarfile.REGTYPE, "NEW ENGINE", ""),
            ("ScriptSentry-main/core/analyzer_service.py", tarfile.REGTYPE, "NEW ENGINE", ""),
        ])
        with mock.patch.object(scriptsentry, "BOOTSTRAP_DIR", self.cache / "bootstrap"), \
             mock.patch.object(scriptsentry, "__file__", str(self.launcher_dir / "scriptsentry.py")), \
             mock.patch.object(scriptsentry, "download_archive", return_value=archive) as download, \
             mock.patch.object(scriptsentry, "install_dependencies"), \
             mock.patch.object(
                 scriptsentry, "run_server",
                 side_effect=lambda engine_dir, server_args: engine_dirs.append(engine_dir),
             ), \
             mock.patch.object(sys, "argv", argv):
            rc = scriptsentry.main()
        return rc, download.call_count, engine_dirs

    def test_plain_run_reuses_cache_without_downloading(self):
        cached = self._seed_cache("OLD ENGINE")
        rc, downloads, engine_dirs = self._run_main(["scriptsentry.py"])
        self.assertEqual(rc, 0)
        self.assertEqual(downloads, 0, "a plain run must not re-download the engine")
        self.assertEqual(engine_dirs, [cached])
        self.assertEqual((cached / "server.py").read_text(encoding="utf-8"), "OLD ENGINE")

    def test_update_discards_cache_and_downloads_fresh_engine(self):
        cached = self._seed_cache("OLD ENGINE")
        rc, downloads, engine_dirs = self._run_main(["scriptsentry.py", "--update"])
        self.assertEqual(rc, 0)
        self.assertEqual(downloads, 1)
        self.assertEqual(engine_dirs, [cached], "the fresh engine must land at the cache path")
        self.assertEqual((cached / "server.py").read_text(encoding="utf-8"), "NEW ENGINE")
        self.assertTrue((cached / scriptsentry.META_NAME).is_file())

    def test_download_meta_roundtrip(self):
        engine = self._seed_cache("OLD ENGINE")
        self.assertEqual(scriptsentry._downloaded_at(engine), "unknown")
        scriptsentry._write_download_meta(engine)
        stamp = scriptsentry._downloaded_at(engine)
        self.assertNotEqual(stamp, "unknown")
        self.assertIn("T", stamp, "timestamp should be ISO-8601")


class DependenciesTest(unittest.TestCase):
    def test_required_packages_include_the_preferred_ast_engine(self):
        # tree-sitter is the engine's first-choice parser; the launcher's
        # fallback install path must never silently leave it out.
        self.assertIn("tree-sitter", scriptsentry.REQUIRED_PACKAGES)
        self.assertIn("tree-sitter-javascript", scriptsentry.REQUIRED_PACKAGES)
        self.assertIn("tree-sitter-typescript", scriptsentry.REQUIRED_PACKAGES)

    def test_import_names_map_to_real_modules(self):
        for dist_name, mod in scriptsentry.IMPORT_NAMES.items():
            self.assertTrue(mod.replace("_", "-") == dist_name or mod == "bs4",
                            f"{dist_name} -> {mod} mapping looks wrong")

    def test_fallback_warning_covers_tree_sitter(self):
        # The printed guidance must mention the preferred parser, not just esprima.
        src = Path(scriptsentry.__file__).read_text(encoding="utf-8")
        self.assertIn("tree-sitter", src)
        self.assertIn("Installing tree-sitter", src)


if __name__ == "__main__":
    unittest.main()
