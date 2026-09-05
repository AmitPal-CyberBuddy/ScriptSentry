"""webui/app.js is a build artifact: fragments in webui/src/app/ must match.

test_progress_reporting.py reads webui/app.js directly (it is what the
pages ship), so a fragment edit without a rebuild would silently make the
tests pass against code the browser never sees. This test closes that gap.
"""
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_SCRIPT = os.path.join(ROOT, "tools", "build_webui.py")
APP_JS = os.path.join(ROOT, "webui", "app.js")


def _load_build_module():
    spec = importlib.util.spec_from_file_location("build_webui", BUILD_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class WebuiBuildTest(unittest.TestCase):
    def test_fragments_exist(self):
        mod = _load_build_module()
        fragments = sorted(f for f in os.listdir(mod.SRC_DIR) if f.endswith(".js"))
        self.assertGreaterEqual(len(fragments), 10,
                                "webui/src/app/ fragments are missing")

    def test_app_js_matches_fragments(self):
        mod = _load_build_module()
        with open(APP_JS, encoding="utf-8") as fh:
            current = fh.read()
        self.assertEqual(
            current, mod.build(),
            "webui/app.js is stale. Edit webui/src/app/, then run "
            "python3 tools/build_webui.py and commit the rebuilt app.js.",
        )

    def test_app_js_is_one_iife(self):
        # The pages load app.js directly; it must stay a single wrapped IIFE.
        with open(APP_JS, encoding="utf-8") as fh:
            src = fh.read()
        self.assertTrue(src.startswith("/* ScriptSentry Web dashboard */"))
        self.assertTrue(src.rstrip().endswith("})();"))


if __name__ == "__main__":
    unittest.main()
