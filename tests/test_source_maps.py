"""Source-map ingestion: analyze the ORIGINAL sources behind minified bundles.

A production bundle ships ``//# sourceMappingURL=...`` pointing at a map that
often embeds the pre-build sources in ``sourcesContent``. Analyzing those
originals is the biggest accuracy lever for production targets: findings keep
real file names and the evidence was never mangled. These tests pin the
contract of that expansion: bounded, deduplicated, cancel-safe, and honest
when the map is missing contents or corrupt.
"""
import base64
import json
import os
import tempfile
import unittest
from unittest import mock

from core.analyzer_service import (
    SOURCEMAP_MAX_SOURCE_CHARS,
    _expand_source_map_sources,
    analyze_content,
)
from core.source_maps import clean_source_name, inspect_source_map, load_source_map


SECRET_SOURCE = (
    "const slackToken = 'xoxb-123456789-abcdefghijklmnopqrstuv';\n"
    "export default slackToken;\n"
)
FLOW_SOURCE = (
    "const q = new URLSearchParams(location.search).get('q');\n"
    "document.getElementById('out').innerHTML = q;\n"
)
PLAIN_SOURCE = "export const version = '1.2.3';\n"


def make_bundle(sources, sources_content=None, with_map=True):
    """A tiny 'minified bundle' with an inline base64 source map."""
    body = "var a=1;function f(x){return x*2}f(2);\n"
    if with_map:
        the_map = json.dumps({
            "version": 3,
            "file": "app.min.js",
            "sources": sources,
            "sourcesContent": sources_content if sources_content is not None
            else [SECRET_SOURCE, FLOW_SOURCE][: len(sources)],
            "mappings": "AAAA",
        })
        body += ("//# sourceMappingURL=data:application/json;base64,"
                 + base64.b64encode(the_map.encode()).decode() + "\n")
    return body


def analyze(code, **kwargs):
    return analyze_content(code, filename="app.min.js", **kwargs)


class SourceMapLoadTest(unittest.TestCase):
    def test_inline_map_yields_named_contents(self):
        bundle = make_bundle(["webpack://demo/./src/config.ts", "webpack://demo/./src/dom.ts"])
        metadata, contents = load_source_map(bundle, base_url="")
        self.assertTrue(metadata["present"])
        self.assertTrue(metadata["available"])
        self.assertEqual(metadata["sources_content_count"], 2)
        names = [name for name, _ in contents]
        self.assertEqual(names, ["./src/config.ts", "./src/dom.ts"],
                         "webpack:// pseudo-URLs must clean up to readable paths")
        self.assertEqual(dict(contents)["./src/config.ts"], SECRET_SOURCE)

    def test_map_without_embedded_contents_is_metadata_only(self):
        bundle = make_bundle(["./src/a.ts"], sources_content=[None])
        metadata, contents = load_source_map(bundle)
        self.assertTrue(metadata["available"])
        self.assertEqual(contents, [])
        self.assertEqual(metadata["sources_content_count"], 0)

    def test_corrupt_inline_map_degrades_without_raising(self):
        bundle = "var x=1;\n//# sourceMappingURL=data:application/json;base64,!!!notbase64!!!\n"
        metadata, contents = load_source_map(bundle)
        self.assertFalse(metadata["available"])
        self.assertEqual(contents, [])
        self.assertTrue(metadata.get("note"))

    def test_no_reference_is_not_present(self):
        metadata, contents = load_source_map("var x=1;\n")
        self.assertFalse(metadata["present"])
        self.assertEqual(contents, [])

    def test_inspect_source_map_stays_metadata_only(self):
        bundle = make_bundle(["./src/config.ts"])
        metadata = inspect_source_map(bundle, base_url="")
        self.assertTrue(metadata["available"])
        self.assertNotIn("sources_analyzed", metadata)


class CleanSourceNameTest(unittest.TestCase):
    def test_loader_prefixes_and_schemes_are_stripped(self):
        self.assertEqual(clean_source_name("webpack://app/./src/App.tsx"), "./src/App.tsx")
        self.assertEqual(
            clean_source_name("webpack://app/./src/App.vue?vue&type=script&lang.ts"),
            "./src/App.vue?vue&type=script&lang.ts")
        self.assertEqual(clean_source_name("src/App.tsx", source_root="packages/web"),
                         "packages/web/src/App.tsx")
        self.assertEqual(clean_source_name(""), "")

    def test_loader_chains_keep_the_final_segment(self):
        self.assertEqual(
            clean_source_name("webpack://app/./src/App.tsx!./loaders/babel.ts"),
            "./loaders/babel.ts")


class SourceMapExpansionTest(unittest.TestCase):
    def test_original_sources_produce_attributed_findings(self):
        result = analyze(make_bundle(["webpack://demo/./src/config.ts", "webpack://demo/./src/dom.ts"]))
        data = result["app.min.js"]
        sm = data["source_map"]
        self.assertEqual(sm["analyzed_sources"], 2)
        self.assertEqual(sm["sources_findings"], 3)

        merged = [f for f in data["findings"] if f.get("via") == "source_map"]
        by_file = {f["file"] for f in merged}
        self.assertIn("./src/config.ts", by_file)
        self.assertIn("./src/dom.ts", by_file)
        # The secret found in the ORIGINAL file keeps its real name...
        secret = next(f for f in merged if f["id"] == "hardcoded_secret")
        self.assertEqual(secret["file"], "./src/config.ts")
        # ...and points back at the bundle it was shipped inside.
        self.assertIn("via source map", secret["origin"])

    def test_bundle_with_source_map_still_scans_the_bundle_itself(self):
        # The expansion is additive: the mangled bundle's own findings stay.
        result = analyze(make_bundle(["./src/dom.ts"]))
        data = result["app.min.js"]
        own = [f for f in data["findings"] if not f.get("via")]
        self.assertTrue(own, "bundle's own analysis must remain in the findings list")

    def test_duplicate_source_content_is_analyzed_once(self):
        result = analyze(make_bundle(["./src/a.ts", "./src/b.ts"],
                                     sources_content=[SECRET_SOURCE, SECRET_SOURCE]))
        sm = result["app.min.js"]["source_map"]
        self.assertEqual(sm["analyzed_sources"], 1)
        self.assertTrue(any(r.startswith("duplicate_source:") for r in sm.get("analysis_skipped", [])))

    def test_oversized_source_is_skipped_with_a_note(self):
        huge = "const pad = '" + "a" * (SOURCEMAP_MAX_SOURCE_CHARS + 10) + "';\n"
        result = analyze(make_bundle(["./src/huge.ts"], sources_content=[huge]))
        sm = result["app.min.js"]["source_map"]
        self.assertEqual(sm["analyzed_sources"], 0)
        self.assertTrue(any(r.startswith("oversized_source:") for r in sm.get("analysis_skipped", [])))

    def test_source_cap_is_respected(self):
        sources = [f"./src/mod{i}.ts" for i in range(20)]
        # Distinct content per source: identical sources dedupe before the
        # cap is reached, which would make this test vacuous.
        contents = [PLAIN_SOURCE + f"// variant {i}\n" for i in range(20)]
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_SOURCEMAP_SOURCES": "3"}):
            result = analyze(make_bundle(sources, sources_content=contents))
        sm = result["app.min.js"]["source_map"]
        self.assertEqual(sm["analyzed_sources"], 3)
        self.assertIn("source_cap_reached", sm.get("analysis_skipped", []))

    def test_kill_switch_disables_expansion(self):
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_SOURCEMAP_ANALYSIS": "0"}):
            result = analyze(make_bundle(["./src/config.ts"]))
        sm = result["app.min.js"]["source_map"]
        self.assertEqual(sm.get("analyzed_sources", 0), 0)
        self.assertIn("disabled", sm.get("analysis_note", ""))

    def test_expansion_reports_progress_events(self):
        events = []
        bundle = make_bundle(["./src/config.ts", "./src/dom.ts"])
        analyze(bundle, progress_callback=lambda **kw: events.append(kw))
        self.assertTrue(any("source map" in str(e.get("message") or "") for e in events),
                        "per-source analysis must show up as heartbeat-style progress events")

    def test_expansion_honors_cancel(self):
        from core.scanner import ScanCancelled

        bundle = make_bundle(["./src/config.ts", "./src/dom.ts"])
        metadata, contents = load_source_map(bundle, base_url="")
        data = {"findings": [], "content_sha256": "x" * 64, "url": ""}
        with self.assertRaises(ScanCancelled):
            _expand_source_map_sources(data, metadata, contents, "",
                                       cancel_check=lambda: True)
        # A cancelled expansion must not leave a half-populated record.
        self.assertNotIn("sources_analyzed", metadata)

    def test_bundle_with_large_inline_map_analyzes_promptly(self):
        # Regression guard for a quadratic regex in the crypto extractor: a
        # production bundle with a multi-hundred-KB *single-line* base64
        # source-map blob used to take minutes in extract_crypto_material
        # (every position scanned to end-of-line looking for ')'). Pre-fix
        # this test ran longer than 240s; post-fix the whole analysis is a
        # few seconds. The bound stays generous for slow CI machines.
        import time

        big_value = "const config = '" + "a" * 300_000 + "';\n"
        bundle = make_bundle(["./src/config.ts"], sources_content=[big_value])
        self.assertGreater(len(bundle), 300_000)
        started = time.perf_counter()
        result = analyze(bundle)
        elapsed = time.perf_counter() - started
        self.assertTrue(result["app.min.js"]["source_map"]["present"])
        self.assertLess(elapsed, 15.0,
                        f"analyzing a large inline-map bundle took {elapsed:.1f}s -- quadratic regex regression?")

    def test_expansion_merges_findings_findings_cap_stays_bounded(self):
        bundle = make_bundle(["./src/config.ts", "./src/dom.ts"])
        data = {"findings": [{"id": "seed", "severity": "LOW"}] * 80,
                "content_sha256": "x" * 64, "url": "https://example.com/app.min.js"}
        metadata, contents = load_source_map(bundle, base_url="")
        _expand_source_map_sources(data, metadata, contents, "https://example.com/app.min.js")
        self.assertEqual(metadata["analyzed_sources"], 2)
        # 80 own + merged, still under the raised-but-bounded cap.
        self.assertLessEqual(len(data["findings"]), 80 + 40)


if __name__ == "__main__":
    unittest.main()
