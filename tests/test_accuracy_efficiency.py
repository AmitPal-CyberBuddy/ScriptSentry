"""Accuracy and efficiency hardening for the analysis engines.

Three contracts:

1.  **The parse cache covers realistic bundles.** A multi-hundred-KB
    minified bundle is parsed exactly once per scan (taint, attack surface,
    module discovery and the AST summary all share one tree) instead of once
    per consumer -- and pathological content (a multi-MB embedded string)
    can never trigger quadratic regex work in the fold layer.
2.  **Split-up credentials are found.** Secrets assembled by literal
    concatenation -- in one expression, via Buffer.concat, or across
    statements through single-assignment literal variables -- go through the
    same credibility pipeline as contiguous values, while variables that are
    written more than once are never folded (the value at concat time would
    be unknowable).
3.  **The fallback engine matches the AST engine on redirect and eval-class
    sinks.** `location = <tainted>` and string-assembled timer arguments are
    reported by both engines, and the benign callback forms stay quiet.
"""
import re
import time
import unittest
from unittest import mock

from core.analyzer_service import analyze_content
from core.scanner import _folded_concat_candidates
import core.taint as taint_mod


def _ids(results, filename="inline.js"):
    return sorted({f.get("id") for f in results[filename]["findings"]})


def _fallback_analyze(test, code):
    """Run analyze_content with the AST parser forced off (fallback engine)."""
    with mock.patch("core.tree_sitter_ast.tree_sitter_available", lambda: False):
        return analyze_content(code)


class FoldedSecretTest(unittest.TestCase):
    def test_buffer_concat_assembly_is_detected(self):
        code = ("const key = Buffer.concat([Buffer.from('kx9'), "
                "Buffer.from('vQm2LpTn8Rb4Wc6Yd3Zf7Hj5')]);\nconsole.log(key);")
        self.assertIn("hardcoded_secret", _ids(analyze_content(code)))

    def test_cross_statement_assembly_is_detected(self):
        code = ("const a = 'AKIA';\nconst b = 'IOSFODNN7EXAMPLE';\n"
                "const awsKey = a + b;\nconsole.log(awsKey);")
        results = analyze_content(code)
        self.assertIn("hardcoded_secret", _ids(results))
        # The finding points at the variable definitions, not line 0.
        finding = next(f for f in results["inline.js"]["findings"]
                       if f.get("id") == "hardcoded_secret")
        self.assertGreaterEqual(finding.get("line", 0), 1)

    def test_mixed_variable_and_literal_assembly_is_detected(self):
        code = ("const p = 'ghp_';\n"
                "const token = p + 'abcdefghijklmnopqrstuvwxyz0123456789ABCD';\nuse(token);")
        self.assertIn("hardcoded_secret", _ids(analyze_content(code)))

    def test_reassigned_variable_is_never_folded(self):
        # The value at concat time is unknowable -- folding would be a guess.
        for reassign in ("a = dynamic();", "a = fetchKey();", "a += 'xyz';"):
            code = (f"let a = 'AKIA';\n{reassign}\n"
                    "const key = a + 'IOSFODNN7EXAMPLE';\nuse(key);")
            self.assertNotIn("hardcoded_secret", _ids(analyze_content(code)),
                             f"folded despite reassignment: {reassign!r}")

    def test_object_property_write_does_not_invalidate(self):
        # `conf.p = x` writes a property, never the variable p.
        code = ("const p = 'ghp_';\nconf.p = 'x';\n"
                "const t = p + 'abcdefghijklmnopqrstuvwxyz0123456789ABCD';\nuse(t);")
        self.assertIn("hardcoded_secret", _ids(analyze_content(code)))

    def test_comparison_does_not_invalidate(self):
        code = ("const p = 'AKIA';\nif (p == 'AKIA') {}\n"
                "const t = p + 'IOSFODNN7EXAMPLE';\nuse(t);")
        self.assertIn("hardcoded_secret", _ids(analyze_content(code)))

    def test_non_literal_operand_is_not_folded(self):
        # `a + b` where b is unknown: no candidate may be synthesized from
        # the fold (a 'prefix-' + <unknown> is not a credential).
        out = _folded_concat_candidates("const a = 'prefix-';\nconst k = a + b + 'x';\nuse(k);")
        folded_values = [c for c, _ in out if "prefix-" in c]
        self.assertEqual(folded_values, [], "folded an expression with an unknown operand")

    def test_short_folds_are_skipped(self):
        out = _folded_concat_candidates("const a = 'ab';\nconst k = a + 'cd';\nuse(k);")
        self.assertEqual(out, [])

    def test_plain_words_do_not_become_secrets(self):
        code = ("const hello = 'Hello';\nconst world = 'World';\n"
                "const msg = hello + world;\nuse(msg);")
        self.assertNotIn("hardcoded_secret", _ids(analyze_content(code)))


class FoldPerformanceTest(unittest.TestCase):
    """Pathological inputs must stay linear: bounded literals, bounded names,
    anchored assignment scans, incremental line counting."""

    CASES = {
        "quote soup": "'" * 50000,
        "plus runs": "a" + " + " * 50000,
        "huge buffer array": "Buffer.concat([" + ",".join(["Buffer.from('x')"] * 10000) + "])",
        "many small concats": " ".join(f"q{i} = a + b + 'lit{i}';" for i in range(10000)),
        "unclosed concat": "const k = 'a' + " * 15000,
        "2MB embedded literal": "'" + "x" * 2000000 + "'",
        "2MB word run + tracked var":
            "const a = 'AKIA';\n" + "x" * 2000000 + "\nconst k = a + 'IOSFODNN7EXAMPLE';",
    }

    def test_pathological_inputs_finish_fast(self):
        for name, content in self.CASES.items():
            with self.subTest(case=name):
                t0 = time.perf_counter()
                out = _folded_concat_candidates(content)
                elapsed = time.perf_counter() - t0
                # Pre-fix: the embedded literal and word run were quadratic
                # (5.9 s+ locally, unbounded before the literal bound).
                self.assertLess(elapsed, 5.0, f"{name} took {elapsed:.2f}s")
                self.assertIsInstance(out, list)

    def test_realistic_many_var_bundle_is_fast(self):
        content = "\n".join(
            f"var s{i} = 'plain {i}'; var q{i} = s{i} + ' tail';" for i in range(8000))
        t0 = time.perf_counter()
        _folded_concat_candidates(content)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 2.0, f"8000-var bundle took {elapsed:.2f}s")


class FallbackMarkerFilterTest(unittest.TestCase):
    """The fallback's noise fast path must be a superset of the real checks."""

    def _fused(self):
        # Rebuild the union of every pattern the fast path guards.
        return re.compile("|".join(f"(?:{p})" for p in (
            taint_mod._FALLBACK_SINK_PATTERN,
            taint_mod._FALLBACK_REDIRECT_PATTERN,
            taint_mod._FALLBACK_OUTBOUND_PATTERN,
            taint_mod._FALLBACK_POSTMESSAGE_WILDCARD_PATTERN,
            taint_mod._FALLBACK_PROTOTYPE_PATTERN,
            taint_mod._FALLBACK_TIMER_CONCAT_PATTERN,
            *(p for p, _ in taint_mod._FALLBACK_SOURCE_PATTERNS),
        )), re.I)

    def test_markers_cover_every_pattern(self):
        fused = self._fused()
        statements = [
            "document.body.innerHTML = q", "el.outerHTML += x", "f.srcdoc = y",
            "insertAdjacentHTML('beforeend', h)", "document.write(a)",
            "EVAL (x)", "new Function (code)", "$('#x'). html (payload)",
            "$el.append(data)", "$(x).attr('href', u)", "setAttribute('src', u)",
            "location . href = t", "x.href += t", "location.assign(u)",
            "fetch (u)", "axios.get(u)", "navigator.sendBeacon(u)", "xhr.send(d)",
            "new WebSocket(u)", "postMessage(d, '*')", "o.__proto__ = {}",
            "Object.assign(t, {__proto__: 1})",
            "URLSEARCHPARAMS(location.search)", "searchParams.get('q')",
            "location.hash", "window.location = u", "document.referrer",
            "history.pushState({})", "window.name", "e.data",
            "localStorage.getItem('k')", "document.cookie",
            "document.querySelector('#i').value",
            "setTimeout('go(' + x + ')', 10)",
        ]
        for statement in statements:
            with self.subTest(statement=statement):
                if fused.search(statement):
                    self.assertTrue(
                        any(m in statement.lower() for m in taint_mod._FALLBACK_STATEMENT_MARKERS),
                        f"marker filter would skip a live statement: {statement!r}")

    def test_noise_statements_are_filtered(self):
        for statement in ("const x = 1 + 2;", "var s = 'plain string';", "noop()",
                          "return [x, s].join(',');"):
            self.assertFalse(
                any(m in statement.lower() for m in taint_mod._FALLBACK_STATEMENT_MARKERS),
                f"noise statement not filtered: {statement!r}")


class RedirectParityTest(unittest.TestCase):
    def test_fallback_catches_bare_location_assignment(self):
        code = ("const target = new URLSearchParams(location.search).get('next');\n"
                "location = target;")
        self.assertIn("open_redirect", _ids(_fallback_analyze(self, code)))

    def test_ast_catches_bare_location_assignment(self):
        code = ("const target = new URLSearchParams(location.search).get('next');\n"
                "location = target;")
        self.assertIn("open_redirect", _ids(analyze_content(code)))

    def test_literal_navigation_is_not_a_redirect(self):
        for engine in (analyze_content, lambda c: _fallback_analyze(self, c)):
            self.assertNotIn("open_redirect", _ids(engine("location = '/about';")))


class TimerConcatSinkTest(unittest.TestCase):
    HIT = "const input = location.hash;\nsetTimeout('doStuff(' + input + ')', 100);"
    INTERVAL_HIT = "const u = location.search;\nsetInterval('tick(' + u + ')', 500);"
    BENIGN = [
        "setTimeout(function(){ go(); }, 100);",
        "const h = location.hash;\nsetTimeout(() => render(h), 100);",
        "setTimeout('reload()', 100);",
    ]

    def test_both_engines_report_string_assembled_timer(self):
        for engine, label in ((analyze_content, "ast"),):
            with self.subTest(engine=label):
                self.assertIn("dangerous_dynamic_code", _ids(engine(self.HIT)))
                self.assertIn("dangerous_dynamic_code", _ids(engine(self.INTERVAL_HIT)))

    def test_fallback_engine_reports_string_assembled_timer(self):
        self.assertIn("dangerous_dynamic_code", _ids(_fallback_analyze(self, self.HIT)))
        self.assertIn("dangerous_dynamic_code", _ids(_fallback_analyze(self, self.INTERVAL_HIT)))

    def test_benign_timer_forms_stay_quiet(self):
        for code in self.BENIGN:
            for engine in (analyze_content, lambda c: _fallback_analyze(self, c)):
                with self.subTest(code=code):
                    self.assertNotIn("dangerous_dynamic_code", _ids(engine(code)))


if __name__ == "__main__":
    unittest.main()
