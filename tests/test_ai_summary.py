"""The --ai flag must be honest: local Ollama only, deterministic fallback.

The review found the flag was cosmetic (it promised openai/azure/ollama
but never called a provider).  The contract now is:

* disabled                    -> no summary at all (None)
* ollama with server up       -> provider == "ollama", llm_text present,
                                 and the prompt carries findings, not raw code
* ollama with server down     -> provider == "ollama_unavailable", never
                                 raises, deterministic fields still present
* anything else (legacy)      -> provider == "rule_based" (never pretend
                                 an LLM answered)
* argparse rejects openai/azure at the CLI boundary
"""
import unittest
from unittest import mock

from ai.llm_engine import _ollama_prompt, build_ai_summary


RESULTS = {
    "app.js": {
        "secret_analysis": [{"kind": "api_key"}],
        "dom_risks": ["innerHTML"],
        "findings": [
            {"id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
             "confidence": "high", "source": "URL query string",
             "sink": "document.body.innerHTML = q"},
        ],
        "notable_features": ["http_client"],
    },
}


class AiSummaryContractTest(unittest.TestCase):
    def test_disabled_produces_no_summary(self):
        self.assertIsNone(build_ai_summary(RESULTS, provider="disabled"))

    def test_legacy_unknown_provider_is_rule_based_not_an_llm(self):
        summary = build_ai_summary(RESULTS, provider="openai", api_key="sk-test", model="gpt-4")
        self.assertEqual(summary["provider"], "rule_based")
        self.assertNotIn("llm_text", summary)
        self.assertTrue(summary["executive_summary"])

    @mock.patch("ai.llm_engine.requests.post")
    def test_ollama_is_called_locally_and_returns_llm_text(self, post):
        post.return_value.status_code = 200
        post.return_value.raise_for_status.return_value = None
        post.return_value.json.return_value = {"response": "Check the query reflection first."}
        summary = build_ai_summary(RESULTS, provider="ollama", model="llama3.1")
        self.assertEqual(summary["provider"], "ollama")
        self.assertEqual(summary["llm_text"], "Check the query reflection first.")
        url = post.call_args.args[0]
        self.assertTrue(url.startswith("http://localhost:11434"), url)
        payload = post.call_args.kwargs.get("json") or post.call_args.args[1]
        self.assertEqual(payload["model"], "llama3.1")
        self.assertFalse(payload["stream"])

    @mock.patch("ai.llm_engine.requests.post")
    def test_ollama_prompt_contains_findings_not_raw_source(self, post):
        post.return_value.status_code = 200
        post.return_value.raise_for_status.return_value = None
        post.return_value.json.return_value = {"response": "ok"}
        # A full source dump must never be sent, even to a local model: the
        # prompt carries structured findings only.
        with_source = dict(RESULTS)
        with_source["app.js"] = dict(RESULTS["app.js"])
        with_source["app.js"]["content"] = "const RAW_MARKER = 'x';\ndocument.body.innerHTML = q;" * 50
        build_ai_summary(with_source, provider="ollama")
        payload = post.call_args.kwargs.get("json") or post.call_args.args[1]
        prompt = payload["prompt"]
        self.assertIn("DOM injection", prompt)
        self.assertIn("URL query string", prompt)
        self.assertNotIn("RAW_MARKER", prompt)

    @mock.patch("ai.llm_engine.requests.post", side_effect=OSError("connection refused"))
    def test_ollama_down_falls_back_without_raising(self, post):
        summary = build_ai_summary(RESULTS, provider="ollama")
        self.assertEqual(summary["provider"], "ollama_unavailable")
        self.assertIn("connection refused", summary["fallback_reason"])
        self.assertTrue(summary["executive_summary"])

    @mock.patch("ai.llm_engine.requests.post")
    def test_ollama_empty_response_falls_back(self, post):
        post.return_value.status_code = 200
        post.return_value.raise_for_status.return_value = None
        post.return_value.json.return_value = {"response": "   "}
        summary = build_ai_summary(RESULTS, provider="ollama")
        self.assertEqual(summary["provider"], "ollama_unavailable")

    def test_prompt_is_bounded(self):
        prompt = _ollama_prompt(RESULTS)
        self.assertLessEqual(len(prompt), 6000)


class AiCliContractTest(unittest.TestCase):
    def test_cli_rejects_cloud_providers(self):
        import argparse
        import main as main_module
        parser = main_module.build_parser() if hasattr(main_module, "build_parser") else None
        if parser is None:
            self.skipTest("no build_parser helper")
        args = parser.parse_args(["--ai", "ollama"])
        self.assertEqual(args.ai, "ollama")
        with self.assertRaises(SystemExit):
            parser.parse_args(["--ai", "openai"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--ai", "azure"])
        # The meaningless cloud key flag is gone.
        self.assertIsNone(getattr(args, "api_key", None))


if __name__ == "__main__":
    unittest.main()
