"""Process-pool analyze engine tests.

The CPU-bound per-document analysis runs in a worker process by default
(``SCRIPTSENTRY_ANALYZE_ENGINE=process``) with the parent keeping all I/O
and progress duties. These tests pin the worker contract (picklable in/out,
heartbeat queue messages, parity with the in-process path) without spinning
up real pools -- the loopback URL-scan tests cover the full engine
end-to-end.
"""
import pickle
import unittest

from core.analyzer_service import (
    _analyze_document_worker,
    _scan_document,
    _scan_document_cpu,
    analyze_engine,
)

MODERN_SNIPPET = (
    "const q = new URLSearchParams(location.search).get('q');\n"
    "document.body.innerHTML = q;\n"
    "const loader = () => import('./chunks/launch-9f2.js');\n"
    "fetch('/api/v1/session', {headers: {Authorization: `Bearer ${t}`}});\n"
)

HEARTBEAT_SNIPPET = "".join(
    f"function generated_{i}(event) {{ event?.preventDefault?.(); }}\n" for i in range(6000)
)


class _FakeQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


class WorkerContractTest(unittest.TestCase):
    def test_worker_output_is_picklable(self):
        data, refs = _analyze_document_worker("bundle.js", MODERN_SNIPPET, "https://x.test/a.js")
        # Everything crossing the process boundary must survive a pickle
        # round trip intact (spawn pools + result transport depend on it).
        data2, refs2 = pickle.loads(pickle.dumps((data, refs)))
        self.assertEqual(data2["url"], "https://x.test/a.js")
        self.assertEqual(data2["content_sha256"], data["content_sha256"])
        self.assertIn("findings", data2)
        self.assertIsInstance(data2["findings"], list)
        self.assertTrue(any("launch-9f2.js" in ref for ref in refs2), refs2)

    def test_worker_heartbeat_queue_messages(self):
        queue = _FakeQueue()
        self.assertGreaterEqual(len(HEARTBEAT_SNIPPET), 150_000)
        _analyze_document_worker("big.js", HEARTBEAT_SNIPPET, "", heartbeat_queue=queue,
                                 phase="scan")
        self.assertTrue(queue.items, "large documents must emit worker heartbeats")
        for phase, name, detail in queue.items:
            self.assertEqual(phase, "scan")
            self.assertEqual(name, "big.js")
            self.assertTrue(detail)

    def test_worker_small_document_emits_no_heartbeats(self):
        queue = _FakeQueue()
        _analyze_document_worker("small.js", MODERN_SNIPPET, "", heartbeat_queue=queue)
        self.assertEqual(queue.items, [])


class EngineSplitParityTest(unittest.TestCase):
    def test_cpu_half_plus_source_map_half_equals_scan_document(self):
        # No source map in this content, so the I/O half is a no-op and both
        # paths must agree exactly.
        data_cpu = _scan_document_cpu("a.js", MODERN_SNIPPET, source_url="https://x.test/a.js")
        data_full = _scan_document("a.js", MODERN_SNIPPET, source_url="https://x.test/a.js")
        self.assertEqual(data_cpu, data_full)


class EngineSelectionTest(unittest.TestCase):
    def test_default_engine_is_process(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SCRIPTSENTRY_ANALYZE_ENGINE", None)
            self.assertEqual(analyze_engine(), "process")

    def test_thread_engine_opt_out(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_ANALYZE_ENGINE": "thread"}):
            self.assertEqual(analyze_engine(), "thread")


if __name__ == "__main__":
    unittest.main()
