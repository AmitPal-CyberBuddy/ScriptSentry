"""Reliability polish: job timestamps, pruning, digests, diagnostics, queries.

Pins the P3 items from the 2026-09 reliability review:

* every job ``*_at`` snapshot field is an epoch float (``created_at`` used to
  be an ISO string while the rest were epochs), with derived ``*_iso`` twins
  for display;
* finished jobs are pruned on *access* (status/result/cancel), not only when a
  new job is created — a long-lived engine no longer pins every finished
  result in memory indefinitely;
* content deduplication uses one digest algorithm (SHA-256) everywhere, so a
  set seeded by one path recognizes duplicates recorded by another;
* ``SCRIPTSENTRY_DEBUG=1`` surfaces the deliberately-suppressed failures
  (downloads, discovery fallback, bookkeeping) on stderr, and stays silent
  otherwise;
* the report route parses its query with ``parse_qsl`` (URL-decoding), not a
  hand-rolled splitter.
"""
import io
import unittest
from datetime import datetime
from unittest import mock
from urllib.parse import urlparse

from core import diag
from core.analyzer_service import _content_digest, _merge_into
from core.jobs import Job, JobManager
from api.http import BaseHandler


class JobTimestampsTest(unittest.TestCase):
    def test_created_at_is_epoch_with_iso_twin(self):
        job = Job()
        snap = job.snapshot()
        self.assertIsInstance(snap["created_at"], float,
                              "created_at must be an epoch float, not ISO text")
        self.assertGreater(snap["created_at"], 0)
        # The display twin parses as ISO-8601.
        parsed = datetime.fromisoformat(snap["created_at_iso"])
        self.assertAlmostEqual(parsed.timestamp(), snap["created_at"], delta=1.0)

    def test_lifecycle_timestamps_are_epoch_floats(self):
        job = Job()
        self.assertIsNone(job.snapshot()["started_at"])
        self.assertIsNone(job.snapshot()["finished_at"])
        self.assertTrue(job.start())
        job.complete({"__scan_summary__": {}})
        snap = job.snapshot()
        self.assertIsInstance(snap["started_at"], float)
        self.assertIsInstance(snap["finished_at"], float)
        self.assertLessEqual(snap["started_at"], snap["finished_at"])
        self.assertIsNotNone(snap["started_at_iso"])
        self.assertIsNotNone(snap["finished_at_iso"])

    def test_cancel_requested_at_is_epoch(self):
        job = Job()
        job.cancel()
        self.assertIsInstance(job.snapshot()["cancel_requested_at"], float)


class JobPruningTest(unittest.TestCase):
    def test_finished_jobs_are_pruned_on_access_after_retention(self):
        manager = JobManager(max_jobs=10, retention_seconds=60)
        job = manager.create()
        self.assertTrue(manager.start(job.id, lambda: {"done": True}) is not None)
        # Let the runner thread finish before backdating.
        for _ in range(50):
            if job.status == "done":
                break
            import time
            time.sleep(0.02)
        self.assertEqual(job.status, "done")
        job.finished_at -= 120  # past the 60s retention floor
        # Accessing any job prunes; the expired one must be gone.
        self.assertIsNone(manager.status(job.id))

    def test_cap_eviction_happens_on_access(self):
        manager = JobManager(max_jobs=3)
        jobs = [manager.create() for _ in range(3)]
        for job in jobs[:2]:
            job.start()
            job.complete({})
        # At cap with two terminal jobs: any get() evicts the oldest terminal
        # record even though no new job was created.
        manager.get(jobs[2].id)
        self.assertIsNone(manager.get(jobs[0].id), "oldest terminal job should be evicted")
        self.assertIsNotNone(manager.get(jobs[1].id))
        self.assertIsNotNone(manager.get(jobs[2].id), "running jobs are never evicted")


class ContentDigestTest(unittest.TestCase):
    def test_digest_matches_the_scanner_content_hash(self):
        code = 'var apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
        # One algorithm everywhere: the crawl dedup digest must equal the
        # per-file content_sha256 the document scan records.
        from core.analyzer_service import _scan_document_cpu
        data = _scan_document_cpu("app.js", code)
        self.assertEqual(_content_digest(code), data["content_sha256"])

    def test_merge_into_dedups_on_the_shared_digest(self):
        results = {}
        seen = set()
        code = "var a = 1;"
        self.assertTrue(_merge_into(results, "a.js", code, seen_hashes=seen))
        self.assertFalse(_merge_into(results, "b.js", code, seen_hashes=seen),
                         "identical content under a new name is a duplicate")
        self.assertTrue(_merge_into(results, "c.js", code + "\n", seen_hashes=seen))


class DiagnosticsTest(unittest.TestCase):
    def test_note_is_silent_by_default(self):
        err = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("sys.stderr", err):
            diag.note("scope", "message")
        self.assertEqual(err.getvalue(), "")

    def test_note_prints_when_enabled(self):
        err = io.StringIO()
        with mock.patch.dict("os.environ", {"SCRIPTSENTRY_DEBUG": "1"}), \
                mock.patch("sys.stderr", err):
            diag.note("scope", "message")
        self.assertIn("[scriptsentry:scope] message", err.getvalue())

    def test_note_never_raises(self):
        with mock.patch.dict("os.environ", {"SCRIPTSENTRY_DEBUG": "1"}), \
                mock.patch("builtins.print", side_effect=OSError("boom")):
            diag.note("scope", "message")  # must not raise


class QueryParamDecodingTest(unittest.TestCase):
    """The report route relies on _query_param; it must URL-decode."""

    @staticmethod
    def _param(query, key, default=""):
        return BaseHandler._query_param(None, urlparse(f"http://engine/api/report?{query}"),
                                        key, default)

    def test_plain_value(self):
        self.assertEqual(self._param("format=sarif", "format", "html"), "sarif")

    def test_url_encoded_value_is_decoded(self):
        self.assertEqual(self._param("format=sa%72if", "format", "html"), "sarif")

    def test_default_when_absent(self):
        self.assertEqual(self._param("", "format", "html"), "html")


if __name__ == "__main__":
    unittest.main()
