# Analysis corpus

Small, reviewable JavaScript fixtures used by `test_corpus.py`. These are not
claims that a pattern alone is exploitable; tests assert the evidence/status
contract. Add a fixture when a detector changes, especially for a known false
positive.

Categories cover secrets, DOM sinks, messaging, prototype pollution, redirects,
storage, data-flow correlation, WebSockets, third-party behavior, obfuscation,
and sanitized/fixture false positives.
