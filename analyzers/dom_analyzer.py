"""DOM sink detection.

The sink catalogue lives in :mod:`core.js_patterns` so that this analyzer and
the taint engine cannot disagree about what counts as a sink -- a sink added
for source-to-sink analysis is immediately visible here.

Patterns are anchored to real code, not to any line that happens to contain two
keywords.  The old ``script_injection`` rule used ``\bscript\b.*\bsrc\b``,
which matched the comment ``// load the script src from config``.
"""
from core.js_patterns import DOM_SINK_PATTERNS, FRAMEWORK_SINKS, dom_sinks_in

# Re-exported: callers and tests import these names from here.
SINK_PATTERNS = DOM_SINK_PATTERNS


def analyze(content, previous=None):
    findings = dom_sinks_in(content)
    for sink in FRAMEWORK_SINKS:
        if sink in (content or ""):
            findings.append(sink)
    return list(dict.fromkeys(findings))
