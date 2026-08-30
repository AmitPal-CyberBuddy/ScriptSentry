"""Structured data-flow summary.

Replaces the old implementation, which returned a single prose string such as
``"input -> api -> storage -> encryption"`` -- impossible to render, filter or
test.  This returns one record per observed capability transition.
"""
import re

STAGES = [
    ("input", re.compile(r"\b(?:fetch|axios|XMLHttpRequest)\s*\("), "network request"),
    ("storage", re.compile(
        r"\b(?:localStorage|sessionStorage|document\s*\.\s*cookie|Cookies?)"
        r"\s*\.\s*(?:setItem|getItem|set|remove)\b"
    ), "client storage access"),
    ("encryption", re.compile(r"\b(?:encrypt|decrypt|cipher|decipher)\s*\("), "crypto operation"),
    ("dom_write", re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\s*(?:=(?!=)|\+=|\()"), "DOM write"),
]


def analyze(content, previous=None):
    content = content or ""
    flow = []
    for name, pattern, description in STAGES:
        if pattern.search(content):
            flow.append({"stage": name, "description": description})
    return flow
