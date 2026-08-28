"""Framework-aware security rules.

Covers common client-side frameworks so dangerous patterns are identified with
the right context instead of generic "DOM injection".
"""
import re


def _line(content, index):
    return content[:index].count("\n") + 1


def analyze_framework(content, filename="inline.js"):
    findings = []
    if not content:
        return findings

    def add(node_id, framework, title, severity, line, evidence, confidence="medium"):
        findings.append({
            "id": node_id,
            "type": title,
            "framework": framework,
            "severity": severity,
            "confidence": confidence,
            "status": "potential",
            "file": filename,
            "line": line,
            "source": "",
            "sink": evidence[:120],
            "flow": [],
            "sanitization_detected": any(h in evidence.lower() for h in ("sanitize", "dopurify", "textcontent", "escapehtml")),
            "evidence": evidence[:240],
        })

    # React
    for m in re.finditer(r"dangerouslySetInnerHTML", content):
        add("react_dangerouslysetinnerhtml", "React", "React dangerouslySetInnerHTML used", "HIGH", _line(content, m.start()), content[m.start():m.start()+160])

    # Angular
    for m in re.finditer(r"(bypassSecurityTrustHtml|bypassSecurityTrustUrl|bypassSecurityTrustResourceUrl)", content):
        add("angular_bypass_security", "Angular", "Angular bypassSecurityTrust* bypasses sanitization", "HIGH", _line(content, m.start()), content[m.start():m.start()+160])

    # Vue
    for m in re.finditer(r"v-html\s*=|\bv-html\b", content):
        add("vue_vhtml", "Vue", "Vue v-html renders raw HTML", "HIGH", _line(content, m.start()), content[m.start():m.start()+140])

    # jQuery — require an actual jQuery chain (`$(...)`, `jQuery(...)`, or a `$el.` var)
    # so plain DOM Element.append/before/after doesn't create noisy framework findings.
    for m in re.finditer(r"\.html\s*\(|\.append\s*\(|\.prepend\s*\(|\.after\s*\(|\.before\s*\(", content):
        snippet = content[max(0, m.start()-120):m.start()+160]
        jquery_chain = re.search(r"(?:\$\s*\(|jQuery\s*\(|\$[A-Za-z_$][\w$]*\s*\.|jquery\.fn)", snippet, re.I)
        if jquery_chain:
            add("jquery_dom_manipulation", "jQuery", "jQuery DOM-manipulation sink", "MEDIUM", _line(content, max(0, m.start()-120)), snippet)

    return findings
