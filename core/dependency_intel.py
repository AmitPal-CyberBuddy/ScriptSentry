"""Known-vulnerability intelligence for libraries found in bundles.

Inventory alone ("this bundle contains jQuery") does not help a tester
prioritize. Most minified bundles carry their library versions in banner
comments or module metadata (``/*! jQuery v3.4.1 */``, ``_.VERSION="4.17.15"``),
and a small curated table of well-documented CVEs turns those versions into
actionable findings with references.

Design constraints:

* **No false CVE claims.** A vulnerability is only reported when the version
  string was actually extracted AND falls inside a documented range. Without
  a version the library stays inventory, exactly as before.
* **Curated, not scraped.** The table below covers widely embedded frontend
  libraries and their most-cited, well-documented advisories. Ranges follow
  the upstream fix versions; each entry carries its CVE id.
* Ranges are plain constraint strings (``"<3.5.0"``, ``">=1.2.0,<3.4.0"``)
  evaluated by :func:`version_in_ranges` -- no dependency on a semver
  package.
"""
import re

__all__ = ["check_dependencies", "version_in_ranges"]


def _parse_version(text):
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(text or "").strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _compare(version, other):
    """Three-way compare of parsed version tuples, padded to equal length."""
    length = max(len(version), len(other))
    left = version + (0,) * (length - len(version))
    right = other + (0,) * (length - len(other))
    return (left > right) - (left < right)


def version_in_ranges(version, constraints):
    """True when ``version`` (e.g. ``"3.4.1"``) satisfies every constraint.

    Constraints are comma-separated ``<x``, ``<=x``, ``>x``, ``>=x``, ``=x``
    comparisons, e.g. ``">=1.2.0,<3.4.0"``. Unparseable input is never
    considered vulnerable.
    """
    parsed = _parse_version(version)
    if parsed is None:
        return False
    for constraint in str(constraints or "").split(","):
        constraint = constraint.strip()
        match = re.match(r"^(<=|>=|<|>|=)?\s*(\d+(?:\.\d+){0,2})$", constraint)
        if not match:
            return False
        operator, bound = match.groups()
        order = _compare(parsed, _parse_version(bound))
        ok = {
            "<": order < 0,
            "<=": order <= 0,
            ">": order > 0,
            ">=": order >= 0,
            "=": order == 0,
            None: order == 0,
        }[operator]
        if not ok:
            return False
    return True


# library key -> banner/metadata version patterns + curated advisories.
LIBRARY_INTEL = {
    "jquery": {
        "name": "jQuery",
        "version_patterns": [
            r"jQuery\s+(?:JavaScript\s+Library\s+)?v(\d+\.\d+(?:\.\d+)?)",
            r"/\*!\s*jQuery\s+v(\d+\.\d+(?:\.\d+)?)",
            r"jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
        ],
        "vulnerabilities": [
            {"ranges": "<3.5.0", "severity": "MEDIUM", "cve": "CVE-2020-11022",
             "summary": "XSS: untrusted HTML passed to jQuery manipulation methods can execute (also CVE-2020-11023)"},
            {"ranges": ">=1.2.0,<3.4.0", "severity": "HIGH", "cve": "CVE-2019-11358",
             "summary": "Prototype pollution via jQuery.extend(deep, ...)"},
            {"ranges": ">=1.4.0,<3.0.0", "severity": "MEDIUM", "cve": "CVE-2015-9251",
             "summary": "XSS via cross-domain ajax responses when dataType is auto-detected"},
        ],
    },
    "lodash": {
        "name": "Lodash",
        "version_patterns": [
            r"_\.VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']",
            r"lodash(?:\.com)?[^0-9]{0,20}v?(\d+\.\d+\.\d+)",
        ],
        "vulnerabilities": [
            {"ranges": "<4.17.19", "severity": "HIGH", "cve": "CVE-2020-8203",
             "summary": "Prototype pollution via zipObjectDeep"},
            {"ranges": "<4.17.21", "severity": "HIGH", "cve": "CVE-2021-23337",
             "summary": "Command injection via template"},
        ],
    },
    "underscore": {
        "name": "Underscore.js",
        "version_patterns": [
            r"Underscore\.js\s+v?(\d+\.\d+\.\d+)",
            r"_\.VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']",
        ],
        "vulnerabilities": [
            {"ranges": "<1.12.1", "severity": "HIGH", "cve": "CVE-2021-23358",
             "summary": "Arbitrary code execution via the template function"},
        ],
    },
    "moment": {
        "name": "Moment.js",
        "version_patterns": [
            r"moment\.version\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']",
            r"[Mm]oment(?:\.js)?\s+v(\d+\.\d+\.\d+)",
        ],
        "vulnerabilities": [
            {"ranges": "<2.29.2", "severity": "MEDIUM", "cve": "CVE-2022-31129",
             "summary": "ReDoS via crafted locale data (also CVE-2022-24785 path traversal)"},
        ],
    },
    "axios": {
        "name": "Axios",
        "version_patterns": [
            r"[Aa]xios\s+v(\d+\.\d+\.\d+)",
            r"axios/(\d+\.\d+\.\d+)",
        ],
        "vulnerabilities": [
            {"ranges": "<0.21.4", "severity": "MEDIUM", "cve": "CVE-2021-3749",
             "summary": "ReDoS via trim that follows a crafted response"},
            {"ranges": "<0.21.1", "severity": "HIGH", "cve": "CVE-2020-28168",
             "summary": "SSRF: absolute URL requests ignore the configured baseURL proxy"},
        ],
    },
    "bootstrap": {
        "name": "Bootstrap",
        "version_patterns": [
            r"Bootstrap\s+v(\d+\.\d+\.\d+)",
            r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)",
        ],
        "vulnerabilities": [
            {"ranges": ">=3.0.0,<3.4.1", "severity": "MEDIUM", "cve": "CVE-2019-8331",
             "summary": "XSS via data-template / tooltip popover content (also affects 4.x < 4.3.1)"},
            {"ranges": ">=4.0.0,<4.3.1", "severity": "MEDIUM", "cve": "CVE-2019-8331",
             "summary": "XSS via data-template / tooltip popover content"},
        ],
    },
    "angular": {
        "name": "AngularJS",
        "version_patterns": [
            r"[Aa]ngular\.?js?\s+v(\d+\.\d+\.\d+)",
            r"AngularJS\s+v(\d+\.\d+\.\d+)",
        ],
        "vulnerabilities": [
            {"ranges": "<1.8.3", "severity": "MEDIUM", "cve": "CVE-2022-25844",
             "summary": "ReDoS in the angular input[url] filter (1.x line, EOL upstream)"},
        ],
    },
    "crypto-js": {
        "name": "CryptoJS",
        "version_patterns": [
            r"crypto-js\s+v?(\d+\.\d+\.\d+)",
            r"cryptojs\s+v(\d+\.\d+\.\d+)",
        ],
        "vulnerabilities": [
            {"ranges": "<4.2.0", "severity": "HIGH", "cve": "CVE-2023-46233",
             "summary": "PBKDF2 defaults to 1 iteration when configured with a shape it does not recognise"},
        ],
    },
}


def extract_version(library_key, content):
    """Best-effort library version from bundle banners/metadata, or ``None``."""
    for pattern in LIBRARY_INTEL.get(library_key, {}).get("version_patterns", []):
        match = re.search(pattern, content or "", re.I)
        if match:
            return match.group(1)
    return None


def match_vulnerabilities(library_key, version):
    """Curated advisories applying to ``version`` of ``library_key``."""
    if not version:
        return []
    return [
        vuln for vuln in LIBRARY_INTEL.get(library_key, {}).get("vulnerabilities", [])
        if version_in_ranges(version, vuln["ranges"])
    ]


def check_dependencies(dependency_entries, content):
    """Annotate dependency entries and return vulnerability risk signals.

    ``dependency_entries`` is the ``dependency_scan`` list produced by the
    scanner (dicts with a ``source`` key). Each entry gains ``version`` when
    one can be extracted and ``vulnerabilities`` when the version falls in a
    known range. The returned risk-signal dicts feed the unified finding
    pipeline (id ``vulnerable_dependency:<lib>`` so one finding per library).
    """
    signals = []
    content = content or ""
    for entry in dependency_entries or []:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("source") or "").lower()
        intel_key = key if key in LIBRARY_INTEL else None
        if intel_key is None:
            continue
        version = extract_version(intel_key, content)
        if version:
            entry["version"] = version
        entry["vulnerabilities"] = match_vulnerabilities(intel_key, version)
        for vuln in entry["vulnerabilities"]:
            severity = str(vuln.get("severity") or "MEDIUM").upper()
            signals.append({
                "id": f"vulnerable_dependency:{intel_key}",
                "severity": severity,
                "title": (f"Vulnerable library: {LIBRARY_INTEL[intel_key]['name']} "
                          f"{version} ({vuln['cve']})"),
                "evidence": [f"{entry.get('name', intel_key)} {version}: {vuln['summary']}"],
                "confidence": "medium",
                "evidence_type": "version_fingerprint",
                "observation": False,
                "reference": vuln["cve"],
            })
    return signals
