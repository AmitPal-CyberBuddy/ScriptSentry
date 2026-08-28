import html
import itertools


def safe_text(val):
    if val is None:
        return ""
    if isinstance(val, dict):
        return safe_text(val.get("value", val.get("signal", "")))
    return html.unescape(str(val))


def _value_of(item):
    if isinstance(item, dict):
        return str(item.get("value", item.get("signal", "")))
    return str(item)


def is_real_crypto_key(k):
    val = _value_of(k).strip('"').strip("'")

    if len(set(val)) < 8:
        return False

    junk = [
        "aria", "router", "component", "label", "data-", "index", "name",
        "button", "form", "icon", "style", "class"
    ]
    if any(j in val.lower() for j in junk):
        return False

    return (
        "EncryptionKey" in k
        or any(c in val for c in ["~", "<", ">", "$", "%", "&", "+", ";", "_"])
        or (len(val) > 14 and not val.isalpha())
    )


def clean_html(val):
    """Decode HTML entities safely for report output."""
    if not val:
        return ""
    return html.unescape(str(val))


def _risk_score(data):
    score = 0
    findings = []

    if data.get("secrets"):
        score += 3
        findings.append("HIGH: Hardcoded secret/token material detected")
    if data.get("keys") and data.get("ivs"):
        score += 4
        findings.append("CRITICAL: Hardcoded key/IV pair detected")
    elif data.get("keys"):
        score += 3
        findings.append("HIGH: Static crypto key material detected")
    elif data.get("ivs"):
        score += 2
        findings.append("MEDIUM: Static IV/nonce material detected")
    if data.get("storage"):
        score += 2
        findings.append("HIGH: Sensitive storage usage detected")
    if data.get("dom_risks"):
        score += 2
        findings.append("HIGH: DOM injection / XSS pattern detected")
    if data.get("crypto_flows") or data.get("real_crypto_detected") or data.get("crypto"):
        score += 2
        findings.append("MEDIUM: Crypto implementation detected")
    if data.get("api_calls") or data.get("endpoints"):
        score += 1
        findings.append("MEDIUM: API request flow detected")
    if data.get("hardcoded_configs"):
        score += 1
        findings.append("LOW: Hardcoded configuration detected")
    if data.get("decoded_strings"):
        score += 1
        findings.append("LOW: Decoded/obfuscated values detected")
    if data.get("suspicious_calls"):
        score += 1
        findings.append("LOW: Suspicious runtime or obfuscation pattern detected")
    if data.get("obfuscation_analysis", {}).get("evidence"):
        score += 1
        findings.append("LOW: Obfuscation evidence detected")

    if score >= 9:
        label = "CRITICAL"
    elif score >= 5:
        label = "HIGH"
    elif score >= 2:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label, findings


def score_risk(data):
    return _risk_score(data)


def _crypto_flow_text(flows):
    out = []
    for f in flows or []:
        if isinstance(f, dict):
            out.append(str(f.get("signal", "")))
        else:
            out.append(str(f))
    return out


def _normalize_data(file_name, data):
    """Return a copy of a scan result normalized for report-friendly rendering."""
    return {
        "name": file_name,
        "score": data.get("score", 0),
        "confidence": data.get("confidence", ""),
        "real_crypto_detected": bool(data.get("real_crypto_detected")),
        "file_size": data.get("file_size", 0),
        "line_count": data.get("line_count", 0),
        "secrets": data.get("secrets", []),
        "keys": data.get("keys", []),
        "ivs": data.get("ivs", []),
        "crypto": data.get("crypto", []),
        "crypto_flows": data.get("crypto_flows", []),
        "endpoints": data.get("endpoints", []),
        "api_calls": data.get("api_calls", []),
        "headers": data.get("headers", []),
        "storage": data.get("storage", []),
        "hardcoded_configs": data.get("hardcoded_configs", []),
        "decoded_strings": data.get("decoded_strings", []),
        "suspicious_calls": data.get("suspicious_calls", []),
        "dom_risks": data.get("dom_risks", []),
        "auth_summary": data.get("auth_summary", []),
        "api_inventory": data.get("api_inventory", []),
        "storage_analysis": data.get("storage_analysis", []),
        "config_summary": data.get("config_summary", []),
        "technology_stack": data.get("technology_stack", []),
        "data_flow_summary": data.get("data_flow_summary", []),
        "obfuscation_analysis": data.get("obfuscation_analysis", {}),
        "secret_analysis": data.get("secret_analysis", []),
        "risk_signals": data.get("risk_signals", []),
        "dependency_scan": data.get("dependency_scan", []),
        "ast_analysis": data.get("ast_analysis", {}),
        "transport": data.get("transport", []),
        "request_methods": data.get("request_methods", []),
        "notable_features": data.get("notable_features", []),
        "dataflows": data.get("dataflows", []),
        "attack_surface": data.get("attack_surface", {}),
        "framework_findings": data.get("framework_findings", []),
        "findings": data.get("findings", []),
        "finding_statuses": data.get("finding_statuses", {}),
        "file_size": data.get("file_size", 0),
        "line_count": data.get("line_count", 0),
    }


def _collect_signals(file_name, data):
    """Collect structured, deduplicated risk signals + remediation across files."""
    signals = []
    seen = set()
    for signal in data.get("risk_signals", []) or []:
        key = (signal.get("id", ""), signal.get("severity", ""), signal.get("title", ""))
        if key in seen or key[0] == "notable_features":
            continue
        seen.add(key)
        signals.append({**signal, "file": file_name})
    # Keep the scanner-level signals, which are the primary source of truth.
    return signals


def build_report_model(results, ai_summary=None, metadata=None):
    """Build a normalized, structured report model used by TXT, HTML and GUI."""
    files = []
    all_signals = []
    all_dependencies = []
    all_endpoints = []
    all_methods = set()
    all_transport = set()
    all_flows = []
    all_findings = []
    all_attack_surface = {
        "endpoints": [], "websockets": [], "sse": [], "graphql": [],
        "parameters": [], "domains": [], "headers": [], "body_fields": [],
        "auth_hints": [], "internal_endpoints": [],
    }
    total_score = 0
    total_count = 0
    max_file_score = 0

    for file_name, data in results.items():
        norm = _normalize_data(file_name, data)
        score, label, findings = score_risk(norm)
        norm["score"] = score
        norm["risk"] = label
        # Keep the structured taint/framework/risk findings for exports and let the
        # human-readable `findings` list carry the coarse risk strings for TXT/HTML.
        norm["rich_findings"] = [f for f in norm.get("findings", []) if isinstance(f, dict)]
        norm["findings"] = findings
        files.append(norm)
        total_score += score
        max_file_score = max(max_file_score, score)
        all_signals.extend(_collect_signals(file_name, data) or [])
        all_dependencies.extend(norm.get("dependency_scan", []) or [])
        all_endpoints.extend(norm.get("endpoints", []) or [])
        all_methods.update(norm.get("request_methods", []) or [])
        all_transport.update(norm.get("transport", []) or [])
        total_count += len(findings)
        for flow in norm.get("dataflows", []) or []:
            all_flows.append({**flow, "file": file_name})
            all_signals.append({
                "id": flow.get("id", "dataflow"), "severity": flow.get("severity", "HIGH"),
                "title": flow.get("type", flow.get("id", "Source-to-sink flow")),
                "evidence": flow.get("evidence") or flow.get("sink", ""), "file": file_name,
                "status": flow.get("status", "potential"), "confidence": flow.get("confidence", "medium"),
            })
        for fw in norm.get("framework_findings", []) or []:
            all_findings.append({**fw, "file": file_name})
            all_signals.append({
                "id": fw.get("id", "framework"), "severity": fw.get("severity", "MEDIUM"),
                "title": fw.get("type", fw.get("id", "Framework risk")),
                "evidence": fw.get("evidence") or fw.get("sink", ""), "file": file_name,
                "status": fw.get("status", "potential"), "confidence": fw.get("confidence", "medium"),
            })
        for f in norm.get("rich_findings", []) or []:
            if isinstance(f, dict):
                all_findings.append({**f, "file": f.get("file", file_name)})
        asrf = norm.get("attack_surface", {}) or {}
        for key in all_attack_surface.keys():
            all_attack_surface[key].extend(asrf.get(key, []) or [])

    # Aggregate category counts for a compact table.
    def count(attr):
        return sum(len(norm.get(attr, []) or []) for norm in files)

    categories = {
        "secrets": count("secrets"),
        "keys": count("keys"),
        "ivs": count("ivs"),
        "crypto_flows": count("crypto_flows"),
        "endpoints": count("endpoints"),
        "api_calls": count("api_calls"),
        "headers": count("headers"),
        "storage": count("storage"),
        "hardcoded_configs": count("hardcoded_configs"),
        "decoded_strings": count("decoded_strings"),
        "suspicious_calls": count("suspicious_calls"),
        "dom_risks": count("dom_risks"),
        "auth": count("auth_summary"),
        "api_inventory": count("api_inventory"),
        "storage_analysis": count("storage_analysis"),
        "tech": count("technology_stack"),
        "features": count("notable_features"),
    }

    overall_risk = _overall_risk_label(total_score, max_file_score)
    overall_color = SEVERITY_COLORS[overall_risk]
    signal_severities = {}
    for signal in all_signals:
        severity = signal.get("severity", "INFO")
        signal_severities[severity] = signal_severities.get(severity, 0) + 1

    def _dedupe_flows(flows):
        out = []
        seen = set()
        for f in flows or []:
            key = (f.get("id"), f.get("line"), str(f.get("sink", "")))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    dedup_attack = {}
    for key, items in all_attack_surface.items():
        uniq = []
        seen = set()
        for item in items or []:
            if isinstance(item, dict):
                sig = (item.get("url") or item.get("operation") or item.get("type") or "", item.get("method") or "", item.get("line") or 0)
            else:
                sig = (str(item),)
            if sig in seen:
                continue
            seen.add(sig)
            uniq.append(item)
        dedup_attack[key] = uniq[:80]

    return {
        "meta": {
            "generated_at": (metadata or {}).get("generated_at", ""),
            "engine": "ScriptSentry Analyzer",
            "engine_version": "2.0",
            "source": (metadata or {}).get("source", ""),
            "mode": (metadata or {}).get("mode", "code"),
        },
        "summary": {
            "total_files": len(files),
            "total_score": total_score,
            "risk_label": overall_risk,
            "risk_color": overall_color,
            "max_file_score": max_file_score,
            "total_findings": total_count,
            "categories": categories,
            "methods": sorted(all_methods),
            "transport": sorted(all_transport),
            "signal_counts": signal_severities,
            "signals": [s for s in all_signals if s.get("id") != "notable_features"],
            "findings": all_findings[:120],
            "dataflows": _dedupe_flows(all_flows)[:80],
        },
        "files": files,
        "all_dependencies": list(dict.fromkeys([(d.get("name") or d.get("source")) for d in all_dependencies if d.get("name") or d.get("source")]))[:40],
        "all_endpoints": list(dict.fromkeys([str(e) for e in all_endpoints]))[:60],
        "attack_surface": dedup_attack,
        "ai_summary": ai_summary or {},
    }


def _overall_risk_label(score, max_file_score):
    if score >= 18 or max_file_score >= 9:
        return "CRITICAL"
    if score >= 8 or max_file_score >= 5:
        return "HIGH"
    if score >= 3 or max_file_score >= 3:
        return "MEDIUM"
    return "LOW"


def _txt_section(title, items, limit=8):
    if not items:
        return []
    lines = [f"\n[{title}]"]
    for item in list(items)[:limit]:
        lines.append(f"  - {safe_text(item)}")
    return lines


def _txt_paragraphs(title, items, limit=4):
    if not items:
        return []
    lines = [f"\n[{title}]"]
    for item in list(items)[:limit]:
        if isinstance(item, dict):
            item = item.get("title") or item.get("name") or item.get("signal") or item.get("evidence") or ""
        lines.append(f"  - {safe_text(item)}")
    return lines


def _remediation(model):
    signals = model["summary"]["signals"]
    ids = {s.get("id") for s in signals}
    steps = []
    if any(i in ids for i in ("hardcoded_secret", "static_crypto_key", "static_iv", "exposed_key_iv_pair")):
        steps.append("Move static keys/IVs/secrets out of client bundles into a server-side credential store.")
    if "sensitive_storage" in ids:
        steps.append("Replace client-side token storage with short-lived sessions, httpOnly cookies, or server-held state.")
    if "dom_injection" in ids:
        steps.append("Sanitize DOM input before innerHTML/insertAdjacentHTML and use textContent where possible.")
    if "unsafe_runtime" in ids:
        steps.append("Remove eval / new Function paths and replace with safe, whitelisted logic.")
    if "client_side_crypto" in ids:
        steps.append("Never rely on browser-side crypto for authorization; enforce encryption rules server-side.")
    if "obfuscation" in ids:
        steps.append("Review obfuscated/decoded paths for embedded control logic before trusting them.")
    if "api_surface" in ids or model["summary"]["transport"]:
        steps.append("Validate every exposed endpoint and apply server-side authorization + rate limiting.")
    if not steps:
        steps.append("No high-confidence risk requires immediate action; review the report's signal list for context.")
    return steps


def generate_report(results, ai_summary=None):
    """Generate a polished, structured text report."""
    model = build_report_model(results, ai_summary=ai_summary)
    summary = model["summary"]
    report = []

    report.append("============================================================")
    report.append(" SCRIPTSENTRY · JAVASCRIPT ANALYSIS REPORT")
    report.append("============================================================")
    report.append(f" Engine      : {model['meta']['engine']} v{model['meta']['engine_version']}")
    report.append(f" Source      : {model['meta']['source'] or 'inline snippet'}")
    report.append(f" Generated   : {model['meta']['generated_at'] or 'now'}")
    report.append(f" Files       : {summary['total_files']}")
    report.append(f" Signals     : {summary['total_findings']}")
    report.append(f" Overall Risk: {summary['risk_label']} ({summary['total_score']})")
    report.append("============================================================\n")

    report.append("========== EXECUTIVE SUMMARY ==========")
    report.append(f"  - Risk posture: {summary['risk_label']} with {summary['total_findings']} findings across {summary['total_files']} file(s).")
    if model["all_endpoints"]:
        report.append(f"  - Mapped {len(model['all_endpoints'])} endpoints and {len(summary['transport'])} transport channel(s).")
    if summary["signal_counts"]:
        report.append("  - Signal mix: " + ", ".join(f"{k.lower()}={v}" for k, v in summary["signal_counts"].items()))
    if model["all_dependencies"]:
        report.append(f"  - Candidate dependencies: {', '.join(model['all_dependencies'][:12])}")
    if model["ai_summary"].get("executive_summary"):
        for line in model["ai_summary"]["executive_summary"][:4]:
            report.append(f"  - {safe_text(line)}")

    # Top risks
    report.append("\n========== TOP RISK SIGNALS ==========")
    top = sorted(summary["signals"], key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s.get("severity", "INFO"), 4))[:12]
    if not top:
        report.append("  - No structured risk signals raised.")
    for sig in top:
        report.append(f"  [{sig.get('severity','INFO')}] {sig.get('title','')} — {sig.get('file','')}")
        evidence = sig.get("evidence", [])
        for item in evidence[:2]:
            report.append(f"      • {safe_text(item)}")

    # Category summary
    report.append("\n========== FINDING COUNTS ==========")
    for key, value in summary["categories"].items():
        if value:
            report.append(f"  {key.replace('_',' ').title():24} {value}")

    # Detailed per-file
    report.append("\n\n========== DETAILED ANALYSIS ==========")
    for norm in model["files"]:
        report.append(f"\n==== {norm['name']} ====")
        report.append(f"  Score: {norm['score']} · Risk: {norm['risk']} · Confidence: {norm['confidence'] or 'n/a'}")
        if norm.get("file_size"):
            report.append(f"  Size: {norm['file_size']} bytes · Lines: {norm['line_count']}")

        if norm["real_crypto_detected"]:
            report.append("\n[🔥 REAL CRYPTO IMPLEMENTATION DETECTED]")
            for flow in _crypto_flow_text(norm["crypto_flows"])[:12]:
                report.append(f"  - {safe_text(flow)}")

        if norm["crypto"]:
            report.extend(_txt_section("Crypto Routines", norm["crypto"], 10))
        if norm["keys"]:
            report.extend(_txt_section("Crypto Keys", norm["keys"], 8))
        if norm["ivs"]:
            report.extend(_txt_section("IV / Nonce", norm["ivs"], 8))
        if norm["secrets"]:
            report.extend(_txt_section("Secrets & Credentials", norm["secrets"], 8))
        if norm["headers"]:
            report.extend(_txt_section("Headers", norm["headers"], 8))
        if norm["secret_analysis"]:
            report.extend(_txt_section("Secret Analysis", [f"{x.get('kind','secret')}:{x.get('classification','')}" for x in norm["secret_analysis"]], 8))
        if norm["auth_summary"]:
            report.extend(_txt_section("Authentication Analysis", [x.get("type") if isinstance(x, dict) else x for x in norm["auth_summary"]], 8))
        if norm["api_inventory"]:
            report.extend(_txt_section("API Inventory", [f"{x.get('kind','api')}:{x.get('endpoint','')}" for x in norm["api_inventory"]], 12))
        if norm["endpoints"]:
            report.extend(_txt_section("Endpoints", norm["endpoints"], 12))
        if norm["api_calls"]:
            report.extend(_txt_section("API Calls", norm["api_calls"], 12))
        if norm["storage_analysis"] or norm["storage"]:
            storage_items = [x if isinstance(x, str) else f"{x.get('storage','storage')}:{x.get('classification','')}" for x in (norm["storage_analysis"] or norm["storage"])]
            report.extend(_txt_section("Storage Analysis", storage_items, 8))
        if norm["config_summary"]:
            report.extend(_txt_section("Configuration Analysis", [x.get("name") if isinstance(x, dict) else x for x in norm["config_summary"]], 8))
        if norm["hardcoded_configs"]:
            report.extend(_txt_section("Hardcoded Config", norm["hardcoded_configs"], 8))
        if norm["technology_stack"]:
            tech = [f"{x.get('name')} {x.get('version','')}".strip() if isinstance(x, dict) else x for x in norm["technology_stack"]]
            report.extend(_txt_section("Technology Stack", tech, 8))
        if norm["dependency_scan"]:
            report.extend(_txt_section("Dependency Scan", [f"{x.get('name')} ({x.get('kind','')})" if isinstance(x, dict) else x for x in norm["dependency_scan"]], 12))
        if norm["dom_risks"]:
            report.extend(_txt_section("DOM Risks", norm["dom_risks"], 8))
        if norm["suspicious_calls"]:
            report.extend(_txt_section("Suspicious Calls", norm["suspicious_calls"], 8))
        if norm["decoded_strings"]:
            report.extend(_txt_section("Decoded / Obfuscated", norm["decoded_strings"], 8))
        if norm["obfuscation_analysis"].get("evidence"):
            report.extend(_txt_section("Obfuscation Evidence", norm["obfuscation_analysis"].get("evidence", []), 6))
        if norm["data_flow_summary"]:
            report.extend(_txt_section("Data Flow Summary", norm["data_flow_summary"], 8))
        if norm["notable_features"]:
            report.extend(_txt_section("Notable Features", norm["notable_features"], 10))
        if norm["ast_analysis"]:
            ast_meta = norm["ast_analysis"]
            report.append(f"\n[🧠 AST Profile] imports={len(ast_meta.get('imports',[]))} exports={len(ast_meta.get('exports',[]))} functions={len(ast_meta.get('functions',[]))} classes={len(ast_meta.get('classes',[]))} complexity={ast_meta.get('complexity',0)}")
            if ast_meta.get("parse_error"):
                report.append(f"  - AST parse note: {safe_text(ast_meta['parse_error'])}")
            if ast_meta.get("imports"):
                report.extend(_txt_section("Imports", [i.get("source") for i in ast_meta["imports"]], 12))

        # Per-file findings
        if norm["findings"]:
            report.append("\n[Findings]")
            for finding in norm["findings"]:
                report.append(f"  - {safe_text(finding)}")

    # Global summary
    report.append("\n\n========== GLOBAL SUMMARY ==========")
    report.append(f"  Overall risk: {summary['risk_label']} ({summary['total_score']})")
    if model["all_endpoints"]:
        report.append("\n[Mapped Endpoints]")
        for ep in model["all_endpoints"][:15]:
            report.append(f"  - {safe_text(ep)}")
    if summary["methods"]:
        report.append(f"\n[Detected HTTP methods] {' , '.join(summary['methods'])}")
    if summary["transport"]:
        report.append(f"\n[Transport Channels] {' , '.join(summary['transport'])}")

    # Remediation
    report.append("\n\n========== REMEDIATION PLAN ==========")
    for i, step in enumerate(_remediation(model), 1):
        report.append(f"  {i}. {step}")

    if model["ai_summary"].get("business_impact"):
        report.append("\n[Business Impact]")
        for line in model["ai_summary"]["business_impact"][:3]:
            report.append(f"  - {safe_text(line)}")

    report.append("\n[Methodology]")
    report.append("  - Regex + AST-based static analysis of client-side JavaScript.")
    report.append("  - Findings are deterministic signals for triage, not proof of exploitation.")
    report.append("  - Always validate with server-side behavior and manual review.")

    return "\n".join(report)


def generate_html_report(results, ai_summary=None):
    """Generate a self-contained, modern HTML report (exportable/shareable)."""
    model = build_report_model(results, ai_summary=ai_summary)
    summary = model["summary"]
    risk_color = summary["risk_color"]

    def esc(v):
        return safe_text(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def items_html(items, limit=6):
        if not items:
            return "<li class=\"muted\">none</li>"
        return "".join(
            f"<li>{esc(item)}</li>"
            for item in list(items)[:limit]
        )

    def dict_items(items, template, limit=6):
        if not items:
            return "<li class=\"muted\">none</li>"
        parts = []
        for item in list(items)[:limit]:
            if isinstance(item, dict):
                flag = getattr(item, "get", None)
                text = template(item) if flag else str(item)
            else:
                text = str(item)
            parts.append(f"<li>{esc(text)}</li>")
        return "".join(parts)

    css = """
    @page { margin: 18mm; }
    * { box-sizing: border-box; }
    body { margin:0; background:#eef2f7; color:#172033; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
    .page { max-width: 1040px; margin: 24px auto; background:#fff; box-shadow: 0 18px 60px rgba(15,23,42,.16); border-radius:18px; overflow:hidden; }
    .hd { padding: 30px 36px; background: linear-gradient(135deg,#0b1b3a,#102a4c 48%,#14365c); color:#eaf4ff; }
    .hd h1 { margin:0; font-size:30px; letter-spacing:-.02em; }
    .hd .sub { margin-top:8px; color:#9dc3e6; font-size:14px; }
    .hd .risk { display:inline-block; margin-top:16px; padding:9px 16px; border-radius:999px; font-weight:800; font-size:15px; background:#RISK; color:#08111f; }
    .grid { display:grid; grid-template-columns: repeat(4,1fr); gap:12px; padding:22px 36px 8px; }
    .stat { background:#f7fafc; border:1px solid #e5e9f1; border-radius:14px; padding:16px; }
    .stat b { display:block; font-size:26px; }
    .stat span { color:#6b7891; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .body { padding: 18px 36px 40px; }
    h2 { margin: 30px 0 12px; font-size:19px; color:#0f2550; }
    .card { border:1px solid #e5e9f1; border-radius:14px; padding:18px; margin:12px 0; }
    .file-head { display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .file-head h3 { margin:0; font-size:16px; color:#0f2550; }
    .pill { padding:4px 10px; border-radius:999px; font-size:11px; font-weight:800; color:#08111f; background:#RISK; }
    .cols { display:grid; grid-template-columns:repeat(2,1fr); gap:14px; margin-top:14px; }
    .sec { background:#f7fafc; border:1px solid #e5e9f1; border-radius:12px; padding:14px; }
    .sec h4 { margin:0 0 8px; font-size:12px; color:#40516e; text-transform:uppercase; letter-spacing:.08em; }
    ul { margin:0; padding-left:18px; color:#2b3a56; font-size:13px; line-height:1.7; }
    .muted { color:#9aa7bd; font-style:italic; }
    .sig { display:flex; gap:10px; align-items:flex-start; border-left:3px solid #RISK; padding:9px 0 9px 12px; }
    .sig b { color:#0f2550; }
    .sev { font-size:10px; font-weight:800; padding:2px 7px; border-radius:999px; }
    .sev-CRITICAL { background:#ff4d6d; color:#fff; }
    .sev-HIGH { background:#ff9f43; color:#fff; }
    .sev-MEDIUM { background:#ffd166; color:#3d3100; }
    .sev-LOW { background:#22d3ee; color:#06303a; }
    .sev-INFO { background:#8b5cf6; color:#fff; }
    .bars { display:grid; gap:8px; margin-top:8px; }
    .bar { display:grid; grid-template-columns:140px 1fr 34px; gap:10px; align-items:center; font-size:12px; color:#40516e; }
    .track { height:9px; border-radius:9px; background:#e5e9f1; overflow:hidden; }
    .track i { display:block; height:100%; border-radius:9px; background:#22d3ee; }
    .foot { padding:18px 36px; border-top:1px solid #e5e9f1; color:#6b7891; font-size:12px; background:#f7fafc; }
    .remed { background:#f2fbfb; border:1px solid #c7eef2; border-radius:14px; padding:16px 18px; margin-top:10px; }
    @media (max-width:760px){ .grid{grid-template-columns:repeat(2,1fr);} .cols{grid-template-columns:1fr;} .hd,.body{padding-left:20px;padding-right:20px;} }
    """.replace("#RISK", risk_color.lstrip("#"))

    html = [
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"<title>ScriptSentry Report — {esc(summary['risk_label'])}</title>",
        f"<style>{css}</style></head><body><div class=\"page\">",
        "<div class=\"hd\">",
        "<h1>🛡️ ScriptSentry Analysis Report</h1>",
        "<div class=\"sub\">JS Intelligence Studio · " + esc(model["meta"]["source"] or "inline snippet") + " · " + esc(model["meta"]["generated_at"] or "now") + "</div>",
        f"<span class=\"risk\">RISK: {esc(summary['risk_label'])} · SCORE {summary['total_score']}</span>",
        "</div>",
        "<div class=\"grid\">",
        f"<div class=\"stat\"><b>{summary['total_files']}</b><span>Files</span></div>",
        f"<div class=\"stat\"><b>{summary['total_findings']}</b><span>Findings</span></div>",
        f"<div class=\"stat\"><b>{len(model['all_endpoints'])}</b><span>Endpoints</span></div>",
        f"<div class=\"stat\"><b>{len(summary['transport'])}</b><span>Transport</span></div>",
        "</div>",
        "<div class=\"body\">",
        "<h2>📌 Executive Summary</h2>",
        "<div class=\"card\"><p>" + esc(f"Risk posture is {summary['risk_label'].lower()} with {summary['total_findings']} findings across {summary['total_files']} file(s).") + "</p>",
        f"<div class=\"bars\">",
    ]

    # Category bars
    max_value = max(summary["categories"].values()) or 1
    for key, value in summary["categories"].items():
        if not value:
            continue
        pct = max(3, min(100, int(value * 100 / max_value)))
        html.append(f"<div class=\"bar\"><span>{esc(key.replace('_',' ').title())}</span><div class=\"track\"><i style=\"width:{pct}%\"></i></div><b>{value}</b></div>")
    html.append("</div></div>")

    # Signals
    html.append("<h2>🚦 Top Risk Signals</h2><div class=\"card\">")
    top = sorted(summary["signals"], key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s.get("severity", "INFO"), 4))[:12]
    if not top:
        html.append("<p class=\"muted\">No structured risk signals raised.</p>")
    for sig in top:
        sev = sig.get("severity", "INFO")
        html.append(f"<div class=\"sig\"><span class=\"sev sev-{esc(sev)}\">{esc(sev)}</span><div><b>{esc(sig.get('title',''))}</b> — {esc(sig.get('file',''))}<br><span>{esc(' · '.join([str(x) for x in (sig.get('evidence', []) or [])][:2]))}</span></div></div>")
    html.append("</div>")

    # Details per file
    html.append("<h2>🔎 Detailed Analysis</h2>")
    for norm in model["files"]:
        html.append(f"<div class=\"card\"><div class=\"file-head\"><h3>{esc(norm['name'])}</h3><span class=\"pill\">{esc(norm['risk'])} · {norm['score']}</span></div>")
        if norm.get("file_size"):
            html.append(f"<p style=\"color:#6b7891;font-size:12px\">{norm['file_size']} bytes · {norm['line_count']} lines · confidence {esc(norm.get('confidence') or 'n/a')}</p>")
        if norm["real_crypto_detected"]:
            html.append(f"<div class=\"sec\"><h4>Real Crypto Implementation</h4><ul>{items_html(_crypto_flow_text(norm['crypto_flows'])[:8], 8)}</ul></div>")
        html.append("<div class=\"cols\">")
        html.append(f"<div class=\"sec\"><h4>Secrets &amp; Credentials</h4><ul>{items_html(norm['secrets'], 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Crypto Keys &amp; IV</h4><ul>{items_html(list(norm['keys']) + list(norm['ivs']), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Authentication Analysis</h4><ul>{dict_items(norm['auth_summary'], lambda x: (x.get('type') or '') + ' — ' + (x.get('evidence') or ''), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>API Inventory</h4><ul>{dict_items(norm['api_inventory'], lambda x: (x.get('kind') or '') + ': ' + (x.get('endpoint') or ''), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Endpoints &amp; API Calls</h4><ul>{items_html(list(norm['endpoints']) + list(norm['api_calls']), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Storage Analysis</h4><ul>{dict_items(norm['storage_analysis'], lambda x: (x.get('storage') or '') + ' — ' + (x.get('classification') or ''), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Technology Stack</h4><ul>{dict_items(norm['technology_stack'], lambda x: (x.get('name') or '') + ' ' + (x.get('version') or ''), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Config &amp; Hardcoded Values</h4><ul>{items_html(list(norm['hardcoded_configs']) + list(norm['config_summary']), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>DOM &amp; Runtime Risks</h4><ul>{items_html(list(norm['dom_risks']) + list(norm['suspicious_calls']), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Obfuscation &amp; Decoded</h4><ul>{items_html(list(norm['decoded_strings']) + list(norm['obfuscation_analysis'].get('evidence', [])), 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Dependencies</h4><ul>{dict_items(norm['dependency_scan'], lambda x: (x.get('name') or '') + ' (' + (x.get('kind') or '') + ')', 6)}</ul></div>")
        html.append(f"<div class=\"sec\"><h4>Transport</h4><ul>{items_html(norm['transport'] + norm['request_methods'], 6)}</ul></div>")
        html.append("</div></div>")

    # Remediation
    html.append("<h2>✅ Recommended Fixes</h2><div class=\"remed\"><ol>")
    for step in _remediation(model):
        html.append(f"<li>{esc(step)}</li>")
    html.append("</ol></div>")

    if model["ai_summary"].get("executive_summary"):
        html.append("<h2>🧠 AI Notes</h2><div class=\"card\"><ul>")
        for line in model["ai_summary"]["executive_summary"][:5]:
            html.append(f"<li>{esc(line)}</li>")
        html.append("</ul></div>")

    html.append("</div><div class=\"foot\">ScriptSentry Analyzer v2.0 · deterministic regex + AST signals · this is a triage report, not a proof of exploitation.</div>")
    html.append("</div></body></html>")
    return "\n".join(html)


def _all_unified_findings(model):
    """Return the richest unified finding list for structured exports."""
    out = []
    seen = set()
    flows = model["summary"].get("dataflows", []) or []
    findings = model["summary"].get("findings", []) or []
    for item in findings:
        key = (item.get("id"), item.get("line"), str(item.get("sink", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    for item in flows:
        key = (item.get("id"), item.get("line"), str(item.get("sink", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def generate_csv_report(results, ai_summary=None):
    """Generate a CSV export of unified findings."""
    import csv
    import io

    model = build_report_model(results, ai_summary=ai_summary)
    findings = _all_unified_findings(model)
    fields = [
        "id", "type", "severity", "confidence", "status", "file", "line",
        "source", "sink", "flow", "evidence", "sanitization_detected", "framework",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        flow = " -> ".join(f.get("flow", []) or [])
        writer.writerow({
            "id": f.get("id", ""),
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
            "status": f.get("status", ""),
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "source": f.get("source", ""),
            "sink": f.get("sink", ""),
            "flow": flow,
            "evidence": f.get("evidence", ""),
            "sanitization_detected": f.get("sanitization_detected", False),
            "framework": f.get("framework", ""),
        })
    return buf.getvalue()


def generate_sarif_report(results, ai_summary=None):
    """Generate a SARIF 2.1.0 export of unified findings."""
    import json
    import uuid

    model = build_report_model(results, ai_summary=ai_summary)
    findings = _all_unified_findings(model)
    rules_map = {}
    results_out = []
    for i, f in enumerate(findings, 1):
        rule_id = str(f.get("id") or f.get("type") or "unknown")
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(f.get("type") or rule_id)},
                "help": {"text": f"ScriptSentry deterministic finding: {f.get('type', rule_id)}"},
                "properties": {"tags": [str(f.get("severity", "")).lower()]},
            }
        # line numbers are typically 1-indexed in ESTree; SARIF expects 0-indexed.
        start_line = max(0, int(f.get("line", 1) or 1) - 1)
        message = f.get("sink") or f.get("evidence") or f.get("type", rule_id)
        if f.get("source"):
            message = f"{f.get('source')} -> {message}"
        if f.get("flow"):
            message += " | path: " + " -> ".join(f.get("flow", [])[:6])
        result = {
            "ruleId": rule_id,
            "level": _sarif_level(f.get("severity", "MEDIUM")),
            "message": {"text": str(message)[:1000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file", ""))},
                    "region": {"startLine": start_line},
                }
            }],
            "properties": {
                "confidence": f.get("confidence", ""),
                "status": f.get("status", ""),
                "source": f.get("source", ""),
                "sink": f.get("sink", ""),
                "sanitization_detected": f.get("sanitization_detected", False),
            },
        }
        results_out.append(result)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ScriptSentry", "version": "2.0",
                               "informationUri": "https://github.com/AmitPal-CyberBuddy/ScriptSentry",
                               "rules": list(rules_map.values())}},
            "results": results_out,
        }],
    }, indent=2, ensure_ascii=False)


def _sarif_level(severity):
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(str(severity).upper(), "warning")


# =========================================
# 🎨 DASHBOARD / GUI PAYLOAD
# =========================================
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d6d",
    "HIGH": "#ff9f43",
    "MEDIUM": "#ffd166",
    "LOW": "#22d3ee",
    "INFO": "#8b5cf6",
}


def _severity_for(category, count):
    if count <= 0:
        return "INFO"
    if category in ("secrets", "keys", "ivs", "hardcoded_configs"):
        return "CRITICAL" if count >= 2 else "HIGH"
    if category in ("storage", "dom_risks", "suspicious_calls", "headers"):
        return "HIGH"
    if category in ("api_calls", "endpoints", "crypto", "auth_summary", "obfuscation"):
        return "MEDIUM"
    if category in ("technology_stack", "notable_features", "config_summary"):
        return "LOW"
    return "INFO"


def _clean_list(items, limit=8):
    out = []
    seen = set()
    for item in items or []:
        if isinstance(item, dict):
            text = safe_text(
                item.get("value", item.get("name", item.get("signal", item.get("endpoint", item.get("storage", "")))))
            ).strip()
        else:
            text = safe_text(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _file_diagnostic(file_name, data):
    counts = {
        "secrets": len(data.get("secrets", []) or []),
        "keys": len(data.get("keys", []) or []),
        "ivs": len(data.get("ivs", []) or []),
        "crypto": len(data.get("crypto", []) or []),
        "endpoints": len(data.get("endpoints", []) or []),
        "headers": len(data.get("headers", []) or []),
        "api_calls": len(data.get("api_calls", []) or []),
        "storage": len(data.get("storage", []) or []),
        "dom_risks": len(data.get("dom_risks", []) or []),
        "suspicious_calls": len(data.get("suspicious_calls", []) or []),
        "hardcoded_configs": len(data.get("hardcoded_configs", []) or []),
        "decoded_strings": len(data.get("decoded_strings", []) or []),
        "technology_stack": len(data.get("technology_stack", []) or []),
        "notable_features": len(data.get("notable_features", []) or []),
        "dataflows": len(data.get("dataflows", []) or []),
        "framework_findings": len(data.get("framework_findings", []) or []),
        "findings": len(data.get("findings", []) or []),
    }
    score, label, findings = score_risk(data)
    ast = data.get("ast_analysis", {}) or {}
    signals = []
    seen_sig = set()
    for sig in data.get("risk_signals", []) or []:
        key = (sig.get("id"), sig.get("severity"), sig.get("title"))
        if key in seen_sig:
            continue
        seen_sig.add(key)
        signals.append({"id": sig.get("id"), "severity": sig.get("severity", "INFO"), "title": sig.get("title", ""), "evidence": _clean_list(sig.get("evidence", []), 3)})
    return {
        "name": file_name,
        "score": score,
        "risk": label,
        "color": SEVERITY_COLORS.get(label, "#22d3ee"),
        "confidence": safe_text(data.get("confidence", "")),
        "size": data.get("file_size", 0),
        "lines": data.get("line_count", 0),
        "counts": counts,
        "findings": findings,
        "signals": signals,
        "deps": _clean_list(data.get("dependency_scan", []), 8),
        "transport": _clean_list(data.get("transport", []), 8),
        "methods": _clean_list(data.get("request_methods", []), 8),
        "complexity": ast.get("complexity", 0),
        "module_system": ast.get("module_system", ""),
        "parse_error": ast.get("parse_error", ""),
        "imports_count": len(ast.get("imports", []) or []),
        "exports_count": len(ast.get("exports", []) or []),
        "functions_count": len(ast.get("functions", []) or []),
        "classes_count": len(ast.get("classes", []) or []),
        "dataflows": data.get("dataflows", [])[:12],
        "attack_surface": data.get("attack_surface", {}) or {},
        "framework_findings": data.get("framework_findings", [])[:12],
        "rich_findings": data.get("findings", [])[:20],
        "finding_statuses": data.get("finding_statuses", {}) or {},
        "crypto_flows": _crypto_flow_text(data.get("crypto_flows", []))[:12],
        "secrets": _clean_list(data.get("secret_analysis", []), 8) or _clean_list(data.get("secrets", []), 8),
        "keys": _clean_list(data.get("keys", []), 8),
        "ivs": _clean_list(data.get("ivs", []), 8),
        "endpoints": _clean_list(data.get("endpoints", []), 12),
        "api_calls": _clean_list(data.get("api_calls", []), 12),
        "storage": _clean_list(data.get("storage", []), 8),
        "dom_risks": _clean_list(data.get("dom_risks", []), 8),
        "suspicious": _clean_list(data.get("suspicious_calls", []), 8),
        "configs": _clean_list(data.get("hardcoded_configs", []), 8),
        "decoded": _clean_list(data.get("decoded_strings", []), 8),
        "tech": _clean_list(data.get("technology_stack", []), 8),
        "features": _clean_list(data.get("notable_features", []), 10),
        "data_flow": _clean_list(data.get("data_flow_summary", []), 8),
        "auth": _clean_list(data.get("auth_summary", []), 8),
        "obfuscation": _clean_list(data.get("obfuscation_analysis", {}).get("evidence", []), 8),
    }


def build_dashboard_payload(results, ai_summary=None, metadata=None):
    files = []
    totals = {}
    findings = []
    flow_count = 0
    overall = 0

    category_meta = [
        ("secrets", "Secrets & Credentials", "#ff4d6d", "shield"),
        ("keys", "Crypto Keys", "#ff9f43", "key"),
        ("ivs", "IV / Nonce", "#ffd166", "vial"),
        ("crypto", "Crypto Routines", "#f472b6", "lock"),
        ("endpoints", "Endpoints", "#22d3ee", "route"),
        ("api_calls", "API Calls", "#38bdf8", "bolt"),
        ("storage", "Storage", "#a78bfa", "database"),
        ("dom_risks", "DOM / XSS", "#fb7185", "bug"),
        ("suspicious_calls", "Suspicious Runtime", "#f97316", "alert"),
        ("hardcoded_configs", "Hardcoded Config", "#fbbf24", "gear"),
        ("decoded_strings", "Decoded / Obfuscated", "#34d399", "sparkles"),
        ("technology_stack", "Tech Stack", "#60a5fa", "layers"),
        ("notable_features", "Notable Features", "#c084fc", "star"),
        ("dataflows", "Source→Sink Flows", "#fb7185", "flow"),
        ("framework_findings", "Framework Risks", "#f97316", "layers"),
    ]

    all_signals = []
    all_deps = []
    all_methods = set()
    all_transport = set()
    all_flows = []
    all_findings = []

    for file_name, data in results.items():
        diag = _file_diagnostic(file_name, data)
        files.append(diag)
        overall += diag["score"]
        for key, label, color, icon in category_meta:
            totals[key] = totals.get(key, 0) + diag["counts"].get(key, 0)
        flow_count += len(diag["crypto_flows"])
        for finding in diag["findings"]:
            findings.append(finding)
        for flow in diag["dataflows"]:
            all_flows.append({**flow, "file": file_name})
        for finding in diag["rich_findings"]:
            all_findings.append({**finding, "file": finding.get("file", file_name)})
        flow_ids = {f.get("id") for f in diag["dataflows"]} | {f.get("id") for f in diag["framework_findings"]}
        for sig in diag["signals"]:
            if sig.get("id") in ("api_surface", "notable_features") or sig.get("id") in flow_ids:
                continue
            all_signals.append({**sig, "file": diag["name"]})
        # Source→sink data flows are the highest-value signals.
        for flow in diag["dataflows"]:
            all_signals.append({
                "id": flow.get("id", "dataflow"),
                "severity": flow.get("severity", "HIGH"),
                "title": flow.get("type", flow.get("id", "Source-to-sink flow")),
                "evidence": flow.get("evidence") or flow.get("sink", ""),
                "source": flow.get("source", ""),
                "sink": flow.get("sink", ""),
                "flow": flow.get("flow", []),
                "status": flow.get("status", "potential"),
                "confidence": flow.get("confidence", "medium"),
                "file": diag["name"],
            })
        for fw in diag["framework_findings"]:
            all_signals.append({
                "id": fw.get("id", "framework_finding"),
                "severity": fw.get("severity", "MEDIUM"),
                "title": fw.get("type", fw.get("id", "Framework risk")),
                "evidence": fw.get("evidence") or fw.get("sink", ""),
                "file": diag["name"],
                "status": fw.get("status", "potential"),
                "confidence": fw.get("confidence", "medium"),
            })
        all_deps.extend(diag["deps"])
        all_methods.update(diag["methods"])
        all_transport.update(diag["transport"])

    max_file_score = max((f["score"] for f in files), default=0)

    # Overall risk label
    if overall >= 18 or max_file_score >= 9:
        risk_label = "CRITICAL"
        risk_color = "#ff4d6d"
    elif overall >= 8 or max_file_score >= 5:
        risk_label = "HIGH"
        risk_color = "#ff9f43"
    elif overall >= 3 or max_file_score >= 3:
        risk_label = "MEDIUM"
        risk_color = "#ffd166"
    else:
        risk_label = "LOW"
        risk_color = "#22d3ee"

    radar_values = []
    for key, label, color, icon in category_meta:
        radar_values.append(min(100, (totals.get(key, 0) * 18)))
    radar_categories = [label for _, label, _, _ in category_meta]
    donut_labels = [label for key, label, _, _ in category_meta if totals.get(key, 0)]
    donut_values = [totals.get(key, 0) for key, _, _, _ in category_meta if totals.get(key, 0)]
    donut_colors = [color for key, _, color, _ in category_meta if totals.get(key, 0)]

    timeline = [
        {"stage": "Discovery", "label": "Files & entry points", "value": len(files), "icon": "search", "color": "#22d3ee"},
        {"stage": "Surface", "label": "Secrets & keys", "value": totals.get("secrets", 0) + totals.get("keys", 0) + totals.get("ivs", 0), "icon": "key", "color": "#ff4d6d"},
        {"stage": "Transport", "label": "APIs & endpoints", "value": totals.get("endpoints", 0) + totals.get("api_calls", 0), "icon": "bolt", "color": "#38bdf8"},
        {"stage": "Runtime", "label": "Storage & DOM", "value": totals.get("storage", 0) + totals.get("dom_risks", 0), "icon": "database", "color": "#a78bfa"},
        {"stage": "Crypto", "label": "Crypto flows", "value": flow_count, "icon": "lock", "color": "#f472b6"},
        {"stage": "Signal", "label": "Obfuscation & config", "value": totals.get("decoded_strings", 0) + totals.get("hardcoded_configs", 0), "icon": "sparkles", "color": "#34d399"},
    ]

    payload = {
        "meta": {
            "generated_at": metadata.get("generated_at", "") if metadata else "",
            "engine": "ScriptSentry Analyzer",
            "engine_version": "2.0",
            "analysis_mode": metadata.get("mode", "code") if metadata else "code",
            "source": metadata.get("source", "") if metadata else "",
            "files": len(files),
        },
        "summary": {
            "overall_score": overall,
            "risk_label": risk_label,
            "risk_color": risk_color,
            "total_findings": sum(totals.values()),
            "total_files": len(files),
            "crypto_flow_count": flow_count,
            "categories": [
                {"key": key, "label": label, "value": totals.get(key, 0),
                 "color": color, "icon": icon} for key, label, color, icon in category_meta
            ],
            "top_findings": list(dict.fromkeys(findings))[:6],
            "signals": all_signals,
            "dependencies": list(dict.fromkeys(all_deps))[:40],
            "methods": sorted(all_methods),
            "transport": sorted(all_transport),
            "dataflows": all_flows[:80],
            "findings": all_findings[:120],
        },
        "files": files,
        "radar": {"labels": radar_categories, "values": radar_values},
        "donut": {"labels": donut_labels, "values": donut_values, "colors": donut_colors},
        "timeline": timeline,
        "ai_summary": ai_summary or {},
    }
    return payload
