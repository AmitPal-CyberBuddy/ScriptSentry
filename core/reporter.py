import html


def safe_text(val):
    if val is None:
        return ""
    return html.unescape(str(val))


def is_real_crypto_key(k):
    val = k.strip('"').strip("'")

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


def score_risk(data):
    score = 0
    findings = []

    if data.get("secrets"):
        score += 3
        findings.append("HIGH: Hardcoded secret/token material detected")
    if data.get("keys") and data.get("ivs"):
        score += 4
        findings.append("CRITICAL: Hardcoded key/IV pair detected")
    if data.get("storage"):
        score += 3
        findings.append("HIGH: Sensitive storage usage detected")
    if data.get("api_calls"):
        score += 1
        findings.append("MEDIUM: API request flow detected")
    if data.get("real_crypto_detected"):
        score += 2
        findings.append("MEDIUM: Crypto implementation detected")
    if data.get("decoded_strings"):
        score += 1
        findings.append("LOW: Decoded/obfuscated values detected")
    if data.get("suspicious_calls"):
        score += 1
        findings.append("LOW: Suspicious runtime or obfuscation pattern detected")

    if score >= 7:
        label = "CRITICAL"
    elif score >= 4:
        label = "HIGH"
    elif score >= 2:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label, findings


def generate_report(results, ai_summary=None):
    report = []
    all_keys = []
    all_ivs = []
    env_keys = []
    global_crypto = False

    report.append("\n========== DETAILED ANALYSIS ==========")

    for file, data in results.items():
        report.append(f"\n==== {file} ====")

        if data.get("real_crypto_detected"):
            global_crypto = True
            report.append("[🔥 REAL CRYPTO IMPLEMENTATION DETECTED]")
            for flow in sorted(set(data.get("crypto_flows", []))):
                report.append(f"  - {flow}")

        if data.get("confidence"):
            report.append(f"\n[📊 Confidence Level: {data['confidence']}]")

        if data.get("env_vars"):
            report.append("\n[🔑 Environment Variables:]")
            for ev in list(set(data["env_vars"]))[:8]:
                clean_ev = safe_text(ev)
                report.append(f"  - {clean_ev}")
                if "EncryptionKey" in clean_ev:
                    val = clean_ev.split(":")[-1].strip().strip('"').strip("'")
                    env_keys.append(val)

        if data.get("keys"):
            unique_keys = list(set(data["keys"]))
            all_keys.extend(unique_keys)
            report.append("\n[🔐 Crypto Keys:]")
            for k in unique_keys[:5]:
                report.append(f"  - {safe_text(k)}")

        if data.get("ivs"):
            unique_ivs = list(set(data["ivs"]))
            all_ivs.extend(unique_ivs)
            report.append("\n[🧪 IVs:]")
            for i in unique_ivs[:5]:
                report.append(f"  - {safe_text(i)}")

        if data.get("secrets"):
            report.append("\n[🔐 Secrets Found:]")
            for s in list(set(data["secrets"]))[:5]:
                report.append(f"  - {safe_text(s)}")

        if data.get("hardcoded_configs"):
            report.append("\n[🧩 Hardcoded Configs:]")
            for cfg in data["hardcoded_configs"][:5]:
                report.append(f"  - {safe_text(cfg)}")

        if data.get("storage"):
            report.append("\n[💾 Storage Usage:]")
            for item in list(set(data["storage"]))[:5]:
                report.append(f"  - {safe_text(item)}")

        if data.get("api_calls"):
            report.append("\n[🌐 API Calls:]")
            for item in list(set(data["api_calls"]))[:8]:
                report.append(f"  - {safe_text(item)}")

        if data.get("secret_analysis"):
            report.append("\n[🔐 Secret Analysis:]")
            for item in data["secret_analysis"][:5]:
                report.append(f"  - {safe_text(item.get('name', 'secret'))}: {safe_text(item.get('classification', ''))}")

        if data.get("auth_summary"):
            report.append("\n[🔑 Authentication Analysis:]")
            for item in data["auth_summary"][:5]:
                report.append(f"  - {safe_text(item.get('type', 'auth'))}")

        if data.get("api_inventory"):
            report.append("\n[🌐 API Inventory:]")
            for item in data["api_inventory"][:6]:
                report.append(f"  - {safe_text(item.get('kind', 'api'))}: {safe_text(item.get('endpoint', ''))}")

        if data.get("config_summary"):
            report.append("\n[⚙️ Configuration Analysis:]")
            for item in data["config_summary"][:5]:
                report.append(f"  - {safe_text(item.get('name', 'config'))}")

        if data.get("storage_analysis"):
            report.append("\n[💽 Storage Analysis:]")
            for item in data["storage_analysis"][:5]:
                report.append(f"  - {safe_text(item.get('storage', 'storage'))}: {safe_text(item.get('classification', ''))}")

        if data.get("technology_stack"):
            report.append("\n[🧰 Technology Stack:]")
            for item in data["technology_stack"][:5]:
                report.append(f"  - {safe_text(item.get('name', 'tech'))} {safe_text(item.get('version', ''))}".strip())

        if data.get("dom_risks"):
            report.append("\n[🛡️ DOM Risks:]")
            for item in data["dom_risks"][:5]:
                report.append(f"  - {safe_text(item)}")

        if data.get("decoded_strings"):
            report.append("\n[🧪 Decoded Strings:]")
            for item in data["decoded_strings"][:5]:
                report.append(f"  - {safe_text(item)}")

        if data.get("obfuscation_analysis"):
            report.append("\n[🕵️ Obfuscation Analysis:]")
            decoded = data["obfuscation_analysis"].get("decoded_values", [])
            evidence = data["obfuscation_analysis"].get("evidence", [])
            for item in decoded[:3]:
                report.append(f"  - decoded: {safe_text(item)}")
            for item in evidence[:3]:
                report.append(f"  - signal: {safe_text(item)}")

        if data.get("data_flow_summary"):
            report.append("\n[🔄 Data Flow Summary:]")
            for item in data["data_flow_summary"][:5]:
                report.append(f"  - {safe_text(item)}")

        if data.get("logic_snippets"):
            report.append("\n[🧠 Crypto Logic:]")
            for line in data["logic_snippets"][:5]:
                report.append(f"  - {safe_text(line)}")

        if data.get("function_defs"):
            report.append("\n[🔍 Crypto Functions:]")
            for f in data["function_defs"][:2]:
                report.append(f"  - {safe_text(f[:200])}")

        if data.get("suspicious_calls"):
            report.append("\n[⚠️ Suspicious Calls:]")
            for item in data["suspicious_calls"][:5]:
                report.append(f"  - {safe_text(item)}")

        risk_score, risk_label, risk_findings = score_risk(data)
        report.append(f"\n[⚠️ Risk Level: {risk_label} ({risk_score})]")
        for finding in risk_findings:
            report.append(f"  - {finding}")

    report.append("\n\n========== FINAL GLOBAL SUMMARY ==========")

    all_keys = list(set(all_keys))
    all_ivs = list(set(all_ivs))
    env_keys = list(set(env_keys))

    if global_crypto:
        report.append("[🔥 CRYPTOGRAPHY DETECTED ACROSS APPLICATION]\n")

    report.append("[🔑 Extracted Keys]")
    if env_keys:
        report.append(f"  - {env_keys[0]}")
    else:
        real_keys = [k for k in all_keys if is_real_crypto_key(k)]
        if real_keys:
            for k in real_keys[:3]:
                report.append(f"  - {k}")
        else:
            for k in all_keys[:3]:
                report.append(f"  - {k}")

    if all_ivs:
        report.append("\n[🧪 Extracted IVs]")
        clean_ivs = []
        for iv in all_ivs:
            iv_clean = clean_html(iv)
            if "parse(" in iv_clean.lower():
                continue
            val = iv_clean.split(":")[-1].strip().strip('"').strip("'")
            if len(val) >= 8:
                clean_ivs.append(val)
        for i in sorted(set(clean_ivs))[:3]:
            report.append(f"  - {i}")

    overall_score = 0
    overall_findings = []
    for data in results.values():
        score, label, findings = score_risk(data)
        overall_score += score
        overall_findings.extend(findings)

    if overall_score >= 10 or (all_keys and all_ivs):
        report.append("\n[🔥🔥 CRITICAL VULNERABILITY]")
        report.append("  - Hardcoded cryptographic material and sensitive data are exposed")
    elif overall_score >= 5 or global_crypto:
        report.append("\n[⚠️ MODERATE RISK]")
        report.append("  - Sensitive data and/or crypto flows were identified")
    else:
        report.append("\n[✅ LOW RISK]")
        report.append("  - No significant exposure detected")

    report.append("\n[📌 Structured Findings]")
    for item in list(dict.fromkeys(overall_findings))[:8]:
        report.append(f"  - {item}")

    if ai_summary:
        report.append("\n[🧠 Executive Summary]")
        for line in ai_summary.get("executive_summary", [])[:5]:
            report.append(f"  - {safe_text(line)}")
        if ai_summary.get("business_impact"):
            report.append("\n[💼 Business Impact]")
            for line in ai_summary["business_impact"][:3]:
                report.append(f"  - {safe_text(line)}")

    if all_keys:
        report.append("\n[🧠 Attack Insight]")
        report.append("  - Extracted keys can be used to replicate encryption")
        report.append("  - API requests can be forged externally")
        report.append("  - Tampering and replay attacks possible")

    return "\n".join(report)


def generate_html_report(results, ai_summary=None):
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<title>JS Analyzer Report</title>",
        "<style>",
        "body{font-family:Arial,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0;}",
        "h1,h2{color:#f8fafc;}",
        ".card{background:#111827;border:1px solid #334155;border-radius:8px;padding:12px;margin-bottom:12px;}",
        ".tag{display:inline-block;padding:3px 6px;background:#1e293b;border-radius:4px;margin-right:6px;}",
        "ul{margin:0;padding-left:18px;}",
        "</style>",
        "</head>",
        "<body>",
        "<h1>JS Analyzer Report</h1>"
    ]

    for file, data in results.items():
        score, label, findings = score_risk(data)
        html_parts.append(f"<div class=\"card\"><h2>{safe_text(file)}</h2>")
        html_parts.append(f"<p><span class=\"tag\">Risk: {label} ({score})</span>")
        if data.get("confidence"):
            html_parts.append(f"<span class=\"tag\">Confidence: {safe_text(data['confidence'])}</span>")
        html_parts.append("</p>")
        html_parts.append("<ul>")
        for finding in findings:
            html_parts.append(f"<li>{safe_text(finding)}</li>")
        html_parts.append("</ul>")
        if data.get("auth_summary"):
            html_parts.append("<p><strong>Authentication Analysis</strong></p><ul>")
            for item in data["auth_summary"][:5]:
                html_parts.append(f"<li>{safe_text(item.get('type', 'auth'))}</li>")
            html_parts.append("</ul>")
        if data.get("api_inventory"):
            html_parts.append("<p><strong>API Inventory</strong></p><ul>")
            for item in data["api_inventory"][:5]:
                html_parts.append(f"<li>{safe_text(item.get('kind', 'api'))}: {safe_text(item.get('endpoint', ''))}</li>")
            html_parts.append("</ul>")
        if data.get("storage_analysis"):
            html_parts.append("<p><strong>Storage Analysis</strong></p><ul>")
            for item in data["storage_analysis"][:5]:
                html_parts.append(f"<li>{safe_text(item.get('storage', 'storage'))}: {safe_text(item.get('classification', ''))}</li>")
            html_parts.append("</ul>")
        if data.get("technology_stack"):
            html_parts.append("<p><strong>Technology Stack</strong></p><ul>")
            for item in data["technology_stack"][:5]:
                html_parts.append(f"<li>{safe_text(item.get('name', 'tech'))} {safe_text(item.get('version', ''))}</li>")
            html_parts.append("</ul>")
        if data.get("data_flow_summary"):
            html_parts.append("<p><strong>Data Flow</strong></p><ul>")
            for item in data["data_flow_summary"][:5]:
                html_parts.append(f"<li>{safe_text(item)}</li>")
            html_parts.append("</ul>")
        html_parts.append("</div>")

    if ai_summary:
        html_parts.append("<div class=\"card\"><h2>Executive Summary</h2><ul>")
        for line in ai_summary.get("executive_summary", [])[:5]:
            html_parts.append(f"<li>{safe_text(line)}</li>")
        html_parts.append("</ul></div>")

    html_parts.append("</body>")
    html_parts.append("</html>")
    return "\n".join(html_parts)
