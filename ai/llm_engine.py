"""Executive summary generation for ScriptSentry reports.

``--ai ollama`` calls a **local** Ollama server, so the privacy contract
holds: scanned code never leaves the machine.  OpenAI/Azure are
deliberately *not* supported -- sending analyzed code to a cloud provider
would contradict the tool's "no code ever leaves your computer" design.

The deterministic rule-based summary is the always-available fallback:
an unreachable or missing Ollama server degrades to it with an honest
``provider`` label instead of pretending an LLM answered.
"""
import json  # noqa: F401  (kept for parity with older integrations)

try:
    import requests
except ImportError:  # pragma: no cover - paste-only installations
    requests = None

OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2"
OLLAMA_TIMEOUT = 60


def _rule_based_summary(results):
    """Deterministic, evidence-derived executive summary (always available)."""
    executive = []
    for _, data in results.items():
        if data.get("secret_analysis"):
            executive.append("Hardcoded secrets and credentials are present in client-side code.")
        if data.get("auth_summary"):
            executive.append("Authentication flows and token handling were detected.")
        if data.get("api_inventory"):
            executive.append("API entry points and request channels were identified.")
        if data.get("dom_risks"):
            executive.append("DOM manipulation and dynamic script usage present potential XSS risk.")
        if data.get("storage_analysis"):
            executive.append("Client-side storage is used for sensitive application state.")
        break

    if not executive:
        executive.append("No obvious issues detected beyond standard client-side JavaScript patterns.")

    return {
        "executive_summary": executive,
        "business_impact": [
            "Client-side exposure can increase the impact of credential theft or session abuse.",
            "Sensitive flows should be validated through server-side enforcement and transport security.",
        ],
        "attack_path": ["input -> storage -> api"],
        "risk_explanation": [
            "The analysis remains rule-based and is intended to support triage, not replace deterministic detection.",
        ],
        "false_positive_review": [
            "Review any findings that originate from sample code or test fixtures.",
        ],
        "remediation_suggestions": [
            "Move secrets to server-side storage, minimize client-side token exposure, and sanitize DOM inputs.",
        ],
    }


def _ollama_prompt(results):
    """Build a compact, evidence-based prompt from findings.

    The prompt carries the structured findings and feature inventory --
    not the raw source code -- so even the local model only sees the
    analysis, keeping the payload small and reviewable.
    """
    lines = [
        "You are a JavaScript security triage assistant. Summarize the "
        "evidence below in 3-5 sentences for a developer: what is risky, "
        "what is uncertain, and what to check first.",
        "",
    ]
    for name, data in results.items():
        lines.append(f"File: {name}")
        findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
        if findings:
            for f in findings[:12]:
                lines.append(
                    f"- [{f.get('severity', 'INFO')}/{f.get('confidence', 'low')}] "
                    f"{f.get('type') or f.get('id')} @ {f.get('source') or '?'} -> "
                    f"{str(f.get('sink') or '')[:100]}"
                )
        else:
            lines.append("- no structured findings")
        features = data.get("notable_features") or []
        if features:
            lines.append(f"  features: {', '.join(str(x) for x in features[:8])}")
        lines.append("")
    lines.append("Be concise and concrete; do not invent findings that are not listed.")
    return "\n".join(lines)[:6000]


def _call_ollama(prompt, *, url, model, timeout=OLLAMA_TIMEOUT):
    """POST one non-streaming completion to a local Ollama server."""
    payload = {
        "model": model or OLLAMA_DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    response = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=timeout)
    response.raise_for_status()
    text = str(response.json().get("response") or "").strip()
    if not text:
        raise ValueError("Ollama returned an empty response")
    return text


def build_ai_summary(results, provider="disabled", api_key=None, model=None,
                     ollama_url=OLLAMA_DEFAULT_URL):
    """Return an executive summary dict, or None when summaries are off.

    ``provider``:
      * ``disabled`` -> None (no summary is produced at all)
      * ``ollama``   -> call the local Ollama server; on any failure fall
                        back to the deterministic summary and label the
                        result ``ollama_unavailable`` so reports stay honest
      * anything else -> deterministic summary labelled ``rule_based``
    """
    if provider == "disabled":
        return None

    summary = _rule_based_summary(results)

    if provider != "ollama":
        summary["provider"] = "rule_based"
        return summary

    if requests is None:
        summary["provider"] = "ollama_unavailable"
        summary["fallback_reason"] = "requests is not installed; local Ollama call not attempted."
        return summary

    try:
        text = _call_ollama(
            _ollama_prompt(results),
            url=ollama_url,
            model=model,
        )
        summary["provider"] = "ollama"
        summary["llm_text"] = text
    except Exception as exc:  # network, HTTP status, empty response
        summary["provider"] = "ollama_unavailable"
        summary["fallback_reason"] = (
            f"Ollama unreachable ({type(exc).__name__}): {str(exc)[:140]}"
        )
    return summary
