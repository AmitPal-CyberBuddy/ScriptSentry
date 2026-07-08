import json


def build_ai_summary(results, provider="disabled", api_key=None, model=None):
    """Return a deterministic, rule-based AI-style summary when no provider is configured."""
    if provider == "disabled":
        return None

    executive = []
    business = []
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

    business.append("Client-side exposure can increase the impact of credential theft or session abuse.")
    business.append("Sensitive flows should be validated through server-side enforcement and transport security.")

    return {
        "executive_summary": executive,
        "business_impact": business,
        "attack_path": ["input -> storage -> api"],
        "risk_explanation": ["The analysis remains rule-based and is intended to support triage, not replace deterministic detection."],
        "false_positive_review": ["Review any findings that originate from sample code or test fixtures."],
        "remediation_suggestions": ["Move secrets to server-side storage, minimize client-side token exposure, and sanitize DOM inputs."],
    }
