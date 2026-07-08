import re


def analyze(content, previous=None):
    inventory = []
    patterns = [
        ("fetch", r'\bfetch\s*\(\s*["\']([^"\']+)["\']'),
        ("axios", r'\baxios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'),
        ("xhr", r'\bnew\s+XMLHttpRequest\b'),
        ("graphql", r'\bgraphql\b'),
        ("websocket", r'\bnew\s+WebSocket\b'),
        ("sse", r'\bEventSource\b'),
    ]
    for kind, pattern in patterns:
        matches = re.findall(pattern, content, flags=re.I)
        if matches:
            for match in matches[:10]:
                inventory.append({"kind": kind, "endpoint": match if isinstance(match, str) else "", "auth_required": bool(re.search(r'(authorization|token|auth)', content, re.I))})
    if not inventory:
        for match in re.findall(r'/(?:api|auth|graphql|v1|v2|oauth|login|logout)/[A-Za-z0-9/_\-]*', content):
            inventory.append({"kind": "path", "endpoint": match, "auth_required": bool(re.search(r'(authorization|token|auth)', content, re.I))})
    return inventory
