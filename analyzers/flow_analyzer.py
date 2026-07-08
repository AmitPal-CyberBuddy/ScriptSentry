import re


def analyze(content, previous=None):
    flow = []
    if re.search(r'\b(?:fetch|axios|XMLHttpRequest)\s*\(', content):
        flow.append("input -> api")
    if re.search(r'\b(localStorage|sessionStorage|document\.cookie|Cookies?)\.(?:setItem|getItem|set|remove)\b', content):
        flow.append("storage")
    if re.search(r'\b(?:encrypt|decrypt|cipher|decipher)\s*\(', content):
        flow.append("encryption")
    if flow:
        return [" -> ".join(flow)]
    return []
