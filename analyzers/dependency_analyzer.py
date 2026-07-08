import re


def analyze(content, previous=None):
    findings = []
    frameworks = [
        ("React", r'(?i)react|createRoot|useState'),
        ("Angular", r'(?i)@angular|ngModel|NgModule'),
        ("Vue", r'(?i)vue|createApp'),
        ("NextJS", r'(?i)next/|next/router'),
        ("Nuxt", r'(?i)nuxt'),
        ("jQuery", r'(?i)\$\(|jQuery'),
        ("Bootstrap", r'(?i)bootstrap'),
    ]
    for name, pattern in frameworks:
        if re.search(pattern, content):
            findings.append({"name": name, "version": "unknown"})
    return findings
