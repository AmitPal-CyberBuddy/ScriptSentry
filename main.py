import argparse
import json
import os
import sys
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None

from config import DEFAULT_PROFILE, REPORT_FORMATS, SCAN_PROFILES
from core.beautifier import beautify
from core.crypto import extract_crypto_material
from core.discovery import extract_js
from core.downloader import download_js
from ai.llm_engine import build_ai_summary
from core.reporter import (
    build_dashboard_payload,
    build_report_model,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)
from core.scanner import scan_file

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

visited = set()
all_results = {}
BASE_URL = ""
OUTPUT_DIR = "output"
BEAUTIFY_DIR = os.path.join(OUTPUT_DIR, "beautified")


def is_noise(item):
    noise_terms = [
        "arrow", "enter", "backspace", "ctrl", "draw", "render", "chart",
        "axis", "tooltip", "legend", "svg", "monaco", "worker", "animation",
        "button", "form", "label"
    ]
    return any(term in str(item).lower() for term in noise_terms)


def reset_state():
    visited.clear()
    all_results.clear()


def ensure_output_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(BEAUTIFY_DIR, exist_ok=True)


def resolve_chunk_path(chunk_name):
    chunk_name = chunk_name.split("?")[0]
    base = os.path.basename(chunk_name)
    if not os.path.isdir(BEAUTIFY_DIR):
        return None

    for root, _, files in os.walk(BEAUTIFY_DIR):
        for filename in files:
            if base == filename or base in filename:
                return os.path.join(root, filename)
    return None


def fetch_missing_chunk(chunk_name):
    global BASE_URL
    try:
        chunk_url = urljoin(BASE_URL, chunk_name)
        print(f"{CYAN}[↓] Fetching missing chunk: {chunk_url}{RESET}")
        response = requests.get(chunk_url, timeout=15)
        if response.status_code == 200:
            safe_name = os.path.basename(chunk_name.split("?")[0]) or "chunk.js"
            path = os.path.join(BEAUTIFY_DIR, safe_name)
            with open(path, "w", encoding="utf-8") as file:
                file.write(response.text)
            return path
    except Exception as exc:
        print(f"{RED}[!] Failed to fetch chunk: {exc}{RESET}")
    return None


def deep_scan(file_path, depth=0, max_depth=5):
    global all_results

    if depth > max_depth or file_path in visited:
        return

    visited.add(file_path)
    print(f"{BLUE}[+] Scanning (depth {depth}) {file_path}{RESET}")

    scan = scan_file(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="latin-1") as file:
                content = file.read()
        except Exception:
            return
    except Exception:
        return

    crypto = extract_crypto_material(content)
    scan.update(crypto)
    all_results[file_path] = scan

    if scan.get("real_crypto_detected"):
        print(f"{RED}[🔥 REAL CRYPTO DETECTED]{RESET}")
        for flow in scan.get("crypto_flows", [])[:5]:
            signal = flow.get("signal") if isinstance(flow, dict) else flow
            print("   ", signal)

    print(f"{YELLOW}[📊] Confidence: {scan.get('confidence')}{RESET}")

    clean_env = [
        ev for ev in scan.get("env_vars", [])
        if not is_noise(ev) and any(x in ev for x in ["EncryptionKey", "EncryptionIV"])
    ]
    if clean_env:
        print(f"{GREEN}[🔑] Environment Keys:{RESET}")
        for ev in clean_env[:6]:
            print("   ", ev)

    clean_secrets = [
        s for s in scan.get("secrets", [])
        if len(str(s)) < 80 and not is_noise(s)
    ]
    if clean_secrets:
        print(f"{GREEN}[🔐] Secrets:{RESET}")
        for s in clean_secrets[:5]:
            print("   ", s)

    if scan.get("keys"):
        print(f"{GREEN}[🔐] Crypto Keys:{RESET}")
        for k in list(dict.fromkeys([k.get("value") if isinstance(k, dict) else k for k in scan["keys"]]))[:5]:
            print("   ", k)

    if scan.get("ivs"):
        print(f"{GREEN}[🧪] IVs:{RESET}")
        for iv in list(dict.fromkeys([i.get("value") if isinstance(i, dict) else i for i in scan["ivs"]]))[:5]:
            print("   ", iv)

    important_logic = [
        line for line in scan.get("logic_snippets", [])
        if any(term in line for term in ["encrypt", "decrypt", "AES"])
    ]
    if important_logic:
        print(f"{CYAN}[🧠] Crypto Logic:{RESET}")
        for line in important_logic[:5]:
            print("   ", line)

    important_funcs = [
        func for func in scan.get("function_defs", [])
        if any(term in func for term in ["encrypt", "decrypt", "AES"])
    ]
    if important_funcs:
        print(f"{BLUE}[🔍] Crypto Functions:{RESET}")
        for func_def in important_funcs[:2]:
            print("------")
            print(func_def[:300])

    if scan.get("target_imports"):
        seen_imports = set()
        print(f"{CYAN}[🎯] Following Crypto Imports:{RESET}")
        for imp in scan["target_imports"]:
            if imp in seen_imports:
                continue
            seen_imports.add(imp)

            next_path = resolve_chunk_path(imp)
            if not next_path:
                next_path = fetch_missing_chunk(imp)

            if next_path:
                print(f"{CYAN}[→] {next_path}{RESET}")
                deep_scan(next_path, depth + 1, max_depth)

    print("-" * 50)


def is_real_crypto_key(k):
    val = k.strip('"').strip("'")
    if len(set(val)) < 6:
        return False

    junk = ["aria", "router", "component", "label", "data-", "index"]
    if any(term in val.lower() for term in junk):
        return False

    return (
        "EncryptionKey" in k
        or any(c in val for c in ["~", "<", ">", "$", "%", "&", "+", ";", "_"])
        or (len(val) >= 12 and not val.isalpha())
    )


def print_final_summary():
    print(f"\n{RED}🔥 ===== FINAL CRYPTO SUMMARY ===== 🔥{RESET}\n")

    keys = []
    ivs = []
    aes_detected = False
    env_keys = []

    for _, data in all_results.items():
        keys += [k.get("value") if isinstance(k, dict) else k for k in data.get("keys", [])]
        ivs += [i.get("value") if isinstance(i, dict) else i for i in data.get("ivs", [])]
        for ev in data.get("env_vars", []):
            if "EncryptionKey" in ev:
                val = ev.split(":")[-1].strip().strip('"').strip("'")
                env_keys.append(val)
        if data.get("real_crypto_detected"):
            aes_detected = True

    keys = list(set(keys))
    ivs = list(set(ivs))
    env_keys = list(set(env_keys))
    real_keys = [k for k in keys if is_real_crypto_key(k)]

    if env_keys:
        print(f"{GREEN}🔑 Key:{RESET} {env_keys[0]}")
    elif real_keys:
        print(f"{GREEN}🔑 Key:{RESET} {real_keys[0]}")
    elif keys:
        print(f"{GREEN}🔑 Key:{RESET} {keys[0]}")

    if ivs:
        clean_iv = max(ivs, key=lambda x: len(x))
        clean_iv = clean_iv.split(":")[-1].strip().strip('"').strip("'")
        print(f"{GREEN}🧪 IV:{RESET} {clean_iv}")

    if aes_detected:
        print(f"{RED}🔒 Algorithm:{RESET} AES-CBC (likely)")

    print(f"\n{RED}⚠️ Exploitability:{RESET}")
    print("   ✔ Client-side encryption")
    print("   ✔ Static key/IV exposed")
    print("   ✔ Fully reversible crypto")
    print("   ✔ Request manipulation possible")


def save_json(ai_summary=None):
    path = os.path.join(OUTPUT_DIR, "report.json")
    try:
        payload = {
            "metadata": {
                "profile": DEFAULT_PROFILE,
                "total_files": len(all_results)
            },
            "results": all_results,
            "report_model": build_report_model(all_results, ai_summary=ai_summary),
            "dashboard": build_dashboard_payload(all_results, ai_summary=ai_summary),
            "ai_summary": ai_summary or {}
        }
        with open(path, "w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)
        print(f"{GREEN}[+] JSON report saved: {path}{RESET}")
    except Exception as exc:
        print(f"{RED}[!] JSON save failed: {exc}{RESET}")


def save_report(report):
    path = os.path.join(OUTPUT_DIR, "report.txt")
    try:
        with open(path, "w", encoding="utf-8") as file:
            file.write(report)
        print(f"{GREEN}[+] Text report saved: {path}{RESET}")
    except Exception as exc:
        print(f"{RED}[!] Text report save failed: {exc}{RESET}")


def save_html_report(report_html):
    path = os.path.join(OUTPUT_DIR, "report.html")
    try:
        with open(path, "w", encoding="utf-8") as file:
            file.write(report_html)
        print(f"{GREEN}[+] HTML report saved: {path}{RESET}")
    except Exception as exc:
        print(f"{RED}[!] HTML report save failed: {exc}{RESET}")


def save_csv_report(report_csv):
    path = os.path.join(OUTPUT_DIR, "report.csv")
    try:
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(report_csv)
        print(f"{GREEN}[+] CSV report saved: {path}{RESET}")
    except Exception as exc:
        print(f"{RED}[!] CSV report save failed: {exc}{RESET}")


def save_sarif_report(report_sarif):
    path = os.path.join(OUTPUT_DIR, "report.sarif")
    try:
        with open(path, "w", encoding="utf-8") as file:
            file.write(report_sarif)
        print(f"{GREEN}[+] SARIF report saved: {path}{RESET}")
    except Exception as exc:
        print(f"{RED}[!] SARIF report save failed: {exc}{RESET}")


def run(urls, max_depth=5, timeout=15, profile="balanced", output_formats=None, ai_provider="disabled", api_key=None, model=None):
    global BASE_URL, DEFAULT_PROFILE
    reset_state()
    DEFAULT_PROFILE = profile
    BASE_URL = urls[0] if urls else ""
    ensure_output_dirs()

    if output_formats is None:
        output_formats = ["all"]

    print(f"{BLUE}[+] Target(s): {', '.join(urls)}{RESET}")

    for url in urls:
        print(f"{CYAN}[+] Analyzing: {url}{RESET}")
        js_files = extract_js(url)
        print(f"{CYAN}[+] Found {len(js_files)} JS files{RESET}")

        downloaded = download_js(js_files)
        print(f"{CYAN}[+] Downloaded {len(downloaded)} files{RESET}")

        beautified = beautify(downloaded)
        print(f"{CYAN}[+] Beautified files{RESET}")

        for file_path in beautified:
            deep_scan(file_path, max_depth=max_depth)

    print_final_summary()
    ai_summary = None
    if ai_provider != "disabled":
        ai_summary = build_ai_summary(all_results, provider=ai_provider, api_key=api_key, model=model)
    report = generate_report(all_results, ai_summary=ai_summary)

    if "all" in output_formats or "txt" in output_formats:
        save_report(report)
    if "all" in output_formats or "json" in output_formats:
        save_json(ai_summary=ai_summary)
    if "all" in output_formats or "html" in output_formats:
        save_html_report(generate_html_report(all_results, ai_summary=ai_summary))
    if "all" in output_formats or "csv" in output_formats:
        save_csv_report(generate_csv_report(all_results, ai_summary=ai_summary))
    if "all" in output_formats or "sarif" in output_formats:
        save_sarif_report(generate_sarif_report(all_results, ai_summary=ai_summary))

    print(f"\n{BLUE}========== FINAL REPORT =========={RESET}\n")
    print(report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze JavaScript assets for crypto, secrets, and endpoints.")
    parser.add_argument("--serve", action="store_true", help="Launch the visual web dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port used by --serve")
    parser.add_argument("urls", nargs="*", help="One or more target URLs to analyze")
    parser.add_argument("--max-depth", type=int, default=5, help="Maximum recursion depth for chunk analysis")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument(
        "--profile",
        choices=sorted(SCAN_PROFILES.keys()),
        default=DEFAULT_PROFILE,
        help="Scan profile to use (balanced, strict, fast)"
    )
    parser.add_argument(
        "--format",
        choices=REPORT_FORMATS,
        default="all",
        help="Report output format to save"
    )
    parser.add_argument(
        "--ai",
        choices=["disabled", "ollama", "openai", "azure"],
        default="disabled",
        help="Optional AI-assisted reasoning provider"
    )
    parser.add_argument("--api-key", default=None, help="API key for AI provider")
    parser.add_argument("--model", default=None, help="Model name for AI provider")
    args = parser.parse_args()

    if args.serve:
        import server
        srv = server.make_server(port=args.port)
        print(f"ScriptSentry dashboard listening on http://0.0.0.0:{args.port}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
        finally:
            srv.server_close()
        sys.exit(0)

    if not args.urls:
        parser.print_help()
        sys.exit(1)

    output_formats = [args.format] if args.format != "all" else ["all"]
    run(
        args.urls,
        max_depth=args.max_depth,
        timeout=args.timeout,
        profile=args.profile,
        output_formats=output_formats,
        ai_provider=args.ai,
        api_key=args.api_key,
        model=args.model,
    )

