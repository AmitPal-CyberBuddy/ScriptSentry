# ===============================
# 📁 PATH CONFIG
# ===============================
OUTPUT_DIR = "output"
JS_DIR = f"{OUTPUT_DIR}/js_files"
BEAUTIFY_DIR = f"{OUTPUT_DIR}/beautified"

# Shared browser-ish User-Agent used by both the HTTP discovery layer and the
# local headless browser (when Playwright runtime evidence is enabled).
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}

# Runtime evidence capture (local headless browser).
# The feature is optional: if Playwright or Chromium is not installed, the
# engine silently falls back to static analysis and reports why.
# Override with SCRIPTSENTRY_RUNTIME_EVIDENCE=0/1 in the server process.
RUNTIME_EVIDENCE = {
    "enabled": True,
    "timeout_ms": 15_000,
    "wait_after_load_ms": 1_500,
    "max_requests": 300,
    "max_console": 120,
}

DEFAULT_PROFILE = "balanced"
REPORT_FORMATS = ["txt", "json", "html", "csv", "sarif", "all"]

# Local engine trust boundary:
# The static UI may be served from a localhost page OR a hosted GitHub Pages
# page. Arbitrary third-party origins must not be able to drive the local engine.
# Add custom origins through SCRIPTSENTRY_ALLOWED_ORIGINS (comma separated).
ALLOWED_ORIGINS = [
    "localhost",
    "127.0.0.1",
    "github.io",
    "file://",
    "null",
]

SCAN_PROFILES = {
    "balanced": {
        "max_depth": 5,
        "timeout": 15,
        "max_files": 50,
        "max_secrets": 20,
        "max_keys": 10,
    },
    "strict": {
        "max_depth": 7,
        "timeout": 20,
        "max_files": 100,
        "max_secrets": 50,
        "max_keys": 20,
    },
    "fast": {
        "max_depth": 3,
        "timeout": 10,
        "max_files": 25,
        "max_secrets": 10,
        "max_keys": 5,
    },
}


# ===============================
# 🔐 SECRET DETECTION PATTERNS
# ===============================
SECRET_REGEX = [

    # ✅ API / KEYS
    r'(?i)api[_-]?key\s*[:=]\s*[\'"][^\'"]+',
    r'(?i)secret\s*[:=]\s*[\'"][^\'"]+',
    r'(?i)client[_-]?secret\s*[:=]\s*[\'"][^\'"]+',

    # ✅ AUTH HEADERS
    r'(?i)authorization\s*[:=]\s*[\'"][^\'"]+',
    r'(?i)bearer\s+[A-Za-z0-9\-\._=]+',
    r'(?i)basic\s+[A-Za-z0-9\=\+\/]+',

    # ✅ TOKENS
    r'(?i)token\s*[:=]\s*[\'"][^\'"]+',
    r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',  # JWT

    # ✅ GENERIC HIGH ENTROPY
    r'[A-Za-z0-9+/]{40,}={0,2}',

    # ✅ PRIVATE KEY BLOCKS
    r'-----BEGIN PRIVATE KEY-----',
    r'-----BEGIN RSA PRIVATE KEY-----',

    # ✅ FIREBASE / GOOGLE
    r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',

]


# ===============================
# 🔐 CRYPTO DETECTION
# ===============================
CRYPTO_KEYWORDS = [

    # ✅ LIBRARIES
    "CryptoJS", "Forge", "sjcl", "OpenPGP",

    # ✅ ALGORITHMS
    "AES", "DES", "RC4",
    "CBC", "ECB", "GCM",
    "HmacSHA", "SHA1", "SHA256", "SHA512",

    # ✅ OPERATIONS
    "encrypt", "decrypt",
    "encode", "decode",

    # ✅ ENCODING
    "Base64", "Utf8", "Hex",
]


# ===============================
# 🚫 NOISE FILTER (GLOBAL ✅)
# ===============================
NOISE_WORDS = [
    "arrow", "enter", "ctrl", "shift",
    "draw", "render", "chart", "axis",
    "tooltip", "legend", "svg",
    "monaco", "worker", "animation",
    "button", "form", "label"
]


# ===============================
# ⚙️ SCANNER SETTINGS (NEW 🔥)
# ===============================
SCAN_CONFIG = {
    "max_depth": 5,
    "max_files": 50,
    "max_secrets": 20,
    "max_keys": 10,
    "timeout": 10
}


# ===============================
# 🚀 PERFORMANCE SETTINGS
# ===============================
PERFORMANCE = {
    "download_workers": 6,
    "beautify_workers": 5
}


# ===============================
# 🧠 CONFIDENCE THRESHOLDS
# ===============================
CONFIDENCE = {
    "high": 7,
    "medium": 4
}


# ===============================
# 📦 FILE RULES
# ===============================
FILE_RULES = {
    "min_js_size": 1,        # keep tiny modules; only drop empty responses
    "max_js_size": 2_000_000  # skip very large files (optional)
}