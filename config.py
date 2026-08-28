# ===============================
# 📁 PATH CONFIG
# ===============================
OUTPUT_DIR = "output"
JS_DIR = f"{OUTPUT_DIR}/js_files"
BEAUTIFY_DIR = f"{OUTPUT_DIR}/beautified"

DEFAULT_PROFILE = "balanced"
REPORT_FORMATS = ["txt", "json", "html", "csv", "sarif", "all"]

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
    "min_js_size": 50,       # ignore tiny responses
    "max_js_size": 2_000_000  # skip very large files (optional)
}