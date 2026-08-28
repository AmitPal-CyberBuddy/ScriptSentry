import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from config import BEAUTIFY_DIR

try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None


# =========================================
# 🧹 SINGLE FILE BEAUTIFY
# =========================================
def beautify_file(input_file):

    name = os.path.basename(input_file)
    output_file = os.path.join(BEAUTIFY_DIR, name)

    # ✅ Skip if already exists
    if os.path.exists(output_file):
        return output_file

    with open(input_file, "r", encoding="utf-8", errors="replace") as source_file:
        source = source_file.read()

    formatted = None
    # 1) Prefer the Python jsbeautifier module (works offline, no system binary)
    if jsbeautifier is not None:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            formatted = jsbeautifier.beautify(source, opts)
        except Exception:
            formatted = None

    # 2) Fall back to the js-beautify command-line tool if available
    if formatted is None and shutil.which("js-beautify") is not None:
        try:
            result = subprocess.run(
                ["js-beautify", input_file],
                capture_output=True,
                text=True,
                timeout=20
            )
            if result.returncode == 0 and result.stdout:
                formatted = result.stdout
        except Exception:
            formatted = None

    # 3) Last resort: keep the raw source so downstream analysis still runs
    if formatted is None:
        formatted = source

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(formatted)

    return output_file


# =========================================
# 🚀 MAIN BEAUTIFY (PARALLEL ✅)
# =========================================
def beautify(files):

    os.makedirs(BEAUTIFY_DIR, exist_ok=True)

    output_files = []

    # ✅ Parallel processing (fast)
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(beautify_file, files))

    # ✅ Clean None values
    output_files = [r for r in results if r]

    return output_files
