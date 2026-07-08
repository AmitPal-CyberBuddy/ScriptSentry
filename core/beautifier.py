import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from config import BEAUTIFY_DIR


# =========================================
# 🧹 SINGLE FILE BEAUTIFY
# =========================================
def beautify_file(input_file):

    name = os.path.basename(input_file)
    output_file = os.path.join(BEAUTIFY_DIR, name)

    # ✅ Skip if already exists
    if os.path.exists(output_file):
        return output_file

    try:
        result = subprocess.run(
            ["js-beautify", input_file],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode == 0 and result.stdout:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
        else:
            # ✅ fallback (raw copy)
            with open(input_file, encoding="utf-8") as src, \
                 open(output_file, "w", encoding="utf-8") as dst:
                dst.write(src.read())

    except Exception:
        # ✅ fallback if tool fails
        try:
            with open(input_file, encoding="utf-8") as src, \
                 open(output_file, "w", encoding="utf-8") as dst:
                dst.write(src.read())
        except:
            return None

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
