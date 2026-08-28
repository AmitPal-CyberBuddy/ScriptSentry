"""Best-effort JavaScript normalization with scan-scoped output support."""
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from config import BEAUTIFY_DIR

try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None


def beautify_file(input_file, output_dir=None):
    output_dir = output_dir or BEAUTIFY_DIR
    name = os.path.basename(input_file)
    output_file = os.path.join(output_dir, name)
    os.makedirs(output_dir, exist_ok=True)
    if os.path.exists(output_file):
        return output_file

    with open(input_file, "r", encoding="utf-8", errors="replace") as source_file:
        source = source_file.read()

    formatted = None
    if jsbeautifier is not None:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            formatted = jsbeautifier.beautify(source, opts)
        except Exception:
            formatted = None

    if formatted is None and shutil.which("js-beautify") is not None:
        try:
            result = subprocess.run(
                ["js-beautify", input_file],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0 and result.stdout:
                formatted = result.stdout
        except Exception:
            formatted = None

    if formatted is None:
        formatted = source
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(formatted)
    return output_file


def beautify(files, output_dir=None, max_workers=5):
    output_dir = output_dir or BEAUTIFY_DIR
    os.makedirs(output_dir, exist_ok=True)
    files = list(files or [])
    if not files:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(files))) as executor:
        results = list(executor.map(lambda path: beautify_file(path, output_dir), files))
    return [result for result in results if result]
