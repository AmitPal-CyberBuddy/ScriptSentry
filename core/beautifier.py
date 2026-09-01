"""Best-effort JavaScript normalization with scan-scoped output support."""
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import BEAUTIFY_DIR

try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None


def beautify_file(input_file, output_dir=None, progress_callback=None, done=0, total=0, cancel_check=None):
    output_dir = output_dir or BEAUTIFY_DIR
    name = os.path.basename(input_file)
    output_file = os.path.join(output_dir, name)
    os.makedirs(output_dir, exist_ok=True)
    if os.path.exists(output_file):
        return output_file

    # Beautifying a large minified bundle is CPU-bound and can take seconds on
    # its own; without a per-file event the whole normalize stage looks frozen.
    if progress_callback:
        progress_callback(
            phase="normalize",
            current=done,
            total=max(total, 1),
            message=f"Normalizing {name} ({min(done + 1, total or 1)}/{total or 1})",
        )
    if cancel_check and cancel_check():
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


def beautify(files, output_dir=None, max_workers=5, progress_callback=None, cancel_check=None):
    output_dir = output_dir or BEAUTIFY_DIR
    os.makedirs(output_dir, exist_ok=True)
    files = list(files or [])
    if not files:
        return []
    if progress_callback:
        progress_callback(
            phase="normalize", current=0, total=len(files),
            message=f"Normalizing {len(files)} downloaded bundle(s)",
        )
    # Report completion as each file lands so the stage advances incrementally
    # instead of jumping from 0/N to done when the pool drains.
    total = len(files)
    completed = 0
    results = []
    max_workers = max(1, min(max_workers, len(files)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(beautify_file, path, output_dir, progress_callback, index, total, cancel_check): path
            for index, path in enumerate(files)
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                results.append(result)
            completed += 1
            if progress_callback:
                progress_callback(
                    phase="normalize", current=completed, total=total,
                    message=f"Normalized {os.path.basename(path)} ({completed}/{total})",
                )
    return results
