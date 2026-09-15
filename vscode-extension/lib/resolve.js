"use strict";

/**
 * Map the engine's SARIF artifact URIs to real files in the workspace.
 *
 * The engine reports basenames (and, for nested files, paths relative to
 * the scan root). A VS Code workspace can contain several files with the
 * same basename, so resolution is exact-then-suffix-then-unique, and
 * refuses to guess when two candidates are equally plausible -- pointing
 * a security finding at the wrong file is worse than not pointing at all.
 *
 * Pure module, no vscode import: unit-tested with plain `node --test`.
 */

/** Build a resolver over the workspace's files.
 *
 *  files: [{ path: "/abs/path/app.js", relative: "src/app.js" }, ...]
 *  Returns { resolve(uri) -> path | null, ambiguous: Set<string> }.
 */
function buildResolver(files) {
  const byRelative = new Map();
  const byBasename = new Map();
  for (const f of files) {
    byRelative.set(f.relative, f.path);
    const base = f.relative.split("/").pop();
    if (!byBasename.has(base)) {
      byBasename.set(base, []);
    }
    byBasename.get(base).push(f);
  }

  function resolve(uri) {
    if (!uri) {
      return null;
    }
    const norm = String(uri).replace(/\\/g, "/").replace(/^\.\//, "");
    if (byRelative.has(norm)) {
      return byRelative.get(norm);
    }
    const base = norm.split("/").pop();
    const candidates = byBasename.get(base) || [];
    if (candidates.length === 0) {
      return null;
    }
    if (candidates.length === 1) {
      return candidates[0].path;
    }
    // Same basename in several places: prefer the file whose relative path
    // ends with the reported path (engine reported "src/app.js", workspace
    // has "packages/x/src/app.js").
    const suffix = candidates.filter((c) => c.relative.endsWith("/" + norm));
    if (suffix.length === 1) {
      return suffix[0].path;
    }
    return null;
  }

  return { resolve };
}

module.exports = { buildResolver };
