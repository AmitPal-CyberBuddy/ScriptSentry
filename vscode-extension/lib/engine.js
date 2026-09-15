"use strict";

/**
 * Engine discovery and invocation for the VS Code extension.
 *
 * The engine is the ScriptSentry CLI (main.py): it takes targets and writes
 * SARIF into an output directory. The extension never bundles the engine --
 * it finds one of:
 *   1. scriptsentry.engineCommand (setting; string split on whitespace, or
 *      an array for paths with spaces)
 *   2. the launcher cache at ~/.scriptsentry/bootstrap/main.py
 *   3. a ScriptSentry checkout open as a workspace folder (self-scan)
 *
 * Only resolveEngineCommand/buildArgs are pure; runScan takes an injectable
 * spawn function so tests never run a real engine.
 */

const path = require("path");

function pythonExe() {
  return process.platform === "win32" ? "python" : "python3";
}

/** Resolve the engine command.
 *
 *  options: {
 *    setting: string | array | undefined,   -- scriptsentry.engineCommand
 *    workspaceFolders: ["/abs/folder", ...],
 *    homeDir: "/home/user",
 *    existsSync: (p) => bool,               -- injectable fs.existsSync
 *  }
 *  Returns { command: string[] | null, source: "setting"|"bootstrap"|"workspace"|"none" }.
 */
function resolveEngineCommand(options) {
  const exists = options.existsSync || (() => false);
  const home = options.homeDir || "";
  const folders = options.workspaceFolders || [];

  if (options.setting) {
    const parts = Array.isArray(options.setting)
      ? options.setting.map(String).filter(Boolean)
      : String(options.setting).trim().split(/\s+/).filter(Boolean);
    if (parts.length) {
      return { command: parts, source: "setting" };
    }
  }

  const bootstrap = path.join(home, ".scriptsentry", "bootstrap", "main.py");
  if (home && exists(bootstrap)) {
    return { command: [pythonExe(), bootstrap], source: "bootstrap" };
  }

  for (const folder of folders) {
    const main = path.join(folder, "main.py");
    if (exists(main) && exists(path.join(folder, "core", "reporter.py"))) {
      return { command: [pythonExe(), main], source: "workspace" };
    }
  }

  return { command: null, source: "none" };
}

/** CLI arguments for a scan: target, SARIF to outDir, profile. */
function buildArgs(target, profile, outDir) {
  return [
    target,
    "--format", "sarif",
    "--output", outDir,
    "--profile", profile || "balanced",
  ];
}

/** Run the engine. Returns a promise for { code, stdout, stderr }.
 *
 *  options: { command, args, cwd, timeoutSeconds, spawn }
 *  `spawn(command, args, options)` must return a child process with the
 *  node API (stdout/stderr streams, "error" and "close" events); tests
 *  inject a fake. The default is child_process.spawn without a shell.
 */
function runScan(options) {
  const spawn = options.spawn || require("child_process").spawn;
  const timeoutMs = Math.max(10, options.timeoutSeconds || 180) * 1000;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(options.command[0], options.command.slice(1).concat(options.args || []), {
        cwd: options.cwd,
        windowsHide: true,
      });
    } catch (err) {
      resolve({ code: -1, stdout: "", stderr: String(err && err.message || err) });
      return;
    }
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        try { child.kill(); } catch (e) { /* already gone */ }
      }
    }, timeoutMs);
    child.stdout && child.stdout.on("data", (d) => { stdout += d; });
    child.stderr && child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr + String(err && err.message || err) });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: code == null ? -1 : code, stdout, stderr });
    });
  });
}

module.exports = { resolveEngineCommand, buildArgs, runScan, pythonExe };
