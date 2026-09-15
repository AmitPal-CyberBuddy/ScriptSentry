"use strict";

/**
 * ScriptSentry for VS Code -- findings from the local ScriptSentry engine,
 * in the Problems panel.
 *
 * The extension never bundles the engine and never sends code anywhere: it
 * spawns the engine CLI (see lib/engine.js for how it's found), reads the
 * SARIF it writes, and maps results to diagnostics. Findings you marked as
 * false positives in the dashboard arrive as SARIF suppressions and are
 * hidden (opt back in with scriptsentry.showSuppressed).
 *
 * Not unit-tested directly (it is thin vscode glue); the pure halves --
 * lib/sarif.js, lib/resolve.js, lib/engine.js -- are covered by
 * node --test test/.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");

const vscode = require("vscode");
const { parseSarif, severityName } = require("./lib/sarif");
const { buildResolver } = require("./lib/resolve");
const { resolveEngineCommand, buildArgs, runScan } = require("./lib/engine");

const LANGUAGES = new Set(["javascript", "typescript", "javascriptreact", "typescriptreact"]);
const MAX_FINDINGS_PER_FILE = 200; // a single minified bundle can be noisy; cap per file

let outputChannel;
let statusBarItem;
let diagnostics;
let scanning = false;

function log(line) {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel("ScriptSentry");
  }
  outputChannel.appendLine(line);
}

function config() {
  return vscode.workspace.getConfiguration("scriptsentry");
}

function workspaceFolders() {
  return (vscode.workspace.workspaceFolders || []).map((f) => f.uri.fsPath);
}

/** The engine command, resolved once per scan (settings can change). */
function engineCommand() {
  const resolved = resolveEngineCommand({
    setting: config().get("engineCommand"),
    workspaceFolders: workspaceFolders(),
    homeDir: os.homedir(),
    existsSync: fs.existsSync,
  });
  if (!resolved.command) {
    vscode.window.showErrorMessage(
      "ScriptSentry: no engine found. Set scriptsentry.engineCommand " +
      "(e.g. \"python3 /path/to/ScriptSentry/main.py\"), or bootstrap one " +
      "with the launcher: python3 scriptsentry.py",
      "Open Settings",
    ).then((choice) => {
      if (choice === "Open Settings") {
        vscode.commands.executeCommand("workbench.action.openSettings", "scriptsentry.engineCommand");
      }
    });
    return null;
  }
  if (resolved.source !== "setting") {
    log("engine found via " + resolved.source + ": " + resolved.command.join(" "));
  }
  return resolved.command;
}

/** All candidate JS/TS files in the workspace, for URI resolution. */
async function workspaceFiles() {
  const uris = await vscode.workspace.findFiles(
    "**/*.{js,mjs,cjs,jsx,ts,tsx}",
    "**/{node_modules,.git,dist,out,build,.scriptsentry}/**",
    20000,
  );
  const folders = workspaceFolders();
  return uris.map((uri) => {
    const p = uri.fsPath;
    let relative = p;
    for (const folder of folders) {
      if (p.startsWith(folder + path.sep)) {
        relative = p.slice(folder.length + 1);
        break;
      }
    }
    return { path: p, relative: relative.replace(/\\/g, "/") };
  });
}

function diagnosticSeverity(name) {
  switch (name) {
    case "error": return vscode.DiagnosticSeverity.Error;
    case "warning": return vscode.DiagnosticSeverity.Warning;
    case "hint": return vscode.DiagnosticSeverity.Hint;
    default: return vscode.DiagnosticSeverity.Information;
  }
}

/** One finding -> one vscode.Diagnostic (range is a whole-line marker). */
function toDiagnostic(finding, showSuppressed) {
  const line = finding.line != null ? finding.line - 1 : 0; // SARIF is 1-based
  const range = new vscode.Range(line, 0, line, 1);
  const suppressed = finding.suppressed;
  if (suppressed && !showSuppressed) {
    return null;
  }
  const parts = [finding.ruleId, finding.message].filter(Boolean).join(": ");
  const withCwe = finding.cwe ? parts + " [" + finding.cwe + "]" : parts;
  const message = suppressed ? "[false positive] " + withCwe : withCwe;
  const sev = suppressed
    ? vscode.DiagnosticSeverity.Hint
    : diagnosticSeverity(severityName(finding.level, finding.securitySeverity));
  const diag = new vscode.Diagnostic(range, message, sev);
  diag.source = "scriptsentry";
  if (finding.ruleId) {
    diag.code = finding.ruleId;
  }
  if (finding.helpUri) {
    diag.codeDescription = { href: finding.helpUri };
  }
  return diag;
}

/** Core scan flow: run engine, parse SARIF, publish diagnostics. */
async function scan(target, label) {
  if (scanning) {
    log("scan already running; skipped " + label);
    return;
  }
  const command = engineCommand();
  if (!command) {
    return;
  }
  const cfg = config();
  scanning = true;
  statusBarItem.text = "$(shield~spin) ScriptSentry";
  statusBarItem.tooltip = "Scanning " + label + "…";
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "scriptsentry-vscode-"));
  try {
    const args = buildArgs(target, cfg.get("profile"), outDir);
    log("scan " + label + ": " + command.join(" ") + " " + args.join(" "));
    const res = await runScan({
      command: command,
      args: args,
      cwd: workspaceFolders()[0] || path.dirname(target),
      timeoutSeconds: cfg.get("engineTimeoutSeconds"),
    });
    if (res.stdout && res.stdout.trim()) {
      log("engine stdout: " + res.stdout.trim().split("\n").slice(-5).join("\n"));
    }
    if (res.stderr && res.stderr.trim()) {
      log("engine stderr: " + res.stderr.trim().split("\n").slice(-5).join("\n"));
    }
    const sarifPath = path.join(outDir, "report.sarif");
    let findings = [];
    if (fs.existsSync(sarifPath)) {
      findings = parseSarif(JSON.parse(fs.readFileSync(sarifPath, "utf8")));
    } else if (res.code !== 0) {
      throw new Error("engine exited " + res.code + " without a report");
    }
    await publish(findings);
    const counts = countBySeverity();
    log("scan " + label + " done: " + findings.length + " findings" +
        " (" + counts.errors + " errors, " + counts.warnings + " warnings)");
    if (findings.length === 0) {
      vscode.window.showInformationMessage("ScriptSentry: no findings in " + label + ".");
    }
  } catch (err) {
    log("scan failed: " + (err && err.stack || err));
    vscode.window.showErrorMessage("ScriptSentry scan failed: " + (err && err.message || err));
  } finally {
    scanning = false;
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch (e) { /* temp cleanup is best-effort */ }
    updateStatusBar();
  }
}

/** Map parsed findings onto real files and set the diagnostic collection. */
async function publish(findings) {
  const files = await workspaceFiles();
  const resolver = buildResolver(files);
  const showSuppressed = config().get("showSuppressed");
  const byFile = new Map();
  let unresolved = 0;
  let suppressedHidden = 0;
  for (const f of findings) {
    if (f.suppressed && !showSuppressed) {
      suppressedHidden++;
      continue;
    }
    const target = resolver.resolve(f.uri);
    if (!target) {
      unresolved++;
      continue;
    }
    if (!byFile.has(target)) {
      byFile.set(target, []);
    }
    if (byFile.get(target).length < MAX_FINDINGS_PER_FILE) {
      const diag = toDiagnostic(f, showSuppressed);
      if (diag) {
        byFile.get(target).push(diag);
      }
    }
  }
  diagnostics.clear();
  for (const [file, diags] of byFile) {
    diagnostics.set(vscode.Uri.file(file), diags);
  }
  if (unresolved) {
    log(unresolved + " finding(s) could not be placed in this workspace " +
        "(SARIF name matched no unique file)");
  }
  if (suppressedHidden) {
    log(suppressedHidden + " suppressed finding(s) hidden (false positives from triage)");
  }
}

function countBySeverity() {
  let errors = 0;
  let warnings = 0;
  for (const [, diags] of diagnostics) {
    for (const d of diags) {
      if (d.severity === vscode.DiagnosticSeverity.Error) errors++;
      else if (d.severity === vscode.DiagnosticSeverity.Warning) warnings++;
    }
  }
  return { errors, warnings };
}

function updateStatusBar() {
  const { errors, warnings } = countBySeverity();
  statusBarItem.text = "$(shield) " +
    (errors || warnings ? errors + " error" + (errors === 1 ? "" : "s") +
      (warnings ? ", " + warnings + " warning" + (warnings === 1 ? "" : "s") : "")
      : "clean");
  statusBarItem.tooltip = "ScriptSentry — click to scan the workspace";
}

let saveTimer = null;
function onDidSave(document) {
  if (!config().get("scanOnSave")) return;
  if (document.uri.scheme !== "file") return;
  if (!LANGUAGES.has(document.languageId)) return;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    saveTimer = null;
    scan(document.uri.fsPath, path.basename(document.uri.fsPath));
  }, 750);
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("scriptsentry");
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 60);
  statusBarItem.command = "scriptsentry.scanWorkspace";
  statusBarItem.text = "$(shield) ScriptSentry";
  statusBarItem.tooltip = "ScriptSentry — click to scan the workspace";
  statusBarItem.show();

  context.subscriptions.push(
    diagnostics,
    statusBarItem,
    vscode.commands.registerCommand("scriptsentry.scanWorkspace", () => {
      const folders = workspaceFolders();
      if (!folders.length) {
        vscode.window.showErrorMessage("ScriptSentry: open a folder first (File → Open Folder).");
        return;
      }
      scan(folders[0], "workspace");
    }),
    vscode.commands.registerCommand("scriptsentry.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.uri.scheme !== "file") {
        vscode.window.showErrorMessage("ScriptSentry: no saved file in the active editor.");
        return;
      }
      scan(editor.document.uri.fsPath, path.basename(editor.document.uri.fsPath));
    }),
    vscode.commands.registerCommand("scriptsentry.clear", () => {
      diagnostics.clear();
      updateStatusBar();
    }),
    vscode.commands.registerCommand("scriptsentry.showOutput", () => {
      if (outputChannel) outputChannel.show();
    }),
    vscode.workspace.onDidSaveTextDocument(onDidSave),
  );
}

module.exports = { activate, deactivate: () => {} };
