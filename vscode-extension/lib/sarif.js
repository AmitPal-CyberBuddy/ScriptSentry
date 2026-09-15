"use strict";

/**
 * Pure SARIF 2.1.0 -> findings parsing for the ScriptSentry VS Code extension.
 *
 * No vscode import: this module is unit-tested with plain `node --test`.
 * The engine's SARIF contract (core/reporter.py):
 *   - result.locations[0].physicalLocation.artifactLocation.uri  (basename
 *     or relative path of the finding's file)
 *   - region.startLine is 1-based per SARIF 2.1.3 §3.30.13, and is OMITTED
 *     when the engine does not know the line (file-level finding)
 *   - properties["security-severity"] is a CVSS-style string ("8.0")
 *   - rule helpUri points at the hosted rule reference
 *   - suppressions[] non-empty == decided false positive (server-side triage)
 */

/** Parse a SARIF document (object) into a flat list of findings. */
function parseSarif(doc) {
  const run = doc && doc.runs && doc.runs[0];
  if (!run) {
    throw new Error("not a SARIF document: runs[0] is missing");
  }
  const rules = {};
  for (const rule of (run.tool && run.tool.driver && run.tool.driver.rules) || []) {
    if (rule && rule.id) {
      rules[rule.id] = rule;
    }
  }
  const findings = [];
  for (const res of run.results || []) {
    const phys = res.locations && res.locations[0] && res.locations[0].physicalLocation;
    const artifact = phys && phys.artifactLocation;
    const region = phys && phys.region;
    const props = res.properties || {};
    const rule = rules[res.ruleId] || {};
    const ruleProps = rule.properties || {};
    const startLine = region && Number(region.startLine);
    findings.push({
      uri: (artifact && artifact.uri) || "",
      // 1-based; null when the engine has no line for this finding.
      line: Number.isFinite(startLine) && startLine >= 1 ? startLine : null,
      ruleId: res.ruleId || "",
      level: res.level || "note",
      message: (res.message && res.message.text) || res.ruleId || "",
      securitySeverity: props["security-severity"] != null
        ? Number(props["security-severity"]) : null,
      cwe: ruleProps.cwe || props.cwe || null,
      helpUri: rule.helpUri || null,
      // Server-side triage decision: decided false positives ship as
      // suppressions and are hidden by default.
      suppressed: Array.isArray(res.suppressions) && res.suppressions.length > 0,
      status: props.status || "",
    });
  }
  return findings;
}

/** Map a SARIF level (+ security-severity as tiebreaker) to a VS Code
 *  severity name. Returns one of "error" | "warning" | "information" | "hint".
 *  Pure: extension.js maps the name to vscode.DiagnosticSeverity. */
function severityName(level, securitySeverity) {
  if (level === "error") return "error";
  if (level === "warning") return "warning";
  // "note" covers two very different things: LOW findings (real but minor,
  // security-severity 3.0) and INFO observations (inventory, 1.0). Keep LOW
  // visible as information; only observations degrade to hints.
  if (securitySeverity != null && Number.isFinite(securitySeverity)) {
    return securitySeverity >= 3 ? "information" : "hint";
  }
  return "information";
}

module.exports = { parseSarif, severityName };
