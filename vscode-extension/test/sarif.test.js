"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { parseSarif, severityName } = require("../lib/sarif");

/** A minimal but faithful engine result for fixture building. */
function sarifDoc(results, rules) {
  return {
    runs: [{
      tool: { driver: { rules: rules || [] } },
      results: results,
    }],
  };
}

function result(overrides) {
  return Object.assign({
    ruleId: "dom_injection",
    level: "error",
    message: { text: "location.hash -> el.innerHTML" },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: "app.js" },
        region: { startLine: 3 },
      },
    }],
    properties: { "security-severity": "8.0", status: "needs_review" },
  }, overrides);
}

test("parseSarif extracts the finding contract", () => {
  const findings = parseSarif(sarifDoc([result()]));
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.uri, "app.js");
  assert.equal(f.line, 3);            // 1-based, as SARIF 2.1.3 requires
  assert.equal(f.ruleId, "dom_injection");
  assert.equal(f.securitySeverity, 8.0);
  assert.equal(f.message, "location.hash -> el.innerHTML");
  assert.equal(f.suppressed, false);
});

test("parseSarif: line 1 stays line 1 (the off-by-one the engine used to have)", () => {
  const findings = parseSarif(sarifDoc([result({
    locations: [{ physicalLocation: {
      artifactLocation: { uri: "a.js" }, region: { startLine: 1 },
    } }],
  })]));
  assert.equal(findings[0].line, 1);
});

test("parseSarif: missing region means a file-level finding, not line 0", () => {
  const findings = parseSarif(sarifDoc([result({
    locations: [{ physicalLocation: { artifactLocation: { uri: "a.js" } } }],
  })]));
  assert.strictEqual(findings[0].line, null);
});

test("parseSarif: SARIF 0 as startLine (spec violation) is treated as unknown", () => {
  const findings = parseSarif(sarifDoc([result({
    locations: [{ physicalLocation: {
      artifactLocation: { uri: "a.js" }, region: { startLine: 0 },
    } }],
  })]));
  assert.strictEqual(findings[0].line, null);
});

test("parseSarif pulls cwe and helpUri from the rule, with result fallback", () => {
  const rules = [{
    id: "dom_injection",
    helpUri: "https://example.test/rules/#dom_injection",
    properties: { cwe: "CWE-79" },
  }];
  const findings = parseSarif(sarifDoc([result()], rules));
  assert.equal(findings[0].cwe, "CWE-79");
  assert.equal(findings[0].helpUri, "https://example.test/rules/#dom_injection");

  const noRule = parseSarif(sarifDoc([result({ ruleId: "unknown_rule" })]));
  assert.strictEqual(noRule[0].cwe, null);
  assert.strictEqual(noRule[0].helpUri, null);
});

test("parseSarif: suppressions mark decided false positives", () => {
  const findings = parseSarif(sarifDoc([result({ suppressions: [{ kind: "external" }] })]));
  assert.equal(findings[0].suppressed, true);
});

test("parseSarif: empty document, no results, malformed input", () => {
  assert.deepEqual(parseSarif(sarifDoc([])), []);
  assert.throws(() => parseSarif({}), /runs\[0\]/);
  assert.throws(() => parseSarif(null), /runs\[0\]/);
});

test("severityName maps levels, with CVSS for notes", () => {
  assert.equal(severityName("error", null), "error");
  assert.equal(severityName("warning", null), "warning");
  // LOW findings are level=note with security-severity 3.0: still actionable.
  assert.equal(severityName("note", 3.0), "information");
  // INFO observations are 1.0: hints.
  assert.equal(severityName("note", 1.0), "hint");
  assert.equal(severityName("note", null), "information");
});
