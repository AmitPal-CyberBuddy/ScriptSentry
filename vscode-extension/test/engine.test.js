"use strict";

const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { resolveEngineCommand, buildArgs, runScan, pythonExe } = require("../lib/engine");

function fsFixture(existing) {
  return (p) => existing.has(path.normalize(p));
}

test("resolveEngineCommand: explicit setting wins, string or array", () => {
  const exists = fsFixture(new Set());
  const fromString = resolveEngineCommand({
    setting: "python3  /opt/ScriptSentry/main.py",
    workspaceFolders: [], homeDir: "/home/u", existsSync: exists,
  });
  assert.deepEqual(fromString.command, ["python3", "/opt/ScriptSentry/main.py"]);
  assert.equal(fromString.source, "setting");

  const fromArray = resolveEngineCommand({
    setting: ["python3", "/opt/My Scripts/main.py"],
    workspaceFolders: [], homeDir: "/home/u", existsSync: exists,
  });
  assert.deepEqual(fromArray.command, ["python3", "/opt/My Scripts/main.py"]);

  assert.deepEqual(resolveEngineCommand({
    setting: "   ", existsSync: exists,
  }).command, null); // whitespace-only setting is empty
});

test("resolveEngineCommand: launcher cache is found when no setting", () => {
  const exists = fsFixture(new Set([path.join("/home/u", ".scriptsentry", "bootstrap", "main.py")]));
  const r = resolveEngineCommand({
    setting: "", workspaceFolders: [], homeDir: "/home/u", existsSync: exists,
  });
  assert.equal(r.source, "bootstrap");
  assert.deepEqual(r.command, [pythonExe(), path.join("/home/u", ".scriptsentry", "bootstrap", "main.py")]);
});

test("resolveEngineCommand: a ScriptSentry checkout in the workspace (self-scan)", () => {
  const checkout = "/w/ScriptSentry";
  const exists = fsFixture(new Set([
    path.join(checkout, "main.py"),
    path.join(checkout, "core", "reporter.py"),
  ]));
  const r = resolveEngineCommand({
    setting: "", workspaceFolders: ["/w/other", checkout], homeDir: "/home/u", existsSync: exists,
  });
  assert.equal(r.source, "workspace");
  assert.deepEqual(r.command, [pythonExe(), path.join(checkout, "main.py")]);
});

test("resolveEngineCommand: a lone main.py is NOT enough (needs core/reporter.py)", () => {
  const exists = fsFixture(new Set([path.join("/w", "main.py")]));
  const r = resolveEngineCommand({
    setting: "", workspaceFolders: ["/w"], homeDir: "/home/u", existsSync: exists,
  });
  assert.equal(r.source, "none");
  assert.strictEqual(r.command, null);
});

test("buildArgs: target, sarif format, output dir, profile", () => {
  assert.deepEqual(
    buildArgs("/w", "strict", "/tmp/out1"),
    ["/w", "--format", "sarif", "--output", "/tmp/out1", "--profile", "strict"],
  );
  // default profile is balanced
  assert.deepEqual(
    buildArgs("/w", undefined, "/tmp/out2"),
    ["/w", "--format", "sarif", "--output", "/tmp/out2", "--profile", "balanced"],
  );
});

/** A fake child process satisfying the node events API. */
function fakeChild(events) {
  const { EventEmitter } = require("node:events");
  return new EventEmitter(events);
}

test("runScan: collects stdout/stderr and exit code", async () => {
  const spawn = () => {
    const child = fakeChild();
    process.nextTick(() => {
      child.emit("close", 0);
    });
    child.stdout = { on: (ev, cb) => { if (ev === "data") cb("out"); } };
    child.stderr = { on: (ev, cb) => { if (ev === "data") cb("err"); } };
    return child;
  };
  const res = await runScan({
    command: ["python3", "main.py"], args: ["--format", "sarif"],
    cwd: "/w", timeoutSeconds: 60, spawn,
  });
  assert.equal(res.code, 0);
  assert.equal(res.stdout, "out");
  assert.equal(res.stderr, "err");
});

test("runScan: spawn errors resolve instead of rejecting", async () => {
  const spawn = () => {
    const child = fakeChild();
    process.nextTick(() => child.emit("error", new Error("ENOENT")));
    child.stdout = { on: () => {} };
    child.stderr = { on: () => {} };
    return child;
  };
  const res = await runScan({ command: ["nope"], spawn });
  assert.equal(res.code, -1);
  assert.match(res.stderr, /ENOENT/);
});
