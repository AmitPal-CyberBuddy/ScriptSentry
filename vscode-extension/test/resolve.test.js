"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { buildResolver } = require("../lib/resolve");

test("resolve: exact relative path wins", () => {
  const r = buildResolver([
    { path: "/w/src/app.js", relative: "src/app.js" },
    { path: "/w/vendor/app.js", relative: "vendor/app.js" },
  ]);
  assert.equal(r.resolve("src/app.js"), "/w/src/app.js");
  assert.equal(r.resolve("vendor/app.js"), "/w/vendor/app.js");
});

test("resolve: unique basename matches directly", () => {
  const r = buildResolver([
    { path: "/w/src/deep/tool.js", relative: "src/deep/tool.js" },
  ]);
  assert.equal(r.resolve("tool.js"), "/w/src/deep/tool.js");
});

test("resolve: duplicate basenames need a suffix match or stay unresolved", () => {
  const r = buildResolver([
    { path: "/w/a/app.js", relative: "a/app.js" },
    { path: "/w/b/app.js", relative: "b/app.js" },
  ]);
  // "b/app.js" disambiguates by suffix
  assert.equal(r.resolve("b/app.js"), "/w/b/app.js");
  // bare "app.js" is ambiguous: refuse to guess
  assert.strictEqual(r.resolve("app.js"), null);
});

test("resolve: backslashes and ./ prefixes are normalized", () => {
  const r = buildResolver([{ path: "/w/src/app.js", relative: "src/app.js" }]);
  assert.equal(r.resolve(".\\src\\app.js"), "/w/src/app.js");
  assert.equal(r.resolve("./src/app.js"), "/w/src/app.js");
});

test("resolve: unknown and empty uris return null, never throw", () => {
  const r = buildResolver([{ path: "/w/a.js", relative: "a.js" }]);
  assert.strictEqual(r.resolve("nope.js"), null);
  assert.strictEqual(r.resolve(""), null);
  assert.strictEqual(r.resolve(null), null);
});
