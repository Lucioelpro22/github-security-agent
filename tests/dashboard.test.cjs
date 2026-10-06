"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { filterFindings, parseReport, MAX_FINDINGS } = require("../dashboard/dashboard.js");

function sample(overrides) {
  return {
    schema_version: 1,
    provider: "github",
    status: "complete",
    repository: "owner/repo",
    base_branch: "main",
    findings: [
      {
        alert_class: "secret_scanning",
        identifier: "7",
        title: "<script>alert('xss')</script>",
        severity: "unknown",
        state: "open",
        secret: "CANARY_SECRET_SHOULD_BE_DROPPED",
        metadata: { leaked: "DROP_ME" },
      },
      {
        alert_class: "dependabot",
        identifier: "8",
        title: "Vulnerable package",
        severity: "high",
        state: "open",
        dependency: "demo-package",
        fixed_version: "2.0.0",
      },
    ],
    ...overrides,
  };
}

test("accepts a complete version 1 report and keeps only allowlisted fields", () => {
  const report = parseReport(JSON.stringify(sample({})));
  assert.equal(report.repository, "owner/repo");
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings[0].title, "<script>alert('xss')</script>");
  assert.equal("secret" in report.findings[0], false);
  assert.equal("metadata" in report.findings[0], false);
  assert.equal(JSON.stringify(report).includes("CANARY_SECRET_SHOULD_BE_DROPPED"), false);
  assert.equal(JSON.stringify(report).includes("DROP_ME"), false);
});

test("rejects malformed, old-version, and incomplete reports", () => {
  assert.throws(() => parseReport("{"), SyntaxError);
  assert.throws(() => parseReport(JSON.stringify(sample({ schema_version: 0 }))), /schema_version/);
  assert.throws(() => parseReport(JSON.stringify(sample({ status: "incomplete" }))), /incompleto/);
});

test("enforces the alert-count and per-finding schema limits", () => {
  const tooMany = Array.from({ length: MAX_FINDINGS + 1 }, () => ({
    alert_class: "dependabot",
    severity: "low",
  }));
  assert.throws(() => parseReport(JSON.stringify(sample({ findings: tooMany }))), /3\.000/);
  assert.throws(
    () =>
      parseReport(
        JSON.stringify(
          sample({
            findings: [{ alert_class: "unknown", severity: "high" }],
          })
        )
      ),
    /categoría o severidad/
  );
});

test("filters by category, severity, and case-insensitive text", () => {
  const findings = parseReport(JSON.stringify(sample({}))).findings;
  assert.equal(filterFindings(findings, { alertClass: "dependabot" }).length, 1);
  assert.equal(filterFindings(findings, { severity: "unknown" }).length, 1);
  assert.equal(filterFindings(findings, { query: "DEMO-PACKAGE" }).length, 1);
});

test("viewer has no remote resources or unsafe HTML insertion APIs", () => {
  const html = fs.readFileSync(path.join(__dirname, "../dashboard/index.html"), "utf8");
  const script = fs.readFileSync(path.join(__dirname, "../dashboard/dashboard.js"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "../dashboard/dashboard.css"), "utf8");
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(script, /\b(fetch|XMLHttpRequest|localStorage|sessionStorage|innerHTML|outerHTML|document\.write)\b/);
  assert.doesNotMatch(css, /https?:\/\//i);
  assert.match(script, /textContent/);
  assert.match(html, /connect-src 'none'/);
});
