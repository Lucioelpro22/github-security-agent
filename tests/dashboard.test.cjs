"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const {
  clearDashboard,
  filterFindings,
  initDashboard,
  MAX_FINDINGS,
  parseReport,
  renderReport,
} = require("../dashboard/dashboard.js");

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
        title: "<img src=x onerror=alert(1)>",
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

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.dataset = {};
    this.handlers = {};
    this.textContent = "";
    this.value = "";
    this.hidden = false;
    this.files = [];
  }

  append(element) {
    this.children.push(element);
  }

  replaceChildren(...elements) {
    this.children = elements;
  }

  addEventListener(type, handler) {
    this.handlers[type] = handler;
  }

  removeEventListener(type, handler) {
    if (this.handlers[type] === handler) delete this.handlers[type];
  }
}

function fakeDocument() {
  const ids = [
    "repository-name",
    "provider-name",
    "summary-cards",
    "finding-rows",
    "search",
    "class-filter",
    "severity-filter",
    "result-count",
    "empty-results",
    "dashboard",
    "status",
    "report-file",
  ];
  const elements = new Map(ids.map((id) => [id, new FakeElement("div")]));
  const created = [];
  return {
    created,
    getElementById(id) {
      return elements.get(id);
    },
    createElement(tagName) {
      const element = new FakeElement(tagName);
      created.push(element);
      return element;
    },
    elements,
  };
}

test("accepts a complete version 1 report and keeps only allowlisted fields", () => {
  const report = parseReport(JSON.stringify(sample({})));
  assert.equal(report.repository, "owner/repo");
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings[0].title, "<img src=x onerror=alert(1)>");
  assert.equal("secret" in report.findings[0], false);
  assert.equal("metadata" in report.findings[0], false);
  assert.equal(JSON.stringify(report).includes("CANARY_SECRET_SHOULD_BE_DROPPED"), false);
  assert.equal(JSON.stringify(report).includes("DROP_ME"), false);
});

test("rejects malformed, old-version, and incomplete reports", () => {
  assert.throws(() => parseReport("{"), SyntaxError);
  assert.throws(() => parseReport(JSON.stringify(sample({ schema_version: 0 }))), /schema_version/);
  assert.throws(() => parseReport(JSON.stringify(sample({ status: "incomplete" }))), /incompleto/);
  assert.throws(
    () =>
      parseReport(
        JSON.stringify(
          sample({
            findings: [{ alert_class: "actions", severity: "low" }],
          })
        )
      ),
    /categoría o severidad/
  );
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

test("renders hostile alert values as text without creating executable elements", () => {
  const report = parseReport(JSON.stringify(sample({})));
  const doc = fakeDocument();
  renderReport(report, doc);
  const tableRow = doc.getElementById("finding-rows").children[0];
  assert.equal(tableRow.children[3].textContent, "<img src=x onerror=alert(1)>");
  assert.equal(doc.created.some((element) => ["img", "script"].includes(element.tagName)), false);
  assert.equal(doc.getElementById("repository-name").textContent, "owner/repo · main");
});

test("invalid imports clear previously rendered findings", async () => {
  const doc = fakeDocument();
  const fileInput = doc.getElementById("report-file");
  const dashboard = doc.getElementById("dashboard");
  const rows = doc.getElementById("finding-rows");
  dashboard.hidden = false;
  rows.append(new FakeElement("tr"));
  initDashboard(doc);
  fileInput.files = [{ size: 4, text: async () => '{"status":"incomplete"}' }];
  await fileInput.handlers.change();
  assert.equal(dashboard.hidden, true);
  assert.equal(rows.children.length, 0);
  assert.match(doc.getElementById("status").textContent, /incompleto/);
});

test("oversized imports are rejected before the file is read", async () => {
  const doc = fakeDocument();
  const fileInput = doc.getElementById("report-file");
  let wasRead = false;
  initDashboard(doc);
  fileInput.files = [
    {
      size: 5 * 1024 * 1024 + 1,
      async text() {
        wasRead = true;
        return "";
      },
    },
  ];
  await fileInput.handlers.change();
  assert.equal(wasRead, false);
  assert.equal(fileInput.value, "");
  assert.match(doc.getElementById("status").textContent, /5 MB/);
});

test("viewer has no remote resources or unsafe HTML insertion APIs", () => {
  const html = fs.readFileSync(path.join(__dirname, "../dashboard/index.html"), "utf8");
  const script = fs.readFileSync(path.join(__dirname, "../dashboard/dashboard.js"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "../dashboard/dashboard.css"), "utf8");
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(
    script,
    /\b(fetch|XMLHttpRequest|localStorage|sessionStorage|innerHTML|outerHTML|document\.write)\b/
  );
  assert.doesNotMatch(css, /https?:\/\//i);
  assert.match(script, /textContent/);
  assert.match(html, /connect-src 'none'/);
});

