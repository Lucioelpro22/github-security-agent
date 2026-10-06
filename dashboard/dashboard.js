"use strict";

const MAX_FINDINGS = 3000;
const MAX_TEXT_LENGTH = 500;
const ALERT_CLASSES = new Set(["dependabot", "code_scanning", "secret_scanning"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical", "unknown"]);
const PROVIDERS = new Set(["empty", "github"]);

function cleanText(value, fallback) {
  if (typeof value !== "string") return fallback || "";
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, MAX_TEXT_LENGTH);
}

function parseReport(text) {
  const report = JSON.parse(text);
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("El archivo no contiene un objeto de informe.");
  }
  if (report.schema_version !== 1) {
    throw new Error("Formato no compatible: se requiere schema_version 1.");
  }
  if (report.status !== "complete") {
    throw new Error("El informe está incompleto o no declara estado complete.");
  }
  if (!PROVIDERS.has(report.provider)) {
    throw new Error("El proveedor declarado no es compatible.");
  }
  if (typeof report.repository !== "string" || report.repository.length > 205) {
    throw new Error("El informe no contiene un repositorio válido.");
  }
  if (typeof report.base_branch !== "string" || report.base_branch.length > 255) {
    throw new Error("El informe no contiene una rama válida.");
  }
  if (!Array.isArray(report.findings) || report.findings.length > MAX_FINDINGS) {
    throw new Error("La lista de hallazgos no es válida o excede el límite de 3.000.");
  }

  const findings = report.findings.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("El informe contiene un hallazgo con formato inválido.");
    }
    const alertClass = cleanText(item.alert_class, "");
    const severity = cleanText(item.severity, "");
    if (!ALERT_CLASSES.has(alertClass) || !SEVERITIES.has(severity)) {
      throw new Error("El informe contiene una categoría o severidad desconocida.");
    }
    return {
      alert_class: alertClass,
      identifier: cleanText(item.identifier, "—"),
      title: cleanText(item.title, "Sin título"),
      severity,
      state: cleanText(item.state, "unknown"),
      rule_id: cleanText(item.rule_id, ""),
      dependency: cleanText(item.dependency, ""),
      fixed_version: cleanText(item.fixed_version, ""),
    };
  });

  return {
    schema_version: 1,
    provider: report.provider,
    status: "complete",
    repository: cleanText(report.repository, ""),
    base_branch: cleanText(report.base_branch, ""),
    findings,
  };
}

function filterFindings(findings, filters) {
  const query = String(filters.query || "").trim().toLocaleLowerCase();
  return findings.filter((finding) => {
    if (filters.alertClass && finding.alert_class !== filters.alertClass) return false;
    if (filters.severity && finding.severity !== filters.severity) return false;
    if (!query) return true;
    const searchable = [
      finding.alert_class,
      finding.identifier,
      finding.title,
      finding.severity,
      finding.state,
      finding.rule_id,
      finding.dependency,
      finding.fixed_version,
    ].join(" ").toLocaleLowerCase();
    return searchable.includes(query);
  });
}

function classLabel(value) {
  const labels = {
    dependabot: "Dependabot",
    code_scanning: "Code Scanning",
    secret_scanning: "Secret Scanning",
    actions: "Actions",
  };
  return labels[value] || "Desconocida";
}

function severityLabel(value) {
  const labels = {
    critical: "Crítica",
    high: "Alta",
    medium: "Media",
    low: "Baja",
    unknown: "Desconocida",
  };
  return labels[value] || "Desconocida";
}

function makeElement(doc, name, text, className) {
  const element = doc.createElement(name);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function renderReport(report, doc) {
  const repository = doc.getElementById("repository-name");
  const providerName = doc.getElementById("provider-name");
  const summary = doc.getElementById("summary-cards");
  const rows = doc.getElementById("finding-rows");

  repository.textContent = report.repository + " · " + report.base_branch;
  providerName.textContent = report.provider === "github" ? "GitHub API" : "Proveedor offline";
  summary.replaceChildren();
  rows.replaceChildren();

  const cards = [
    ["Total", report.findings.length],
    ["Dependabot", report.findings.filter((f) => f.alert_class === "dependabot").length],
    ["Code Scanning", report.findings.filter((f) => f.alert_class === "code_scanning").length],
    ["Secret Scanning", report.findings.filter((f) => f.alert_class === "secret_scanning").length],
    ["Severidad crítica", report.findings.filter((f) => f.severity === "critical").length],
    ["Severidad alta", report.findings.filter((f) => f.severity === "high").length],
    ["Severidad media", report.findings.filter((f) => f.severity === "medium").length],
    ["Severidad baja", report.findings.filter((f) => f.severity === "low").length],
    ["Severidad desconocida", report.findings.filter((f) => f.severity === "unknown").length],
  ];
  for (const card of cards) {
    const wrapper = doc.createElement("div");
    wrapper.className = "summary-card";
    wrapper.append(makeElement(doc, "span", String(card[0]), "summary-label"));
    wrapper.append(makeElement(doc, "strong", String(card[1]), "summary-value"));
    summary.append(wrapper);
  }

  const applyFilters = () => {
    const filtered = filterFindings(report.findings, {
      query: doc.getElementById("search").value,
      alertClass: doc.getElementById("class-filter").value,
      severity: doc.getElementById("severity-filter").value,
    });
    rows.replaceChildren();
    for (const finding of filtered) {
      const row = doc.createElement("tr");
      row.append(makeElement(doc, "td", classLabel(finding.alert_class)));
      row.append(makeElement(doc, "td", finding.identifier));
      const severityCell = doc.createElement("td");
      const severity = makeElement(doc, "span", severityLabel(finding.severity), "severity");
      severity.dataset.severity = finding.severity;
      severityCell.append(severity);
      row.append(severityCell);
      row.append(makeElement(doc, "td", finding.title));
      const detail = finding.dependency || finding.rule_id || "—";
      const version = finding.fixed_version ? " · corregido en " + finding.fixed_version : "";
      row.append(makeElement(doc, "td", detail + version));
      rows.append(row);
    }
    doc.getElementById("result-count").textContent =
      "Mostrando " + filtered.length + " de " + report.findings.length;
    doc.getElementById("empty-results").hidden = filtered.length !== 0;
  };

  for (const id of ["search", "class-filter", "severity-filter"]) {
    const control = doc.getElementById(id);
    const previous = control.dashboardFilterHandler;
    if (previous) {
      control.removeEventListener("input", previous);
      control.removeEventListener("change", previous);
    }
    control.dashboardFilterHandler = applyFilters;
    control.addEventListener("input", applyFilters);
    control.addEventListener("change", applyFilters);
  }
  applyFilters();
}

function clearDashboard(doc) {
  doc.getElementById("dashboard").hidden = true;
  doc.getElementById("summary-cards").replaceChildren();
  doc.getElementById("finding-rows").replaceChildren();
  doc.getElementById("repository-name").textContent = "";
  doc.getElementById("provider-name").textContent = "";
  doc.getElementById("result-count").textContent = "";
  doc.getElementById("empty-results").hidden = true;
  doc.getElementById("search").value = "";
  doc.getElementById("class-filter").value = "";
  doc.getElementById("severity-filter").value = "";
}

function initDashboard(doc) {
  const fileInput = doc.getElementById("report-file");
  const status = doc.getElementById("status");
  fileInput.addEventListener("change", async () => {
    clearDashboard(doc);
    status.dataset.state = "";
    status.textContent = "Validando el informe…";
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = "";
    if (!file) {
      status.textContent = "Seleccioná un informe completo compatible para comenzar.";
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      status.dataset.state = "error";
      status.textContent = "El archivo supera el límite local de 5 MB.";
      return;
    }
    try {
      const report = parseReport(await file.text());
      renderReport(report, doc);
      doc.getElementById("dashboard").hidden = false;
      status.dataset.state = "success";
      status.textContent = "Informe completo cargado desde el equipo. No se realizó ninguna conexión de red.";
    } catch (error) {
      status.dataset.state = "error";
      status.textContent = error instanceof Error ? error.message : "No se pudo leer el informe.";
    }
  });
}

if (typeof document !== "undefined") {
  initDashboard(document);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    parseReport,
    filterFindings,
    renderReport,
    clearDashboard,
    initDashboard,
    MAX_FINDINGS,
  };
}
