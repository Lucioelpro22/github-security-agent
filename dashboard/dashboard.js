"use strict";

const MAX_FINDINGS = 5000;
const MAX_TEXT_LENGTH = 500;
const MAX_REPORT_BYTES = 5 * 1024 * 1024;
const ALERT_CLASSES = new Set(["dependabot", "code_scanning", "secret_scanning"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical", "unknown"]);
const CONFIDENCES = new Set(["low", "medium", "high"]);
const LOCAL_SEVERITIES = new Set(["low", "medium", "high"]);
const PROVIDERS = new Set(["empty", "github"]);
const ECOSYSTEMS = new Set(["PyPI", "npm", "crates.io", "Swift"]);

function cleanText(value, fallback) {
  if (typeof value !== "string") return fallback || "";
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, " ")
    .slice(0, MAX_TEXT_LENGTH);
}

function safeCount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("El informe contiene un conteo inválido: " + label + ".");
  }
  return value;
}

function safeRelativePath(value, label) {
  if (typeof value !== "string" || value.length > 1000) {
    throw new Error("El informe contiene una ruta inválida: " + label + ".");
  }
  const cleaned = cleanText(value, "").replace(/\\/g, "/");
  if (cleaned.startsWith("/") || /^[A-Za-z]:/.test(cleaned) || cleaned.split("/").includes("..")) {
    return "[ruta no relativa omitida]";
  }
  return cleaned.slice(0, MAX_TEXT_LENGTH);
}

function commonReport(report, type) {
  if (report.schema_version !== 1 || report.report_type !== type) {
    throw new Error("El formato del informe no coincide con su tipo o versión.");
  }
  if (!["complete", "incomplete"].includes(report.status)) {
    throw new Error("El informe no declara un estado compatible.");
  }
}

function normalizeGithub(report) {
  if (report.schema_version !== 1) {
    throw new Error("Formato de alertas GitHub no compatible: se requiere schema_version 1.");
  }
  if (report.report_type && report.report_type !== "github_alerts") {
    throw new Error("Tipo de informe GitHub no compatible.");
  }
  if (!["complete", "incomplete"].includes(report.status)) {
    throw new Error("El informe no declara un estado compatible.");
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
    throw new Error("La lista de hallazgos no es válida o excede el límite de 5.000.");
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
      detail: [cleanText(item.dependency, ""), cleanText(item.rule_id, ""),
        item.fixed_version ? "corregido en " + cleanText(item.fixed_version, "") : ""]
        .filter(Boolean).join(" · "),
      search_text: cleanText(item.dependency, "") + " " + cleanText(item.rule_id, ""),
    };
  });

  return {
    report_type: "github_alerts",
    status: report.status,
    header: cleanText(report.repository, "") + " · " + cleanText(report.base_branch, ""),
    source_label: report.provider === "github" ? "GitHub API" : "Proveedor offline",
    findings,
    dependencies: [],
    metrics: [],
    errors: [],
    lookup: "",
  };
}

function normalizeLocalScan(report) {
  commonReport(report, "local_scan");
  const filesScanned = safeCount(report.files_scanned, "files_scanned");
  const filesSkipped = safeCount(report.files_skipped, "files_skipped");
  if (typeof report.root !== "string" || report.root.length > 1000) {
    throw new Error("El informe no contiene una raíz local válida.");
  }
  if (!Array.isArray(report.findings) || report.findings.length > MAX_FINDINGS) {
    throw new Error("La lista de hallazgos excede el límite de 5.000 o no es válida.");
  }
  const findings = report.findings.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("El informe local contiene un hallazgo inválido.");
    }
    const severity = cleanText(item.severity, "");
    const confidence = cleanText(item.confidence, "");
    if (!LOCAL_SEVERITIES.has(severity) || !CONFIDENCES.has(confidence)) {
      throw new Error("El informe local contiene severidad o confianza desconocida.");
    }
    if (!Number.isSafeInteger(item.line) || item.line < 1) {
      throw new Error("El informe local contiene un número de línea inválido.");
    }
    const file = safeRelativePath(item.file, "file");
    const rule = cleanText(item.rule_id, "");
    const recommendation = cleanText(item.recommendation, "");
    return {
      alert_class: "local_scan",
      identifier: rule,
      title: cleanText(item.summary, "Hallazgo local"),
      severity,
      state: "Confianza: " + confidence,
      detail: file + ":" + item.line + " · Confianza: " + confidence +
        (recommendation ? " · " + recommendation : ""),
      search_text: rule + " " + file + " " + recommendation,
    };
  });
  return {
    report_type: "local_scan",
    status: report.status,
    header: "Repositorio local · ruta omitida",
    source_label: "Análisis local",
    findings,
    dependencies: [],
    metrics: [["Archivos analizados", filesScanned], ["Archivos omitidos", filesSkipped]],
    errors: [],
    lookup: "",
  };
}

function normalizeDependencyReport(report) {
  commonReport(report, "dependency_audit");
  const manifestsScanned = safeCount(report.manifests_scanned, "manifests_scanned");
  if (!Array.isArray(report.dependencies) || report.dependencies.length > MAX_FINDINGS) {
    throw new Error("El inventario de paquetes excede el límite de 5.000 o no es válido.");
  }
  if (!Array.isArray(report.advisories) || report.advisories.length > MAX_FINDINGS) {
    throw new Error("La lista de avisos excede el límite de 5.000 o no es válida.");
  }
  if (report.dependencies.length + report.advisories.length > MAX_FINDINGS) {
    throw new Error("El total combinado de paquetes y avisos excede el límite de 5.000.");
  }
  if (!Array.isArray(report.errors) || report.errors.length > 100) {
    throw new Error("La lista de errores no es válida.");
  }
  if (!["not_requested", "complete", "incomplete"].includes(report.advisory_lookup)) {
    throw new Error("El estado de consulta OSV no es compatible.");
  }
  const dependencies = report.dependencies.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("El inventario contiene un paquete inválido.");
    }
    if (!ECOSYSTEMS.has(item.ecosystem)) {
      throw new Error("El inventario contiene un ecosistema desconocido.");
    }
    return {
      name: cleanText(item.name, "Paquete desconocido"),
      version: cleanText(item.version, "Versión desconocida"),
      ecosystem: item.ecosystem,
      manifest: safeRelativePath(item.manifest, "manifest"),
    };
  });
  const findings = report.advisories.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item) ||
        !item.dependency || typeof item.dependency !== "object" || Array.isArray(item.dependency)) {
      throw new Error("El informe contiene un aviso o dependencia inválida.");
    }
    const dependency = item.dependency;
    if (!ECOSYSTEMS.has(dependency.ecosystem)) {
      throw new Error("El aviso contiene un ecosistema desconocido.");
    }
    const packageInfo = cleanText(dependency.name, "Paquete desconocido") + "@" +
      cleanText(dependency.version, "Versión desconocida");
    const manifest = safeRelativePath(dependency.manifest, "manifest");
    return {
      alert_class: "dependency_advisory",
      identifier: cleanText(item.advisory_id, "ID no disponible"),
      title: cleanText(item.summary, "Aviso OSV sin resumen"),
      severity: "unknown",
      state: "Severidad no incluida en el origen",
      detail: packageInfo + " · " + dependency.ecosystem + " · " + manifest,
      search_text: packageInfo + " " + dependency.ecosystem + " " + manifest,
    };
  });
  const errors = report.errors.map((item) => {
    if (typeof item !== "string") throw new Error("El informe contiene un detalle de error inválido.");
    const text = cleanText(item, "");
    const lower = text.toLocaleLowerCase();
    if (lower.endsWith("could not enumerate directory")) return "No se pudo enumerar un directorio.";
    if (lower.endsWith("skipped by size limit")) return "Se omitió un lockfile por su tamaño.";
    if (lower.endsWith("could not safely parse lockfile")) return "No se pudo interpretar un lockfile.";
    if (lower === "scan time limit reached") return "Se alcanzó el límite de tiempo del análisis.";
    if (lower === "dependency count reached configured limit") return "Se alcanzó el límite de dependencias.";
    if (/^osv lookup limited to the first \d+ dependencies$/i.test(text)) {
      return "La consulta OSV alcanzó su límite de paquetes.";
    }
    if (/^osv lookup skipped \d+ invalid package identifiers$/i.test(text)) {
      return "La consulta OSV omitió identificadores de paquetes inválidos.";
    }
    if (/^osv lookup failed: [A-Za-z]+$/i.test(text)) return "Falló una consulta a OSV.";
    return "Detalle de auditoría omitido por seguridad.";
  });
  let lookupLabel = "Consulta OSV no solicitada";
  if (report.advisory_lookup === "complete") lookupLabel = "Consulta OSV completa";
  if (report.advisory_lookup === "incomplete") lookupLabel = "Consulta OSV incompleta";
  return {
    report_type: "dependency_audit",
    status: report.status,
    header: "Inventario local de dependencias",
    source_label: "Auditoría de dependencias",
    findings,
    dependencies,
    metrics: [
      ["Lockfiles analizados", manifestsScanned],
      ["Paquetes inventariados", dependencies.length],
      ["Avisos OSV devueltos", findings.length],
      ["Consulta OSV", lookupLabel],
    ],
    errors,
    lookup: report.advisory_lookup,
  };
}

function parseReport(text) {
  const report = JSON.parse(text);
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("El archivo no contiene un objeto de informe.");
  }
  if (report.report_type === "local_scan") return normalizeLocalScan(report);
  if (report.report_type === "dependency_audit") return normalizeDependencyReport(report);
  if (report.report_type === "github_alerts" ||
      (report.report_type === undefined && Array.isArray(report.findings))) {
    return normalizeGithub(report);
  }
  throw new Error("Tipo de informe no compatible.");
}

function filterFindings(findings, filters) {
  const query = String(filters.query || "").trim().toLocaleLowerCase();
  return findings.filter((finding) => {
    if (filters.alertClass && finding.alert_class !== filters.alertClass) return false;
    if (filters.severity && finding.severity !== filters.severity) return false;
    if (!query) return true;
    const searchable = [
      finding.alert_class, finding.identifier, finding.title, finding.severity,
      finding.state, finding.detail, finding.search_text,
    ].join(" ").toLocaleLowerCase();
    return searchable.includes(query);
  });
}

function classLabel(value) {
  const labels = {
    dependabot: "Dependabot",
    code_scanning: "Code Scanning",
    secret_scanning: "Secret Scanning",
    local_scan: "Análisis local",
    dependency_advisory: "Aviso OSV",
  };
  return labels[value] || "Desconocida";
}

function severityLabel(value) {
  const labels = {
    critical: "Crítica",
    high: "Alta",
    medium: "Media",
    low: "Baja",
    unknown: "No incluida",
  };
  return labels[value] || "Desconocida";
}

function makeElement(doc, name, text, className) {
  const element = doc.createElement(name);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function summaryCards(report) {
  if (report.report_type === "dependency_audit") return report.metrics;
  if (report.report_type === "local_scan") {
    return [
      ["Hallazgos", report.findings.length],
      ...report.metrics,
      ...["high", "medium", "low"].map((severity) => [
        "Severidad " + severityLabel(severity),
        report.findings.filter((item) => item.severity === severity).length,
      ]),
    ];
  }
  return [
    ["Total", report.findings.length],
    ["Dependabot", report.findings.filter((f) => f.alert_class === "dependabot").length],
    ["Code Scanning", report.findings.filter((f) => f.alert_class === "code_scanning").length],
    ["Secret Scanning", report.findings.filter((f) => f.alert_class === "secret_scanning").length],
    ...["critical", "high", "medium", "low", "unknown"].map((severity) => [
      "Severidad " + severityLabel(severity),
      report.findings.filter((f) => f.severity === severity).length,
    ]),
  ];
}

function renderReport(report, doc) {
  doc.getElementById("repository-name").textContent = report.header;
  doc.getElementById("provider-name").textContent = report.source_label;
  const summary = doc.getElementById("summary-cards");
  const rows = doc.getElementById("finding-rows");
  summary.replaceChildren();
  rows.replaceChildren();

  for (const card of summaryCards(report)) {
    const wrapper = doc.createElement("div");
    wrapper.className = "summary-card";
    wrapper.append(makeElement(doc, "span", String(card[0]), "summary-label"));
    wrapper.append(makeElement(doc, "strong", String(card[1]), "summary-value"));
    summary.append(wrapper);
  }
  const options = doc.getElementById("class-filter");
  const categoryOptions = [
    ["dependabot", "Dependabot"],
    ["code_scanning", "Code Scanning"],
    ["secret_scanning", "Secret Scanning"],
    ["local_scan", "Análisis local"],
    ["dependency_advisory", "Aviso OSV"],
  ];
  options.replaceChildren(makeElement(doc, "option", "Todas", ""));
  options.children[0].value = "";
  for (const [value, label] of categoryOptions) {
    const option = makeElement(doc, "option", label, "");
    option.value = value;
    options.append(option);
  }

  const warning = doc.getElementById("report-warning");
  const warningText = doc.getElementById("warning-text");
  const warningErrors = doc.getElementById("warning-errors");
  warningText.textContent = report.status === "incomplete"
    ? "Informe incompleto: los resultados pueden ser parciales."
    : report.report_type === "dependency_audit" && report.lookup === "not_requested"
      ? "Se inventariaron paquetes; no se consultaron avisos OSV."
      : report.report_type === "dependency_audit" && report.lookup === "complete" && report.findings.length === 0
        ? "La consulta OSV no devolvió avisos para las versiones inventariadas; esto no demuestra ausencia de vulnerabilidades."
        : report.lookup === "incomplete"
          ? "La consulta OSV quedó incompleta; los resultados pueden ser parciales."
          : "";
  warningErrors.replaceChildren();
  for (const error of report.errors) warningErrors.append(makeElement(doc, "li", error, ""));
  warning.hidden = !warningText.textContent && report.errors.length === 0;

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
      row.append(makeElement(doc, "td", finding.detail || "—"));
      rows.append(row);
    }
    doc.getElementById("result-count").textContent =
      "Mostrando " + filtered.length + " de " + report.findings.length;
    const empty = doc.getElementById("empty-results");
    empty.hidden = filtered.length !== 0;
    if (report.report_type === "dependency_audit" && report.status === "incomplete") {
      empty.textContent = "El informe está incompleto; revisá la advertencia antes de interpretar la lista de avisos.";
    } else if (report.report_type === "dependency_audit" && report.lookup === "complete") {
      empty.textContent = "OSV no devolvió avisos para las versiones inventariadas; no equivale a ausencia de vulnerabilidades.";
    } else if (report.report_type === "dependency_audit" && report.lookup === "not_requested") {
      empty.textContent = "No se consultaron avisos OSV. El inventario de paquetes aparece abajo.";
    } else {
      empty.textContent = "No hay hallazgos que coincidan con estos filtros.";
    }
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

  const inventory = doc.getElementById("dependency-inventory");
  const inventoryRows = doc.getElementById("dependency-rows");
  inventory.hidden = report.report_type !== "dependency_audit";
  inventoryRows.replaceChildren();
  if (report.report_type === "dependency_audit") {
    for (const item of report.dependencies) {
      const row = doc.createElement("tr");
      row.append(makeElement(doc, "td", item.name));
      row.append(makeElement(doc, "td", item.version));
      row.append(makeElement(doc, "td", item.ecosystem));
      row.append(makeElement(doc, "td", item.manifest));
      inventoryRows.append(row);
    }
  }
}

function clearDashboard(doc) {
  doc.getElementById("dashboard").hidden = true;
  doc.getElementById("summary-cards").replaceChildren();
  doc.getElementById("finding-rows").replaceChildren();
  doc.getElementById("dependency-rows").replaceChildren();
  doc.getElementById("dependency-inventory").hidden = true;
  doc.getElementById("report-warning").hidden = true;
  doc.getElementById("warning-text").textContent = "";
  doc.getElementById("warning-errors").replaceChildren();
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
      status.textContent = "Seleccioná un informe compatible para comenzar.";
      return;
    }
    if (file.size > MAX_REPORT_BYTES) {
      status.dataset.state = "error";
      status.textContent = "El archivo supera el límite local de 5 MiB.";
      return;
    }
    try {
      const report = parseReport(await file.text());
      renderReport(report, doc);
      doc.getElementById("dashboard").hidden = false;
      status.dataset.state = "success";
      status.textContent = "Informe cargado desde el equipo. No se realizó ninguna conexión de red.";
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
    MAX_REPORT_BYTES,
  };
}
