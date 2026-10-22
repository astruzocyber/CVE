// Exports of the currently filtered alerts (CSV / JSON / Markdown) plus the
// per-alert clipboard snippets. The string builders are pure and DOM-free.

import { downloadBlob, todayStamp } from "./dom.js";
import { fmtScore, fmtPct, fmtDay, cvssVersionText, osvFixText, nvdFixText, nvdFixIsRelease, nvdUrl, isNum } from "./format.js";

// A cell starting with one of these is executed as a formula by Excel/Sheets
// (CSV injection). Prefixing a single quote neutralises it.
export const CSV_FORMULA_TRIGGER_RE = /^[=+\-@\t\r]/;

export function csvCell(value) {
  if (value === null || value === undefined) return "";
  let s = String(value);
  if (typeof value === "string" && CSV_FORMULA_TRIGGER_RE.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const toCsvRow = (cells) => cells.map(csvCell).join(",");

const CSV_COLUMNS = [
  ["cve_id", (a) => a.cve_id],
  ["risk_score", (a) => a.risk_score],
  ["risk_score_prev", (a) => a.risk_score_prev],
  ["cvss_score", (a) => a.cvss_score],
  ["cvss_version", (a) => a.cvss_version],
  ["epss_score", (a) => a.epss_score],
  ["epss_score_prev", (a) => a.epss_score_prev],
  ["epss_percentile", (a) => a.epss_percentile],
  ["kev", (a) => a.kev],
  ["kev_date_added", (a) => a.kev_date_added],
  ["kev_due_date", (a) => a.kev_due_date],
  ["kev_ransomware_use", (a) => a.kev_ransomware_use],
  ["kev_required_action", (a) => a.kev_required_action],
  ["kev_notes", (a) => a.kev_notes],
  ["attack_vector", (a) => a.cvss_vector_components?.attack_vector],
  ["attack_complexity", (a) => a.cvss_vector_components?.attack_complexity],
  ["privileges_required", (a) => a.cvss_vector_components?.privileges_required],
  ["user_interaction", (a) => a.cvss_vector_components?.user_interaction],
  ["source", (a) => a.source],
  ["affected", (a) => (a.affected || []).join("; ")],
  ["cwe_ids", (a) => (a.cwe_ids || []).join("; ")],
  ["matched_keywords", (a) => (a.matched_keywords || []).join("; ")],
  ["published", (a) => a.published],
  ["nvd_last_modified", (a) => a.nvd_last_modified],
  ["vuln_status", (a) => a.vuln_status],
  ["first_seen", (a) => a.first_seen],
  ["osv_id", (a) => a.osv_id],
  ["osv_fixed_versions", (a) => (a.osv_fixed_versions || []).map(osvFixText).join("; ")],
  ["nvd_fix_versions", (a) => (a.nvd_fix_versions || []).map(nvdFixText).join("; ")],
  ["nvd_reference_links", (a) => (a.nvd_reference_links || []).map((r) => `${r.tags?.[0] || "Reference"}: ${r.url}`).join("; ")],
  ["dependabot_url", (a) => a.dependabot_url],
  ["description", (a) => a.description],
];

export function toCsv(alerts) {
  const lines = [toCsvRow(CSV_COLUMNS.map(([name]) => name))];
  for (const a of alerts) lines.push(toCsvRow(CSV_COLUMNS.map(([, get]) => get(a))));
  return lines.join("\r\n");
}

const mdCell = (s) => String(s).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function toMarkdownReport(alerts, now = new Date()) {
  const lines = [
    "# Vulnerability alert report",
    "",
    `Generated: ${now.toISOString()} · ${alerts.length} alert(s)`,
    "",
    "| CVE | Risk | CVSS | EPSS | KEV | Affected | Source |",
    "|---|---|---|---|---|---|---|",
  ];
  for (const a of alerts) {
    const risk = isNum(a.risk_score) ? a.risk_score.toFixed(0) : "n/a";
    const kev = a.kev ? (a.kev_ransomware_use ? "Yes (ransomware)" : "Yes") : "No";
    const affected = (a.affected || []).join(", ") || "n/a";
    lines.push(`| ${mdCell(a.cve_id)} | ${risk} | ${fmtScore(a.cvss_score)} | ${fmtPct(a.epss_score)} | ${kev} | ${mdCell(affected)} | ${mdCell(a.source || "unknown")} |`);
  }
  return lines.join("\n");
}

export function alertToMarkdown(a) {
  const version = cvssVersionText(a.cvss_version);
  const lines = [`### ${a.cve_id}`, ""];
  if (a.description) lines.push(a.description, "");
  lines.push(`- **CVSS:** ${fmtScore(a.cvss_score)}${version ? ` (${version})` : ""}`);
  lines.push(`- **EPSS:** ${fmtPct(a.epss_score)}`);
  lines.push(`- **Risk score:** ${isNum(a.risk_score) ? a.risk_score.toFixed(0) : "n/a"}/100`);
  lines.push(`- **KEV:** ${a.kev ? `Yes${a.kev_ransomware_use ? " (known ransomware use)" : ""}` : "No"}`);
  if (a.kev && a.kev_date_added) lines.push(`- **KEV added:** ${a.kev_date_added}`);
  if (a.kev && a.kev_due_date) lines.push(`- **KEV remediation due:** ${a.kev_due_date}`);
  if (a.kev && a.kev_required_action) lines.push(`- **Required action:** ${a.kev_required_action}`);
  lines.push(`- **Source:** ${a.source || "unknown"}`);
  lines.push(`- **Affected:** ${(a.affected || []).join(", ") || "n/a"}`);
  if ((a.cwe_ids || []).length) lines.push(`- **Weakness (CWE):** ${a.cwe_ids.join(", ")}`);
  lines.push(`- **Published:** ${fmtDay(a.published)}`);
  lines.push(`- **First seen (tracked):** ${fmtDay(a.first_seen)}`);
  const nvd = nvdUrl(a.cve_id);
  if (nvd) lines.push(`- **NVD:** ${nvd}`);
  if (a.dependabot_url) lines.push(`- **Dependabot alert:** ${a.dependabot_url}`);
  if ((a.osv_fixed_versions || []).length) lines.push(`- **Fix available (OSV.dev):** ${a.osv_fixed_versions.map(osvFixText).join(", ")}`);
  if ((a.nvd_fix_versions || []).length) {
    const label = a.nvd_fix_versions.some(nvdFixIsRelease) ? "Fix available (NVD)" : "Affected versions (NVD)";
    lines.push(`- **${label}:** ${a.nvd_fix_versions.map(nvdFixText).join(", ")}`);
  }
  if (a.osv_id) lines.push(`- **OSV.dev:** https://osv.dev/vulnerability/${encodeURIComponent(a.osv_id)}`);
  if ((a.nvd_reference_links || []).length) {
    lines.push(`- **Vendor links:** ${a.nvd_reference_links.map((r) => `[${r.tags?.[0] || "Reference"}](${r.url})`).join(", ")}`);
  }
  return lines.join("\n");
}

/** A config/suppressions.yaml entry, expiring one year out so it gets re-reviewed. */
export function suppressionSnippet(a, now = new Date()) {
  const expires = new Date(now);
  expires.setFullYear(expires.getFullYear() + 1);
  return [
    `- cve_id: "${a.cve_id}"`,
    `  reason: "REPLACE ME: why this does not apply (verified by <name>, <date>)"`,
    `  expires: "${expires.toISOString().slice(0, 10)}"`,
  ].join("\n");
}

export const exportCsv = (alerts) =>
  downloadBlob(`\uFEFF${toCsv(alerts)}`, "text/csv;charset=utf-8", `vulnerability-alerts-${todayStamp()}.csv`);

export const exportJson = (alerts) =>
  downloadBlob(JSON.stringify(alerts, null, 2), "application/json", `vulnerability-alerts-${todayStamp()}.json`);

export const exportMarkdown = (alerts) =>
  downloadBlob(toMarkdownReport(alerts), "text/markdown", `vulnerability-alert-report-${todayStamp()}.md`);
