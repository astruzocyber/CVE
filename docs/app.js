// Static dashboard: fetches data/alerts.json + data/stats.json (same repo, same deploy)
// and renders filterable/sortable cards. No backend, no build step.

let allAlerts = [];

function severityClass(cvss) {
  if (cvss === null || cvss === undefined) return "";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

function riskClass(score) {
  if (typeof score !== "number") return "";
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function fmtScore(v, digits = 1) {
  return typeof v === "number" ? v.toFixed(digits) : "n/a";
}

function fmtDate(iso) {
  if (!iso) return "unknown";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function isOverdue(alert) {
  if (!alert.kev_due_date) return false;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  return !isNaN(due) && due.getTime() < Date.now();
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function renderCard(alert) {
  const sevClass = severityClass(alert.cvss_score);
  const rClass = riskClass(alert.risk_score);
  const overdue = isOverdue(alert);
  const kevBadge = alert.kev ? `<span class="badge kev">KEV</span>` : "";
  const overdueBadge = overdue ? `<span class="badge overdue">OVERDUE</span>` : "";
  const ransomwareBadge = alert.kev_ransomware_use ? `<span class="badge ransomware">RANSOMWARE</span>` : "";
  const sevBadge = sevClass
    ? `<span class="badge ${sevClass}">${sevClass}</span>`
    : "";
  const sourceBadge = `<span class="badge source">${escapeHtml(alert.source || "unknown")}</span>`;
  const affected = (alert.affected || []).join(", ") || "n/a";
  const epssPct = typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a";
  const riskVal = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(0) : "n/a";

  return `
    <div class="card">
      <div class="card-header">
        <span class="cve-id">${escapeHtml(alert.cve_id)}</span>
        <div class="badges">${kevBadge}${ransomwareBadge}${overdueBadge}${sevBadge}${sourceBadge}</div>
      </div>
      <div class="risk-row">
        <div class="risk-bar-track"><div class="risk-bar-fill ${rClass}" style="width:${Math.min(100, alert.risk_score || 0)}%"></div></div>
        <span class="risk-label">Risk ${riskVal}/100</span>
      </div>
      <div class="description">${escapeHtml(alert.description || "(no description)")}</div>
      <div class="scores">
        <span>CVSS: <strong>${fmtScore(alert.cvss_score)}</strong></span>
        <span>EPSS: <strong>${epssPct}</strong></span>
        ${alert.kev_due_date ? `<span>KEV due: <strong>${escapeHtml(alert.kev_due_date)}</strong></span>` : ""}
      </div>
      <div class="affected">Affected: ${escapeHtml(affected)}</div>
      <div class="card-footer">
        <span>Published: ${fmtDate(alert.published)}</span>
        <span>${alert.dependabot_url ? `<a href="${alert.dependabot_url}" target="_blank" rel="noopener">View alert</a>` : ""}</span>
      </div>
    </div>
  `;
}

function matchesSource(alert, filter) {
  if (filter === "all") return true;
  const src = alert.source || "";
  return src === filter || src.startsWith(filter + ":");
}

function applyFiltersAndRender() {
  const search = document.getElementById("search").value.trim().toLowerCase();
  const kevFilter = document.getElementById("kev-filter").value;
  const sourceFilter = document.getElementById("source-filter").value;
  const sortBy = document.getElementById("sort-by").value;

  let filtered = allAlerts.filter((a) => {
    if (kevFilter === "kev" && !a.kev) return false;
    if (kevFilter === "non-kev" && a.kev) return false;
    if (kevFilter === "overdue" && !isOverdue(a)) return false;
    if (kevFilter === "ransomware" && !a.kev_ransomware_use) return false;
    if (!matchesSource(a, sourceFilter)) return false;
    if (search) {
      const haystack = [
        a.cve_id,
        a.description,
        ...(a.affected || []),
        ...(a.matched_keywords || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    if (sortBy === "cvss_score" || sortBy === "epss_score" || sortBy === "risk_score") {
      return (b[sortBy] ?? -1) - (a[sortBy] ?? -1);
    }
    if (sortBy === "cve_id") {
      return (a.cve_id || "").localeCompare(b.cve_id || "");
    }
    // default: first_seen, newest first
    return (b.first_seen || "").localeCompare(a.first_seen || "");
  });

  const grid = document.getElementById("card-grid");
  const emptyState = document.getElementById("empty-state");
  document.getElementById("result-count").textContent = `${filtered.length} of ${allAlerts.length} alerts`;

  if (filtered.length === 0) {
    grid.innerHTML = "";
    emptyState.hidden = false;
  } else {
    emptyState.hidden = true;
    grid.innerHTML = filtered.map(renderCard).join("");
  }

  window.__lastFiltered = filtered;
}

function toCsvRow(fields) {
  return fields
    .map((f) => {
      const s = f === null || f === undefined ? "" : String(f);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    })
    .join(",");
}

function exportCsv() {
  const rows = window.__lastFiltered || allAlerts;
  const header = ["cve_id", "risk_score", "cvss_score", "epss_score", "kev", "kev_due_date",
    "kev_ransomware_use", "source", "affected", "published", "first_seen", "description"];
  const lines = [toCsvRow(header)];
  for (const a of rows) {
    lines.push(toCsvRow([
      a.cve_id, a.risk_score, a.cvss_score, a.epss_score, a.kev, a.kev_due_date,
      a.kev_ransomware_use, a.source, (a.affected || []).join("; "), a.published,
      a.first_seen, a.description,
    ]));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnerability-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

async function loadStats() {
  try {
    const res = await fetch("data/stats.json", { cache: "no-store" });
    if (!res.ok) return;
    const stats = await res.json();
    document.getElementById("stats-bar").hidden = false;
    document.getElementById("stat-total").textContent = stats.total_alerts ?? "-";
    document.getElementById("stat-critical").textContent = stats.by_severity?.critical ?? "-";
    document.getElementById("stat-kev").textContent = stats.kev_count ?? "-";
    document.getElementById("stat-overdue").textContent = stats.kev_overdue_count ?? "-";
    document.getElementById("stat-ransomware").textContent = stats.kev_ransomware_count ?? "-";
    document.getElementById("stat-epss").textContent =
      typeof stats.avg_epss === "number" ? (stats.avg_epss * 100).toFixed(1) + "%" : "-";
  } catch {
    // stats.json is optional/may not exist yet on the very first run -- fail quietly
  }
}

async function loadData() {
  try {
    const res = await fetch("data/alerts.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allAlerts = await res.json();
  } catch (e) {
    allAlerts = [];
    document.getElementById("last-updated").textContent =
      "Could not load data/alerts.json (no data yet, or fetch failed).";
    applyFiltersAndRender();
    return;
  }

  const latest = allAlerts.reduce((max, a) => {
    return a.first_seen && a.first_seen > max ? a.first_seen : max;
  }, "");
  document.getElementById("last-updated").textContent = latest
    ? `Most recent alert added: ${fmtDate(latest)} \u2022 ${allAlerts.length} total alerts tracked`
    : `${allAlerts.length} total alerts tracked`;

  applyFiltersAndRender();
  loadStats();
}

document.getElementById("search").addEventListener("input", applyFiltersAndRender);
document.getElementById("kev-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("source-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("sort-by").addEventListener("change", applyFiltersAndRender);
document.getElementById("export-csv").addEventListener("click", exportCsv);

loadData();
