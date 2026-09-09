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
  const matchedKeywords = alert.matched_keywords || [];
  const matchedHtml = matchedKeywords.length
    ? `<div class="matched">Watchlist match: ${matchedKeywords.map((k) => `<span class="badge match">${escapeHtml(k)}</span>`).join("")}</div>`
    : "";
  const epssPct = typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a";
  const riskVal = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(0) : "n/a";
  const b = alert.risk_score_breakdown;
  const breakdownHtml = b ? `
      <div class="score-breakdown" hidden>
        <div class="breakdown-row"><span>CVSS ${fmtScore(b.cvss_raw)} &times; 35%</span><span>= ${fmtScore(b.cvss_component)} pts</span></div>
        <div class="breakdown-row"><span>EPSS ${typeof b.epss_raw === "number" ? (b.epss_raw * 100).toFixed(1) + "%" : "n/a"} &times; 40%</span><span>= ${fmtScore(b.epss_component)} pts</span></div>
        <div class="breakdown-row"><span>KEV bonus</span><span>= ${fmtScore(b.kev_bonus)} pts</span></div>
        <div class="breakdown-row breakdown-total"><span>Total${b.capped ? " (capped at 100)" : ""}</span><span>= ${riskVal} pts</span></div>
      </div>` : "";
  const toggleBtn = b ? `<button class="score-toggle" type="button" title="Show risk score breakdown" aria-expanded="false">breakdown &#9662;</button>` : "";

  return `
    <div class="card">
      <div class="card-header">
        <span class="cve-id">${escapeHtml(alert.cve_id)}</span>
        <div class="badges">${kevBadge}${ransomwareBadge}${overdueBadge}${sevBadge}${sourceBadge}</div>
      </div>
      <div class="risk-row">
        <div class="risk-bar-track"><div class="risk-bar-fill ${rClass}" style="width:${Math.min(100, alert.risk_score || 0)}%"></div></div>
        <span class="risk-label">Risk ${riskVal}/100</span>
        ${toggleBtn}
      </div>
      ${breakdownHtml}
      <div class="description">${escapeHtml(alert.description || "(no description)")}</div>
      <div class="scores">
        <span>CVSS: <strong>${fmtScore(alert.cvss_score)}</strong></span>
        <span>EPSS: <strong>${epssPct}</strong></span>
        ${alert.kev_due_date ? `<span>KEV due: <strong>${escapeHtml(alert.kev_due_date)}</strong></span>` : ""}
      </div>
      <div class="affected">Affected: ${escapeHtml(affected)}</div>
      ${matchedHtml}
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

// --- Dependency-scoped filtering (client-side only; nothing is uploaded) ---
let dependencyPackageNames = null; // null = no filter active; Set of lowercase names otherwise

function parsePackageJson(text) {
  const names = new Set();
  try {
    const obj = JSON.parse(text);
    for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
      if (obj[section]) {
        for (const name of Object.keys(obj[section])) names.add(name.toLowerCase());
      }
    }
  } catch (e) {
    throw new Error("Could not parse as package.json: " + e.message);
  }
  return names;
}

function parseRequirementsTxt(text) {
  const names = new Set();
  for (let line of text.split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    // Strip version specifiers / extras / environment markers: name==1.0, name>=1.0, name[extra], name; marker
    const m = line.match(/^([A-Za-z0-9._-]+)/);
    if (m) names.add(m[1].toLowerCase());
  }
  return names;
}

function detectAndParseDependencyFile(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return parsePackageJson(trimmed);
  return parseRequirementsTxt(trimmed);
}

function alertMatchesPackages(alert, packageNames) {
  const haystack = (alert.affected || []).join(" ").toLowerCase() + " " + (alert.description || "").toLowerCase();
  for (const pkg of packageNames) {
    if (pkg && haystack.includes(pkg)) return true;
  }
  return false;
}

function setupDependencyFilter() {
  const fileInput = document.getElementById("dep-file-input");
  const textInput = document.getElementById("dep-text-input");
  const applyBtn = document.getElementById("dep-apply-btn");
  const clearBtn = document.getElementById("dep-clear-btn");
  const statusEl = document.getElementById("dep-status");
  if (!fileInput || !applyBtn) return;

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    textInput.value = await file.text();
  });

  applyBtn.addEventListener("click", () => {
    const text = textInput.value;
    if (!text.trim()) {
      statusEl.textContent = "Paste or choose a package.json / requirements.txt first.";
      return;
    }
    try {
      const names = detectAndParseDependencyFile(text);
      if (names.size === 0) {
        statusEl.textContent = "No package names found in that file.";
        return;
      }
      dependencyPackageNames = names;
      statusEl.textContent = `Filtering to ${names.size} package(s): ${[...names].slice(0, 8).join(", ")}${names.size > 8 ? "..." : ""}`;
      applyFiltersAndRender();
    } catch (e) {
      statusEl.textContent = "Error: " + e.message;
    }
  });

  clearBtn.addEventListener("click", () => {
    dependencyPackageNames = null;
    textInput.value = "";
    fileInput.value = "";
    statusEl.textContent = "";
    applyFiltersAndRender();
  });
}

// --- Shareable filter state via URL query params (read on load, written on
// every filter change with replaceState so it never spams browser history). ---
function readFiltersFromURL() {
  const params = new URLSearchParams(location.search);
  const searchEl = document.getElementById("search");
  const kevEl = document.getElementById("kev-filter");
  const sourceEl = document.getElementById("source-filter");
  const sortEl = document.getElementById("sort-by");
  if (params.has("q")) searchEl.value = params.get("q");
  // Setting .value to an option that doesn't exist on a <select> is a no-op
  // in every browser, so an unrecognized/stale param value safely falls back
  // to whatever the element's default selection already was.
  if (params.has("kev")) kevEl.value = params.get("kev");
  if (params.has("source")) sourceEl.value = params.get("source");
  if (params.has("sort")) sortEl.value = params.get("sort");
}

function updateURLFromFilters(search, kevFilter, sourceFilter, sortBy) {
  const params = new URLSearchParams();
  if (search) params.set("q", search);
  if (kevFilter && kevFilter !== "all") params.set("kev", kevFilter);
  if (sourceFilter && sourceFilter !== "all") params.set("source", sourceFilter);
  if (sortBy && sortBy !== "risk_score") params.set("sort", sortBy);
  const qs = params.toString();
  const newUrl = location.pathname + (qs ? "?" + qs : "") + location.hash;
  history.replaceState(null, "", newUrl);
}

function applyFiltersAndRender() {
  const search = document.getElementById("search").value.trim().toLowerCase();
  const kevFilter = document.getElementById("kev-filter").value;
  const sourceFilter = document.getElementById("source-filter").value;
  const sortBy = document.getElementById("sort-by").value;
  updateURLFromFilters(search, kevFilter, sourceFilter, sortBy);

  let filtered = allAlerts.filter((a) => {
    if (kevFilter === "kev" && !a.kev) return false;
    if (kevFilter === "non-kev" && a.kev) return false;
    if (kevFilter === "overdue" && !isOverdue(a)) return false;
    if (kevFilter === "ransomware" && !a.kev_ransomware_use) return false;
    if (!matchesSource(a, sourceFilter)) return false;
    if (dependencyPackageNames && !alertMatchesPackages(a, dependencyPackageNames)) return false;
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

// Pipeline runs on a 4-hour schedule (.github/workflows/cve-alerts.yml). If the
// most recent generated_at is older than STALE_THRESHOLD_MS, something is wrong
// with the scheduled Action (broken workflow, disabled schedule, repeated
// failures) and a security lead viewing this public dashboard should know the
// data may be out of date rather than silently trusting it. Threshold is set
// generously above the 4h cadence to tolerate a single missed/delayed run
// without false-alarming on normal GitHub Actions scheduling jitter.
const STALE_THRESHOLD_MS = 20 * 60 * 60 * 1000; // 20 hours

function checkStaleness(generatedAt) {
  const banner = document.getElementById("stale-banner");
  if (!banner) return;
  if (!generatedAt) {
    banner.hidden = true;
    return;
  }
  const generated = new Date(generatedAt);
  if (isNaN(generated)) {
    banner.hidden = true;
    return;
  }
  const ageMs = Date.now() - generated.getTime();
  if (ageMs > STALE_THRESHOLD_MS) {
    const hours = Math.round(ageMs / (60 * 60 * 1000));
    banner.textContent = `\u26a0 Data may be stale: last successful update was ${hours}h ago (expected every ~4h). The aggregation pipeline may be failing -- check GitHub Actions.`;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

async function loadStats() {
  try {
    const res = await fetch("data/stats.json", { cache: "no-store" });
    if (!res.ok) return;
    const stats = await res.json();
    checkStaleness(stats.generated_at);
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

// Click delegation for the per-card risk-score breakdown toggle (avoids
// attaching a listener per card on every re-render).
document.getElementById("card-grid").addEventListener("click", (e) => {
  const btn = e.target.closest(".score-toggle");
  if (!btn) return;
  const panel = btn.closest(".risk-row").nextElementSibling;
  if (panel && panel.classList.contains("score-breakdown")) {
    panel.hidden = !panel.hidden;
    btn.innerHTML = panel.hidden ? "breakdown &#9662;" : "breakdown &#9652;";
    btn.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
  }
});

// --- Historical trend chart (Chart.js via CDN, client-side render only) ---
async function loadTrendChart() {
  const canvas = document.getElementById("trend-chart");
  if (!canvas || typeof Chart === "undefined") return;
  try {
    const res = await fetch("data/history/trend.csv", { cache: "no-store" });
    if (!res.ok) return;
    const csvText = await res.text();
    const lines = csvText.trim().split("\n");
    if (lines.length < 2) return; // header only, not enough data yet
    const rows = lines.slice(1).map((line) => line.split(","));
    const labels = rows.map((r) => r[0]);
    const kevOverdue = rows.map((r) => (r[3] === "" ? null : Number(r[3])));
    const avgEpss = rows.map((r) => (r[5] === "" ? null : Number(r[5]) * 100));

    document.getElementById("trend-section").hidden = false;
    new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "KEV overdue count",
            data: kevOverdue,
            borderColor: "#ff5c5c",
            backgroundColor: "rgba(255,92,92,0.15)",
            yAxisID: "y",
            tension: 0.2,
          },
          {
            label: "Avg EPSS (%)",
            data: avgEpss,
            borderColor: "#4f9dff",
            backgroundColor: "rgba(79,157,255,0.15)",
            yAxisID: "y1",
            tension: 0.2,
          },
        ],
      },
      options: {
        responsive: true,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { ticks: { maxTicksLimit: 8, color: "#9aa5b1" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: { position: "left", title: { display: true, text: "KEV overdue count", color: "#9aa5b1" }, ticks: { color: "#9aa5b1" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y1: { position: "right", title: { display: true, text: "Avg EPSS (%)", color: "#9aa5b1" }, ticks: { color: "#9aa5b1" }, grid: { drawOnChartArea: false } },
        },
        plugins: { legend: { labels: { color: "#e6e9ef" } } },
      },
    });
  } catch {
    // Chart.js CDN unreachable or trend.csv not yet generated -- fail quietly,
    // the rest of the dashboard still works without it.
  }
}

document.getElementById("search").addEventListener("input", applyFiltersAndRender);
document.getElementById("kev-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("source-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("sort-by").addEventListener("change", applyFiltersAndRender);
document.getElementById("export-csv").addEventListener("click", exportCsv);

readFiltersFromURL();
setupDependencyFilter();
loadData();
loadTrendChart();
