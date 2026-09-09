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

// How many whole days past the CISA KEV BOD 22-01 remediation due date this
// alert is, or null if not overdue / no due date. Purely a display magnitude
// for the existing OVERDUE badge -- the overdue/non-overdue decision itself
// still comes from isOverdue() above, unchanged.
function overdueDays(alert) {
  if (!isOverdue(alert)) return null;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  const diffMs = Date.now() - due.getTime();
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

// Whole days remaining until the CISA KEV BOD 22-01 remediation due date, or
// null if there is no due date or it has already passed (that case is
// covered by isOverdue()/overdueDays() above, not this function -- the two
// are mutually exclusive by construction). Purely a display magnitude used
// to flag upcoming deadlines before they become overdue, mirroring the
// existing overdue-days feature symmetrically on the other side of "today".
function daysUntilDue(alert) {
  if (!alert.kev_due_date || isOverdue(alert)) return null;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  if (isNaN(due)) return null;
  const diffMs = due.getTime() - Date.now();
  return Math.ceil(diffMs / (24 * 60 * 60 * 1000));
}

// Human-readable "how long has this been on our radar" age, computed from
// first_seen (set once by aggregate.py the first time a CVE/GHSA/Dependabot
// alert is ingested and never touched again on subsequent refresh cycles --
// see build_final_entry()/the "keep the original first_seen" merge logic in
// scripts/aggregate.py). Distinct from "Published" (the vendor/NVD publish
// date, which can predate first_seen by years for old CVEs that only start
// matching the watchlist later) -- this answers "how long has our team known
// about this" for triage aging/backlog purposes, a gap the card had no way
// to answer before (only a "days overdue"/"days until due" concept existed,
// scoped to KEV deadlines specifically).
function firstSeenAge(alert) {
  if (!alert.first_seen) return null;
  const seen = new Date(alert.first_seen);
  if (isNaN(seen)) return null;
  const days = Math.floor((Date.now() - seen.getTime()) / (24 * 60 * 60 * 1000));
  return days < 0 ? 0 : days;
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
  const overdueDaysVal = overdue ? overdueDays(alert) : null;
  const overdueBadge = overdue
    ? `<span class="badge overdue">OVERDUE${typeof overdueDaysVal === "number" ? ` (${overdueDaysVal}d)` : ""}</span>`
    : "";
  const ransomwareBadge = alert.kev_ransomware_use ? `<span class="badge ransomware">RANSOMWARE</span>` : "";
  const dueSoonDays = daysUntilDue(alert);
  const dueSoonBadge = typeof dueSoonDays === "number" && dueSoonDays <= 7
    ? `<span class="badge due-soon">DUE SOON (${dueSoonDays}d)</span>`
    : "";
  const sevBadge = sevClass
    ? `<span class="badge ${sevClass}">${sevClass}</span>`
    : "";
  const sourceBadge = `<span class="badge source">${escapeHtml(alert.source || "unknown")}</span>`;
  const affected = (alert.affected || []).join(", ") || "n/a";
  const matchedKeywords = alert.matched_keywords || [];
  const matchedHtml = matchedKeywords.length
    ? `<div class="matched">Watchlist match: ${matchedKeywords.map((k) => `<span class="badge match">${escapeHtml(k)}</span>`).join("")}</div>`
    : "";
  const cweIds = alert.cwe_ids || [];
  const cweHtml = cweIds.length
    ? `<div class="cwe-row">Weakness: ${cweIds.map((c) => {
        const num = c.replace(/^CWE-/i, "");
        return /^\d+$/.test(num)
          ? `<a class="badge cwe" href="https://cwe.mitre.org/data/definitions/${num}.html" target="_blank" rel="noopener" title="View ${escapeHtml(c)} on cwe.mitre.org">${escapeHtml(c)}</a>`
          : `<span class="badge cwe">${escapeHtml(c)}</span>`;
      }).join("")}</div>`
    : "";
  const epssPct = typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a";
  const riskVal = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(0) : "n/a";
  const b = alert.risk_score_breakdown;
  const breakdownHtml = b ? `
      <div class="score-breakdown" hidden>
        <div class="breakdown-row"><span>CVSS ${fmtScore(b.cvss_raw)} &times; ${b.cvss_weight || "35%"}</span><span>= ${fmtScore(b.cvss_component)} pts</span></div>
        <div class="breakdown-row"><span>EPSS ${typeof b.epss_raw === "number" ? (b.epss_raw * 100).toFixed(1) + "%" : "n/a"} &times; ${b.epss_weight || "40%"}</span><span>= ${fmtScore(b.epss_component)} pts</span></div>
        <div class="breakdown-row"><span>${b.kev_weight || "KEV bonus"}</span><span>= ${fmtScore(b.kev_bonus)} pts</span></div>
        <div class="breakdown-row breakdown-total"><span>Total${b.capped ? " (capped at 100)" : ""}</span><span>= ${riskVal} pts</span></div>
        ${b.weight_redistributed ? `<div class="breakdown-note">Note: CVSS/EPSS weight was redistributed because one score is not yet available for this CVE.</div>` : ""}
      </div>` : "";
  const toggleBtn = b ? `<button class="score-toggle" type="button" title="Show risk score breakdown" aria-expanded="false">breakdown &#9662;</button>` : "";

  const cveIdSafe = escapeHtml(alert.cve_id);
  return `
    <div class="card" data-cve-id="${cveIdSafe}" id="alert-${cveIdSafe}">
      <div class="card-header">
        <button class="cve-id cve-link-btn" type="button" data-cve="${cveIdSafe}" title="Copy a direct link to this alert">${cveIdSafe}</button>
        <div class="badges">${kevBadge}${ransomwareBadge}${overdueBadge}${dueSoonBadge}${sevBadge}${sourceBadge}</div>
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
      ${cweHtml}
      <div class="card-footer">
        <span>Published: ${fmtDate(alert.published)}</span>
        <span class="age-badge" title="Days since this alert was first ingested by the pipeline">${(() => { const age = firstSeenAge(alert); return typeof age === "number" ? `First seen: ${age}d ago` : ""; })()}</span>
        <span class="footer-links">
          ${alert.cve_id && /^CVE-/i.test(alert.cve_id) ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}" target="_blank" rel="noopener">View on NVD</a>` : ""}
          ${alert.dependabot_url ? `<a href="${alert.dependabot_url}" target="_blank" rel="noopener">View alert</a>` : ""}
        </span>
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
  const severityEl = document.getElementById("severity-filter");
  const sourceEl = document.getElementById("source-filter");
  const sortEl = document.getElementById("sort-by");
  if (params.has("q")) searchEl.value = params.get("q");
  // Setting .value to an option that doesn't exist on a <select> is a no-op
  // in every browser, so an unrecognized/stale param value safely falls back
  // to whatever the element's default selection already was.
  if (params.has("kev")) kevEl.value = params.get("kev");
  if (params.has("sev") && severityEl) severityEl.value = params.get("sev");
  if (params.has("source")) sourceEl.value = params.get("source");
  if (params.has("sort")) sortEl.value = params.get("sort");
}

function updateURLFromFilters(search, kevFilter, severityFilter, sourceFilter, sortBy) {
  const params = new URLSearchParams();
  if (search) params.set("q", search);
  if (kevFilter && kevFilter !== "all") params.set("kev", kevFilter);
  if (severityFilter && severityFilter !== "all") params.set("sev", severityFilter);
  if (sourceFilter && sourceFilter !== "all") params.set("source", sourceFilter);
  if (sortBy && sortBy !== "risk_score") params.set("sort", sortBy);
  const qs = params.toString();
  const newUrl = location.pathname + (qs ? "?" + qs : "") + location.hash;
  history.replaceState(null, "", newUrl);
}

function applyFiltersAndRender() {
  const search = document.getElementById("search").value.trim().toLowerCase();
  const kevFilter = document.getElementById("kev-filter").value;
  const severityFilter = document.getElementById("severity-filter").value;
  const sourceFilter = document.getElementById("source-filter").value;
  const sortBy = document.getElementById("sort-by").value;
  updateURLFromFilters(search, kevFilter, severityFilter, sourceFilter, sortBy);

  let filtered = allAlerts.filter((a) => {
    if (kevFilter === "kev" && !a.kev) return false;
    if (kevFilter === "non-kev" && a.kev) return false;
    if (kevFilter === "overdue" && !isOverdue(a)) return false;
    if (kevFilter === "due-soon") {
      const d = daysUntilDue(a);
      if (typeof d !== "number" || d < 0 || d > 7) return false;
    }
    if (kevFilter === "ransomware" && !a.kev_ransomware_use) return false;
    if (severityFilter !== "all" && severityClass(a.cvss_score) !== severityFilter) return false;
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
    if (sortBy === "kev_due_date") {
      // Soonest deadline first. Entries with no due date (non-KEV, or KEV
      // with no published due date) are not "most urgent" -- they have no
      // deadline at all -- so they sort to the end, not the front, avoiding
      // the classic bug where empty-string/undefined compares as "smallest".
      const ad = a.kev_due_date, bd = b.kev_due_date;
      if (!ad && !bd) return 0;
      if (!ad) return 1;
      if (!bd) return -1;
      return ad.localeCompare(bd);
    }
    if (sortBy === "first_seen_oldest") {
      // Oldest-ingested first -- surfaces long-lingering un-triaged alerts
      // that keep getting pushed off-screen by the default newest-first
      // sort, so a backlog of stale un-actioned alerts doesn't silently
      // hide at the bottom of the list forever.
      return (a.first_seen || "").localeCompare(b.first_seen || "");
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
    "kev_ransomware_use", "source", "affected", "cwe_ids", "published", "first_seen", "description"];
  const lines = [toCsvRow(header)];
  for (const a of rows) {
    lines.push(toCsvRow([
      a.cve_id, a.risk_score, a.cvss_score, a.epss_score, a.kev, a.kev_due_date,
      a.kev_ransomware_use, a.source, (a.affected || []).join("; "), (a.cwe_ids || []).join("; "),
      a.published, a.first_seen, a.description,
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

// stats.by_source (e.g. {"nvd": 440, "ghsa": 3, "dependabot:owner/repo": 2}) has been
// computed by the pipeline since early cycles but was never surfaced on the dashboard --
// a viewer had no quick way to see the source mix (e.g. "is this mostly NVD sweep noise,
// or are GHSA/Dependabot actually contributing?") without exporting CSV and counting
// manually. Renders a small inline pill per source, sorted by count descending. Purely
// additive: reads an existing stats.json field, no new API calls, no schema changes.
function renderSourceBreakdown(bySource) {
  const el = document.getElementById("source-breakdown");
  if (!el) return;
  if (!bySource || typeof bySource !== "object" || Object.keys(bySource).length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = Object.entries(bySource).sort((a, b) => b[1] - a[1]);
  el.innerHTML = entries
    .map(([src, count]) => `<span class="source-pill">${escapeHtml(src)}: <strong>${escapeHtml(String(count))}</strong></span>`)
    .join("");
  el.hidden = false;
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
    renderSourceBreakdown(stats.by_source);
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
  highlightFromHash();
}

// Click delegation for the per-card risk-score breakdown toggle (avoids
// attaching a listener per card on every re-render).
document.getElementById("card-grid").addEventListener("click", (e) => {
  const toggleBtn = e.target.closest(".score-toggle");
  if (toggleBtn) {
    const panel = toggleBtn.closest(".risk-row").nextElementSibling;
    if (panel && panel.classList.contains("score-breakdown")) {
      panel.hidden = !panel.hidden;
      toggleBtn.innerHTML = panel.hidden ? "breakdown &#9662;" : "breakdown &#9652;";
      toggleBtn.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
    }
    return;
  }

  // Per-CVE shareable deep link: clicking the CVE ID copies a URL that,
  // when opened, scrolls to and highlights that exact card -- useful for a
  // security lead pointing a teammate at one specific alert rather than the
  // whole filtered view (complements the existing filter-state URL params).
  const linkBtn = e.target.closest(".cve-link-btn");
  if (linkBtn) {
    const cve = linkBtn.dataset.cve;
    const url = `${location.origin}${location.pathname}${location.search}#alert-${encodeURIComponent(cve)}`;
    const originalText = linkBtn.textContent;
    const showCopied = () => {
      linkBtn.textContent = "Copied!";
      setTimeout(() => {
        linkBtn.textContent = originalText;
      }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(showCopied).catch(() => {});
    }
    history.replaceState(null, "", url);
  }
});

// If the page was opened with a #alert-CVE-... hash (from the copy-link
// button above, or a hand-typed link), scroll to that card and highlight it
// briefly once the data has rendered. No-op if the card doesn't exist (e.g.
// filtered out or not in the current dataset) -- fails quietly.
function highlightFromHash() {
  if (!location.hash) return;
  const target = document.querySelector(
    `.card[id="${CSS.escape(location.hash.slice(1))}"]`
  );
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  target.classList.add("highlighted");
  setTimeout(() => target.classList.remove("highlighted"), 2500);
}

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

// The search box previously fired a full filter+sort+innerHTML re-render (plus a
// history.replaceState URL sync) on every single keystroke. With 445+ alerts and
// growing, typing a multi-character search term meant repeated full-grid rebuilds
// for every intermediate substring the user never intended to search for -- wasted
// work and, on lower-end mobile devices, visible input lag. Debouncing to 150ms
// (well under human-perceptible "instant" response, per common UX guidance of
// ~100-300ms for search-as-you-type) collapses rapid keystrokes into a single
// render after the user pauses, with zero change in final filtered results.
let searchDebounceTimer = null;
document.getElementById("search").addEventListener("input", () => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(applyFiltersAndRender, 150);
});
document.getElementById("kev-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("severity-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("source-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("sort-by").addEventListener("change", applyFiltersAndRender);
document.getElementById("export-csv").addEventListener("click", exportCsv);

// Single-click reset of every filter/sort control back to its default, plus
// clearing the dependency-file filter and the URL's filter query params --
// previously a viewer with search + kev-filter + severity + source + a
// pasted dependency file active had to clear each control individually to
// get back to the unfiltered board. Deliberately does NOT touch a #alert-...
// hash (a direct deep-link to one card is a distinct concern from filters).
document.getElementById("reset-filters").addEventListener("click", () => {
  document.getElementById("search").value = "";
  document.getElementById("kev-filter").value = "all";
  document.getElementById("severity-filter").value = "all";
  document.getElementById("source-filter").value = "all";
  document.getElementById("sort-by").value = "risk_score";
  dependencyPackageNames = null;
  const depText = document.getElementById("dep-text-input");
  const depFile = document.getElementById("dep-file-input");
  const depStatus = document.getElementById("dep-status");
  if (depText) depText.value = "";
  if (depFile) depFile.value = "";
  if (depStatus) depStatus.textContent = "";
  applyFiltersAndRender();
});

readFiltersFromURL();
setupDependencyFilter();
loadData();
loadTrendChart();
