// Static dashboard: fetches data/alerts.json (same repo, same deploy) and renders
// filterable/sortable cards. No backend, no build step.

let allAlerts = [];

function severityClass(cvss) {
  if (cvss === null || cvss === undefined) return "";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
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

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function renderCard(alert) {
  const sevClass = severityClass(alert.cvss_score);
  const kevBadge = alert.kev ? `<span class="badge kev">KEV</span>` : "";
  const sevBadge = sevClass
    ? `<span class="badge ${sevClass}">${sevClass}</span>`
    : "";
  const sourceBadge = `<span class="badge source">${escapeHtml(alert.source || "unknown")}</span>`;
  const affected = (alert.affected || []).join(", ") || "n/a";
  const epssPct = typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a";

  return `
    <div class="card">
      <div class="card-header">
        <span class="cve-id">${escapeHtml(alert.cve_id)}</span>
        <div class="badges">${kevBadge}${sevBadge}${sourceBadge}</div>
      </div>
      <div class="description">${escapeHtml(alert.description || "(no description)")}</div>
      <div class="scores">
        <span>CVSS: <strong>${fmtScore(alert.cvss_score)}</strong></span>
        <span>EPSS: <strong>${epssPct}</strong></span>
      </div>
      <div class="affected">Affected: ${escapeHtml(affected)}</div>
      <div class="card-footer">
        <span>Published: ${fmtDate(alert.published)}</span>
        <span>${alert.dependabot_url ? `<a href="${alert.dependabot_url}" target="_blank" rel="noopener">View alert</a>` : ""}</span>
      </div>
    </div>
  `;
}

function applyFiltersAndRender() {
  const search = document.getElementById("search").value.trim().toLowerCase();
  const kevFilter = document.getElementById("kev-filter").value;
  const sortBy = document.getElementById("sort-by").value;

  let filtered = allAlerts.filter((a) => {
    if (kevFilter === "kev" && !a.kev) return false;
    if (kevFilter === "non-kev" && a.kev) return false;
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
    if (sortBy === "cvss_score" || sortBy === "epss_score") {
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
}

document.getElementById("search").addEventListener("input", applyFiltersAndRender);
document.getElementById("kev-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("sort-by").addEventListener("change", applyFiltersAndRender);

loadData();
