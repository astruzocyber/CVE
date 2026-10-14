// Overview KPIs, summary metrics, breakdown chips and the freshness line.
// KPI counts are computed from the alerts themselves so a tile's number always
// equals the result count you get by clicking it.

import { byId, escapeHtml } from "./dom.js";
import {
  SEVERITY_ORDER, severityClass, isOverdue, isDueSoon, isNewWithin24h, isRejected, riskDelta, fmtScore, fmtPct,
  fmtDateTime, isNum,
} from "./format.js";
import { cweName } from "./cwe-names.js";

export const STALE_THRESHOLD_MS = 20 * 60 * 60 * 1000; // pipeline runs ~every 4 h

export function computeKpis(alerts) {
  const k = { total: alerts.length, critical: 0, kev: 0, overdue: 0, dueSoon: 0, ransomware: 0, fresh: 0, rejected: 0, up: 0, down: 0 };
  for (const a of alerts) {
    if (severityClass(a.cvss_score) === "critical") k.critical++;
    if (a.kev) k.kev++;
    if (isOverdue(a)) k.overdue++;
    if (isDueSoon(a)) k.dueSoon++;
    if (a.kev_ransomware_use) k.ransomware++;
    if (isNewWithin24h(a)) k.fresh++;
    if (isRejected(a)) k.rejected++;
    const d = riskDelta(a);
    if (d !== null && Math.round(d) > 0) k.up++;
    if (d !== null && Math.round(d) < 0) k.down++;
  }
  return k;
}

const average = (alerts, field) => {
  const vals = alerts.map((a) => a[field]).filter(isNum);
  return vals.length ? vals.reduce((s, v) => s + v, 0) / vals.length : null;
};

export function renderOverview(alerts, stats) {
  const k = computeKpis(alerts);
  const set = (id, v) => { byId(id).textContent = String(v); };
  set("stat-total", k.total);
  set("stat-critical", k.critical);
  set("stat-kev", k.kev);
  set("stat-overdue", k.overdue);
  set("stat-due-soon", k.dueSoon);
  set("stat-ransomware", k.ransomware);
  set("stat-new", k.fresh);
  set("stat-rejected", k.rejected);
  byId("stat-rejected-tile").hidden = k.rejected === 0;
  byId("stats-bar").hidden = false;

  set("stat-avg-risk", fmtScore(stats?.avg_risk_score ?? average(alerts, "risk_score")));
  set("stat-avg-cvss", fmtScore(stats?.avg_cvss_score ?? average(alerts, "cvss_score"), 2));
  set("stat-epss", fmtPct(stats?.avg_epss ?? average(alerts, "epss_score"), 2));
  set("stat-risk-trend", `▲ ${k.up} / ▼ ${k.down}`);
  byId("metric-row").hidden = false;
}

/** Fallback breakdowns when data/stats.json is missing or older than the alerts. */
function countBy(alerts, keysOf) {
  const out = {};
  for (const a of alerts) for (const key of keysOf(a)) if (key) out[key] = (out[key] || 0) + 1;
  return out;
}

const topN = (obj, n) => Object.entries(obj || {}).filter(([, c]) => isNum(c) && c > 0).sort((x, y) => y[1] - x[1]).slice(0, n);

/**
 * chip(): one breakdown chip. `action` is a data-* payload the main module
 * routes to a filter; spans (no action) are informational only.
 */
function chip(label, count, max, action, title, mod = "") {
  const width = max ? Math.max(5, Math.round((count / max) * 20) * 5) : 0;
  const inner = `<span class="chip__label">${escapeHtml(label)}</span><span class="chip__count">${count}</span><span class="chip__bar w-${width}" aria-hidden="true"></span>`;
  const cls = `chip${mod ? ` chip--${mod}` : ""}`;
  if (!action) return `<span class="${cls}" title="${escapeHtml(title)}">${inner}</span>`;
  return `<button type="button" class="${cls}" data-filter="${escapeHtml(action[0])}" data-value="${escapeHtml(action[1])}" title="${escapeHtml(title)}">${inner}</button>`;
}

function fillPanel(panelId, listId, entries) {
  const panel = byId(panelId);
  if (!entries.length) {
    panel.hidden = true;
    return;
  }
  byId(listId).innerHTML = entries.join("");
  panel.hidden = false;
}

const SOURCE_FILTERS = new Set(["nvd", "ghsa", "dependabot"]);
const AGE_ORDER = ["0-1d", "1-7d", "7-30d", "30d+"];

export function renderBreakdowns(alerts, stats) {
  const sev = stats?.by_severity ?? countBy(alerts, (a) => [severityClass(a.cvss_score) || "unknown"]);
  const sevEntries = SEVERITY_ORDER.filter((b) => sev[b] > 0);
  const sevMax = Math.max(0, ...sevEntries.map((b) => sev[b]));
  fillPanel("severity-panel", "severity-breakdown", sevEntries.map((b) =>
    chip(b === "unknown" ? "no CVSS" : b, sev[b], sevMax, ["sev", b], `Filter to ${b} severity`, b)));

  const src = topN(stats?.by_source ?? countBy(alerts, (a) => [a.source || "unknown"]), 10);
  const srcMax = src[0]?.[1] ?? 0;
  fillPanel("source-panel", "source-breakdown", src.map(([s, c]) => {
    const base = String(s).split(":")[0];
    return chip(s, c, srcMax, SOURCE_FILTERS.has(base) ? ["source", base] : null, `Source: ${s}`);
  }));

  const age = stats?.by_age_bucket ?? {};
  const ageEntries = AGE_ORDER.filter((b) => age[b] > 0);
  const ageMax = Math.max(0, ...ageEntries.map((b) => age[b]));
  fillPanel("age-panel", "age-breakdown", ageEntries.map((b) => chip(b, age[b], ageMax, null, `First seen ${b} ago`)));

  const searchChips = (obj, label) => {
    const entries = topN(obj, 10);
    const max = entries[0]?.[1] ?? 0;
    return entries.map(([key, c]) => chip(label(key), c, max, ["q", key], `Search for ${key}`));
  };
  fillPanel("keyword-panel", "keyword-breakdown",
    searchChips(stats?.by_matched_keyword ?? countBy(alerts, (a) => a.matched_keywords || []), (k) => k));
  fillPanel("cwe-panel", "cwe-breakdown",
    searchChips(stats?.by_cwe ?? countBy(alerts, (a) => a.cwe_ids || []), (c) => (cweName(c) ? `${c} · ${cweName(c)}` : c)));
  fillPanel("vendor-panel", "vendor-breakdown", searchChips(stats?.by_vendor_product ?? {}, (v) => v));
}

export function renderFreshness(generatedAt, count, now = Date.now()) {
  const meta = byId("last-updated");
  const banner = byId("stale-banner");
  const t = generatedAt ? new Date(generatedAt) : null;
  if (!t || Number.isNaN(t.getTime())) {
    meta.textContent = `${count} alerts · last update time unknown`;
    banner.hidden = true;
    return;
  }
  const ageMs = Math.max(0, now - t.getTime());
  const hours = Math.floor(ageMs / 3_600_000);
  const ago = hours < 1 ? "less than 1 h ago" : `${hours} h ago`;
  meta.textContent = `${count} alerts · updated ${fmtDateTime(generatedAt)} (${ago})`;
  if (ageMs > STALE_THRESHOLD_MS) {
    banner.textContent = `⚠ Data may be stale: the last successful update was ${hours} h ago (expected every ~4 h). The pipeline may be failing; check GitHub Actions.`;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}
