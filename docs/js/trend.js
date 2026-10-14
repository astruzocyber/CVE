// Historical trend chart from data/history/trend.csv.
// Chart.js is loaded from jsDelivr (pinned + SRI) as a classic deferred script
// that runs before this module, so it is read from window.Chart. If the CDN is
// blocked the section explains that instead of throwing.

import { byId } from "./dom.js";
import { fmtDay, isNum } from "./format.js";

const SERIES = [
  { col: "total_alerts", label: "Total alerts", token: "--c-accent", axis: "y" },
  { col: "critical_count", label: "Critical", token: "--c-critical", axis: "y" },
  { col: "high_count", label: "High", token: "--c-high", axis: "y" },
  { col: "kev_count", label: "In KEV", token: "--c-warn", axis: "y" },
  { col: "avg_risk_score", label: "Avg risk score", token: "--c-muted", axis: "y1", dashed: true },
];

/** Parse the trend CSV by header name (robust to new columns being appended). */
export function parseTrendCsv(text) {
  const lines = String(text || "").trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const header = lines[0].split(",").map((h) => h.trim());
  const rows = [];
  for (const line of lines.slice(1)) {
    const cells = line.split(",");
    const row = {};
    header.forEach((h, i) => {
      const raw = (cells[i] ?? "").trim();
      row[h] = h === "timestamp" ? raw : raw === "" ? null : Number(raw);
    });
    if (row.timestamp && !Number.isNaN(Date.parse(row.timestamp))) rows.push(row);
  }
  rows.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  return rows;
}

/** One row per calendar day (the last snapshot of that day) keeps the chart readable. */
export function lastPerDay(rows) {
  const byDay = new Map();
  for (const r of rows) byDay.set(r.timestamp.slice(0, 10), r);
  return [...byDay.values()];
}

export function trendSummary(rows) {
  if (rows.length < 2) return "";
  const first = rows[0];
  const last = rows[rows.length - 1];
  const diff = (col) => (isNum(first[col]) && isNum(last[col]) ? last[col] - first[col] : null);
  const signed = (n) => (n > 0 ? `+${n}` : String(n));
  const parts = [`${rows.length} days since ${fmtDay(first.timestamp)}`];
  const total = diff("total_alerts");
  if (total !== null) parts.push(`total ${signed(total)}`);
  const kev = diff("kev_count");
  if (kev !== null) parts.push(`KEV ${signed(kev)}`);
  return parts.join(" · ");
}

let chart = null;
let rows = [];

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";

function build() {
  const canvas = byId("trend-chart");
  const Chart = window.Chart;
  if (!Chart) {
    canvas.setAttribute("aria-label", "Trend chart unavailable: the charting library could not be loaded.");
    byId("trend-hint").textContent = "Chart library blocked or offline";
    return;
  }
  chart?.destroy();
  const grid = cssVar("--c-border");
  const text = cssVar("--c-text-muted");
  chart = new Chart(canvas, {
    type: "line",
    data: {
      labels: rows.map((r) => r.timestamp.slice(0, 10)),
      datasets: SERIES.filter((s) => rows.some((r) => isNum(r[s.col]))).map((s) => ({
        label: s.label,
        data: rows.map((r) => r[s.col]),
        borderColor: cssVar(s.token),
        backgroundColor: cssVar(s.token),
        borderDash: s.dashed ? [6, 4] : [],
        yAxisID: s.axis,
        pointRadius: 0,
        pointHitRadius: 8,
        borderWidth: 2,
        tension: 0.25,
        spanGaps: true,
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ? false : { duration: 300 },
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: text, boxWidth: 12, usePointStyle: true } } },
      scales: {
        x: { ticks: { color: text, maxRotation: 0, autoSkipPadding: 16 }, grid: { color: grid } },
        y: { beginAtZero: true, ticks: { color: text, precision: 0 }, grid: { color: grid }, title: { display: true, text: "Alerts", color: text } },
        y1: { position: "right", beginAtZero: true, max: 100, ticks: { color: text }, grid: { drawOnChartArea: false }, title: { display: true, text: "Avg risk", color: text } },
      },
    },
  });
  const summary = trendSummary(rows);
  canvas.setAttribute("aria-label", `Historical trend chart. ${summary}`);
}

/** Load the CSV now (cheap) but only draw the chart the first time the section is opened. */
export async function initTrend() {
  const section = byId("trend-section");
  try {
    const res = await fetch("data/history/trend.csv", { cache: "no-cache" });
    if (!res.ok) return;
    rows = lastPerDay(parseTrendCsv(await res.text()));
  } catch {
    return;
  }
  if (rows.length < 2) return;
  byId("trend-hint").textContent = trendSummary(rows);
  section.hidden = false;
  section.addEventListener("toggle", () => {
    if (section.open && !chart) build();
  });
  if (section.open) build();
}

/** Re-colour after a theme switch (colours come from CSS custom properties). */
export function refreshTrendTheme() {
  if (chart) build();
}
