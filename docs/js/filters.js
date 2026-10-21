// Filter controls: ONE declarative list drives URL sync, reset, saved views,
// active-filter chips, and the filter predicate. Adding a filter = one entry.

import { byId } from "./dom.js";
import { state } from "./state.js";
import { isReviewed } from "./reviewed.js";
import {
  severityClass, isOverdue, isDueSoon, isNewWithin24h, isRejected, hasFixAvailable, riskDelta, isNum,
} from "./format.js";

/**
 * key:   name used in code and in the readFilters() result
 * param: URL query parameter (kept identical to v1 so old shared links/saved views work)
 * kind:  "text" | "select" | "number" | "check"
 * def:   default value (omitted from the URL)
 */
export const FILTERS = [
  { key: "q", param: "q", kind: "text", def: "", el: () => byId("search"), label: (v) => `Search: “${v}”` },
  // Exact breakdown-chip filter ("kw:<keyword>", "cwe:<id>", "vp:<vendor/product>"),
  // so a chip's result count equals the number printed on the chip (a free-text
  // search for "cisco/ios" also matched cisco/ios_xe: 75 results under a "33" chip).
  { key: "facet", param: "facet", kind: "text", def: "", el: () => byId("facet-filter"), label: facetLabel },
  { key: "kev", param: "kev", kind: "select", def: "all", el: () => byId("kev-filter") },
  { key: "sev", param: "sev", kind: "select", def: "all", el: () => byId("severity-filter") },
  { key: "source", param: "source", kind: "select", def: "all", el: () => byId("source-filter") },
  { key: "sort", param: "sort", kind: "select", def: "risk_score", el: () => byId("sort-by"), chip: false },
  { key: "minRisk", param: "minrisk", kind: "number", def: "", el: () => byId("min-risk"), label: (v) => `Risk ≥ ${v}`, advanced: true },
  { key: "minEpss", param: "minepss", kind: "number", def: "", el: () => byId("min-epss"), label: (v) => `EPSS ≥ ${v}%`, advanced: true },
  { key: "hideReviewed", param: "hidereviewed", kind: "check", def: false, el: () => byId("hide-reviewed"), label: () => "Hiding reviewed", advanced: true },
  { key: "newOnly", param: "newonly", kind: "check", def: false, el: () => byId("new-only"), label: () => "New (24 h)", advanced: true },
  { key: "hideRejected", param: "hiderejected", kind: "check", def: false, el: () => byId("hide-rejected"), label: () => "Hiding rejected", advanced: true },
  { key: "hasFixOnly", param: "hasfixonly", kind: "check", def: false, el: () => byId("has-fix-only"), label: () => "Fix available", advanced: true },
];

const FACET_FIELDS = { kw: "matched_keywords", cwe: "cwe_ids", vp: "affected" };
const FACET_NAMES = { kw: "Watchlist", cwe: "CWE", vp: "Product" };

/** "kw:wordpress" -> ["matched_keywords", "wordpress"]; null if malformed. */
export function parseFacet(value) {
  const s = String(value || "");
  const i = s.indexOf(":");
  if (i < 1) return null;
  const field = FACET_FIELDS[s.slice(0, i)];
  const term = s.slice(i + 1);
  return field && term ? [field, term] : null;
}

function facetLabel(v) {
  const kind = String(v).split(":")[0];
  return parseFacet(v) ? `${FACET_NAMES[kind]}: ${String(v).slice(kind.length + 1)}` : `Facet: ${v}`;
}

const byKey = Object.fromEntries(FILTERS.map((f) => [f.key, f]));

function getValue(f) {
  const el = f.el();
  if (!el) return f.def;
  if (f.kind === "check") return el.checked;
  if (f.kind === "text") return el.value.trim();
  return el.value;
}

/** Set a control, rejecting values a <select> doesn't offer (which would otherwise blank it). */
function setValue(f, value) {
  const el = f.el();
  if (!el) return;
  if (f.kind === "check") {
    el.checked = Boolean(value);
  } else if (f.kind === "select") {
    const ok = [...el.options].some((o) => o.value === value);
    el.value = ok ? value : f.def;
  } else if (f.kind === "number") {
    const n = value === "" || value === null ? NaN : Number(value);
    el.value = Number.isFinite(n) ? String(Math.min(100, Math.max(0, n))) : "";
  } else {
    el.value = value ?? "";
  }
}

export const readFilters = () => Object.fromEntries(FILTERS.map((f) => [f.key, getValue(f)]));

export function setFilter(key, value) {
  setValue(byKey[key], value);
}

export function resetFilters() {
  for (const f of FILTERS) setValue(f, f.def);
}

/** Apply a query string (shared link or saved view). Absent params reset to default. */
export function applyQueryString(qs) {
  const params = new URLSearchParams(qs);
  for (const f of FILTERS) {
    if (!params.has(f.param)) setValue(f, f.def);
    else if (f.kind === "check") setValue(f, params.get(f.param) === "1");
    else setValue(f, params.get(f.param));
  }
}

export function toQueryString(values = readFilters()) {
  const params = new URLSearchParams();
  for (const f of FILTERS) {
    const v = values[f.key];
    if (v === f.def || v === "" || v === false) continue;
    params.set(f.param, f.kind === "check" ? "1" : String(v));
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export function syncUrl(values) {
  history.replaceState(null, "", location.pathname + toQueryString(values) + location.hash);
}

/** How many "More filters" panel controls are active (for the toggle badge). */
export function countAdvanced(values = readFilters()) {
  return FILTERS.filter((f) => f.advanced && values[f.key] !== f.def && values[f.key] !== "").length + (state.depPackages ? 1 : 0);
}

/** Human-readable descriptors for the active-filter chip row. */
export function activeFilterChips(values = readFilters()) {
  const chips = [];
  for (const f of FILTERS) {
    if (f.chip === false) continue;
    const v = values[f.key];
    if (v === f.def || v === "") continue;
    let text;
    if (f.label) text = f.label(v);
    else {
      const opt = [...f.el().options].find((o) => o.value === v);
      text = opt ? opt.textContent.replace(/^\w+: /, "") : v;
    }
    chips.push({ key: f.key, text });
  }
  if (state.depPackages) chips.push({ key: "deps", text: `Dependencies (${state.depPackages.size})` });
  return chips;
}

function matchesPackages(alert, names) {
  const haystack = `${(alert.affected || []).join(" ")} ${alert.description || ""}`.toLowerCase();
  for (const pkg of names) if (pkg && haystack.includes(pkg)) return true;
  return false;
}

const KEV_PREDICATES = {
  all: () => true,
  kev: (a) => Boolean(a.kev),
  "non-kev": (a) => !a.kev,
  overdue: (a) => isOverdue(a),
  "due-soon": (a) => isDueSoon(a),
  ransomware: (a) => Boolean(a.kev_ransomware_use),
};

export function makePredicate(v) {
  const minRisk = v.minRisk === "" ? null : Number(v.minRisk);
  const minEpss = v.minEpss === "" ? null : Number(v.minEpss);
  const q = v.q.toLowerCase();
  const kevOk = KEV_PREDICATES[v.kev] ?? KEV_PREDICATES.all;
  const deps = state.depPackages;
  const facet = v.facet ? parseFacet(v.facet) : null;
  return (a) => {
    if (v.facet && !(facet && (a[facet[0]] || []).includes(facet[1]))) return false;
    if (v.hideReviewed && isReviewed(a.cve_id)) return false;
    if (v.newOnly && !isNewWithin24h(a)) return false;
    if (v.hideRejected && isRejected(a)) return false;
    if (v.hasFixOnly && !hasFixAvailable(a)) return false;
    if (!kevOk(a)) return false;
    if (v.sev !== "all" && (severityClass(a.cvss_score) || "unknown") !== v.sev) return false;
    if (v.source !== "all") {
      const src = a.source || "";
      if (src !== v.source && !src.startsWith(`${v.source}:`)) return false;
    }
    if (isNum(minRisk) && !(isNum(a.risk_score) && a.risk_score >= minRisk)) return false;
    if (isNum(minEpss) && !(isNum(a.epss_score) && a.epss_score * 100 >= minEpss)) return false;
    if (deps && !matchesPackages(a, deps)) return false;
    if (q && !(state.searchIndex.get(a.cve_id) ?? "").includes(q)) return false;
    return true;
  };
}

// Missing values always sort last, never first.
const desc = (field) => (a, b) => (b[field] ?? -Infinity) - (a[field] ?? -Infinity);
const strMissingLast = (get, dir) => (a, b) => {
  const x = get(a) || "";
  const y = get(b) || "";
  if (!x && !y) return 0;
  if (!x) return 1;
  if (!y) return -1;
  return dir * x.localeCompare(y);
};

export const SORTS = {
  risk_score: desc("risk_score"),
  cvss_score: desc("cvss_score"),
  epss_score: desc("epss_score"),
  first_seen: strMissingLast((a) => a.first_seen, -1),
  first_seen_oldest: strMissingLast((a) => a.first_seen, 1),
  published: strMissingLast((a) => a.published, -1),
  kev_due_date: strMissingLast((a) => a.kev_due_date, 1),
  cve_id: strMissingLast((a) => a.cve_id, 1),
  risk_delta: (a, b) => {
    const da = riskDelta(a);
    const db = riskDelta(b);
    if (da === null && db === null) return 0;
    if (da === null) return 1;
    if (db === null) return -1;
    return db - da;
  },
};

/** Ascending vs descending, used for aria-sort on table headers. */
export const SORT_IS_ASCENDING = new Set(["first_seen_oldest", "kev_due_date", "cve_id"]);

export function filterAndSort(values) {
  const out = state.alerts.filter(makePredicate(values));
  out.sort(SORTS[values.sort] ?? SORTS.risk_score);
  return out;
}
