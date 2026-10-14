// Shared mutable application state. Every module reads/writes through this
// single object so there is exactly one source of truth at runtime.

export const PAGE_SIZE = { cards: 48, table: 150 };

export const state = {
  /** Every alert from data/alerts.json, untouched (exports rely on that). */
  alerts: [],
  /** Lower-cased search haystack per CVE id, built once after load. */
  searchIndex: new Map(),
  /** Alerts matching the current filters, already sorted. */
  filtered: [],
  /** How many of `filtered` are currently rendered (progressive rendering). */
  visible: PAGE_SIZE.cards,
  /** "cards" | "table" */
  view: "cards",
  /** Lower-cased package names from the dependency filter, or null when off. */
  depPackages: null,
  /** Parsed data/stats.json, or null if unavailable. */
  stats: null,
};

export function buildSearchIndex(alerts) {
  const index = new Map();
  for (const a of alerts) {
    const parts = [a.cve_id, a.description, ...(a.affected || []), ...(a.matched_keywords || []), ...(a.cwe_ids || [])];
    index.set(a.cve_id, parts.join(" ").toLowerCase());
  }
  return index;
}

export const findAlert = (cveId) => state.alerts.find((a) => a.cve_id === cveId) ?? null;
