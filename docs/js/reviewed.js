// Local-only "mark as reviewed" triage state (per browser, never uploaded).

import { storage, downloadBlob, todayStamp } from "./dom.js";

const KEY = "reviewedCves"; // unchanged from v1 so existing progress survives the redesign

function load() {
  const arr = storage.getJson(KEY, []);
  return new Set(Array.isArray(arr) ? arr.filter((x) => typeof x === "string") : []);
}

const reviewed = load();

const save = () => storage.setJson(KEY, [...reviewed]);

export const isReviewed = (cveId) => reviewed.has(cveId);

export function toggleReviewed(cveId) {
  if (reviewed.has(cveId)) reviewed.delete(cveId);
  else reviewed.add(cveId);
  save();
  return reviewed.has(cveId);
}

/** Mark many at once; returns how many were newly added. */
export function markReviewed(cveIds) {
  let added = 0;
  for (const id of cveIds) {
    if (id && !reviewed.has(id)) {
      reviewed.add(id);
      added++;
    }
  }
  if (added) save();
  return added;
}

export function countReviewed(alerts) {
  let n = 0;
  for (const a of alerts) if (reviewed.has(a.cve_id)) n++;
  return n;
}

export function exportReviewedState() {
  const payload = { version: 1, exported_at: new Date().toISOString(), reviewed_cve_ids: [...reviewed].sort() };
  downloadBlob(JSON.stringify(payload, null, 2), "application/json", `reviewed-state-${todayStamp()}.json`);
}

/** Merge (union, never replace) a previously exported file. Resolves to a status message. */
export async function importReviewedState(file) {
  let data;
  try {
    data = JSON.parse(await file.text());
  } catch {
    throw new Error("Import failed: the file is not valid JSON.");
  }
  const ids = Array.isArray(data?.reviewed_cve_ids) ? data.reviewed_cve_ids.filter((x) => typeof x === "string") : null;
  if (!ids) throw new Error("Import failed: not a reviewed-state export (missing reviewed_cve_ids).");
  const added = markReviewed(ids);
  return `Imported ${ids.length} reviewed CVE(s), ${added} new (merged with existing).`;
}
