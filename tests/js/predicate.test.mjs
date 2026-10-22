// Unit tests for every board filter in docs/js/filters.js makePredicate().
// A mutation probe (audit 2026-10-22) deleted or inverted each of these checks
// and the rest of the suite stayed green, so each filter is pinned here.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { FILTERS, makePredicate, SORTS } from "../../docs/js/filters.js";
import { state, buildSearchIndex } from "../../docs/js/state.js";
import { toggleReviewed, isReviewed } from "../../docs/js/reviewed.js";
import { ageBucket } from "../../docs/js/format.js";

const DAY = 24 * 60 * 60 * 1000;
const defaults = (over = {}) => ({ ...Object.fromEntries(FILTERS.map((f) => [f.key, f.def])), ...over });
const A = (id, extra = {}) => ({ cve_id: id, description: "", affected: [], matched_keywords: [], cwe_ids: [], ...extra });
const ids = (alerts, values) => {
  state.alerts = alerts;
  state.searchIndex = buildSearchIndex(alerts);
  state.depPackages = null;
  return alerts.filter(makePredicate(defaults(values))).map((a) => a.cve_id);
};
const dayIso = (offsetDays) => new Date(Date.now() + offsetDays * DAY).toISOString().slice(0, 10);

test("defaults show every alert", () => {
  const alerts = [A("CVE-1"), A("CVE-2", { vuln_status: "Rejected", kev: true }), A("CVE-3", { cvss_score: 9.8 })];
  assert.deepEqual(ids(alerts, {}), ["CVE-1", "CVE-2", "CVE-3"]);
});

test("hide reviewed drops only reviewed alerts", () => {
  const alerts = [A("CVE-R1"), A("CVE-R2")];
  if (!isReviewed("CVE-R1")) toggleReviewed("CVE-R1");
  try {
    assert.deepEqual(ids(alerts, { hideReviewed: true }), ["CVE-R2"]);
    assert.deepEqual(ids(alerts, { hideReviewed: false }), ["CVE-R1", "CVE-R2"]);
  } finally {
    toggleReviewed("CVE-R1");
  }
});

test("new (24 h) keeps only alerts first seen in the last day", () => {
  const alerts = [
    A("CVE-NEW", { first_seen: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() }),
    A("CVE-OLD", { first_seen: new Date(Date.now() - 3 * DAY).toISOString() }),
    A("CVE-NONE"),
  ];
  assert.deepEqual(ids(alerts, { newOnly: true }), ["CVE-NEW"]);
});

test("hide rejected drops only NVD-rejected records", () => {
  const alerts = [A("CVE-1", { vuln_status: "Rejected" }), A("CVE-2", { vuln_status: "Analyzed" }), A("CVE-3")];
  assert.deepEqual(ids(alerts, { hideRejected: true }), ["CVE-2", "CVE-3"]);
});

test("fix available keeps only alerts with a fixed version", () => {
  const alerts = [A("CVE-1", { osv_fixed_versions: ["1.2.3"] }), A("CVE-2", { osv_fixed_versions: [] }), A("CVE-3")];
  assert.deepEqual(ids(alerts, { hasFixOnly: true }), ["CVE-1"]);
});

test("KEV filter: kev, non-kev, overdue, due soon, ransomware", () => {
  const alerts = [
    A("CVE-PLAIN"),
    A("CVE-OVERDUE", { kev: true, kev_due_date: dayIso(-3) }),
    A("CVE-DUE", { kev: true, kev_due_date: dayIso(3) }),
    A("CVE-LATER", { kev: true, kev_due_date: dayIso(40), kev_ransomware_use: true }),
  ];
  assert.deepEqual(ids(alerts, { kev: "kev" }), ["CVE-OVERDUE", "CVE-DUE", "CVE-LATER"]);
  assert.deepEqual(ids(alerts, { kev: "non-kev" }), ["CVE-PLAIN"]);
  assert.deepEqual(ids(alerts, { kev: "overdue" }), ["CVE-OVERDUE"]);
  assert.deepEqual(ids(alerts, { kev: "due-soon" }), ["CVE-DUE"]);
  assert.deepEqual(ids(alerts, { kev: "ransomware" }), ["CVE-LATER"]);
  assert.equal(ids(alerts, { kev: "bogus" }).length, 4, "unknown value falls back to all");
});

test("severity filter uses CVSS bands; unscored alerts are 'unknown'", () => {
  const alerts = [A("C", { cvss_score: 9.0 }), A("H", { cvss_score: 8.9 }), A("M", { cvss_score: 4.0 }),
    A("L", { cvss_score: 3.9 }), A("U", { cvss_score: null })];
  assert.deepEqual(ids(alerts, { sev: "critical" }), ["C"]);
  assert.deepEqual(ids(alerts, { sev: "high" }), ["H"]);
  assert.deepEqual(ids(alerts, { sev: "medium" }), ["M"]);
  assert.deepEqual(ids(alerts, { sev: "low" }), ["L"]);
  assert.deepEqual(ids(alerts, { sev: "unknown" }), ["U"]);
});

test("source filter matches the source or its 'source:' sub-sources only", () => {
  const alerts = [A("N", { source: "nvd" }), A("K", { source: "kev" }), A("G", { source: "ghsa:npm" }),
    A("X", { source: "kevlar" }), A("Z")];
  assert.deepEqual(ids(alerts, { source: "kev" }), ["K"]);
  assert.deepEqual(ids(alerts, { source: "ghsa" }), ["G"]);
  assert.deepEqual(ids(alerts, { source: "nvd" }), ["N"]);
});

test("risk and EPSS minimums include the threshold itself", () => {
  const alerts = [A("AT", { risk_score: 50, epss_score: 0.5 }), A("BELOW", { risk_score: 49.9, epss_score: 0.49999 })];
  assert.deepEqual(ids(alerts, { minRisk: "50" }), ["AT"]);
  assert.deepEqual(ids(alerts, { minEpss: "50" }), ["AT"]);
});

test("EPSS minimum is not fooled by float rounding (29.0% passes 'EPSS >= 29%')", () => {
  // 0.29 * 100 === 28.999999999999996 in IEEE doubles; the card shows 29.0%.
  const alerts = [A("E29", { epss_score: 0.29 }), A("E57", { epss_score: 0.57 }), A("E07", { epss_score: 0.07 })];
  assert.deepEqual(ids(alerts, { minEpss: "29" }), ["E29", "E57"]);
  assert.deepEqual(ids(alerts, { minEpss: "57" }), ["E57"]);
  assert.deepEqual(ids(alerts, { minEpss: "7" }), ["E29", "E57", "E07"]);
});

test("risk change sort: biggest rise first, alerts without a change last", () => {
  const xs = [A("none"), A("down", { risk_score: 40, risk_score_prev: 50 }), A("up", { risk_score: 70, risk_score_prev: 50 }),
    A("none2", { risk_score: 10 })];
  assert.deepEqual([...xs].sort(SORTS.risk_delta).map((a) => a.cve_id), ["up", "down", "none", "none2"]);
});

test("date sorts: newest/oldest first and missing dates last in both directions", () => {
  const xs = [A("mid", { first_seen: "2026-10-10T00:00:00Z" }), A("none"), A("new", { first_seen: "2026-10-20T00:00:00Z" }),
    A("old", { first_seen: "2026-10-01T00:00:00Z" })];
  assert.deepEqual([...xs].sort(SORTS.first_seen).map((a) => a.cve_id), ["new", "mid", "old", "none"]);
  assert.deepEqual([...xs].sort(SORTS.first_seen_oldest).map((a) => a.cve_id), ["old", "mid", "new", "none"]);
});

test("time-on-board buckets switch exactly at 7 and 30 days", () => {
  const now = Date.parse("2026-10-22T12:00:00Z");
  const at = (ms) => ageBucket({ first_seen: new Date(now - ms).toISOString() }, now);
  assert.equal(at(7 * DAY - 1000), "1-7d");
  assert.equal(at(7 * DAY), "7-30d");
  assert.equal(at(30 * DAY - 1000), "7-30d");
  assert.equal(at(30 * DAY), "30d+");
});
