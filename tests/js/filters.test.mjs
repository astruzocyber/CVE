// Unit tests for docs/js/filters.js (pure filter/sort logic; no DOM needed).
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { FILTERS, parseFacet, makePredicate, toQueryString, SORTS } from "../../docs/js/filters.js";
import { state, buildSearchIndex } from "../../docs/js/state.js";

const defaults = (over = {}) => ({ ...Object.fromEntries(FILTERS.map((f) => [f.key, f.def])), ...over });
const run = (alerts, values) => {
  state.alerts = alerts;
  state.searchIndex = buildSearchIndex(alerts);
  state.depPackages = null;
  return alerts.filter(makePredicate(defaults(values)));
};

const A = (id, extra = {}) => ({ cve_id: id, description: "", affected: [], matched_keywords: [], cwe_ids: [], ...extra });

test("parseFacet maps kinds to fields and rejects malformed values", () => {
  assert.deepEqual(parseFacet("vp:cisco/ios"), ["affected", "cisco/ios"]);
  assert.deepEqual(parseFacet("kw:Microsoft Office"), ["matched_keywords", "Microsoft Office"]);
  assert.deepEqual(parseFacet("cwe:CWE-94"), ["cwe_ids", "CWE-94"]);
  assert.deepEqual(parseFacet("kw:a:b"), ["matched_keywords", "a:b"]);
  for (const bad of ["", "vp:", ":x", "zz:x", "noprefix", null, undefined]) assert.equal(parseFacet(bad), null, String(bad));
});

test("facet filter is an exact tag match, not a substring search", () => {
  const alerts = [
    A("CVE-1", { affected: ["cisco/ios"] }),
    A("CVE-2", { affected: ["cisco/ios_xe"] }),
    A("CVE-3", { description: "affects cisco/ios devices" }),
  ];
  assert.deepEqual(run(alerts, { facet: "vp:cisco/ios" }).map((a) => a.cve_id), ["CVE-1"]);
  // The free-text search is deliberately broader (the bug the facet fixed).
  assert.equal(run(alerts, { q: "cisco/ios" }).length, 3);
});

test("a malformed facet matches nothing instead of silently showing everything", () => {
  assert.equal(run([A("CVE-1", { affected: ["x"] })], { facet: "bogus" }).length, 0);
});

test("facet survives the shared-link query string", () => {
  assert.match(toQueryString(defaults({ facet: "vp:cisco/ios" })), /facet=vp%3Acisco%2Fios/);
  assert.equal(toQueryString(defaults()), "");
});

test("number thresholds reject missing values instead of passing them", () => {
  const alerts = [A("CVE-1", { risk_score: 80, epss_score: 0.5 }), A("CVE-2", { risk_score: null, epss_score: null })];
  assert.deepEqual(run(alerts, { minRisk: "50" }).map((a) => a.cve_id), ["CVE-1"]);
  assert.deepEqual(run(alerts, { minEpss: "10" }).map((a) => a.cve_id), ["CVE-1"]);
});

test("sorts put missing values last", () => {
  const xs = [A("b", { risk_score: null, kev_due_date: "" }), A("a", { risk_score: 10, kev_due_date: "2026-01-01" })];
  assert.equal([...xs].sort(SORTS.risk_score)[0].cve_id, "a");
  assert.equal([...xs].sort(SORTS.kev_due_date)[0].cve_id, "a");
});

// Invariant on the published data: every breakdown chip's number (from stats.json)
// must equal the number of results its exact-tag filter returns.
test("published breakdown chip counts equal facet filter results", () => {
  const dataDir = fileURLToPath(new URL("../../docs/data/", import.meta.url));
  const alerts = JSON.parse(readFileSync(dataDir + "alerts.json", "utf8"));
  const stats = JSON.parse(readFileSync(dataDir + "stats.json", "utf8"));
  const list = Array.isArray(alerts) ? alerts : alerts.alerts;
  state.alerts = list;
  state.searchIndex = buildSearchIndex(list);
  state.depPackages = null;
  let checked = 0;
  const bad = [];
  for (const [kind, key] of [["kw", "by_matched_keyword"], ["cwe", "by_cwe"], ["vp", "by_vendor_product"]]) {
    for (const [term, count] of Object.entries(stats[key] || {})) {
      const n = list.filter(makePredicate(defaults({ facet: `${kind}:${term}` }))).length;
      if (n !== count) bad.push(`${kind}:${term} chip=${count} results=${n}`);
      checked++;
    }
  }
  assert.ok(checked > 0, "stats.json has no breakdowns to check");
  assert.deepEqual(bad, []);
});
