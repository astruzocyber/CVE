// "Time on board" chips must describe the alerts as of now, like the KPI tiles.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderBreakdowns, computeKpis } from "../../docs/js/overview.js";

function fakeDom() {
  const els = {};
  globalThis.document = {
    getElementById: (id) => (els[id] ??= { id, hidden: true, innerHTML: "", textContent: "" }),
  };
  return els;
}

const at = (iso, fn) => {
  const real = Date.now;
  Date.now = () => Date.parse(iso);
  try { return fn(); } finally { Date.now = real; }
};

const ageCounts = (html) =>
  Object.fromEntries([...html.matchAll(/chip__label">([^<]+)<\/span><span class="chip__count">(\d+)/g)].map((m) => [m[1], Number(m[2])]));

// stats.json written at 2026-10-22T20:00Z, when both alerts were < 1 day old.
const ALERTS = [
  { cve_id: "CVE-1", first_seen: "2026-10-22T19:00:00Z" },
  { cve_id: "CVE-2", first_seen: "2026-10-22T02:00:00Z" },
  { cve_id: "CVE-3", first_seen: "2026-09-01T00:00:00Z" },
];
const STATS = { total_alerts: 3, by_age_bucket: { "0-1d": 2, "1-7d": 0, "7-30d": 0, "30d+": 1 } };

test("age chips are measured at view time, not when stats.json was written", () => {
  const els = fakeDom();
  // Viewed 19 h after generation: CVE-2 is now 1.7 days old.
  at("2026-10-23T15:00:00Z", () => renderBreakdowns(ALERTS, STATS));
  assert.deepEqual(ageCounts(els["age-breakdown"].innerHTML), { "0-1d": 1, "1-7d": 1, "30d+": 1 });
  assert.equal(els["age-panel"].hidden, false);
});

test("the 0-1d chip equals the 'New in last 24 h' tile", () => {
  for (const t of ["2026-10-22T20:00:00Z", "2026-10-23T02:00:00Z", "2026-10-23T19:00:00Z", "2026-10-24T00:00:00Z"]) {
    const els = fakeDom();
    at(t, () => renderBreakdowns(ALERTS, STATS));
    const fresh = at(t, () => computeKpis(ALERTS).fresh);
    assert.equal(ageCounts(els["age-breakdown"].innerHTML)["0-1d"] ?? 0, fresh, t);
  }
});

test("age chips still render when stats.json is missing or out of date", () => {
  const els = fakeDom();
  at("2026-10-22T20:00:00Z", () => renderBreakdowns(ALERTS, null));
  assert.deepEqual(ageCounts(els["age-breakdown"].innerHTML), { "0-1d": 2, "30d+": 1 });
  assert.equal(els["age-panel"].hidden, false);
});
