// Deep links: escalation-board / Discord / briefing links must resolve to a card.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { alertIdFromHash } from "../../docs/js/format.js";

test("alertIdFromHash accepts canonical and bare CVE/GHSA hashes", () => {
  assert.equal(alertIdFromHash("#alert-CVE-2026-84731"), "CVE-2026-84731");
  assert.equal(alertIdFromHash("#alert-CVE-2026-84731".replace("-", "%2D")), "CVE-2026-84731");
  // bare ids: links already posted to Discord / pasted briefings use this form
  assert.equal(alertIdFromHash("#CVE-2026-84731"), "CVE-2026-84731");
  assert.equal(alertIdFromHash("#GHSA-mvwm-9m2h-87p9"), "GHSA-mvwm-9m2h-87p9");
});

test("alertIdFromHash ignores unrelated anchors and bad encodings", () => {
  for (const h of ["", "#", "#main", "#esc-grid", "#CVE-2026", "#%E0%A4%A", "#alert"]) {
    assert.equal(alertIdFromHash(h), "", h);
  }
});

test("escalation board CVE links use the #alert- deep-link form", () => {
  const src = readFileSync(fileURLToPath(new URL("../../docs/js/escalations.js", import.meta.url)), "utf8");
  const refs = [...src.matchAll(/#\$\{(?:encodeURIComponent\()?it\.ref/g)];
  assert.equal(refs.length, 0, "found a bare #${it.ref} link; cards are id=alert-<id>");
  assert.ok(src.includes("#alert-${encodeURIComponent(it.ref)}"));
});

test("deep-link re-aim treats a card whose top is above the viewport as off target", async () => {
  const { deepLinkOffTarget } = await import("../../docs/js/format.js");
  // Seen live: panels above the board shifted the card up after the scroll,
  // leaving its header (CVE id) 49-79px above the viewport. The old |top| > 80
  // tolerance accepted that.
  for (const top of [-49, -79, -1, 81, 600]) assert.equal(deepLinkOffTarget(top), true, String(top));
  for (const top of [0, 48, 80]) assert.equal(deepLinkOffTarget(top), false, String(top));
});
