// Escalation board asset dropdown: "Asset (N)" must equal the cards shown.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assetCounts } from "../../docs/js/escalations.js";

const items = [
  { tier: "escalate", assets: ["Identity", "Windows"] },
  { tier: "work", assets: ["Identity"] },
  { tier: "work", assets: ["Identity"], closed: true },
  { tier: "escalate", assets: ["Browsers"], closed: true },
];

test("assetCounts follows the tier filter", () => {
  assert.deepEqual(assetCounts(items, { tier: "escalate", closed: false }), { Identity: 1, Windows: 1 });
  assert.deepEqual(assetCounts(items, { tier: "work", closed: false }), { Identity: 1 });
});

test("assetCounts excludes closed items unless shown", () => {
  assert.deepEqual(assetCounts(items, { tier: "", closed: false }), { Identity: 2, Windows: 1 });
  assert.deepEqual(assetCounts(items, { tier: "", closed: true }), { Identity: 3, Windows: 1, Browsers: 1 });
});

test("assetCounts on the published board matches what each dropdown choice shows", () => {
  const path = fileURLToPath(new URL("../../docs/data/escalations.json", import.meta.url));
  const data = JSON.parse(readFileSync(path, "utf8"));
  for (const tier of ["escalate", "work", ""]) {
    for (const closed of [false, true]) {
      const s = { tier, closed };
      const counts = assetCounts(data.items, s);
      for (const a of data.assets || []) {
        const shown = data.items.filter((it) => (!tier || it.tier === tier) && (closed || !it.closed)
          && (it.assets || []).includes(a.name)).length;
        assert.equal(counts[a.name] || 0, shown, `${a.name} tier=${tier} closed=${closed}`);
      }
    }
  }
});
