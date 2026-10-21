// Unit tests for the KEV due-date helpers in docs/js/format.js.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { isOverdue, overdueDays, daysUntilDue, isDueSoon, kevStatus } from "../../docs/js/format.js";

const at = (iso, fn) => {
  const real = Date.now;
  Date.now = () => Date.parse(iso);
  try { return fn(); } finally { Date.now = real; }
};
const A = { kev: true, kev_due_date: "2026-10-23" };

test("the KEV due date itself is 'due today', not overdue (matches the pipeline's kev_overdue_count)", () => {
  for (const t of ["2026-10-23T00:00:00Z", "2026-10-23T01:00:00Z", "2026-10-23T23:59:59Z"]) {
    at(t, () => {
      assert.equal(isOverdue(A), false, t);
      assert.equal(overdueDays(A), null, t);
      assert.equal(daysUntilDue(A), 0, t);
      assert.equal(isDueSoon(A), true, t);
      assert.equal(kevStatus(A), "Due soon", t);
    });
  }
});

test("overdue starts the next UTC day and counts whole days past the due date", () => {
  at("2026-10-24T00:00:00Z", () => { assert.equal(isOverdue(A), true); assert.equal(overdueDays(A), 1); assert.equal(daysUntilDue(A), null); });
  at("2026-10-25T12:00:00Z", () => { assert.equal(overdueDays(A), 2); assert.equal(kevStatus(A), "Overdue"); });
});

test("days until due before the due date", () => {
  at("2026-10-22T12:00:00Z", () => assert.equal(daysUntilDue(A), 1));
  at("2026-10-15T12:00:00Z", () => { assert.equal(daysUntilDue(A), 8); assert.equal(isDueSoon(A), false); });
  at("2026-10-22T12:00:00Z", () => assert.equal(isOverdue({ kev: true }), false));
});
