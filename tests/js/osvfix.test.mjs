// Unit tests for the OSV.dev fix-line helpers in docs/js/format.js.
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { osvFixText, osvFixCommitUrl, osvFixIsCommit } from "../../docs/js/format.js";

const SHA = "3bd7aa32e1b6c41166575529a10fb2346d9eaa2e";

test("package fix keeps the package -> version wording", () => {
  const f = { package: "foo", ecosystem: "PyPI", fixed: "1.2.3" };
  assert.equal(osvFixText(f), "foo (PyPI) → 1.2.3");
  assert.equal(osvFixIsCommit(f), false);
  assert.equal(osvFixCommitUrl(f), null);
});

test("source-only fix names the repo and says it is a commit, not a version", () => {
  const f = { package: null, ecosystem: null, fixed: SHA, repo: "https://github.com/traefik/traefik" };
  assert.equal(osvFixText(f), `github.com/traefik/traefik → fix commit ${SHA.slice(0, 12)} (source fix, no release version stated)`);
  assert.equal(osvFixCommitUrl(f), `https://github.com/traefik/traefik/commit/${SHA}`);
});

test("legacy entry without repo no longer renders as '? → <hash>'", () => {
  const f = { package: null, ecosystem: null, fixed: SHA };
  assert.ok(!osvFixText(f).startsWith("?"));
  assert.match(osvFixText(f), /upstream source → fix commit 3bd7aa32e1b6/);
  assert.equal(osvFixCommitUrl(f), null);
});

test("commit links only for well-formed GitHub/GitLab repo URLs", () => {
  const gl = { package: null, fixed: SHA, repo: "https://gitlab.com/grp/proj.git" };
  assert.equal(osvFixCommitUrl(gl), `https://gitlab.com/grp/proj/-/commit/${SHA}`);
  assert.equal(osvFixCommitUrl({ package: null, fixed: SHA, repo: "https://git.kernel.org/pub/scm/linux" }), null);
  assert.equal(osvFixCommitUrl({ package: null, fixed: SHA, repo: "javascript:alert(1)//github.com/a/b" }), null);
  assert.equal(osvFixCommitUrl({ package: null, fixed: "not-a-sha", repo: "https://github.com/a/b" }), null);
});
