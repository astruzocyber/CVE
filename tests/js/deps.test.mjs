// Unit tests for docs/js/deps.js (dependency-file parsers for the board filter).
// Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDependencyFile, readDependencies } from "../../docs/js/deps.js";

const names = (text) => [...parseDependencyFile(text)].sort();

test("pyproject PEP 621: extras brackets don't end the dependencies array", () => {
  const text = `[build-system]
requires = ["hatchling"]

[project]
name = "demo"
dependencies = [
  "fastapi>=0.100",
  "uvicorn[standard]>=0.20",
  # "flask",  commented out
  'jinja2 ; python_version >= "3.9"',
  "requests [socks] == 2.32",
]
`;
  assert.deepEqual(names(text), ["fastapi", "jinja2", "requests", "uvicorn"]);
});

test("pyproject PEP 621: one-line array", () => {
  assert.deepEqual(names(`[project]\ndependencies = ["Django>=5", "celery[redis]"]\n`), ["celery", "django"]);
});

test("pyproject Poetry tables skip python and read inline-table entries", () => {
  const text = `[tool.poetry.dependencies]
python = "^3.11"
uvicorn = {extras = ["standard"], version = "^0.20"}
Pillow = "^10"

[tool.poetry.group.dev.dependencies]
pytest = "^8"
`;
  assert.deepEqual(names(text), ["pillow", "pytest", "uvicorn"]);
});

test("Pipfile packages and dev-packages", () => {
  assert.deepEqual(names(`[packages]\nrequests = "*"\n\n[dev-packages]\nblack = "*"\n`), ["black", "requests"]);
});

test("requirements.txt strips versions, extras, markers, options and comments", () => {
  const text = "# top\n-r base.txt\nDjango==5.0\r\nrequests[socks]>=2 ; python_version>'3'\n\n-e git+https://x/y#egg=z\nurllib3\n";
  assert.deepEqual(names(text), ["django", "requests", "urllib3"]);
});

test("package.json reads every dependency section", () => {
  const text = JSON.stringify({ dependencies: { Lodash: "1" }, devDependencies: { jest: "1" }, peerDependencies: { react: "18" } });
  assert.deepEqual(names(text), ["jest", "lodash", "react"]);
});

test("go.mod adds the module path and its last segment", () => {
  const text = "module example.com/m\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\nrequire golang.org/x/net v0.20.0\n";
  assert.deepEqual(names(text), ["gin", "github.com/gin-gonic/gin", "golang.org/x/net", "net"]);
});

test("Apply on malformed package.json reports the error and keeps the board, never throws", () => {
  const bad = '{ "dependencies": { "lodash": "1" ';
  const fresh = readDependencies(bad);
  assert.equal(fresh.names, null);
  assert.match(fresh.message, /^Could not parse as package\.json: /);
  assert.doesNotMatch(fresh.message, /still applied/);
  const kept = readDependencies(bad, true);
  assert.equal(kept.names, null);
  assert.match(kept.message, /The previous dependency filter is still applied\.$/);
  const empty = readDependencies("   ", true);
  assert.equal(empty.names, null);
  assert.match(empty.message, /^No package names found\..*still applied\.$/);
  const ok = readDependencies('{ "dependencies": { "lodash": "1" } }', true);
  assert.deepEqual([...ok.names], ["lodash"]);
  assert.equal(ok.message, "Filtering by 1 package name(s).");
});
