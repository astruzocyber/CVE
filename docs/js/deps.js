// Dependency-file parsers for the "Match your dependencies" filter.
// Pure functions: text in, Set of lower-cased package names out. Nothing is uploaded.

function parsePackageJson(text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new Error(`Could not parse as package.json: ${e.message}`);
  }
  const names = new Set();
  for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    if (obj && typeof obj[section] === "object" && obj[section]) {
      for (const name of Object.keys(obj[section])) names.add(name.toLowerCase());
    }
  }
  return names;
}

function parseRequirementsTxt(text) {
  const names = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)/); // strips ==1.0, >=, [extras], ; markers
    if (m) names.add(m[1].toLowerCase());
  }
  return names;
}

/** go.mod: both single-line `require x v1` and `require ( ... )` blocks.
 *  Adds the full module path and its last segment to maximise match recall. */
function parseGoMod(text) {
  const names = new Set();
  let inBlock = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^require\s*\(/.test(line)) { inBlock = true; continue; }
    if (inBlock && line.startsWith(")")) { inBlock = false; continue; }
    const m = inBlock ? line.match(/^(\S+)\s+v[0-9]/) : line.match(/^require\s+(\S+)\s+v[0-9]/);
    if (m) {
      const path = m[1].toLowerCase();
      names.add(path);
      names.add(path.split("/").pop());
    }
  }
  return names;
}

/** Minimal TOML dependency extraction for pyproject.toml (Poetry / PEP 621) and Pipfile. */
function parseTomlDependencies(text) {
  const names = new Set();
  const depTable = /^\[(tool\.poetry\.(dependencies|dev-dependencies|group\.[^.\]]+\.dependencies)|packages|dev-packages)\]/;
  let inTable = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("[")) { inTable = depTable.test(line); continue; }
    if (!inTable) continue;
    const m = line.match(/^["']?([A-Za-z0-9._-]+)["']?\s*=/);
    if (m && m[1].toLowerCase() !== "python") names.add(m[1].toLowerCase());
  }
  const arr = text.match(/dependencies\s*=\s*\[([^\]]*)\]/s); // PEP 621 array form
  if (arr) {
    for (const item of arr[1].match(/["']([^"']+)["']/g) || []) {
      const m = item.replace(/["']/g, "").match(/^([A-Za-z0-9._-]+)/);
      if (m) names.add(m[1].toLowerCase());
    }
  }
  return names;
}

export function parseDependencyFile(text) {
  const t = text.trim();
  if (t.startsWith("{")) return parsePackageJson(t);
  if (/^module\s+\S+/m.test(t) && /^go\s+[0-9]/m.test(t)) return parseGoMod(t);
  if (/^\[(tool\.poetry|project|packages|dev-packages)/m.test(t)) return parseTomlDependencies(t);
  return parseRequirementsTxt(t);
}
