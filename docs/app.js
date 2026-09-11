// Static dashboard: fetches data/alerts.json + data/stats.json (same repo, same deploy)
// and renders filterable/sortable cards. No backend, no build step.

let allAlerts = [];

// Human-readable names for CWE (Common Weakness Enumeration) IDs, keyed by
// numeric ID (no "CWE-" prefix). CWE IDs have been shown as bare badges
// (card view) and a bare joined cell (table view, cycle 94) since they were
// added -- an analyst unfamiliar with the numbering (e.g. "is CWE-416 the
// bad one?") had to open a new tab to cwe.mitre.org just to know what class
// of bug a row represents. This is a small static curated map (not a live
// API call -- MITRE's CWE list is a fixed taxonomy that changes rarely, and
// a live fetch would add an external dependency risk for zero benefit over
// a literal table) covering every CWE ID actually observed in the current
// tracked-alert dataset (97 distinct IDs as of this cycle) plus a handful of
// other very common ones, so unrecognized/future IDs simply fall back to no
// name shown (existing behavior), never a broken link or blank lookup.
const CWE_NAMES = {
  "20": "Improper Input Validation", "22": "Path Traversal", "36": "Absolute Path Traversal",
  "59": "Link Following", "73": "External Control of File Name/Path", "74": "Injection",
  "76": "Equivalent Special Element Injection", "78": "OS Command Injection", "79": "Cross-Site Scripting (XSS)",
  "89": "SQL Injection", "93": "CRLF Injection", "94": "Code Injection", "95": "Eval Injection",
  "98": "PHP File Inclusion", "119": "Improper Restriction of Memory Buffer Bounds",
  "120": "Buffer Copy without Checking Size (Classic Buffer Overflow)", "121": "Stack-based Buffer Overflow",
  "122": "Heap-based Buffer Overflow", "125": "Out-of-bounds Read", "129": "Improper Validation of Array Index",
  "131": "Incorrect Calculation of Buffer Size", "180": "Incorrect Behavior Order: Validate Before Canonicalize",
  "184": "Incomplete List of Disallowed Inputs", "190": "Integer Overflow or Wraparound",
  "193": "Off-by-one Error", "197": "Numeric Truncation Error", "200": "Exposure of Sensitive Information",
  "208": "Observable Timing Discrepancy", "209": "Generation of Error Message Containing Sensitive Info",
  "250": "Execution with Unnecessary Privileges", "269": "Improper Privilege Management",
  "276": "Incorrect Default Permissions", "284": "Improper Access Control", "285": "Improper Authorization",
  "287": "Improper Authentication", "290": "Authentication Bypass by Spoofing",
  "294": "Authentication Bypass by Capture-replay", "297": "Improper Validation of Certificate with Host Mismatch",
  "306": "Missing Authentication for Critical Function", "308": "Use of Single-factor Authentication",
  "311": "Missing Encryption of Sensitive Data", "312": "Cleartext Storage of Sensitive Information",
  "319": "Cleartext Transmission of Sensitive Information", "330": "Use of Insufficiently Random Values",
  "345": "Insufficient Verification of Data Authenticity", "347": "Improper Verification of Cryptographic Signature",
  "352": "Cross-Site Request Forgery (CSRF)", "362": "Race Condition", "367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
  "400": "Uncontrolled Resource Consumption", "407": "Inefficient Regular Expression Complexity (ReDoS)",
  "415": "Double Free", "416": "Use After Free", "427": "Uncontrolled Search Path Element",
  "434": "Unrestricted Upload of File with Dangerous Type", "436": "Interpretation Conflict",
  "441": "Server-Side Request Forgery (SSRF)-adjacent Proxy/Confused Deputy", "459": "Incomplete Cleanup",
  "470": "Unsafe Reflection", "476": "NULL Pointer Dereference", "480": "Use of Incorrect Operator",
  "502": "Deserialization of Untrusted Data", "506": "Embedded Malicious Code",
  "613": "Insufficient Session Expiration", "620": "Unverified Password Change",
  "636": "Not Failing Securely ('Failing Open')", "639": "Insecure Direct Object Reference (IDOR)",
  "664": "Improper Control of a Resource Through its Lifetime", "665": "Improper Initialization",
  "668": "Exposure of Resource to Wrong Sphere", "672": "Operation on a Resource after Expiration or Release",
  "682": "Incorrect Calculation", "691": "Insufficient Control Flow Management",
  "693": "Protection Mechanism Failure", "697": "Incorrect Comparison", "703": "Improper Check/Handling of Exceptional Conditions",
  "704": "Incorrect Type Conversion or Cast", "706": "Use of Incorrectly-resolved Name or Reference",
  "707": "Improper Neutralization", "770": "Allocation of Resources Without Limits or Throttling",
  "787": "Out-of-bounds Write", "789": "Uncontrolled Memory Allocation",
  "807": "Reliance on Untrusted Inputs in a Security Decision", "825": "Expired Pointer Dereference",
  "843": "Type Confusion", "862": "Missing Authorization", "863": "Incorrect Authorization",
  "908": "Use of Uninitialized Resource", "916": "Use of Password Hash With Insufficient Computational Effort",
  "918": "Server-Side Request Forgery (SSRF)", "941": "Incorrectly Specified Destination in a Communication Channel",
  "943": "Improper Neutralization of Special Elements in Data Query Logic",
  "1050": "Excessive Platform Resource Consumption within a Loop",
  "1284": "Improper Validation of Specified Quantity in Input", "1289": "Improper Validation of Unsafe Equivalence in Input",
  "1321": "Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)",
  "1336": "Improper Neutralization of Special Elements Used in a Template Engine",
};
function cweName(cweId) {
  const num = String(cweId || "").replace(/^CWE-/i, "");
  return CWE_NAMES[num] || null;
}

// Client-side "mark as reviewed" triage state. Purely local (localStorage),
// per-browser, never sent anywhere and never touches the shared dataset --
// this is a per-analyst workflow aid, not shared team state. Answers a real
// gap: on every reload the board shows all N alerts with zero memory of
// which ones a given analyst has already triaged, forcing them to re-scan
// the same already-handled entries every session. Stored as a Set of CVE
// IDs under a single localStorage key; a JSON parse failure (corrupted/old
// data) falls back to an empty set rather than throwing.
const REVIEWED_KEY = "reviewedCves";
function loadReviewedSet() {
  try {
    const raw = localStorage.getItem(REVIEWED_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? new Set(arr) : new Set();
  } catch (e) {
    return new Set();
  }
}
let reviewedCves = loadReviewedSet();
function saveReviewedSet() {
  try {
    localStorage.setItem(REVIEWED_KEY, JSON.stringify([...reviewedCves]));
  } catch (e) {}
}
function toggleReviewed(cveId) {
  if (reviewedCves.has(cveId)) reviewedCves.delete(cveId);
  else reviewedCves.add(cveId);
  saveReviewedSet();
}

// Export/import of the reviewed-state set: the reviewedCves Set has been
// localStorage-only since cycle 48, meaning it's trapped on one browser --
// an analyst who clears cache, switches devices, or hands off a triage
// session to a teammate loses (or can't share) their review progress
// entirely, with zero way to recover or transfer it. Export produces a
// small JSON file ({version, exported_at, reviewed_cve_ids: [...]}) via a
// client-side Blob download (no server, no new API call). Import reads a
// user-selected file and MERGES its CVE IDs into the current set (union,
// not replace) so importing a teammate's export can't silently erase an
// analyst's own progress -- a deliberate, safer default for shared/handoff
// use. Malformed/non-JSON files fail with a visible status message rather
// than throwing or silently no-opping.
function exportReviewedState() {
  const payload = {
    version: 1,
    exported_at: new Date().toISOString(),
    reviewed_cve_ids: [...reviewedCves].sort(),
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `reviewed-state-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
function importReviewedState(file, statusEl) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      const ids = Array.isArray(data.reviewed_cve_ids) ? data.reviewed_cve_ids : null;
      if (!ids) throw new Error("missing reviewed_cve_ids array");
      let added = 0;
      for (const id of ids) {
        if (typeof id === "string" && !reviewedCves.has(id)) {
          reviewedCves.add(id);
          added++;
        }
      }
      saveReviewedSet();
      applyFiltersAndRender();
      renderReviewedProgress();
      if (statusEl) statusEl.textContent = `Imported ${ids.length} reviewed CVE(s), ${added} new (merged with existing).`;
    } catch (e) {
      if (statusEl) statusEl.textContent = "Import failed: not a valid reviewed-state export file.";
    }
  };
  reader.onerror = () => {
    if (statusEl) statusEl.textContent = "Import failed: could not read file.";
  };
  reader.readAsText(file);
}

// Reviewed-progress indicator: cycle 48 added the per-card toggle and a
// "hide reviewed" filter, but gave no at-a-glance sense of overall triage
// completion (e.g. "have I gotten through most of the backlog, or barely
// started?"). Counts against the FULL tracked set (allAlerts), not the
// currently-filtered view, since "how much of my total backlog have I
// cleared" is a distinct question from "how many match my current filter" --
// a security lead filtering down to a handful of KEV-overdue alerts still
// wants the denominator to be the whole board, not the narrowed view.
function renderReviewedProgress() {
  const el = document.getElementById("reviewed-progress");
  if (!el) return;
  const total = allAlerts.length;
  if (total === 0) {
    el.textContent = "";
    return;
  }
  const reviewedCount = allAlerts.reduce((n, a) => n + (reviewedCves.has(a.cve_id) ? 1 : 0), 0);
  const pct = Math.round((reviewedCount / total) * 100);
  el.textContent = `\u2713 ${reviewedCount} of ${total} reviewed (${pct}%)`;
}

function severityClass(cvss) {
  if (cvss === null || cvss === undefined) return "";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

function riskClass(score) {
  if (typeof score !== "number") return "";
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function fmtScore(v, digits = 1) {
  return typeof v === "number" ? v.toFixed(digits) : "n/a";
}

// cvss_version arrives from NVD/GHSA as raw strings like "CVSS V31", "CVSS V40",
// "CVSS V30", or "GHSA CVSS" (a source-specific label, not an NVD version code).
// Normalizes to a compact human label (e.g. "v3.1", "v4.0") for display; NVD's
// CVSS v4.0 scores use a materially different metric set/weighting than v3.x, so
// surfacing the version is a real signal, not cosmetic -- an analyst comparing two
// "CVSS 8.8" cards should know if they were scored on different rubrics.
function cvssVersionText(raw) {
  if (!raw) return null;
  const m = /^CVSS V(\d)(\d)$/.exec(raw);
  if (m) return `v${m[1]}.${m[2]}`;
  return raw; // e.g. "GHSA CVSS" -- pass through as-is, still informative
}

function cvssVersionLabel(raw) {
  const text = cvssVersionText(raw);
  return text ? ` <span class="cvss-version" title="CVSS scoring version">${escapeHtml(text)}</span>` : "";
}

function fmtDate(iso) {
  if (!iso) return "unknown";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function isOverdue(alert) {
  if (!alert.kev_due_date) return false;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  return !isNaN(due) && due.getTime() < Date.now();
}

// How many whole days past the CISA KEV BOD 22-01 remediation due date this
// alert is, or null if not overdue / no due date. Purely a display magnitude
// for the existing OVERDUE badge -- the overdue/non-overdue decision itself
// still comes from isOverdue() above, unchanged.
function overdueDays(alert) {
  if (!isOverdue(alert)) return null;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  const diffMs = Date.now() - due.getTime();
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

// Whole days remaining until the CISA KEV BOD 22-01 remediation due date, or
// null if there is no due date or it has already passed (that case is
// covered by isOverdue()/overdueDays() above, not this function -- the two
// are mutually exclusive by construction). Purely a display magnitude used
// to flag upcoming deadlines before they become overdue, mirroring the
// existing overdue-days feature symmetrically on the other side of "today".
function daysUntilDue(alert) {
  if (!alert.kev_due_date || isOverdue(alert)) return null;
  const due = new Date(alert.kev_due_date + "T00:00:00Z");
  if (isNaN(due)) return null;
  const diffMs = due.getTime() - Date.now();
  return Math.ceil(diffMs / (24 * 60 * 60 * 1000));
}

// Human-readable "how long has this been on our radar" age, computed from
// first_seen (set once by aggregate.py the first time a CVE/GHSA/Dependabot
// alert is ingested and never touched again on subsequent refresh cycles --
// see build_final_entry()/the "keep the original first_seen" merge logic in
// scripts/aggregate.py). Distinct from "Published" (the vendor/NVD publish
// date, which can predate first_seen by years for old CVEs that only start
// matching the watchlist later) -- this answers "how long has our team known
// about this" for triage aging/backlog purposes, a gap the card had no way
// to answer before (only a "days overdue"/"days until due" concept existed,
// scoped to KEV deadlines specifically).
function firstSeenAge(alert) {
  if (!alert.first_seen) return null;
  const seen = new Date(alert.first_seen);
  if (isNaN(seen)) return null;
  const days = Math.floor((Date.now() - seen.getTime()) / (24 * 60 * 60 * 1000));
  return days < 0 ? 0 : days;
}

// "NEW" badge/filter: distinct from the existing "First seen: Nd ago" badge
// (cycle 19, always-visible aging label) and "Sort: Newest first" -- this
// answers a binary triage question ("did anything land on my board since I
// last checked, roughly in the last day") that scanning first_seen ages or
// re-sorting doesn't answer at a glance across dozens of cards. 24h chosen
// to comfortably span the pipeline's 4h run cadence (multiple runs' worth
// of "new" stay flagged for a full day even if an analyst only checks once
// daily) without staying stuck "new" for so long it loses meaning.
const NEW_WITHIN_MS = 24 * 60 * 60 * 1000;
function isNewWithin24h(alert) {
  if (!alert.first_seen) return false;
  const seen = new Date(alert.first_seen);
  if (isNaN(seen)) return false;
  return (Date.now() - seen.getTime()) <= NEW_WITHIN_MS;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

// CISA KEV catalog "notes" field is a semicolon-separated mix of vendor advisory
// URLs and generic boilerplate (BOD 26-04 directive links, Forensics Triage
// Requirements links, and a redundant NVD link -- the dashboard already links to
// NVD in the card footer). Extract only genuine vendor/advisory links so a viewer
// can jump straight to the vendor's patch notes without wading through repeated
// directive boilerplate present on every KEV entry.
function kevNotesLinksHtml(notes) {
  if (!notes || typeof notes !== "string") return "";
  const parts = notes.split(";").map((p) => p.trim()).filter(Boolean);
  const urlRe = /(https?:\/\/\S+)/;
  const links = [];
  for (const part of parts) {
    const m = part.match(urlRe);
    if (!m) continue;
    const url = m[1];
    if (/nvd\.nist\.gov/i.test(url)) continue;
    if (/bod-26-04|forensics-triage/i.test(url)) continue;
    const label = part.slice(0, m.index).replace(/:$/, "").trim();
    links.push({ url, label: label || "Vendor advisory" });
  }
  if (!links.length) return "";
  return `<div class="kev-notes">Advisories: ${links.map((l) =>
    `<a href="${escapeHtml(l.url)}" target="_blank" rel="noopener">${escapeHtml(l.label)}</a>`
  ).join(" &middot; ")}</div>`;
}

function renderCard(alert) {
  const sevClass = severityClass(alert.cvss_score);
  const rClass = riskClass(alert.risk_score);
  const overdue = isOverdue(alert);
  const kevBadge = alert.kev ? `<span class="badge kev">KEV</span>` : "";
  const overdueDaysVal = overdue ? overdueDays(alert) : null;
  const overdueBadge = overdue
    ? `<span class="badge overdue">OVERDUE${typeof overdueDaysVal === "number" ? ` (${overdueDaysVal}d)` : ""}</span>`
    : "";
  const ransomwareBadge = alert.kev_ransomware_use ? `<span class="badge ransomware">RANSOMWARE</span>` : "";
  const dueSoonDays = daysUntilDue(alert);
  const dueSoonBadge = typeof dueSoonDays === "number" && dueSoonDays <= 7
    ? `<span class="badge due-soon">DUE SOON (${dueSoonDays}d)</span>`
    : "";
  const newBadge = isNewWithin24h(alert) ? `<span class="badge new-alert">NEW</span>` : "";
  // NVD withdrew this CVE ID entirely (duplicate, disputed, or withdrawn by
  // the CNA) -- see extract_vuln_status() in aggregate.py for full rationale.
  // Surfaced as a loud, distinct badge (not just another severity/source
  // badge) because a rejected CVE ID carries fundamentally different meaning
  // than any other tracked alert: any CVSS/EPSS/risk_score on the card may
  // be stale/meaningless data NVD itself no longer stands behind.
  const rejectedBadge = alert.vuln_status === "Rejected"
    ? `<span class="badge rejected" title="NVD has withdrawn this CVE ID (duplicate, disputed, or withdrawn by the CNA) -- scores below may be stale">REJECTED BY NVD</span>`
    : "";
  const sevBadge = sevClass
    ? `<span class="badge ${sevClass}">${sevClass}</span>`
    : "";
  const sourceBadge = `<span class="badge source">${escapeHtml(alert.source || "unknown")}</span>`;
  const affected = (alert.affected || []).join(", ") || "n/a";
  const kevActionHtml = alert.kev && alert.kev_required_action
    ? `<div class="kev-action"><strong>CISA required action:</strong> ${escapeHtml(alert.kev_required_action)}</div>`
    : "";
  const kevNotesHtml = alert.kev && alert.kev_notes ? kevNotesLinksHtml(alert.kev_notes) : "";
  const matchedKeywords = alert.matched_keywords || [];
  const matchedHtml = matchedKeywords.length
    ? `<div class="matched">Watchlist match: ${matchedKeywords.map((k) => `<span class="badge match">${escapeHtml(k)}</span>`).join("")}</div>`
    : "";
  const cweIds = alert.cwe_ids || [];
  const cweHtml = cweIds.length
    ? `<div class="cwe-row">Weakness: ${cweIds.map((c) => {
        const num = c.replace(/^CWE-/i, "");
        const name = cweName(c);
        const title = name ? `${escapeHtml(c)}: ${escapeHtml(name)}` : `View ${escapeHtml(c)} on cwe.mitre.org`;
        const label = name ? `${escapeHtml(c)} (${escapeHtml(name)})` : escapeHtml(c);
        return /^\d+$/.test(num)
          ? `<a class="badge cwe" href="https://cwe.mitre.org/data/definitions/${num}.html" target="_blank" rel="noopener" title="${title}">${label}</a>`
          : `<span class="badge cwe">${escapeHtml(c)}</span>`;
      }).join("")}</div>`
    : "";
  const epssPct = typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a";
  const epssPercentileTitle = typeof alert.epss_percentile === "number"
    ? ` title="Higher than ${(alert.epss_percentile * 100).toFixed(0)}% of all scored CVEs (EPSS percentile)"`
    : "";
  const epssPercentileHtml = typeof alert.epss_percentile === "number"
    ? ` <span class="epss-percentile"${epssPercentileTitle}>(top ${(100 - alert.epss_percentile * 100).toFixed(0)}%)</span>`
    : "";
  // Mirrors riskDelta below, but for the raw EPSS probability rather than the
  // composite risk_score -- risk_score blends in CVSS/KEV too, so its delta
  // alone can't tell an analyst whether a risk_score change was actually
  // EPSS-driven (exploitation-likelihood shift) vs. a CVSS/KEV change.
  const epssDelta = (typeof alert.epss_score === "number" && typeof alert.epss_score_prev === "number")
    ? alert.epss_score - alert.epss_score_prev
    : null;
  const epssDeltaHtml = epssDelta && Math.abs(epssDelta) >= 0.0005
    ? `<span class="epss-delta ${epssDelta > 0 ? "risk-up" : "risk-down"}" title="EPSS changed from ${(alert.epss_score_prev * 100).toFixed(1)}% to ${(alert.epss_score * 100).toFixed(1)}% since the last refresh">${epssDelta > 0 ? "\u25b2" : "\u25bc"}${epssDelta > 0 ? "+" : ""}${(epssDelta * 100).toFixed(1)}pp</span>`
    : "";
  const vc = alert.cvss_vector_components;
  const exploitLabels = { NETWORK: "Network", ADJACENT_NETWORK: "Adjacent", LOCAL: "Local", PHYSICAL: "Physical",
    LOW: "Low", HIGH: "High", NONE: "None", REQUIRED: "Required" };
  const exploitChipHtml = vc && vc.attack_vector
    ? `<span class="exploit-chip" title="CVSS vector: attack vector=${escapeHtml(vc.attack_vector || "?")}, complexity=${escapeHtml(vc.attack_complexity || "?")}, privileges=${escapeHtml(vc.privileges_required || "?")}, user interaction=${escapeHtml(vc.user_interaction || "?")}">`
      + `${escapeHtml(exploitLabels[vc.attack_vector] || vc.attack_vector)}`
      + (vc.privileges_required === "NONE" && vc.user_interaction === "NONE" ? " \u00b7 no auth/interaction" : "")
      + `</span>`
    : "";
  const riskVal = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(0) : "n/a";
  const riskDelta = (typeof alert.risk_score === "number" && typeof alert.risk_score_prev === "number")
    ? Math.round(alert.risk_score - alert.risk_score_prev)
    : null;
  const riskDeltaHtml = riskDelta && riskDelta !== 0
    ? `<span class="risk-delta ${riskDelta > 0 ? "risk-up" : "risk-down"}" title="Risk score changed from ${alert.risk_score_prev.toFixed(0)} to ${alert.risk_score.toFixed(0)} since the last refresh">${riskDelta > 0 ? "\u25b2" : "\u25bc"}${riskDelta > 0 ? "+" : ""}${riskDelta}</span>`
    : "";
  const b = alert.risk_score_breakdown;
  const breakdownHtml = b ? `
      <div class="score-breakdown" hidden>
        <div class="breakdown-row"><span>CVSS ${fmtScore(b.cvss_raw)} &times; ${b.cvss_weight || "35%"}</span><span>= ${fmtScore(b.cvss_component)} pts</span></div>
        <div class="breakdown-row"><span>EPSS ${typeof b.epss_raw === "number" ? (b.epss_raw * 100).toFixed(1) + "%" : "n/a"} &times; ${b.epss_weight || "40%"}</span><span>= ${fmtScore(b.epss_component)} pts</span></div>
        <div class="breakdown-row"><span>${b.kev_weight || "KEV bonus"}</span><span>= ${fmtScore(b.kev_bonus)} pts</span></div>
        <div class="breakdown-row breakdown-total"><span>Total${b.capped ? " (capped at 100)" : ""}</span><span>= ${riskVal} pts</span></div>
        ${b.weight_redistributed ? `<div class="breakdown-note">Note: CVSS/EPSS weight was redistributed because one score is not yet available for this CVE.</div>` : ""}
      </div>` : "";
  const toggleBtn = b ? `<button class="score-toggle" type="button" title="Show risk score breakdown" aria-expanded="false">breakdown &#9662;</button>` : "";

  const cveIdSafe = escapeHtml(alert.cve_id);
  const isReviewed = reviewedCves.has(alert.cve_id);
  const reviewedBtn = `<button class="review-toggle-btn${isReviewed ? " reviewed" : ""}" type="button" data-cve="${cveIdSafe}" title="${isReviewed ? "Marked reviewed -- click to unmark" : "Mark this alert as reviewed"}" aria-pressed="${isReviewed ? "true" : "false"}">${isReviewed ? "\u2713 Reviewed" : "Mark reviewed"}</button>`;
  const copyMdBtn = `<button class="copy-md-btn" type="button" data-cve="${cveIdSafe}" title="Copy this alert as Markdown for an incident ticket">Copy as Markdown</button>`;
  const copySuppressBtn = `<button class="copy-suppress-btn" type="button" data-cve="${cveIdSafe}" title="Copy a ready-to-paste config/suppressions.yaml entry for this alert (accepted-risk / false-positive)">Copy suppression YAML</button>`;
  return `
    <div class="card${isReviewed ? " reviewed-card" : ""}" data-cve-id="${cveIdSafe}" id="alert-${cveIdSafe}">
      <div class="card-header">
        <button class="cve-id cve-link-btn" type="button" data-cve="${cveIdSafe}" title="Copy a direct link to this alert">${cveIdSafe}</button>
        <div class="badges">${newBadge}${rejectedBadge}${kevBadge}${ransomwareBadge}${overdueBadge}${dueSoonBadge}${sevBadge}${sourceBadge}</div>
      </div>
      <div class="risk-row">
        <div class="risk-bar-track"><div class="risk-bar-fill ${rClass}" style="width:${Math.min(100, alert.risk_score || 0)}%"></div></div>
        <span class="risk-label">Risk ${riskVal}/100</span>
        ${riskDeltaHtml}
        ${toggleBtn}
      </div>
      ${breakdownHtml}
      <div class="description">${escapeHtml(alert.description || "(no description)")}</div>
      <div class="scores">
        <span>CVSS: <strong>${fmtScore(alert.cvss_score)}</strong>${cvssVersionLabel(alert.cvss_version)}</span>
        <span>EPSS: <strong>${epssPct}</strong>${epssPercentileHtml}${epssDeltaHtml}</span>
        ${alert.kev_date_added ? `<span title="Date this CVE was added to the CISA Known Exploited Vulnerabilities catalog">KEV added: <strong>${escapeHtml(alert.kev_date_added)}</strong></span>` : ""}
        ${alert.kev_due_date ? `<span>KEV due: <strong>${escapeHtml(alert.kev_due_date)}</strong></span>` : ""}
        ${exploitChipHtml}
      </div>
      <div class="affected">Affected: ${escapeHtml(affected)}</div>
      ${kevActionHtml}
      ${kevNotesHtml}
      ${matchedHtml}
      ${cweHtml}
      <div class="card-footer">
        <span>Published: ${fmtDate(alert.published)}</span>
        ${(() => {
          // nvd_last_modified answers a distinct question from "published": has NVD
          // revised the record (rescored CVSS, corrected CWE, edited description)
          // since initial publication? Only render when it's a genuinely different
          // calendar day from published, so a record with no post-publication edits
          // (the common case) doesn't get a redundant, noisy second date shown.
          if (!alert.nvd_last_modified || !alert.published) return "";
          const pubDay = String(alert.published).slice(0, 10);
          const modDay = String(alert.nvd_last_modified).slice(0, 10);
          if (modDay === pubDay) return "";
          return `<span class="revised-badge" title="NVD has revised this record since initial publication (rescored CVSS, corrected CWE/description, etc.)">Revised: ${escapeHtml(fmtDate(alert.nvd_last_modified))}</span>`;
        })()}
        <span class="age-badge" title="Days since this alert was first ingested by the pipeline">${(() => { const age = firstSeenAge(alert); return typeof age === "number" ? `First seen: ${age}d ago` : ""; })()}</span>
        <span class="footer-links">
          ${alert.cve_id && /^CVE-/i.test(alert.cve_id) ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}" target="_blank" rel="noopener">View on NVD</a>` : ""}
          ${alert.dependabot_url ? `<a href="${alert.dependabot_url}" target="_blank" rel="noopener">View alert</a>` : ""}
          ${alert.osv_id ? `<a href="https://osv.dev/vulnerability/${encodeURIComponent(alert.osv_id)}" target="_blank" rel="noopener" title="OSV.dev open-source vulnerability record with fixed-version data">View on OSV.dev</a>` : ""}
        </span>
        ${(() => {
          // osv_fixed_versions (cycle 61, OSV.dev read-only enrichment) answers a
          // distinct question none of the existing fields answer: which exact
          // package version actually fixes this CVE, if OSV.dev has that data.
          // Renders only when non-empty; most alerts (non-package-ecosystem CVEs,
          // or ones OSV hasn't curated) have none and show nothing extra.
          const fixed = alert.osv_fixed_versions;
          if (!Array.isArray(fixed) || fixed.length === 0) return "";
          const items = fixed.map(f => `${escapeHtml(f.package || "?")}${f.ecosystem ? ` (${escapeHtml(f.ecosystem)})` : ""} \u2192 ${escapeHtml(f.fixed || "?")}`).join(", ");
          return `<div class="osv-fixed" title="Fixed version(s) per OSV.dev">Fix available: ${items}</div>`;
        })()}
        ${(() => {
          // nvd_fix_versions (cycle 78, NVD configurations CPE-match parsing)
          // covers the population OSV.dev never curates: vendor/OS/hardware
          // CVEs (Windows, Cisco IOS, PAN-OS, browsers, firmware, etc.) that
          // still carry a precise "fixed in version X" boundary in NVD's own
          // CPE match data. Zero new API calls -- parsed from the NVD
          // response already fetched every run. Renders only when non-empty.
          const nfixed = alert.nvd_fix_versions;
          if (!Array.isArray(nfixed) || nfixed.length === 0) return "";
          const items = nfixed.map(f => {
            const rel = f.fix_type === "up_to_and_including" ? "next release after" : "before";
            return `${escapeHtml(f.vendor || "?")} ${escapeHtml(f.product || "?")} \u2192 fixed ${rel} ${escapeHtml(f.fixed || "?")}`;
          }).join(", ");
          return `<div class="osv-fixed" title="Fixed version(s) per NVD CPE match data">Fix available (NVD): ${items}</div>`;
        })()}
        ${(() => {
          // nvd_reference_links (cycle 79, NVD references array tag-filtering)
          // gives an analyst a direct path to the vendor's own advisory or
          // patch/release-notes page, distinct from nvd_fix_versions (a parsed
          // version boundary) and from the generic "View on NVD" link (which
          // only ever points at NVD's own record, never the vendor's).
          // Zero new API calls -- parsed from the NVD response already
          // fetched every run. Renders only when non-empty.
          const refLinks = alert.nvd_reference_links;
          if (!Array.isArray(refLinks) || refLinks.length === 0) return "";
          const items = refLinks.map(r => {
            const label = (r.tags && r.tags[0]) || "Reference";
            return `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(label)}</a>`;
          }).join(" &middot; ");
          return `<div class="osv-fixed" title="Vendor advisory / patch / release notes links per NVD">Vendor links: ${items}</div>`;
        })()}
        ${copyMdBtn}
        ${copySuppressBtn}
        ${reviewedBtn}
      </div>
    </div>
  `;
}

// Formats an alert as a Markdown block for pasting into an incident ticket,
// Slack/Teams message, or postmortem doc -- pulls together the fields a
// triage analyst would otherwise have to copy one-by-one from the card.
function alertToMarkdown(alert) {
  const lines = [];
  lines.push(`### ${alert.cve_id}`);
  lines.push("");
  if (alert.description) lines.push(alert.description);
  lines.push("");
  lines.push(`- **CVSS:** ${fmtScore(alert.cvss_score)}${cvssVersionText(alert.cvss_version) ? ` (${cvssVersionText(alert.cvss_version)})` : ""}`);
  lines.push(`- **EPSS:** ${typeof alert.epss_score === "number" ? (alert.epss_score * 100).toFixed(1) + "%" : "n/a"}`);
  lines.push(`- **Risk score:** ${typeof alert.risk_score === "number" ? alert.risk_score.toFixed(0) : "n/a"}/100`);
  lines.push(`- **KEV:** ${alert.kev ? "Yes" + (alert.kev_ransomware_use ? " (known ransomware use)" : "") : "No"}`);
  if (alert.kev && alert.kev_date_added) lines.push(`- **KEV added:** ${alert.kev_date_added}`);
  if (alert.kev && alert.kev_due_date) lines.push(`- **KEV remediation due:** ${alert.kev_due_date}`);
  if (alert.kev && alert.kev_required_action) lines.push(`- **Required action:** ${alert.kev_required_action}`);
  lines.push(`- **Source:** ${alert.source || "unknown"}`);
  lines.push(`- **Affected:** ${(alert.affected || []).join(", ") || "n/a"}`);
  if ((alert.cwe_ids || []).length) lines.push(`- **Weakness (CWE):** ${alert.cwe_ids.join(", ")}`);
  lines.push(`- **Published:** ${fmtDate(alert.published)}`);
  lines.push(`- **First seen (tracked):** ${fmtDate(alert.first_seen)}`);
  lines.push(`- **NVD:** https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}`);
  if (alert.dependabot_url) lines.push(`- **Dependabot alert:** ${alert.dependabot_url}`);
  if (Array.isArray(alert.osv_fixed_versions) && alert.osv_fixed_versions.length) {
    lines.push(`- **Fix available (OSV.dev):** ${alert.osv_fixed_versions.map(f => `${f.package || "?"}${f.ecosystem ? ` (${f.ecosystem})` : ""} -> ${f.fixed || "?"}`).join(", ")}`);
  }
  if (Array.isArray(alert.nvd_fix_versions) && alert.nvd_fix_versions.length) {
    lines.push(`- **Fix available (NVD):** ${alert.nvd_fix_versions.map(f => `${f.vendor || "?"} ${f.product || "?"} -> fixed ${f.fix_type === "up_to_and_including" ? "next release after" : "before"} ${f.fixed || "?"}`).join(", ")}`);
  }
  if (alert.osv_id) lines.push(`- **OSV.dev:** https://osv.dev/vulnerability/${encodeURIComponent(alert.osv_id)}`);
  if (Array.isArray(alert.nvd_reference_links) && alert.nvd_reference_links.length) {
    lines.push(`- **Vendor links:** ${alert.nvd_reference_links.map(r => `[${(r.tags && r.tags[0]) || "Reference"}](${r.url})`).join(", ")}`);
  }
  return lines.join("\n");
}

// config/suppressions.yaml (accepted-risk list, see aggregate.py load_suppressions())
// has existed since the earliest cycles and is a genuinely powerful pipeline feature --
// exclude a reviewed-false-positive/accepted-risk CVE from future alert.json output and
// GitHub Issue creation, with a mandatory reason and an auto-expiring date so it
// resurfaces for re-review rather than becoming a silent permanent blind spot. But there
// was zero frontend affordance to actually use it: an analyst who decided "not
// applicable, we don't run this" had to hand-type the exact YAML schema (cve_id, reason,
// expires) from memory/docs into the file themselves, a real friction point that likely
// meant the feature was rarely used despite already being fully wired end-to-end in the
// pipeline. Generates a ready-to-paste YAML list-item block with the CVE ID pre-filled,
// a placeholder reason the analyst must edit, and expires defaulted to exactly one year
// from today (keeps every suppression time-boxed by default, matching the file's own
// documented convention -- never silently permanent).
function suppressionSnippet(alert) {
  const expires = new Date();
  expires.setFullYear(expires.getFullYear() + 1);
  const expiresStr = expires.toISOString().slice(0, 10);
  const reasonPlaceholder = "REPLACE ME: why this does not apply (verified by <name>, <date>)";
  return `- cve_id: "${alert.cve_id}"\n  reason: "${reasonPlaceholder}"\n  expires: "${expiresStr}"`;
}

function matchesSource(alert, filter) {
  if (filter === "all") return true;
  const src = alert.source || "";
  return src === filter || src.startsWith(filter + ":");
}

// --- Dependency-scoped filtering (client-side only; nothing is uploaded) ---
let dependencyPackageNames = null; // null = no filter active; Set of lowercase names otherwise

function parsePackageJson(text) {
  const names = new Set();
  try {
    const obj = JSON.parse(text);
    for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
      if (obj[section]) {
        for (const name of Object.keys(obj[section])) names.add(name.toLowerCase());
      }
    }
  } catch (e) {
    throw new Error("Could not parse as package.json: " + e.message);
  }
  return names;
}

function parseRequirementsTxt(text) {
  const names = new Set();
  for (let line of text.split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    // Strip version specifiers / extras / environment markers: name==1.0, name>=1.0, name[extra], name; marker
    const m = line.match(/^([A-Za-z0-9._-]+)/);
    if (m) names.add(m[1].toLowerCase());
  }
  return names;
}

function detectAndParseDependencyFile(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return parsePackageJson(trimmed);
  return parseRequirementsTxt(trimmed);
}

function alertMatchesPackages(alert, packageNames) {
  const haystack = (alert.affected || []).join(" ").toLowerCase() + " " + (alert.description || "").toLowerCase();
  for (const pkg of packageNames) {
    if (pkg && haystack.includes(pkg)) return true;
  }
  return false;
}

function setupDependencyFilter() {
  const fileInput = document.getElementById("dep-file-input");
  const textInput = document.getElementById("dep-text-input");
  const applyBtn = document.getElementById("dep-apply-btn");
  const clearBtn = document.getElementById("dep-clear-btn");
  const statusEl = document.getElementById("dep-status");
  if (!fileInput || !applyBtn) return;

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    textInput.value = await file.text();
  });

  applyBtn.addEventListener("click", () => {
    const text = textInput.value;
    if (!text.trim()) {
      statusEl.textContent = "Paste or choose a package.json / requirements.txt first.";
      return;
    }
    try {
      const names = detectAndParseDependencyFile(text);
      if (names.size === 0) {
        statusEl.textContent = "No package names found in that file.";
        return;
      }
      dependencyPackageNames = names;
      statusEl.textContent = `Filtering to ${names.size} package(s): ${[...names].slice(0, 8).join(", ")}${names.size > 8 ? "..." : ""}`;
      applyFiltersAndRender();
    } catch (e) {
      statusEl.textContent = "Error: " + e.message;
    }
  });

  clearBtn.addEventListener("click", () => {
    dependencyPackageNames = null;
    textInput.value = "";
    fileInput.value = "";
    statusEl.textContent = "";
    applyFiltersAndRender();
  });
}

// --- Shareable filter state via URL query params (read on load, written on
// every filter change with replaceState so it never spams browser history). ---
function readFiltersFromURL() {
  const params = new URLSearchParams(location.search);
  const searchEl = document.getElementById("search");
  const kevEl = document.getElementById("kev-filter");
  const severityEl = document.getElementById("severity-filter");
  const sourceEl = document.getElementById("source-filter");
  const sortEl = document.getElementById("sort-by");
  const minRiskEl = document.getElementById("min-risk");
  const minEpssEl = document.getElementById("min-epss");
  if (params.has("q")) searchEl.value = params.get("q");
  // Setting .value to an option that doesn't exist on a <select> is a no-op
  // in every browser, so an unrecognized/stale param value safely falls back
  // to whatever the element's default selection already was.
  if (params.has("kev")) kevEl.value = params.get("kev");
  if (params.has("sev") && severityEl) severityEl.value = params.get("sev");
  if (params.has("source")) sourceEl.value = params.get("source");
  if (params.has("sort")) sortEl.value = params.get("sort");
  if (params.has("minrisk") && minRiskEl) {
    // Ignore malformed/non-numeric values rather than propagating NaN into
    // the input, mirroring the <select> no-op-on-unrecognized-value pattern.
    const n = Number(params.get("minrisk"));
    if (Number.isFinite(n)) minRiskEl.value = n;
  }
  if (params.has("minepss") && minEpssEl) {
    const n = Number(params.get("minepss"));
    if (Number.isFinite(n)) minEpssEl.value = n;
  }
  const hideReviewedEl = document.getElementById("hide-reviewed");
  if (params.has("hidereviewed") && hideReviewedEl) {
    hideReviewedEl.checked = params.get("hidereviewed") === "1";
  }
  const newOnlyEl = document.getElementById("new-only");
  if (params.has("newonly") && newOnlyEl) {
    newOnlyEl.checked = params.get("newonly") === "1";
  }
  const hideRejectedEl = document.getElementById("hide-rejected");
  if (params.has("hiderejected") && hideRejectedEl) {
    hideRejectedEl.checked = params.get("hiderejected") === "1";
  }
  const hasFixOnlyEl = document.getElementById("has-fix-only");
  if (params.has("hasfixonly") && hasFixOnlyEl) {
    hasFixOnlyEl.checked = params.get("hasfixonly") === "1";
  }
}

// Whether an alert has a known fix-version signal from either enrichment
// source: cycle 61's OSV.dev osv_fixed_versions (open-source package
// ecosystems) or cycle 78's NVD-configurations-derived nvd_fix_versions
// (vendor/OS/hardware CVEs). Shared by the "Fix available only" filter
// below and kept in sync with the two "Fix available" card-render checks
// this mirrors (see renderCard's osv_fixed_versions/nvd_fix_versions
// handling above).
function hasFixAvailable(alert) {
  return (
    (Array.isArray(alert.osv_fixed_versions) && alert.osv_fixed_versions.length > 0) ||
    (Array.isArray(alert.nvd_fix_versions) && alert.nvd_fix_versions.length > 0)
  );
}

function updateURLFromFilters(search, kevFilter, severityFilter, sourceFilter, sortBy, minRisk, minEpss, hideReviewed, newOnly, hideRejected, hasFixOnly) {
  const params = new URLSearchParams();
  if (search) params.set("q", search);
  if (kevFilter && kevFilter !== "all") params.set("kev", kevFilter);
  if (severityFilter && severityFilter !== "all") params.set("sev", severityFilter);
  if (sourceFilter && sourceFilter !== "all") params.set("source", sourceFilter);
  if (sortBy && sortBy !== "risk_score") params.set("sort", sortBy);
  if (typeof minRisk === "number" && !Number.isNaN(minRisk)) params.set("minrisk", String(minRisk));
  if (typeof minEpss === "number" && !Number.isNaN(minEpss)) params.set("minepss", String(minEpss));
  if (hideReviewed) params.set("hidereviewed", "1");
  if (newOnly) params.set("newonly", "1");
  if (hideRejected) params.set("hiderejected", "1");
  if (hasFixOnly) params.set("hasfixonly", "1");
  const qs = params.toString();
  const newUrl = location.pathname + (qs ? "?" + qs : "") + location.hash;
  history.replaceState(null, "", newUrl);
}

function applyFiltersAndRender() {
  const search = document.getElementById("search").value.trim().toLowerCase();
  const kevFilter = document.getElementById("kev-filter").value;
  const severityFilter = document.getElementById("severity-filter").value;
  const sourceFilter = document.getElementById("source-filter").value;
  const sortBy = document.getElementById("sort-by").value;
  const minRiskRaw = document.getElementById("min-risk").value;
  const minRisk = minRiskRaw === "" ? null : Number(minRiskRaw);
  const minEpssRaw = document.getElementById("min-epss").value;
  const minEpss = minEpssRaw === "" ? null : Number(minEpssRaw);
  const hideReviewed = document.getElementById("hide-reviewed").checked;
  const newOnly = document.getElementById("new-only").checked;
  const hideRejected = document.getElementById("hide-rejected").checked;
  const hasFixOnly = document.getElementById("has-fix-only").checked;
  updateURLFromFilters(search, kevFilter, severityFilter, sourceFilter, sortBy, minRisk, minEpss, hideReviewed, newOnly, hideRejected, hasFixOnly);

  let filtered = allAlerts.filter((a) => {
    if (hideReviewed && reviewedCves.has(a.cve_id)) return false;
    if (newOnly && !isNewWithin24h(a)) return false;
    if (hideRejected && a.vuln_status === "Rejected") return false;
    if (hasFixOnly && !hasFixAvailable(a)) return false;
    if (kevFilter === "kev" && !a.kev) return false;
    if (kevFilter === "non-kev" && a.kev) return false;
    if (kevFilter === "overdue" && !isOverdue(a)) return false;
    if (kevFilter === "due-soon") {
      const d = daysUntilDue(a);
      if (typeof d !== "number" || d < 0 || d > 7) return false;
    }
    if (kevFilter === "ransomware" && !a.kev_ransomware_use) return false;
    if (severityFilter !== "all" && severityClass(a.cvss_score) !== severityFilter) return false;
    if (!matchesSource(a, sourceFilter)) return false;
    if (typeof minRisk === "number" && !Number.isNaN(minRisk)) {
      if (typeof a.risk_score !== "number" || a.risk_score < minRisk) return false;
    }
    if (typeof minEpss === "number" && !Number.isNaN(minEpss)) {
      // epss_score is stored as a 0-1 probability; the input is a 0-100 percentage.
      if (typeof a.epss_score !== "number" || a.epss_score * 100 < minEpss) return false;
    }
    if (dependencyPackageNames && !alertMatchesPackages(a, dependencyPackageNames)) return false;
    if (search) {
      const haystack = [
        a.cve_id,
        a.description,
        ...(a.affected || []),
        ...(a.matched_keywords || []),
        ...(a.cwe_ids || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    if (sortBy === "cvss_score" || sortBy === "epss_score" || sortBy === "risk_score") {
      return (b[sortBy] ?? -1) - (a[sortBy] ?? -1);
    }
    if (sortBy === "risk_delta") {
      // Biggest risk-score *increase* since last refresh first. Entries with
      // no prior score recorded yet (brand new, or never refreshed) sort to
      // the end -- they have no delta, not "most urgent by delta".
      const da = (typeof a.risk_score === "number" && typeof a.risk_score_prev === "number")
        ? a.risk_score - a.risk_score_prev : null;
      const db = (typeof b.risk_score === "number" && typeof b.risk_score_prev === "number")
        ? b.risk_score - b.risk_score_prev : null;
      if (da === null && db === null) return 0;
      if (da === null) return 1;
      if (db === null) return -1;
      return db - da;
    }
    if (sortBy === "cve_id") {
      return (a.cve_id || "").localeCompare(b.cve_id || "");
    }
    if (sortBy === "kev_due_date") {
      // Soonest deadline first. Entries with no due date (non-KEV, or KEV
      // with no published due date) are not "most urgent" -- they have no
      // deadline at all -- so they sort to the end, not the front, avoiding
      // the classic bug where empty-string/undefined compares as "smallest".
      const ad = a.kev_due_date, bd = b.kev_due_date;
      if (!ad && !bd) return 0;
      if (!ad) return 1;
      if (!bd) return -1;
      return ad.localeCompare(bd);
    }
    if (sortBy === "first_seen_oldest") {
      // Oldest-ingested first -- surfaces long-lingering un-triaged alerts
      // that keep getting pushed off-screen by the default newest-first
      // sort, so a backlog of stale un-actioned alerts doesn't silently
      // hide at the bottom of the list forever.
      return (a.first_seen || "").localeCompare(b.first_seen || "");
    }
    if (sortBy === "published") {
      // Distinct from first_seen (when the pipeline ingested it): this is
      // the actual vendor/NVD publish date, which can differ from first_seen
      // by years for older CVEs that only start matching the watchlist
      // later. Missing values sort to the end, not treated as newest.
      const ap = a.published || "", bp = b.published || "";
      if (!ap && !bp) return 0;
      if (!ap) return 1;
      if (!bp) return -1;
      return bp.localeCompare(ap);
    }
    // default: first_seen, newest first
    return (b.first_seen || "").localeCompare(a.first_seen || "");
  });

  const grid = document.getElementById("card-grid");
  const emptyState = document.getElementById("empty-state");
  document.getElementById("result-count").textContent = `${filtered.length} of ${allAlerts.length} alerts`;
  renderReviewedProgress();

  if (filtered.length === 0) {
    grid.innerHTML = "";
    emptyState.hidden = false;
  } else {
    emptyState.hidden = true;
    grid.innerHTML = filtered.map(renderCard).join("");
  }
  renderTable(filtered);

  window.__lastFiltered = filtered;
}

// Dense sortable table view: an alternative to the card grid for triaging
// large alert counts (hundreds of cards requires a lot of scrolling; a table
// lets an analyst scan CVE/CVSS/EPSS/Risk/KEV/Source/First-seen columns at a
// glance, side by side, sortable by click). Shares the exact same filtered
// dataset as the card grid (computed once in applyFiltersAndRender) so both
// views always agree; only one is visible at a time via #view-toggle.
function renderTable(filtered) {
  const tbody = document.getElementById("alerts-table-body");
  if (!tbody) return;
  tbody.innerHTML = filtered
    .map((a) => {
      // Ransomware indicator in table view's KEV column (cycle 93): card
      // view has shown a distinct red "RANSOMWARE" badge (from
      // kev_ransomware_use -- CISA KEV's flag for known ransomware
      // campaign use, the highest-priority triage signal on the board)
      // alongside the KEV/OVERDUE/DUE SOON badges since early cycles, and
      // it already drives a dedicated "ransomware" KEV-filter option and
      // the stats-bar ransomware count -- but the dense table view (cycle
      // 76) collapsed every KEV entry into a plain "KEV"/"OVERDUE"/"DUE
      // SOON" string with zero ransomware signal, so an analyst
      // bulk-scanning table view (without the ransomware filter active)
      // had no way to see which rows were known-ransomware without
      // switching back to card view. Reuses the exact same
      // kev_ransomware_use field unchanged, appended as a " (RANSOMWARE)"
      // suffix so it composes with any of the existing three KEV states.
      const kevLabel = a.kev
        ? (isOverdue(a) ? "OVERDUE" : (typeof daysUntilDue(a) === "number" && daysUntilDue(a) <= 7 ? "DUE SOON" : "KEV")) +
          (a.kev_ransomware_use ? " (RANSOMWARE)" : "")
        : "-";
      const products = (a.affected || []).slice(0, 3).join(", ") || "-";
      // "Fix" column (cycle 83): the card view has shown "Fix available: ..."
      // lines (osv_fixed_versions since cycle 61, nvd_fix_versions since
      // cycle 78) and cycle 82 added a board-wide "Fix available only"
      // filter built on the same two fields via hasFixAvailable() -- but
      // the dense table view (cycle 76) never surfaced this signal at all,
      // so switching to table view for bulk scanning silently dropped a
      // triage-relevant column present everywhere else. Reuses the exact
      // same hasFixAvailable() predicate the filter checkbox already uses,
      // so table and card/filter views can never disagree on which alerts
      // count as having a fix.
      const fixLabel = hasFixAvailable(a) ? "Yes" : "-";
      // Severity color-coding on the CVSS cell (cycle 87): card view has
      // shown a colored severity badge (critical/high/medium/low, via the
      // existing .badge.<class> CSS rules) since early cycles, but the
      // dense table view (cycle 76) rendered the raw CVSS number in plain
      // text with zero color signal -- a real gap for bulk/table-mode
      // triage, where scanning for red/orange rows is far faster than
      // reading every numeric score. Reuses the exact same severityClass()
      // classification and .badge.<class> color palette already defined
      // for cards, so table and card views can never disagree on what
      // counts as "critical" vs "high" etc.
      const cvssSevClass = severityClass(a.cvss_score);
      // REJECTED-by-NVD indicator in table view (cycle 88): card view has
      // shown a "REJECTED BY NVD" badge since cycle 77 (vuln_status ==
      // "Rejected" means NVD has withdrawn the CVE ID -- duplicate,
      // disputed, or withdrawn by the CNA -- so its CVSS/EPSS/risk scores
      // may be stale/meaningless), and cycle 81 added a board-wide "Hide
      // rejected CVEs" filter built on the same field -- but the dense
      // table view (cycle 76) never surfaced this signal at all, so an
      // analyst bulk-scanning table view (with the hide-rejected filter
      // off) had zero visual cue that a row's scores might be stale.
      const isRejected = a.vuln_status === "Rejected";
      // Risk-score color-coding on the Risk cell (cycle 89): cycle 87 added
      // the same CVSS-column color treatment reusing severityClass(), but
      // the composite Risk column (the board's primary sort/triage metric,
      // combining CVSS+EPSS+KEV) was left as plain uncolored text -- the
      // single most important number on the row had the least visual
      // salience. Reuses the exact same riskClass() classification (and
      // the risk-bar-fill's own critical/high/medium/low thresholds) card
      // view has used since early cycles, so table and card views can
      // never disagree on what counts as a "critical" risk score.
      const riskCls = riskClass(a.risk_score);
      // Watchlist keyword-match column in table view (cycle 90): card view
      // has shown a green "Watchlist match" badge per matched keyword since
      // cycle 8 (a.matched_keywords -- the watchlist.yaml term(s) that
      // caused a CVE to surface), but the dense table view (cycle 76) never
      // surfaced this signal at all -- an analyst bulk-scanning table view
      // had no way to tell which rows were watchlist-driven vs. generic
      // source sweep results without switching back to card view. Reuses
      // the exact same matched_keywords field unchanged (168/603 alerts
      // currently populated), joined with ", " for a compact single cell.
      const watchlistLabel = Array.isArray(a.matched_keywords) && a.matched_keywords.length
        ? a.matched_keywords.map((k) => escapeHtml(k)).join(", ")
        : "-";
      // CWE (Common Weakness Enumeration) column in table view (cycle 94):
      // card view has shown a "Weakness: CWE-XXX" row (clickable badges
      // linking to cwe.mitre.org) since early cycles via alert.cwe_ids, but
      // the dense table view (cycle 76) never surfaced this signal at all --
      // an analyst bulk-scanning table view had no way to see the underlying
      // vulnerability class (e.g. CWE-79 XSS, CWE-89 SQLi) without switching
      // back to card view. Reuses the exact same cwe_ids field unchanged
      // (already used by card view, CSV export, and search), joined with
      // ", " for a compact single cell -- no new CSS/logic to disagree with
      // card view on content, though table cells are plain text (no links)
      // to keep the dense view lightweight.
      const cweLabel = Array.isArray(a.cwe_ids) && a.cwe_ids.length
        ? a.cwe_ids.map((c) => {
            const name = cweName(c);
            return name
              ? `<span title="${escapeHtml(c)}: ${escapeHtml(name)}">${escapeHtml(c)}</span>`
              : escapeHtml(c);
          }).join(", ")
        : "-";
      // Risk-score trend delta in table view (cycle 91): card view has shown
      // a risk-delta badge (up/down arrow + point change since the last
      // refresh, via .risk-delta/.risk-up/.risk-down CSS) since it was added
      // for score-refresh tracking, but the dense table view (cycle 76) never
      // surfaced this signal -- an analyst bulk-scanning table view had no
      // way to see which rows just got materially riskier/safer without
      // switching back to card view. Reuses the exact same computation card
      // view uses (risk_score - risk_score_prev) and the exact same CSS
      // classes, so table and card views can never disagree on direction.
      const tableRiskDelta = (typeof a.risk_score === "number" && typeof a.risk_score_prev === "number")
        ? Math.round(a.risk_score - a.risk_score_prev)
        : null;
      const tableRiskDeltaHtml = tableRiskDelta && tableRiskDelta !== 0
        ? ` <span class="risk-delta ${tableRiskDelta > 0 ? "risk-up" : "risk-down"}" title="Risk score changed from ${a.risk_score_prev.toFixed(0)} to ${a.risk_score.toFixed(0)} since the last refresh">${tableRiskDelta > 0 ? "\u25b2" : "\u25bc"}${tableRiskDelta > 0 ? "+" : ""}${tableRiskDelta}</span>`
        : "";
      // EPSS-delta indicator in table view (cycle 92): card view has shown
      // an EPSS-delta badge (up/down arrow + percentage-point change since
      // the last refresh, via .epss-delta/.risk-up/.risk-down CSS) since
      // epss_score_prev tracking was added, but the dense table view
      // (cycle 76) never surfaced it -- cycle 91 closed the identical gap
      // for the Risk column but flagged this as the direct follow-up.
      // Reuses the exact same computation and CSS classes card view uses
      // (epss_score - epss_score_prev, >= 0.0005 threshold to avoid
      // noise), so table and card views can never disagree on direction.
      const tableEpssDelta = (typeof a.epss_score === "number" && typeof a.epss_score_prev === "number")
        ? a.epss_score - a.epss_score_prev
        : null;
      const tableEpssDeltaHtml = tableEpssDelta && Math.abs(tableEpssDelta) >= 0.0005
        ? ` <span class="epss-delta ${tableEpssDelta > 0 ? "risk-up" : "risk-down"}" title="EPSS changed from ${(a.epss_score_prev * 100).toFixed(1)}% to ${(a.epss_score * 100).toFixed(1)}% since the last refresh">${tableEpssDelta > 0 ? "\u25b2" : "\u25bc"}${tableEpssDelta > 0 ? "+" : ""}${(tableEpssDelta * 100).toFixed(1)}pp</span>`
        : "";
      // Attack Vector column in table view (cycle 95): card view has shown
      // an "exploit chip" (attack vector -- Network/Adjacent/Local/Physical
      // -- plus a "no auth/interaction" flag when privileges_required and
      // user_interaction are both NONE) via alert.cvss_vector_components
      // since cycles 30/31, a genuinely high-value triage signal (a
      // network-exploitable, no-auth, no-interaction bug is far more
      // urgent than an identical CVSS score requiring local access), but
      // the dense table view (cycle 76) never surfaced it -- an analyst
      // bulk-scanning table view had no way to see exploitability
      // preconditions without switching back to card view. Reuses the
      // exact same exploitLabels map and cvss_vector_components field
      // unchanged, so table and card views can never disagree.
      const tvc = a.cvss_vector_components;
      const tableExploitLabels = { NETWORK: "Network", ADJACENT_NETWORK: "Adjacent", LOCAL: "Local", PHYSICAL: "Physical" };
      const attackVectorLabel = tvc && tvc.attack_vector
        ? escapeHtml(tableExploitLabels[tvc.attack_vector] || tvc.attack_vector) +
          (tvc.privileges_required === "NONE" && tvc.user_interaction === "NONE" ? " (no auth/interaction)" : "")
        : "-";
      // Reviewed toggle in table view (cycle 96): card view has offered a
      // "Mark reviewed" button (backed by the existing reviewedCves
      // Set/localStorage state, see toggleReviewed()) since it was added
      // for local-only triage tracking, and the stats bar already shows a
      // reviewed-progress count reading the same state -- but the dense
      // table view (cycle 76) had no way to mark or even see an alert's
      // reviewed status without switching back to card view, which
      // defeats the point of bulk-scanning many rows at once. Reuses the
      // exact same reviewedCves.has() check and a dedicated
      // .table-review-toggle-btn delegated click handler (below) that
      // calls the same toggleReviewed() used by card view, so table and
      // card views can never disagree on reviewed state.
      const isRowReviewed = reviewedCves.has(a.cve_id);
      const reviewedCellHtml = `<button class="table-review-toggle-btn${isRowReviewed ? " reviewed" : ""}" type="button" data-cve="${escapeHtml(a.cve_id || "")}" title="${isRowReviewed ? "Marked reviewed -- click to unmark" : "Mark this alert as reviewed"}" aria-pressed="${isRowReviewed ? "true" : "false"}">${isRowReviewed ? "\u2713" : "Mark"}</button>`;
      // Revised-since-publication indicator in table view (cycle 98): card
      // view has shown a "Revised: <date>" badge since nvd_last_modified
      // tracking was added -- rendered only when NVD's last-modified date
      // differs from the published date (i.e. NVD has actually revised the
      // record: rescored CVSS, corrected CWE/description, etc. post
      // publication) -- but the dense table view (cycle 76) never surfaced
      // this signal at all, so an analyst bulk-scanning table view had no
      // way to tell a freshly-revised record (whose CVSS/CWE/description
      // may have just changed) from a stable one without switching back to
      // card view. Reuses the exact same day-string comparison card view
      // uses (nvd_last_modified vs published, compared at calendar-day
      // granularity) so table and card views can never disagree on which
      // rows count as "revised". Rendered as a small superscript-style
      // marker next to the CVE ID (not a full column) to keep the dense
      // table lightweight, per the same "compact cell, tooltip for detail"
      // convention already used for CWE and KEV columns.
      const isRevised = (() => {
        if (!a.nvd_last_modified || !a.published) return false;
        return String(a.nvd_last_modified).slice(0, 10) !== String(a.published).slice(0, 10);
      })();
      const revisedMarkHtml = isRevised
        ? ` <span class="table-revised-mark" title="NVD has revised this record since initial publication (rescored CVSS, corrected CWE/description, etc.) -- last modified ${escapeHtml(fmtDate(a.nvd_last_modified))}">\u270e</span>`
        : "";
      return `<tr data-cve="${escapeHtml(a.cve_id || "")}"${isRejected ? ' class="table-row-rejected"' : ""}>
        <td><a href="#alert-${escapeHtml(a.cve_id || "")}" class="table-cve-link">${escapeHtml(a.cve_id || "")}</a>${isRejected ? ' <span class="table-rejected-tag" title="NVD has withdrawn this CVE ID -- scores may be stale">REJECTED</span>' : ""}${revisedMarkHtml}</td>
        <td class="${cvssSevClass ? `table-cvss-${cvssSevClass}` : ""}">${fmtScore(a.cvss_score)}</td>
        <td>${typeof a.epss_score === "number" ? (a.epss_score * 100).toFixed(1) + "%" : "-"}${tableEpssDeltaHtml}</td>
        <td class="${riskCls ? `table-risk-${riskCls}` : ""}">${fmtScore(a.risk_score, 0)}${tableRiskDeltaHtml}</td>
        <td>${escapeHtml(kevLabel)}</td>
        <td>${escapeHtml(a.source || "-")}</td>
        <td>${fmtDate(a.first_seen)}</td>
        <td>${escapeHtml(products)}</td>
        <td class="${hasFixAvailable(a) ? "table-fix-yes" : ""}">${escapeHtml(fixLabel)}</td>
        <td class="table-watchlist-cell">${watchlistLabel}</td>
        <td class="table-cwe-cell">${cweLabel}</td>
        <td>${escapeHtml(attackVectorLabel)}</td>
        <td>${reviewedCellHtml}</td>
      </tr>`;
    })
    .join("");
}

// Click delegation for the Reviewed toggle button in table view (cycle 96):
// attached to the table body (not #card-grid, which only covers card view's
// own click delegation) so the mark/unmark action works regardless of which
// view is currently visible. Reuses the exact same toggleReviewed() state
// mutation card view's own handler uses, so table and card views can never
// disagree on reviewed state; re-renders via applyFiltersAndRender() since
// renderTable() is already a cheap full-rebuild with no per-row
// breakdown/expand state to preserve (unlike renderCard()'s single-card
// in-place patch).
document.getElementById("alerts-table-body")?.addEventListener("click", (e) => {
  const btn = e.target.closest(".table-review-toggle-btn");
  if (!btn) return;
  toggleReviewed(btn.dataset.cve);
  applyFiltersAndRender();
  renderReviewedProgress();
});

// Client-side click-to-sort on table headers -- reuses the exact same
// sort-by values already wired to #sort-by (kept in sync both ways) so
// switching to table view, sorting a column, then switching back to card
// view preserves the same order instead of resetting to the default.
document.getElementById("alerts-table")?.querySelector("thead")?.addEventListener("click", (e) => {
  const th = e.target.closest("th[data-sort]");
  if (!th) return;
  const sortBy = document.getElementById("sort-by");
  if (sortBy) {
    sortBy.value = th.dataset.sort;
    applyFiltersAndRender();
  }
});

function applyViewMode(mode) {
  const grid = document.getElementById("card-grid");
  const tableWrapper = document.getElementById("table-view-wrapper");
  const btn = document.getElementById("view-toggle");
  const isTable = mode === "table";
  if (grid) grid.hidden = isTable;
  if (tableWrapper) tableWrapper.hidden = !isTable;
  if (btn) {
    btn.textContent = isTable ? "\u25a4 Card view" : "\u2630 Table view";
    btn.setAttribute("aria-pressed", String(isTable));
  }
  try { localStorage.setItem("viewMode", mode); } catch (e) {}
}
(function initViewMode() {
  let saved = "cards";
  try { saved = localStorage.getItem("viewMode") || "cards"; } catch (e) {}
  applyViewMode(saved);
})();
document.getElementById("view-toggle")?.addEventListener("click", () => {
  const grid = document.getElementById("card-grid");
  const currentlyTable = grid ? grid.hidden : false;
  applyViewMode(currentlyTable ? "cards" : "table");
});

function toCsvRow(fields) {
  return fields
    .map((f) => {
      const s = f === null || f === undefined ? "" : String(f);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    })
    .join(",");
}

function exportCsv() {
  const rows = window.__lastFiltered || allAlerts;
  // Columns intentionally mirror every field already rendered on the card UI --
  // cvss_vector_components (cycle 30/31 exploitability chip), kev_required_action
  // (cycle 27), and kev_notes (cycle 28) were added to the schema and frontend
  // display but never carried through to CSV export, so a viewer exporting for
  // offline reporting/compliance tracking silently lost that data even though
  // it's visible on-screen. Purely additive columns reading existing fields --
  // no new API calls, no schema changes, no risk to existing columns/consumers.
  //
  // Cycle 62: osv_id/osv_fixed_versions (cycle 61's OSV.dev enrichment, already
  // rendered on-card and already included in exportJson()'s raw objects and
  // alertToMarkdown()'s single-alert export) had the exact same gap this
  // comment already documents for cvss_vector_components/kev_required_action/
  // kev_notes -- visible on screen and in the other two export formats, but
  // silently dropped from CSV. Added as two more purely-additive columns:
  // osv_id as-is, osv_fixed_versions flattened to "pkg (ecosystem) -> version"
  // entries joined by "; " (same join convention as affected/cwe_ids/
  // matched_keywords above) so it survives a spreadsheet's single-cell-per-
  // field model without losing the package/ecosystem/version structure.
  // Cycle 63: kev_date_added (date a CVE was added to the CISA KEV catalog)
  // has been populated in the schema since the earliest cycles and is shown
  // nowhere on the dashboard at all -- kev_due_date (the remediation deadline)
  // was always rendered/exported, but the catalog-addition date itself (useful
  // for gauging how long a KEV entry has been known/tracked, distinct from the
  // BOD 22-01 deadline) was silently missing from the card UI, Markdown export,
  // and CSV export. Added as a new "KEV added" line on-card (next to CVSS/EPSS),
  // in alertToMarkdown(), and as a new CSV column here.
  // Cycle 85: dependabot_url (already rendered on-card as "View alert" and in
  // alertToMarkdown() as "Dependabot alert: ..." since early cycles) had the
  // exact same card+Markdown-but-not-CSV gap that cycle 79's
  // nvd_reference_links (closed in cycle 84) and osv_id (closed in cycle 62)
  // had before it -- an analyst exporting Dependabot-sourced alerts to CSV
  // for offline triage silently lost the direct link back to the
  // originating GitHub Dependabot alert. Added as-is (already a plain URL
  // string, no flattening needed); empty for non-Dependabot sources.
  // Cycle 86: cvss_version (CVSS scoring rubric version -- "CVSS V31",
  // "CVSS V40", "CVSS V30", or GHSA's own "GHSA CVSS" label) has been
  // extracted and stored on every alert since the earliest cycles but was
  // never surfaced anywhere: not on-card, not in alertToMarkdown(), not in
  // CSV. This is a genuine data-completeness gap, not cosmetic -- NVD's
  // CVSS v4.0 (29 of 603 current alerts) uses a materially different metric
  // set/weighting than v3.x (573 alerts) or v3.0 (1 alert), so two cards
  // both reading "CVSS 8.8" may not be directly comparable if scored on
  // different rubrics, and an analyst had no way to know without digging
  // into the raw NVD record. Added a compact "vX.Y" label next to the CVSS
  // score on-card (new cvssVersionText()/cvssVersionLabel() helpers,
  // normalizing "CVSS V31" -> "v3.1"), a "(vX.Y)" suffix in
  // alertToMarkdown(), and a new cvss_version CSV column here.
  const header = ["cve_id", "risk_score", "risk_score_prev", "cvss_score", "cvss_version", "epss_score", "epss_score_prev", "epss_percentile", "kev", "kev_date_added", "kev_due_date",
    "kev_ransomware_use", "kev_required_action", "kev_notes", "attack_vector", "attack_complexity",
    "privileges_required", "user_interaction", "source", "affected", "cwe_ids", "matched_keywords", "published",
    "nvd_last_modified", "vuln_status", "first_seen", "osv_id", "osv_fixed_versions", "nvd_fix_versions", "nvd_reference_links", "dependabot_url", "description"];
  const lines = [toCsvRow(header)];
  for (const a of rows) {
    const vc = a.cvss_vector_components || {};
    const osvFixed = (a.osv_fixed_versions || [])
      .map((f) => `${f.package || "?"}${f.ecosystem ? ` (${f.ecosystem})` : ""} -> ${f.fixed || "?"}`)
      .join("; ");
    // nvd_fix_versions (cycle 78): same flatten-to-string convention as
    // osv_fixed_versions above, for CSV's single-cell-per-field model.
    const nvdFixed = (a.nvd_fix_versions || [])
      .map((f) => `${f.vendor || "?"} ${f.product || "?"} -> fixed ${f.fix_type === "up_to_and_including" ? "next release after" : "before"} ${f.fixed || "?"}`)
      .join("; ");
    // nvd_reference_links (cycle 79): already rendered on cards and in the
    // Markdown export (alertToMarkdown) but was missing from CSV export --
    // this closes that gap using the same flatten-to-string convention.
    const refLinksFlat = (a.nvd_reference_links || [])
      .map((r) => `${(r.tags && r.tags[0]) || "Reference"}: ${r.url}`)
      .join("; ");
    lines.push(toCsvRow([
      a.cve_id, a.risk_score, a.risk_score_prev, a.cvss_score, a.cvss_version, a.epss_score, a.epss_score_prev, a.epss_percentile, a.kev, a.kev_date_added, a.kev_due_date,
      a.kev_ransomware_use, a.kev_required_action, a.kev_notes, vc.attack_vector, vc.attack_complexity,
      vc.privileges_required, vc.user_interaction, a.source, (a.affected || []).join("; "),
      (a.cwe_ids || []).join("; "), (a.matched_keywords || []).join("; "), a.published, a.nvd_last_modified,
      a.vuln_status, a.first_seen, a.osv_id, osvFixed, nvdFixed, refLinksFlat, a.dependabot_url, a.description,
    ]));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnerability-alerts-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

function exportMarkdownReport() {
  // Cycle 51 added alertToMarkdown() for a single-alert detail block (pasting one
  // CVE into an incident ticket), and cycles 32/34/37 added CSV/JSON bulk export
  // for spreadsheet/scripting consumers -- but there was no bulk, human-readable
  // Markdown summary of the *currently filtered view* itself, which is what a
  // security lead actually wants to paste into a weekly status update, a GitHub
  // issue, or a Slack/Teams channel post ("here's this week's KEV-overdue list").
  // Produces a Markdown table (one row per alert: CVE, risk score, CVSS, EPSS,
  // KEV status, affected, source) plus a one-line generated-at/count header --
  // reuses only fields already rendered on-screen, so it's a pure additive
  // client-side reduction of window.__lastFiltered with zero new API calls and
  // zero backend/schema changes.
  const rows = window.__lastFiltered || allAlerts;
  const lines = [];
  lines.push(`# Vulnerability alert report`);
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()} -- ${rows.length} alert(s)`);
  lines.push("");
  lines.push("| CVE | Risk | CVSS | EPSS | KEV | Affected | Source |");
  lines.push("|---|---|---|---|---|---|---|");
  for (const a of rows) {
    const risk = typeof a.risk_score === "number" ? a.risk_score.toFixed(0) : "n/a";
    const cvss = fmtScore(a.cvss_score);
    const epss = typeof a.epss_score === "number" ? (a.epss_score * 100).toFixed(1) + "%" : "n/a";
    const kev = a.kev ? (a.kev_ransomware_use ? "Yes (ransomware)" : "Yes") : "No";
    const affected = ((a.affected || []).join(", ") || "n/a").replace(/\|/g, "\\|");
    lines.push(`| ${a.cve_id} | ${risk} | ${cvss} | ${epss} | ${kev} | ${affected} | ${a.source || "unknown"} |`);
  }
  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnerability-alert-report-${new Date().toISOString().slice(0, 10)}.md`;
  link.click();
  URL.revokeObjectURL(url);
}

function exportJson() {
  // Exports the currently-filtered alert set (or all alerts if no filter has
  // run yet) as a raw JSON array -- exportCsv() (cycle 32/34) already covers a
  // flattened subset of fields for spreadsheet/compliance workflows, but a
  // viewer scripting against this data (e.g. feeding it into their own SIEM
  // ingestion, a Python/jq pipeline, or a custom alert router) currently has
  // to either scrape docs/data/alerts.json directly (which is unfiltered and
  // undocumented as a public contract) or manually reconstruct full nested
  // fields (cvss_vector_components, risk_score_breakdown, kev_* fields) lost
  // in the CSV's flattened/joined columns. This exports the exact objects
  // already backing the filtered on-screen view -- zero backend/schema
  // changes, zero new API calls, zero cost.
  const rows = window.__lastFiltered || allAlerts;
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `vulnerability-alerts-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

// Pipeline runs on a 4-hour schedule (.github/workflows/cve-alerts.yml). If the
// most recent generated_at is older than STALE_THRESHOLD_MS, something is wrong
// with the scheduled Action (broken workflow, disabled schedule, repeated
// failures) and a security lead viewing this public dashboard should know the
// data may be out of date rather than silently trusting it. Threshold is set
// generously above the 4h cadence to tolerate a single missed/delayed run
// without false-alarming on normal GitHub Actions scheduling jitter.
const STALE_THRESHOLD_MS = 20 * 60 * 60 * 1000; // 20 hours

function checkStaleness(generatedAt) {
  const banner = document.getElementById("stale-banner");
  if (!banner) return;
  if (!generatedAt) {
    banner.hidden = true;
    return;
  }
  const generated = new Date(generatedAt);
  if (isNaN(generated)) {
    banner.hidden = true;
    return;
  }
  const ageMs = Date.now() - generated.getTime();
  if (ageMs > STALE_THRESHOLD_MS) {
    const hours = Math.round(ageMs / (60 * 60 * 1000));
    banner.textContent = `\u26a0 Data may be stale: last successful update was ${hours}h ago (expected every ~4h). The aggregation pipeline may be failing -- check GitHub Actions.`;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

// stats.by_source (e.g. {"nvd": 440, "ghsa": 3, "dependabot:owner/repo": 2}) has been
// computed by the pipeline since early cycles but was never surfaced on the dashboard --
// a viewer had no quick way to see the source mix (e.g. "is this mostly NVD sweep noise,
// or are GHSA/Dependabot actually contributing?") without exporting CSV and counting
// manually. Renders a small inline pill per source, sorted by count descending. Purely
// additive: reads an existing stats.json field, no new API calls, no schema changes.
function renderSourceBreakdown(bySource) {
  const el = document.getElementById("source-breakdown");
  if (!el) return;
  if (!bySource || typeof bySource !== "object" || Object.keys(bySource).length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = Object.entries(bySource).sort((a, b) => b[1] - a[1]);
  // Cycle 66: the severity/CWE/vendor breakdown pills (cycles 33/45/58) were all
  // made clickable one-click drill-down filters, but this source-breakdown pill
  // row (cycle 15) was left as plain inert <span> text -- the only breakdown row
  // on the dashboard that doesn't match the "click a pill to filter" pattern
  // every other stats-bar breakdown uses. Only render a pill as a filter button
  // if its key corresponds to an actual <option> in #source-filter (nvd/ghsa/
  // dependabot); any other/future source key still renders as inert text so an
  // unrecognized value never produces a dead/no-op button.
  const filterableSources = new Set(["nvd", "ghsa", "dependabot"]);
  el.innerHTML = entries
    .map(([src, count]) => {
      const label = `${escapeHtml(src)}: <strong>${escapeHtml(String(count))}</strong>`;
      if (filterableSources.has(src)) {
        return `<button type="button" class="source-pill" data-source="${escapeHtml(src)}" title="Filter by source: ${escapeHtml(src)}">${label}</button>`;
      }
      return `<span class="source-pill">${label}</span>`;
    })
    .join("");
  el.querySelectorAll("button.source-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sourceEl = document.getElementById("source-filter");
      if (!sourceEl) return;
      sourceEl.value = btn.getAttribute("data-source");
      applyFiltersAndRender();
    });
  });
  el.hidden = false;
}

// compute_stats() has computed by_severity ({"critical":N,"high":N,"medium":N,
// "low":N,"unknown":N}) since early cycles for the "Critical" stat pill, but the
// medium/low/unknown bands were never surfaced anywhere on the dashboard -- a viewer
// could see the critical count but had no visibility into the overall severity mix.
// Renders one clickable pill per non-zero band (reusing the existing severity color
// convention from card borders/badges); clicking a pill sets the severity-filter
// dropdown to that band and re-applies filters, giving a one-click drill-down.
// Purely additive: reads an existing stats.json field, no new API calls.
function renderSeverityBreakdown(bySeverity) {
  const el = document.getElementById("severity-breakdown");
  if (!el) return;
  if (!bySeverity || typeof bySeverity !== "object") {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const order = ["critical", "high", "medium", "low", "unknown"];
  const entries = order
    .map((band) => [band, bySeverity[band]])
    .filter(([, count]) => typeof count === "number" && count > 0);
  if (entries.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.innerHTML = entries
    .map(([band, count]) =>
      `<button type="button" class="severity-pill ${band}" data-severity="${band}" title="Filter to ${band} severity">${band}: <strong>${count}</strong></button>`
    )
    .join("");
  el.hidden = false;
  el.querySelectorAll(".severity-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const severityEl = document.getElementById("severity-filter");
      if (!severityEl) return;
      const band = btn.getAttribute("data-severity");
      // "unknown" has no matching <option> in the existing severity-filter
      // dropdown (which only offers all/critical/high/medium/low) -- silently
      // no-op rather than setting an invalid value.
      if (band === "unknown") return;
      severityEl.value = band;
      applyFiltersAndRender();
    });
  });
}


// stats.json now includes a top-10 by_cwe map (cycle 45), the same shape and
// derivation pattern as by_severity/by_source above -- one clickable pill per
// CWE, sorted by count descending server-side. Clicking a pill sets the
// existing search box to that CWE ID and re-applies filters, reusing the
// already-CWE-aware search haystack from an earlier cycle (no new filter
// plumbing needed). Purely additive: reads an existing (now-extended)
// stats.json field, no new API calls.
function renderCweBreakdown(byCwe) {
  const el = document.getElementById("cwe-breakdown");
  if (!el) return;
  if (!byCwe || typeof byCwe !== "object" || Object.keys(byCwe).length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = Object.entries(byCwe).sort((a, b) => b[1] - a[1]);
  el.innerHTML = entries
    .map(([cwe, count]) =>
      `<button type="button" class="cwe-pill" data-cwe="${escapeHtml(cwe)}" title="Search for ${escapeHtml(cwe)}">${escapeHtml(cwe)}: <strong>${count}</strong></button>`
    )
    .join("");
  el.hidden = false;
  el.querySelectorAll(".cwe-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const searchEl = document.getElementById("search");
      if (!searchEl) return;
      searchEl.value = btn.getAttribute("data-cwe");
      applyFiltersAndRender();
    });
  });
}


// stats.json now includes a top-10 by_vendor_product map, built from the
// already-extracted `affected` field (vendor/product pairs matched via
// watchlist config or Dependabot package names) -- a distinct triage axis
// from severity/source/CWE: "which of OUR actual vendors/products dominate
// current alert volume". Mirrors the by_cwe pill pattern exactly: clicking a
// pill sets the search box to that vendor/product string and re-applies
// filters, reusing the existing affected-aware search haystack. Purely
// additive: reads an existing (now-extended) stats.json field, no new API
// calls.
function renderVendorBreakdown(byVendorProduct) {
  const el = document.getElementById("vendor-breakdown");
  if (!el) return;
  if (!byVendorProduct || typeof byVendorProduct !== "object" || Object.keys(byVendorProduct).length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = Object.entries(byVendorProduct).sort((a, b) => b[1] - a[1]);
  el.innerHTML = entries
    .map(([vp, count]) =>
      `<button type="button" class="vendor-pill" data-vp="${escapeHtml(vp)}" title="Search for ${escapeHtml(vp)}">${escapeHtml(vp)}: <strong>${count}</strong></button>`
    )
    .join("");
  el.hidden = false;
  el.querySelectorAll(".vendor-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const searchEl = document.getElementById("search");
      if (!searchEl) return;
      searchEl.value = btn.getAttribute("data-vp");
      applyFiltersAndRender();
    });
  });
}


// stats.json now includes a top-10 by_matched_keyword map, built from the
// already-extracted `matched_keywords` field (config/watchlist.yaml term(s)
// that caused a CVE to surface, already rendered as a per-card "Watchlist
// match" badge since an early cycle and included in the search haystack/CSV
// export) -- a distinct triage axis from severity/source/CWE/vendor: "which
// of OUR configured watch terms are driving current alert volume". Mirrors
// the by_cwe/by_vendor_product pill pattern exactly: clicking a pill sets the
// search box to that keyword and re-applies filters, reusing the existing
// matched_keywords-aware search haystack. Purely additive: reads an existing
// (now-extended) stats.json field, no new API calls.
function renderKeywordBreakdown(byMatchedKeyword) {
  const el = document.getElementById("keyword-breakdown");
  if (!el) return;
  if (!byMatchedKeyword || typeof byMatchedKeyword !== "object" || Object.keys(byMatchedKeyword).length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = Object.entries(byMatchedKeyword).sort((a, b) => b[1] - a[1]);
  el.innerHTML = entries
    .map(([kw, count]) =>
      `<button type="button" class="keyword-pill" data-kw="${escapeHtml(kw)}" title="Search for ${escapeHtml(kw)}">${escapeHtml(kw)}: <strong>${count}</strong></button>`
    )
    .join("");
  el.hidden = false;
  el.querySelectorAll(".keyword-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const searchEl = document.getElementById("search");
      if (!searchEl) return;
      searchEl.value = btn.getAttribute("data-kw");
      applyFiltersAndRender();
    });
  });
}

// stats.json now includes by_age_bucket (cycle 104): a fixed-order
// distribution of currently-tracked alerts by first_seen age ("0-1d",
// "1-7d", "7-30d", "30d+"), answering "how is our current backlog
// distributed by age" at a glance -- distinct from new_alerts_count (only
// the <24h bucket) and the per-card age badge (only visible one card at a
// time). No matching filter control exists for this axis (unlike
// severity/CWE/vendor/keyword), so pills render as inert (non-clickable)
// info, same fallback pattern already used for unrecognized source keys in
// renderSourceBreakdown(). Fixed bucket order (not sorted by count) since
// the buckets form a natural chronological sequence, not an arbitrary
// top-N ranking.
function renderAgeBreakdown(byAgeBucket) {
  const el = document.getElementById("age-breakdown");
  if (!el) return;
  const order = ["0-1d", "1-7d", "7-30d", "30d+"];
  if (!byAgeBucket || typeof byAgeBucket !== "object") {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  const entries = order
    .map((bucket) => [bucket, byAgeBucket[bucket]])
    .filter(([, count]) => typeof count === "number" && count > 0);
  if (entries.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.innerHTML = entries
    .map(([bucket, count]) =>
      `<span class="age-pill" title="First seen ${escapeHtml(bucket)} ago">${escapeHtml(bucket)}: <strong>${count}</strong></span>`
    )
    .join("");
  el.hidden = false;
}


async function loadStats() {
  try {
    const res = await fetch("data/stats.json", { cache: "no-store" });
    if (!res.ok) return;
    const stats = await res.json();
    checkStaleness(stats.generated_at);
    document.getElementById("stats-bar").hidden = false;
    document.getElementById("stat-total").textContent = stats.total_alerts ?? "-";
    document.getElementById("stat-critical").textContent = stats.by_severity?.critical ?? "-";
    document.getElementById("stat-kev").textContent = stats.kev_count ?? "-";
    document.getElementById("stat-overdue").textContent = stats.kev_overdue_count ?? "-";
    const dueSoonEl = document.getElementById("stat-due-soon");
    if (dueSoonEl) {
      dueSoonEl.textContent = stats.kev_due_soon_count ?? "-";
    }
    document.getElementById("stat-ransomware").textContent = stats.kev_ransomware_count ?? "-";
    document.getElementById("stat-epss").textContent =
      typeof stats.avg_epss === "number" ? (stats.avg_epss * 100).toFixed(1) + "%" : "-";
    const avgRiskEl = document.getElementById("stat-avg-risk");
    if (avgRiskEl) {
      avgRiskEl.textContent = typeof stats.avg_risk_score === "number" ? stats.avg_risk_score : "-";
    }
    const avgCvssEl = document.getElementById("stat-avg-cvss");
    if (avgCvssEl) {
      avgCvssEl.textContent = typeof stats.avg_cvss_score === "number" ? stats.avg_cvss_score : "-";
    }
    const riskTrendEl = document.getElementById("stat-risk-trend");
    if (riskTrendEl) {
      const up = stats.risk_increasing_count;
      const down = stats.risk_decreasing_count;
      riskTrendEl.textContent = (typeof up === "number" && typeof down === "number")
        ? `\u25b2${up} / \u25bc${down}`
        : "-";
    }
    // See rejected_count's rationale in aggregate.py's compute_stats() --
    // hidden entirely when zero (the common case) rather than showing a
    // permanent "0" tile, consistent with stat-due-soon's null-guard above.
    const rejectedTile = document.getElementById("stat-rejected-tile");
    const rejectedEl = document.getElementById("stat-rejected");
    if (rejectedTile && rejectedEl) {
      const rejected = stats.rejected_count;
      if (typeof rejected === "number" && rejected > 0) {
        rejectedEl.textContent = rejected;
        rejectedTile.hidden = false;
      } else {
        rejectedTile.hidden = true;
      }
    }
    renderSourceBreakdown(stats.by_source);
    renderSeverityBreakdown(stats.by_severity);
    renderCweBreakdown(stats.by_cwe);
    renderVendorBreakdown(stats.by_vendor_product);
    renderKeywordBreakdown(stats.by_matched_keyword);
    renderAgeBreakdown(stats.by_age_bucket);
  } catch {
    // stats.json is optional/may not exist yet on the very first run -- fail quietly
  }
}

async function loadData() {
  try {
    const res = await fetch("data/alerts.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allAlerts = await res.json();
  } catch (e) {
    allAlerts = [];
    document.getElementById("last-updated").textContent =
      "Could not load data/alerts.json (no data yet, or fetch failed).";
    applyFiltersAndRender();
    return;
  }

  const latest = allAlerts.reduce((max, a) => {
    return a.first_seen && a.first_seen > max ? a.first_seen : max;
  }, "");
  document.getElementById("last-updated").textContent = latest
    ? `Most recent alert added: ${fmtDate(latest)} \u2022 ${allAlerts.length} total alerts tracked`
    : `${allAlerts.length} total alerts tracked`;

  applyFiltersAndRender();
  loadStats();
  highlightFromHash();
}

// Click delegation for the per-card risk-score breakdown toggle (avoids
// attaching a listener per card on every re-render).
document.getElementById("card-grid").addEventListener("click", (e) => {
  const toggleBtn = e.target.closest(".score-toggle");
  if (toggleBtn) {
    const panel = toggleBtn.closest(".risk-row").nextElementSibling;
    if (panel && panel.classList.contains("score-breakdown")) {
      panel.hidden = !panel.hidden;
      toggleBtn.innerHTML = panel.hidden ? "breakdown &#9662;" : "breakdown &#9652;";
      toggleBtn.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
    }
    return;
  }

  // Per-CVE shareable deep link: clicking the CVE ID copies a URL that,
  // when opened, scrolls to and highlights that exact card -- useful for a
  // security lead pointing a teammate at one specific alert rather than the
  // whole filtered view (complements the existing filter-state URL params).
  const linkBtn = e.target.closest(".cve-link-btn");
  if (linkBtn) {
    const cve = linkBtn.dataset.cve;
    const url = `${location.origin}${location.pathname}${location.search}#alert-${encodeURIComponent(cve)}`;
    const originalText = linkBtn.textContent;
    const showCopied = () => {
      linkBtn.textContent = "Copied!";
      setTimeout(() => {
        linkBtn.textContent = originalText;
      }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(showCopied).catch(() => {});
    }
    history.replaceState(null, "", url);
    return;
  }

  // Copy-as-Markdown: formats the alert's key triage fields as a Markdown
  // block suitable for pasting directly into an incident ticket / Slack
  // message, saving an analyst from manually re-typing CVE ID, scores,
  // affected packages, and KEV status by hand.
  const copyMdBtn = e.target.closest(".copy-md-btn");
  if (copyMdBtn) {
    const cve = copyMdBtn.dataset.cve;
    const alert = allAlerts.find((a) => a.cve_id === cve);
    if (alert) {
      const md = alertToMarkdown(alert);
      const originalText = copyMdBtn.textContent;
      const showCopied = () => {
        copyMdBtn.textContent = "Copied!";
        setTimeout(() => {
          copyMdBtn.textContent = originalText;
        }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(md).then(showCopied).catch(() => {});
      }
    }
    return;
  }

  // Copy-suppression-YAML: generates a ready-to-paste config/suppressions.yaml
  // list-item entry (cve_id, placeholder reason, expires = +1 year) for this alert,
  // so an analyst who has reviewed and accepted the risk / confirmed a false positive
  // doesn't have to hand-type the exact YAML schema from memory (see suppressionSnippet
  // above for the full rationale).
  const copySuppressBtn = e.target.closest(".copy-suppress-btn");
  if (copySuppressBtn) {
    const cve = copySuppressBtn.dataset.cve;
    const alert = allAlerts.find((a) => a.cve_id === cve);
    if (alert) {
      const snippet = suppressionSnippet(alert);
      const originalText = copySuppressBtn.textContent;
      const showCopied = () => {
        copySuppressBtn.textContent = "Copied!";
        setTimeout(() => {
          copySuppressBtn.textContent = originalText;
        }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(snippet).then(showCopied).catch(() => {});
      }
    }
    return;
  }

  // Mark-as-reviewed toggle: local-only triage state (see reviewedCves
  // above). Re-renders just this card in place rather than the whole grid
  // to avoid losing scroll position / other open breakdown panels; if the
  // "hide reviewed" filter is active, a full re-filter is needed instead
  // since the card may need to disappear entirely.
  const reviewBtn = e.target.closest(".review-toggle-btn");
  if (reviewBtn) {
    const cve = reviewBtn.dataset.cve;
    toggleReviewed(cve);
    const hideReviewedEl = document.getElementById("hide-reviewed");
    if (hideReviewedEl && hideReviewedEl.checked) {
      applyFiltersAndRender();
    } else {
      const card = reviewBtn.closest(".card");
      const alert = allAlerts.find((a) => a.cve_id === cve);
      if (card && alert) {
        card.outerHTML = renderCard(alert);
      }
      renderReviewedProgress();
    }
  }
});

// If the page was opened with a #alert-CVE-... hash (from the copy-link
// button above, or a hand-typed link), scroll to that card and highlight it
// briefly once the data has rendered. No-op if the card doesn't exist (e.g.
// filtered out or not in the current dataset) -- fails quietly.
function highlightFromHash() {
  if (!location.hash) return;
  const target = document.querySelector(
    `.card[id="${CSS.escape(location.hash.slice(1))}"]`
  );
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  target.classList.add("highlighted");
  setTimeout(() => target.classList.remove("highlighted"), 2500);
}

// --- Historical trend chart (Chart.js via CDN, client-side render only) ---
async function loadTrendChart() {
  const canvas = document.getElementById("trend-chart");
  if (!canvas || typeof Chart === "undefined") return;
  try {
    const res = await fetch("data/history/trend.csv", { cache: "no-store" });
    if (!res.ok) return;
    const csvText = await res.text();
    const lines = csvText.trim().split("\n");
    if (lines.length < 2) return; // header only, not enough data yet
    const rows = lines.slice(1).map((line) => line.split(","));
    const labels = rows.map((r) => r[0]);
    const totalAlerts = rows.map((r) => (r[1] === "" || r[1] === undefined ? null : Number(r[1])));
    const kevCount = rows.map((r) => (r[2] === "" || r[2] === undefined ? null : Number(r[2])));
    const kevOverdue = rows.map((r) => (r[3] === "" ? null : Number(r[3])));
    const kevRansomware = rows.map((r) => (r[4] === "" || r[4] === undefined ? null : Number(r[4])));
    const avgEpss = rows.map((r) => (r[5] === "" ? null : Number(r[5]) * 100));
    const avgRiskScore = rows.map((r) => (r[6] === "" || r[6] === undefined ? null : Number(r[6])));
    // critical_count/high_count columns added in a later schema revision;
    // older rows won't have index 7/8 at all -- treat missing same as empty.
    const criticalCount = rows.map((r) => (r[7] === "" || r[7] === undefined ? null : Number(r[7])));
    const highCount = rows.map((r) => (r[8] === "" || r[8] === undefined ? null : Number(r[8])));
    // avg_cvss_score column added in a later schema revision; older rows
    // won't have index 9 at all -- treat missing same as empty.
    const avgCvssScore = rows.map((r) => (r[9] === "" || r[9] === undefined ? null : Number(r[9])));
    // kev_due_soon_count column added in a later schema revision; older rows
    // won't have index 10 at all -- treat missing same as empty.
    const kevDueSoon = rows.map((r) => (r[10] === "" || r[10] === undefined ? null : Number(r[10])));
    // medium_count/low_count columns added in a later schema revision; older
    // rows won't have index 11/12 at all -- treat missing same as empty.
    const mediumCount = rows.map((r) => (r[11] === "" || r[11] === undefined ? null : Number(r[11])));
    const lowCount = rows.map((r) => (r[12] === "" || r[12] === undefined ? null : Number(r[12])));
    // new_alerts_count column added in a later schema revision; older rows
    // won't have index 13 at all -- treat missing same as empty.
    const newAlertsCount = rows.map((r) => (r[13] === "" || r[13] === undefined ? null : Number(r[13])));
    // risk_increasing_count/risk_decreasing_count columns added in a later
    // schema revision; older rows won't have indices 14/15 at all -- treat
    // missing same as empty.
    const riskIncreasing = rows.map((r) => (r[14] === "" || r[14] === undefined ? null : Number(r[14])));
    const riskDecreasing = rows.map((r) => (r[15] === "" || r[15] === undefined ? null : Number(r[15])));

    document.getElementById("trend-section").hidden = false;
    new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Total tracked alerts",
            data: totalAlerts,
            borderColor: "#9aa5b1",
            backgroundColor: "rgba(154,165,177,0.08)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Total KEV count",
            data: kevCount,
            borderColor: "#c77dff",
            backgroundColor: "rgba(199,125,255,0.1)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "KEV overdue count",
            data: kevOverdue,
            borderColor: "#ff5c5c",
            backgroundColor: "rgba(255,92,92,0.15)",
            yAxisID: "y",
            tension: 0.2,
          },
          {
            label: "KEV ransomware-use count",
            data: kevRansomware,
            borderColor: "#ff9f40",
            backgroundColor: "rgba(255,159,64,0.15)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Avg EPSS (%)",
            data: avgEpss,
            borderColor: "#4f9dff",
            backgroundColor: "rgba(79,157,255,0.15)",
            yAxisID: "y1",
            tension: 0.2,
          },
          {
            label: "Avg risk score",
            data: avgRiskScore,
            borderColor: "#3ddc97",
            backgroundColor: "rgba(61,220,151,0.12)",
            yAxisID: "y1",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Critical severity count",
            data: criticalCount,
            borderColor: "#e63946",
            backgroundColor: "rgba(230,57,70,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "High severity count",
            data: highCount,
            borderColor: "#f4a261",
            backgroundColor: "rgba(244,162,97,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Avg CVSS score",
            data: avgCvssScore,
            borderColor: "#00b4d8",
            backgroundColor: "rgba(0,180,216,0.12)",
            yAxisID: "y1",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "KEV due soon (<=7d) count",
            data: kevDueSoon,
            borderColor: "#ffd166",
            backgroundColor: "rgba(255,209,102,0.12)",
            yAxisID: "y",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Medium severity count",
            data: mediumCount,
            borderColor: "#ffb703",
            backgroundColor: "rgba(255,183,3,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Low severity count",
            data: lowCount,
            borderColor: "#8ecae6",
            backgroundColor: "rgba(142,202,230,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "New alerts this run",
            data: newAlertsCount,
            borderColor: "#06d6a0",
            backgroundColor: "rgba(6,214,160,0.12)",
            yAxisID: "y",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Risk increasing (count)",
            data: riskIncreasing,
            borderColor: "#ef476f",
            backgroundColor: "rgba(239,71,111,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
          {
            label: "Risk decreasing (count)",
            data: riskDecreasing,
            borderColor: "#06a77d",
            backgroundColor: "rgba(6,167,125,0.12)",
            yAxisID: "y2",
            tension: 0.2,
            hidden: true,
          },
        ],
      },
      options: {
        responsive: true,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { ticks: { maxTicksLimit: 8, color: "#9aa5b1" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: { position: "left", title: { display: true, text: "KEV overdue count", color: "#9aa5b1" }, ticks: { color: "#9aa5b1" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y1: { position: "right", title: { display: true, text: "Avg EPSS (%)", color: "#9aa5b1" }, ticks: { color: "#9aa5b1" }, grid: { drawOnChartArea: false } },
          y2: { position: "right", display: false, title: { display: false } },
        },
        plugins: { legend: { labels: { color: "#e6e9ef" } }, tooltip: { mode: "index", intersect: false } },
      },
    });
  } catch {
    // Chart.js CDN unreachable or trend.csv not yet generated -- fail quietly,
    // the rest of the dashboard still works without it.
  }
}

// The search box previously fired a full filter+sort+innerHTML re-render (plus a
// history.replaceState URL sync) on every single keystroke. With 445+ alerts and
// growing, typing a multi-character search term meant repeated full-grid rebuilds
// for every intermediate substring the user never intended to search for -- wasted
// work and, on lower-end mobile devices, visible input lag. Debouncing to 150ms
// (well under human-perceptible "instant" response, per common UX guidance of
// ~100-300ms for search-as-you-type) collapses rapid keystrokes into a single
// render after the user pauses, with zero change in final filtered results.
let searchDebounceTimer = null;
document.getElementById("search").addEventListener("input", () => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(applyFiltersAndRender, 150);
});
document.getElementById("kev-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("severity-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("source-filter").addEventListener("change", applyFiltersAndRender);
document.getElementById("sort-by").addEventListener("change", applyFiltersAndRender);
document.getElementById("hide-reviewed").addEventListener("change", applyFiltersAndRender);
document.getElementById("new-only").addEventListener("change", applyFiltersAndRender);
document.getElementById("hide-rejected").addEventListener("change", applyFiltersAndRender);
document.getElementById("has-fix-only").addEventListener("change", applyFiltersAndRender);
let minRiskDebounceTimer = null;
document.getElementById("min-risk").addEventListener("input", () => {
  clearTimeout(minRiskDebounceTimer);
  minRiskDebounceTimer = setTimeout(applyFiltersAndRender, 150);
});
let minEpssDebounceTimer = null;
document.getElementById("min-epss").addEventListener("input", () => {
  clearTimeout(minEpssDebounceTimer);
  minEpssDebounceTimer = setTimeout(applyFiltersAndRender, 150);
});
document.getElementById("export-csv").addEventListener("click", exportCsv);
document.getElementById("export-json").addEventListener("click", exportJson);
document.getElementById("export-md-report").addEventListener("click", exportMarkdownReport);
document.getElementById("print-view").addEventListener("click", () => window.print());
// Bulk "mark filtered as reviewed": complements the existing per-card
// review-toggle-btn (cycle 48) -- marking hundreds of individually-matched
// alerts (e.g. everything that just matched a search/filter combo the
// analyst has already triaged as a batch) one click at a time was the only
// option until now. Operates on window.__lastFiltered (the same
// currently-visible set backing Export CSV/JSON/Markdown report), so it
// only ever marks what's on screen -- never the full untouched dataset --
// and reuses the already-validated reviewedCves Set/localStorage plumbing
// from cycle 48 unchanged.
const markFilteredReviewedBtn = document.getElementById("mark-filtered-reviewed");
if (markFilteredReviewedBtn) {
  markFilteredReviewedBtn.addEventListener("click", () => {
    const rows = window.__lastFiltered || allAlerts;
    if (!rows.length) return;
    let added = 0;
    for (const a of rows) {
      if (!reviewedCves.has(a.cve_id)) {
        reviewedCves.add(a.cve_id);
        added++;
      }
    }
    if (added > 0) saveReviewedSet();
    applyFiltersAndRender();
    renderReviewedProgress();
  });
}
const exportReviewedBtn = document.getElementById("export-reviewed");
if (exportReviewedBtn) exportReviewedBtn.addEventListener("click", exportReviewedState);
const importReviewedInput = document.getElementById("import-reviewed-input");
if (importReviewedInput) {
  importReviewedInput.addEventListener("change", () => {
    const file = importReviewedInput.files && importReviewedInput.files[0];
    if (!file) return;
    importReviewedState(file, document.getElementById("import-reviewed-status"));
    importReviewedInput.value = "";
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem("theme", theme); } catch (e) {}
  const btn = document.getElementById("theme-toggle");
  if (btn) {
    const isLight = theme === "light";
    btn.textContent = isLight ? "☀️ Light" : "🌙 Dark";
    btn.setAttribute("aria-pressed", String(isLight));
  }
}
(function initTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current);
})();
document.getElementById("theme-toggle").addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "light" ? "dark" : "light");
});

// Single-click reset of every filter/sort control back to its default, plus
// clearing the dependency-file filter and the URL's filter query params --
// previously a viewer with search + kev-filter + severity + source + a
// pasted dependency file active had to clear each control individually to
// get back to the unfiltered board. Deliberately does NOT touch a #alert-...
// hash (a direct deep-link to one card is a distinct concern from filters).
document.getElementById("reset-filters").addEventListener("click", () => {
  document.getElementById("search").value = "";
  document.getElementById("kev-filter").value = "all";
  document.getElementById("severity-filter").value = "all";
  document.getElementById("source-filter").value = "all";
  document.getElementById("sort-by").value = "risk_score";
  document.getElementById("min-risk").value = "";
  document.getElementById("min-epss").value = "";
  const hideReviewedReset = document.getElementById("hide-reviewed");
  if (hideReviewedReset) hideReviewedReset.checked = false;
  const newOnlyReset = document.getElementById("new-only");
  if (newOnlyReset) newOnlyReset.checked = false;
  const hideRejectedReset = document.getElementById("hide-rejected");
  if (hideRejectedReset) hideRejectedReset.checked = false;
  const hasFixOnlyReset = document.getElementById("has-fix-only");
  if (hasFixOnlyReset) hasFixOnlyReset.checked = false;
  dependencyPackageNames = null;
  const depText = document.getElementById("dep-text-input");
  const depFile = document.getElementById("dep-file-input");
  const depStatus = document.getElementById("dep-status");
  if (depText) depText.value = "";
  if (depFile) depFile.value = "";
  if (depStatus) depStatus.textContent = "";
  applyFiltersAndRender();
});

// Keyboard-shortcuts help modal (cycle 80): opened via the toolbar button,
// the "?" key, or closed via its own close button, Escape, or clicking the
// dimmed backdrop. Mirrors the existing .score-breakdown hidden-attribute
// toggle pattern used throughout the app -- no new state management needed.
function openShortcutsModal() {
  const modal = document.getElementById("shortcuts-modal");
  if (modal) modal.hidden = false;
}
function closeShortcutsModal() {
  const modal = document.getElementById("shortcuts-modal");
  if (modal) modal.hidden = true;
}
function isShortcutsModalOpen() {
  const modal = document.getElementById("shortcuts-modal");
  return modal && !modal.hidden;
}
document.getElementById("kbd-hint-btn")?.addEventListener("click", openShortcutsModal);
document.getElementById("shortcuts-modal-close")?.addEventListener("click", closeShortcutsModal);
document.getElementById("shortcuts-modal")?.addEventListener("click", (e) => {
  if (e.target && e.target.id === "shortcuts-modal") closeShortcutsModal();
});

// Keyboard shortcuts for the most common triage actions -- prior to this,
// every filter/search/reset action required a mouse click, real friction for
// a security-team tool where analysts triage dozens/hundreds of alerts in a
// sitting. Guards against firing while the user is typing in any text input/
// textarea/contenteditable (checks e.target, not just focus state) so normal
// typing (e.g. "r" in a search query) is never hijacked. Does not fire with
// Ctrl/Cmd/Alt held, to avoid colliding with browser/OS shortcuts.
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target;
  const isTyping = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);

  if (e.key === "/" && !isTyping) {
    e.preventDefault();
    const search = document.getElementById("search");
    if (search) search.focus();
    return;
  }
  if (e.key === "Escape") {
    if (isShortcutsModalOpen()) {
      closeShortcutsModal();
      return;
    }
    if (isTyping && t.blur) t.blur();
    return;
  }
  if (isTyping) return;
  if (e.key === "?") {
    e.preventDefault();
    if (isShortcutsModalOpen()) closeShortcutsModal();
    else openShortcutsModal();
    return;
  }
  if (e.key === "r" || e.key === "R") {
    e.preventDefault();
    document.getElementById("reset-filters").click();
    return;
  }
  if (e.key === "t" || e.key === "T") {
    e.preventDefault();
    document.getElementById("theme-toggle").click();
    return;
  }
  if (e.key === "v" || e.key === "V") {
    e.preventDefault();
    document.getElementById("view-toggle")?.click();
    return;
  }
});

readFiltersFromURL();
setupDependencyFilter();
loadData();
loadTrendChart();
