// Pure domain helpers: classification, formatting and date math for one alert.
// No DOM access here so these stay trivially testable.

const DAY_MS = 24 * 60 * 60 * 1000;
export const NEW_WITHIN_MS = DAY_MS;

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

/** CVSS -> severity band. Returns "" when CVSS is not published yet. */
export function severityClass(cvss) {
  if (typeof cvss !== "number") return "";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}

/** Composite risk score -> same four bands (thresholds 75/50/25). */
export function riskClass(score) {
  if (typeof score !== "number") return "";
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * URL hash -> alert id for deep links. Canonical form is "#alert-<id>"; a bare
 * "#CVE-…" / "#GHSA-…" is also accepted because escalation-board links and
 * already-sent Discord/briefing links used that form. Returns "" otherwise.
 */
export function alertIdFromHash(hash) {
  let id = String(hash || "").replace(/^#/, "");
  try { id = decodeURIComponent(id); } catch { return ""; }
  if (id.startsWith("alert-")) id = id.slice("alert-".length);
  else if (!/^(CVE-\d{4}-\d+|GHSA(-[0-9a-z]{4}){3})$/i.test(id)) return "";
  return id;
}

export const isNum = (v) => typeof v === "number" && Number.isFinite(v);
export const fmtScore = (v, digits = 1) => (isNum(v) ? v.toFixed(digits) : "n/a");
export const fmtPct = (p, digits = 1) => (isNum(p) ? `${(p * 100).toFixed(digits)}%` : "n/a");

function parseDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtDateTime(iso) {
  const d = parseDate(iso);
  return d ? d.toLocaleString() : "unknown";
}

export function fmtDay(iso) {
  const d = parseDate(iso);
  return d ? d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "unknown";
}

/** "CVSS V31" -> "v3.1"; other labels (e.g. "GHSA CVSS") pass through. */
export function cvssVersionText(raw) {
  if (!raw) return null;
  const m = /^CVSS V(\d)(\d)$/.exec(raw);
  return m ? `v${m[1]}.${m[2]}` : String(raw);
}

// KEV due dates are calendar dates (YYYY-MM-DD) and are interpreted as UTC midnight.
function dueDate(alert) {
  return alert.kev_due_date ? parseDate(`${alert.kev_due_date}T00:00:00Z`) : null;
}

export function isOverdue(alert) {
  const due = dueDate(alert);
  return Boolean(due) && due.getTime() < Date.now();
}

export function overdueDays(alert) {
  const due = dueDate(alert);
  if (!due || due.getTime() >= Date.now()) return null;
  return Math.floor((Date.now() - due.getTime()) / DAY_MS);
}

/** Whole days until the KEV due date; null if none or already overdue. */
export function daysUntilDue(alert) {
  const due = dueDate(alert);
  if (!due || due.getTime() < Date.now()) return null;
  return Math.ceil((due.getTime() - Date.now()) / DAY_MS);
}

export function isDueSoon(alert) {
  const d = daysUntilDue(alert);
  return d !== null && d <= 7;
}

/** Whole days since the pipeline first ingested this alert. */
export function firstSeenAge(alert) {
  const seen = parseDate(alert.first_seen);
  if (!seen) return null;
  return Math.max(0, Math.floor((Date.now() - seen.getTime()) / DAY_MS));
}

export function isNewWithin24h(alert) {
  const seen = parseDate(alert.first_seen);
  return Boolean(seen) && Date.now() - seen.getTime() <= NEW_WITHIN_MS;
}

export const isRejected = (alert) => alert.vuln_status === "Rejected";

/** NVD revised the record on a different calendar day than it was published. */
export function isRevised(alert) {
  if (!alert.nvd_last_modified || !alert.published) return false;
  return String(alert.nvd_last_modified).slice(0, 10) !== String(alert.published).slice(0, 10);
}

export function hasFixAvailable(alert) {
  return (
    (Array.isArray(alert.osv_fixed_versions) && alert.osv_fixed_versions.length > 0) ||
    (Array.isArray(alert.nvd_fix_versions) && alert.nvd_fix_versions.length > 0)
  );
}

export function riskDelta(alert) {
  return isNum(alert.risk_score) && isNum(alert.risk_score_prev) ? alert.risk_score - alert.risk_score_prev : null;
}

export function epssDelta(alert) {
  return isNum(alert.epss_score) && isNum(alert.epss_score_prev) ? alert.epss_score - alert.epss_score_prev : null;
}

/** KEV status label shared by table view and exports. */
export function kevStatus(alert) {
  if (!alert.kev) return null;
  if (isOverdue(alert)) return "Overdue";
  if (isDueSoon(alert)) return "Due soon";
  return "KEV";
}

const ATTACK_VECTORS = { NETWORK: "Network", ADJACENT_NETWORK: "Adjacent", LOCAL: "Local", PHYSICAL: "Physical" };

/** e.g. "Network · no auth/interaction"; null when no CVSS vector is known. */
export function attackVectorLabel(alert) {
  const vc = alert.cvss_vector_components;
  if (!vc?.attack_vector) return null;
  const base = ATTACK_VECTORS[vc.attack_vector] ?? vc.attack_vector;
  const noAuth = vc.privileges_required === "NONE" && vc.user_interaction === "NONE";
  return noAuth ? `${base} · no auth/interaction` : base;
}

export function osvFixText(f) {
  return `${f.package || "?"}${f.ecosystem ? ` (${f.ecosystem})` : ""} → ${f.fixed || "?"}`;
}

export function nvdFixText(f) {
  const rel = f.fix_type === "up_to_and_including" ? "next release after" : "before";
  return `${f.vendor || "?"} ${f.product || "?"} → fixed ${rel} ${f.fixed || "?"}`;
}

export const nvdUrl = (cveId) =>
  cveId && /^CVE-/i.test(cveId) ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` : null;
