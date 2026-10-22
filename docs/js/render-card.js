// Card view markup for one alert. Pure string builder: alert in, HTML out.
// Every external value is escaped; every external URL passes safeUrl().

import { escapeHtml, extLink } from "./dom.js";
import { cweName } from "./cwe-names.js";
import { isReviewed } from "./reviewed.js";
import {
  severityClass, riskClass, fmtScore, fmtPct, fmtDay, fmtDateTime, cvssVersionText, isOverdue, overdueDays,
  daysUntilDue, firstSeenAge, isNewWithin24h, isRejected, isRevised, riskDelta, epssDelta, attackVectorLabel,
  osvFixText, osvFixCommitUrl, nvdFixText, nvdFixIsRelease, hasFixAvailable, nvdUrl, isNum,
} from "./format.js";

const badge = (cls, text, title = "") =>
  `<span class="badge badge--${cls}"${title ? ` title="${escapeHtml(title)}"` : ""}>${escapeHtml(text)}</span>`;

export function deltaHtml(delta, kind, prev, curr) {
  if (kind === "risk") {
    if (delta === null) return "";
    const d = Math.round(delta);
    if (d === 0) return "";
    const title = `Risk score changed from ${prev.toFixed(0)} to ${curr.toFixed(0)} since the last refresh`;
    return `<span class="delta delta--${d > 0 ? "up" : "down"}" title="${title}">${d > 0 ? "▲ +" : "▼ "}${d}</span>`;
  }
  if (delta === null || Math.abs(delta) < 0.0005) return "";
  const title = `EPSS changed from ${(prev * 100).toFixed(1)}% to ${(curr * 100).toFixed(1)}% since the last refresh`;
  return `<span class="delta delta--${delta > 0 ? "up" : "down"}" title="${title}">${delta > 0 ? "▲ +" : "▼ "}${(delta * 100).toFixed(1)}pp</span>`;
}

function statusBadges(a) {
  const out = [];
  if (a.esc_tier === "escalate") out.push(badge("overdue", "Escalate", `Hits your environment: ${(a.esc_assets || []).join(", ")}`));
  else if (a.esc_tier === "work") out.push(badge("due-soon", "Work", `Hits your environment: ${(a.esc_assets || []).join(", ")}`));
  if (isNewWithin24h(a)) out.push(badge("new", "New"));
  if (isRejected(a)) out.push(badge("rejected", "Rejected by NVD", "NVD has withdrawn this CVE ID (duplicate, disputed, or withdrawn by the CNA). Scores may be stale."));
  if (a.kev) out.push(badge("kev", "KEV", "Listed in CISA's Known Exploited Vulnerabilities catalog"));
  if (a.kev_ransomware_use) out.push(badge("ransomware", "Ransomware", "Known use in ransomware campaigns (CISA KEV)"));
  if (isOverdue(a)) {
    const d = overdueDays(a);
    out.push(badge("overdue", `Overdue${isNum(d) ? ` ${d}d` : ""}`, `Past the CISA BOD 22-01 due date (${a.kev_due_date})`));
  } else {
    const d = daysUntilDue(a);
    if (d !== null && d <= 7) out.push(badge("due-soon", d === 0 ? "Due today" : `Due in ${d}d`, `CISA BOD 22-01 due date: ${a.kev_due_date}`));
  }
  const sev = severityClass(a.cvss_score);
  if (sev) out.push(badge(sev, sev));
  out.push(badge("source", a.source || "unknown"));
  return out.join("");
}

function breakdownHtml(a, riskVal) {
  const b = a.risk_score_breakdown;
  if (!b) return "";
  const epssRaw = isNum(b.epss_raw) ? `${(b.epss_raw * 100).toFixed(1)}%` : "n/a";
  return `
    <div class="score-breakdown" id="bd-${escapeHtml(a.cve_id)}" hidden>
      <div class="score-breakdown__row"><span>CVSS ${fmtScore(b.cvss_raw)} × ${escapeHtml(b.cvss_weight || "35%")}</span><span>${fmtScore(b.cvss_component)} pts</span></div>
      <div class="score-breakdown__row"><span>EPSS ${epssRaw} × ${escapeHtml(b.epss_weight || "40%")}</span><span>${fmtScore(b.epss_component)} pts</span></div>
      <div class="score-breakdown__row"><span>${escapeHtml(b.kev_weight || "KEV bonus")}</span><span>${fmtScore(b.kev_bonus)} pts</span></div>
      <div class="score-breakdown__row score-breakdown__total"><span>Total${b.capped ? " (capped at 100)" : ""}</span><span>${riskVal} pts</span></div>
      ${b.weight_redistributed ? `<p class="score-breakdown__note">CVSS/EPSS weight was redistributed because one score is not yet available for this CVE.</p>` : ""}
    </div>`;
}

function cweChips(a) {
  const ids = a.cwe_ids || [];
  if (!ids.length) return "";
  return ids.map((c) => {
    const num = String(c).replace(/^CWE-/i, "");
    const name = cweName(c);
    const text = name ? `${c} · ${name}` : c;
    return /^\d+$/.test(num)
      ? `<a class="tag tag--cwe" href="https://cwe.mitre.org/data/definitions/${num}.html" target="_blank" rel="noopener noreferrer" title="${escapeHtml(text)}">${escapeHtml(text)}</a>`
      : `<span class="tag tag--cwe">${escapeHtml(c)}</span>`;
  }).join("");
}

/** CISA KEV notes mix vendor advisories with boilerplate; keep only vendor links. */
function kevAdvisoryLinks(notes) {
  if (typeof notes !== "string" || !notes) return [];
  const links = [];
  for (const part of notes.split(";").map((p) => p.trim()).filter(Boolean)) {
    const m = part.match(/(https?:\/\/\S+)/);
    if (!m) continue;
    let host = "";
    let path = "";
    try {
      const u = new URL(m[1]);
      host = u.hostname.toLowerCase();
      path = (u.pathname + u.search).toLowerCase();
    } catch { /* keep unparseable links; extLink() drops unsafe ones */ }
    if (host === "nvd.nist.gov" || host.endsWith(".nvd.nist.gov")) continue;
    if (path.includes("bod-26-04") || path.includes("forensics-triage")) continue;
    links.push(extLink(m[1], part.slice(0, m.index).replace(/:$/, "").trim() || "Vendor advisory"));
  }
  return links.filter(Boolean);
}

function detailsSection(a) {
  const rows = [];
  const osv = Array.isArray(a.osv_fixed_versions) ? a.osv_fixed_versions : [];
  const nvd = Array.isArray(a.nvd_fix_versions) ? a.nvd_fix_versions : [];
  if (osv.length) {
    const line = (f) => {
      const url = osvFixCommitUrl(f);
      return escapeHtml(osvFixText(f)) + (url ? ` · ${extLink(url, "commit")}` : "");
    };
    rows.push(["Fix (OSV.dev)", osv.map(line).join("<br>")]);
  }
  if (nvd.length) rows.push([nvd.some(nvdFixIsRelease) ? "Fix (NVD)" : "Affected (NVD)", nvd.map((f) => escapeHtml(nvdFixText(f))).join("<br>")]);
  const advisories = a.kev ? kevAdvisoryLinks(a.kev_notes) : [];
  if (advisories.length) rows.push(["KEV advisories", advisories.join(" · ")]);
  const refs = (Array.isArray(a.nvd_reference_links) ? a.nvd_reference_links : [])
    .map((r) => extLink(r.url, r.tags?.[0] || "Reference")).filter(Boolean);
  if (refs.length) rows.push(["Vendor links", refs.join(" · ")]);
  if (a.kev_date_added) rows.push(["KEV added", escapeHtml(a.kev_date_added)]);
  if (a.published) rows.push(["Published", escapeHtml(fmtDay(a.published))]);
  if (isRevised(a)) rows.push(["Revised by NVD", escapeHtml(fmtDay(a.nvd_last_modified))]);
  if (a.first_seen) rows.push(["First seen here", escapeHtml(fmtDateTime(a.first_seen))]);
  if (!rows.length) return "";
  return `
    <details class="card__details">
      <summary>Details${hasFixAvailable(a) ? ` <span class="badge badge--fix">Fix available</span>` : ""}</summary>
      <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
    </details>`;
}

export function renderCard(a) {
  const id = escapeHtml(a.cve_id);
  const reviewed = isReviewed(a.cve_id);
  const rCls = riskClass(a.risk_score) || "none";
  const riskVal = isNum(a.risk_score) ? a.risk_score.toFixed(0) : "n/a";
  const width = isNum(a.risk_score) ? Math.max(0, Math.min(100, Math.round(a.risk_score / 5) * 5)) : 0;
  const version = cvssVersionText(a.cvss_version);
  const vector = attackVectorLabel(a);
  const age = firstSeenAge(a);
  const pctl = isNum(a.epss_percentile) ? `<span class="muted" title="Higher than ${(a.epss_percentile * 100).toFixed(0)}% of all scored CVEs">top ${(100 - a.epss_percentile * 100).toFixed(0)}%</span>` : "";
  const affected = (a.affected || []).join(", ");
  const watch = (a.matched_keywords || []).map((k) => `<span class="tag tag--watch" title="Matched watchlist term">${escapeHtml(k)}</span>`).join("");
  const nvdHref = nvdUrl(a.cve_id);

  return `
  <article class="card card--${rCls}${reviewed ? " is-reviewed" : ""}" id="alert-${id}" data-cve="${id}">
    <header class="card__head">
      <button type="button" class="card__id" data-action="copy-link" data-cve="${id}" title="Copy a direct link to this alert">${id}</button>
      <div class="risk-pill risk-pill--${rCls}" title="Composite risk score (0–100)"><span class="risk-pill__value">${riskVal}</span><span class="risk-pill__label">risk</span></div>
    </header>
    <div class="card__badges">${statusBadges(a)}</div>
    <div class="riskbar" aria-hidden="true"><span class="riskbar__fill riskbar__fill--${rCls} w-${width}"></span></div>
    <p class="card__desc">${escapeHtml(a.description || "(no description)")}</p>
    <dl class="card__metrics">
      <div><dt>CVSS</dt><dd>${fmtScore(a.cvss_score)}${version ? ` <span class="muted">${escapeHtml(version)}</span>` : ""}</dd></div>
      <div><dt>EPSS</dt><dd>${fmtPct(a.epss_score)} ${pctl}${deltaHtml(epssDelta(a), "epss", a.epss_score_prev, a.epss_score)}</dd></div>
      <div><dt>Risk change</dt><dd>${deltaHtml(riskDelta(a), "risk", a.risk_score_prev, a.risk_score) || `<span class="muted">none</span>`}</dd></div>
      ${a.kev_due_date ? `<div><dt>KEV due</dt><dd>${escapeHtml(a.kev_due_date)}</dd></div>` : ""}
      ${vector ? `<div class="card__metric--wide"><dt>Attack vector</dt><dd>${escapeHtml(vector)}</dd></div>` : ""}
    </dl>
    ${affected ? `<p class="card__affected"><span class="muted">Affected:</span> ${escapeHtml(affected)}</p>` : ""}
    ${a.kev && a.kev_required_action ? `<p class="callout callout--danger"><strong>CISA required action:</strong> ${escapeHtml(a.kev_required_action)}</p>` : ""}
    ${watch || (a.cwe_ids || []).length ? `<div class="card__tags">${watch}${cweChips(a)}</div>` : ""}
    ${a.risk_score_breakdown ? `<button type="button" class="link-btn card__bd-toggle" data-action="toggle-breakdown" aria-expanded="false" aria-controls="bd-${id}">Score breakdown</button>${breakdownHtml(a, riskVal)}` : ""}
    ${detailsSection(a)}
    <footer class="card__foot">
      <div class="card__links">
        ${nvdHref ? extLink(nvdHref, "NVD") : ""}
        ${a.osv_id ? extLink(`https://osv.dev/vulnerability/${encodeURIComponent(a.osv_id)}`, "OSV.dev") : ""}
        ${a.dependabot_url ? extLink(a.dependabot_url, "Dependabot alert") : ""}
        ${isNum(age) ? `<span class="muted" title="Days since the pipeline first ingested this alert">on board ${age}d</span>` : ""}
      </div>
      <div class="card__actions">
        <button type="button" class="btn btn--sm btn--ghost" data-action="copy-md" data-cve="${id}" title="Copy as Markdown for a ticket">Copy MD</button>
        <button type="button" class="btn btn--sm btn--ghost" data-action="copy-yaml" data-cve="${id}" title="Copy a config/suppressions.yaml entry (accepted risk / false positive)">Suppress YAML</button>
        <button type="button" class="btn btn--sm${reviewed ? " btn--done" : ""}" data-action="toggle-reviewed" data-cve="${id}" aria-pressed="${reviewed}">${reviewed ? "✓ Reviewed" : "Mark reviewed"}</button>
      </div>
    </footer>
  </article>`;
}
