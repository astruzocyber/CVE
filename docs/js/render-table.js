// Table view markup for one alert row. Pure string builder: alert in, HTML out.

import { escapeHtml } from "./dom.js";
import { cweName } from "./cwe-names.js";
import { isReviewed } from "./reviewed.js";
import {
  severityClass, riskClass, fmtScore, fmtPct, fmtDay, kevStatus, isRejected, isRevised, hasFixAvailable,
  riskDelta, epssDelta, attackVectorLabel, isNum,
} from "./format.js";
import { deltaHtml } from "./render-card.js";

const DASH = `<span class="muted">–</span>`;

function kevCell(a) {
  const status = kevStatus(a);
  if (!status) return DASH;
  const cls = status === "Overdue" ? "overdue" : status === "Due soon" ? "due-soon" : "kev";
  const title = a.kev_due_date ? `CISA due date: ${a.kev_due_date}` : "In CISA KEV";
  return `<span class="badge badge--${cls}" title="${escapeHtml(title)}">${escapeHtml(status)}</span>` +
    (a.kev_ransomware_use ? ` <span class="badge badge--ransomware" title="Known ransomware use">R</span>` : "");
}

function cweCell(a) {
  const ids = a.cwe_ids || [];
  if (!ids.length) return DASH;
  return ids.map((c) => {
    const name = cweName(c);
    return `<span${name ? ` title="${escapeHtml(`${c}: ${name}`)}"` : ""}>${escapeHtml(c)}</span>`;
  }).join(", ");
}

export function renderRow(a) {
  const id = escapeHtml(a.cve_id);
  const reviewed = isReviewed(a.cve_id);
  const sev = severityClass(a.cvss_score);
  const risk = riskClass(a.risk_score);
  const products = (a.affected || []).slice(0, 3).join(", ");
  const more = (a.affected || []).length > 3 ? ` <span class="muted">+${a.affected.length - 3}</span>` : "";
  const watch = (a.matched_keywords || []).map(escapeHtml).join(", ");
  const vector = attackVectorLabel(a);

  return `<tr data-cve="${id}"${isRejected(a) ? ` class="is-rejected"` : ""}>
    <th scope="row"><a href="#alert-${id}" class="mono">${id}</a>${isRejected(a) ? ` <span class="badge badge--rejected" title="Rejected by NVD">Rejected</span>` : ""}${isRevised(a) ? ` <span class="muted" title="${escapeHtml(`Revised by NVD on ${fmtDay(a.nvd_last_modified)}`)}">✎</span>` : ""}</th>
    <td class="num"><span class="score score--${risk || "none"}">${isNum(a.risk_score) ? a.risk_score.toFixed(0) : "n/a"}</span>${deltaHtml(riskDelta(a), "risk", a.risk_score_prev, a.risk_score)}</td>
    <td class="num"><span class="score score--${sev || "none"}">${fmtScore(a.cvss_score)}</span></td>
    <td class="num">${fmtPct(a.epss_score)}${deltaHtml(epssDelta(a), "epss", a.epss_score_prev, a.epss_score)}</td>
    <td>${kevCell(a)}</td>
    <td class="cell-wrap">${products ? escapeHtml(products) + more : DASH}</td>
    <td>${vector ? escapeHtml(vector) : DASH}</td>
    <td>${hasFixAvailable(a) ? `<span class="badge badge--fix">Yes</span>` : DASH}</td>
    <td class="cell-wrap">${cweCell(a)}</td>
    <td class="cell-wrap">${watch || DASH}</td>
    <td>${escapeHtml(a.source || "unknown")}</td>
    <td class="nowrap">${a.first_seen ? escapeHtml(fmtDay(a.first_seen)) : DASH}</td>
    <td><button type="button" class="btn btn--sm${reviewed ? " btn--done" : ""}" data-action="toggle-reviewed" data-cve="${id}" aria-pressed="${reviewed}">${reviewed ? "✓" : "Mark"}</button></td>
  </tr>`;
}
