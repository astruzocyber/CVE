// "Escalate now" board: CVEs and threat-intel items that hit YOUR estate
// (config/environment.yaml), tiered ESCALATE / WORK by scripts/escalate.py.
// Data: data/escalations.json. Every reason shown is the literal rule hit
// computed in the pipeline -- nothing is generated in the browser.
import { byId, escapeHtml, extLink, copyText, downloadBlob, todayStamp } from "./dom.js";

const state = { data: null, tier: "escalate", asset: "", closed: false };
const REPO = "https://github.com/astruzocyber/CVE";
const TRIAGE_EDIT = `${REPO}/edit/main/config/triage.yaml`;
const STATUS_BADGE = {
  acknowledged: "badge--source", in_progress: "badge--due-soon", escalated: "badge--overdue",
  resolved: "badge--kev", false_positive: "badge--kev", accepted_risk: "badge--kev",
};
const TIER_LABEL = { escalate: "Escalate", work: "Work" };
const TIER_BADGE = { escalate: "badge--overdue", work: "badge--due-soon" };
const CRIT_BADGE = { critical: "badge--critical", high: "badge--high", medium: "badge--medium" };
const SITE = "https://astruzocyber.github.io/CVE/";

const day = (iso) => (iso ? String(iso).slice(0, 10) : "date unknown");

function visible() {
  return (state.data?.items || []).filter(
    (it) => (!state.tier || it.tier === state.tier) && (!state.asset || (it.assets || []).includes(state.asset))
      && (state.closed || !it.closed),
  );
}

// YAML snippet to paste under `entries:` in config/triage.yaml (GitHub web editor).
function triageSnippet(it) {
  const t = it.triage || {};
  const q = (v) => JSON.stringify(String(v || ""));
  return [
    `  ${q(it.key)}:`,
    `    status: ${t.status || "acknowledged"}   # acknowledged | in_progress | escalated | resolved | false_positive | accepted_risk`,
    `    owner: ${q(t.owner || "")}`,
    `    note: ${q(t.note || it.title.replace(/\s+/g, " ").slice(0, 120))}`,
    `    date: ${q(t.date || todayStamp())}`,
  ].join("\n");
}

function triageLine(it) {
  const t = it.triage;
  if (!t) return `<p class="esc-triage"><span class="badge">untriaged</span></p>`;
  const bits = [t.owner && `owner ${t.owner}`, t.date && day(t.date)].filter(Boolean).join(" · ");
  return `<p class="esc-triage"><span class="badge ${STATUS_BADGE[t.status] || ""}">${escapeHtml(t.status.replace("_", " "))}</span>
    ${escapeHtml(bits)}${t.note ? ` — ${escapeHtml(t.note)}` : ""}</p>`;
}

function renderItem(it) {
  const title = it.kind === "intel"
    ? extLink(it.link, it.title) || escapeHtml(it.title)
    : `<a href="#${encodeURIComponent(it.ref)}" title="Open this CVE on the dashboard">${escapeHtml(it.title)}</a>`;
  const reasons = (it.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const cov = it.coverage || [];
  const kind = it.kind === "cve" ? "CVE" : it.kind === "bundle" ? `Bundle · ${(it.cve_ids || []).length} CVEs`
    : cov.length ? `News · ${cov.length} reports` : `News · ${it.source || ""}`;
  const coverage = cov.length
    ? `<details class="esc-coverage"><summary>${it.advisory_batch ? `All ${cov.length} advisories in this release` : `All ${cov.length} reports of this incident`}</summary><ul>${cov
        .filter((c) => !c.dup)
        .map((c) => `<li>${extLink(c.link, c.title) || escapeHtml(c.title)} <span class="muted">· ${escapeHtml(c.source || "")} · ${escapeHtml(day(c.date))}</span></li>`)
        .join("")}</ul></details>`
    : "";
  const meta = [kind, day(it.date)].join(" · ");
  return `<article class="card esc-card esc-card--${escapeHtml(it.tier)}${it.closed ? " esc-card--closed" : ""}">
    <div class="card__head">
      <h3 class="intel-card__title">${title}</h3>
      <span class="badge ${TIER_BADGE[it.tier] || ""}">${escapeHtml(TIER_LABEL[it.tier] || it.tier)}</span>
    </div>
    <p class="card__affected">${escapeHtml(meta)}</p>
    <div class="card__badges">
      <span class="badge ${CRIT_BADGE[it.criticality] || ""}" title="Highest criticality of the matched assets">${escapeHtml(it.criticality)} asset</span>
      ${(it.assets || []).map((a) => `<span class="badge badge--source">${escapeHtml(a)}</span>`).join("")}
    </div>
    ${triageLine(it)}
    <ul class="esc-reasons">${reasons}</ul>
    ${coverage}
    <div class="esc-actions">
      <button type="button" class="btn btn--sm" data-esc-triage="${escapeHtml(it.key)}"
        title="Copy a triage entry, then paste it under entries: in config/triage.yaml">Copy triage entry</button>
    </div>
  </article>`;
}

function render() {
  const list = visible();
  byId("esc-grid").innerHTML = list.map(renderItem).join("");
  byId("esc-empty").hidden = list.length > 0;
  const c = state.data.counts || {};
  const o = state.data.open || c;
  byId("esc-count").textContent =
    `${list.length} shown · ${o.escalate || 0} open escalate · ${o.work || 0} open work · ${state.data.triaged || 0} triaged`;
}

// Plain-text briefing for a team channel / ticket / standup.
function briefText(list) {
  const d = state.data;
  const lines = [
    `Security briefing ${todayStamp()} -- items affecting our environment`,
    `Source: ${SITE} (rules: config/environment.yaml; CVEs from last ${d.window_days?.cve}d, news from last ${d.window_days?.intel}d)`,
    "",
  ];
  for (const tier of ["escalate", "work"]) {
    const group = list.filter((it) => it.tier === tier);
    if (!group.length) continue;
    lines.push(`== ${TIER_LABEL[tier].toUpperCase()} (${group.length}) ==`);
    group.forEach((it, i) => {
      lines.push(`${i + 1}. ${it.title.replace(/\s+/g, " ").slice(0, 200)}`);
      lines.push(`   Assets: ${(it.assets || []).join(", ")} [${it.criticality}]`);
      for (const r of (it.reasons || []).slice(1)) lines.push(`   - ${r}`);
      if (it.triage) lines.push(`   Triage: ${it.triage.status}${it.triage.owner ? ` (${it.triage.owner})` : ""}${it.triage.note ? ` -- ${it.triage.note}` : ""}`);
      lines.push(`   Link: ${it.kind === "intel" ? it.link : `${SITE}#${it.ref}`}`);
    });
    lines.push("");
  }
  return lines.join("\n");
}

function present() {
  document.body.classList.add("presenting-esc");
  const done = () => { document.body.classList.remove("presenting-esc"); window.removeEventListener("afterprint", done); };
  window.addEventListener("afterprint", done);
  window.print();
}

function renderAssetSelect() {
  const counts = {};
  for (const it of state.data.items) for (const a of it.assets || []) counts[a] = (counts[a] || 0) + 1;
  byId("esc-asset").innerHTML = `<option value="">All assets</option>` + (state.data.assets || [])
    .filter((a) => counts[a.name])
    .map((a) => `<option value="${escapeHtml(a.name)}">${escapeHtml(a.name)} (${counts[a.name]})</option>`)
    .join("");
}

/** Loads data/escalations.json, renders the board, and tags matching alerts
 *  (alert.esc_tier) so the main CVE list can show an Escalate/Work badge. */
export async function initEscalations(alerts, rerender) {
  const section = byId("esc-section");
  if (!section) return;
  try {
    const res = await fetch("data/escalations.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.data = await res.json();
  } catch {
    return; // board stays hidden
  }
  if (!state.data || !Array.isArray(state.data.items)) return;

  const byCve = new Map();
  for (const it of state.data.items) {
    if (it.kind === "cve") byCve.set(it.ref, it);
    else if (it.kind === "bundle") for (const id of it.cve_ids || []) byCve.set(id, it);
  }
  let tagged = 0;
  for (const a of alerts || []) {
    const hit = byCve.get(a.cve_id);
    if (hit) { a.esc_tier = hit.tier; a.esc_assets = hit.assets; tagged += 1; }
  }
  if (tagged && rerender) rerender();

  section.hidden = false;
  byId("esc-hint").textContent =
    `Matched against ${state.data.assets?.length || 0} assets in your environment profile · updated ${day(state.data.generated_at)}`;
  renderAssetSelect();
  byId("esc-tier").addEventListener("change", (e) => { state.tier = e.target.value; render(); });
  byId("esc-asset").addEventListener("change", (e) => { state.asset = e.target.value; render(); });
  byId("esc-copy").addEventListener("click", () => copyText(briefText(visible()), "Briefing copied"));
  byId("esc-download").addEventListener("click", () =>
    downloadBlob(briefText(visible()), "text/plain", `security-briefing-${todayStamp()}.txt`));
  byId("esc-present").addEventListener("click", present);
  byId("esc-closed")?.addEventListener("change", (e) => { state.closed = e.target.checked; render(); });
  byId("esc-grid").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-esc-triage]");
    if (!btn) return;
    const it = state.data.items.find((x) => x.key === btn.dataset.escTriage);
    if (!it) return;
    copyText(triageSnippet(it), "Triage entry copied -- paste it into config/triage.yaml");
    window.open(TRIAGE_EDIT, "_blank", "noopener");
  });
  render();
}
