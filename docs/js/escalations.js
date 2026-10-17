// "Escalate now" board: CVEs and threat-intel items that hit YOUR estate
// (config/environment.yaml), tiered ESCALATE / WORK by scripts/escalate.py.
// Data: data/escalations.json. Every reason shown is the literal rule hit
// computed in the pipeline -- nothing is generated in the browser.
import { byId, escapeHtml, extLink, copyText, downloadBlob, todayStamp } from "./dom.js";

const state = { data: null, tier: "escalate", asset: "" };
const TIER_LABEL = { escalate: "Escalate", work: "Work" };
const TIER_BADGE = { escalate: "badge--overdue", work: "badge--due-soon" };
const CRIT_BADGE = { critical: "badge--critical", high: "badge--high", medium: "badge--medium" };
const SITE = "https://astruzocyber.github.io/CVE/";

const day = (iso) => (iso ? String(iso).slice(0, 10) : "date unknown");

function visible() {
  return (state.data?.items || []).filter(
    (it) => (!state.tier || it.tier === state.tier) && (!state.asset || (it.assets || []).includes(state.asset)),
  );
}

function renderItem(it) {
  const title = it.kind === "intel"
    ? extLink(it.link, it.title) || escapeHtml(it.title)
    : `<a href="#${encodeURIComponent(it.ref)}" title="Open this CVE on the dashboard">${escapeHtml(it.title)}</a>`;
  const reasons = (it.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const meta = [it.kind === "cve" ? "CVE" : `News · ${it.source || ""}`, day(it.date)].join(" · ");
  return `<article class="card esc-card esc-card--${escapeHtml(it.tier)}">
    <div class="card__head">
      <h3 class="intel-card__title">${title}</h3>
      <span class="badge ${TIER_BADGE[it.tier] || ""}">${escapeHtml(TIER_LABEL[it.tier] || it.tier)}</span>
    </div>
    <p class="card__affected">${escapeHtml(meta)}</p>
    <div class="card__badges">
      <span class="badge ${CRIT_BADGE[it.criticality] || ""}" title="Highest criticality of the matched assets">${escapeHtml(it.criticality)} asset</span>
      ${(it.assets || []).map((a) => `<span class="badge badge--source">${escapeHtml(a)}</span>`).join("")}
    </div>
    <ul class="esc-reasons">${reasons}</ul>
  </article>`;
}

function render() {
  const list = visible();
  byId("esc-grid").innerHTML = list.map(renderItem).join("");
  byId("esc-empty").hidden = list.length > 0;
  const c = state.data.counts || {};
  byId("esc-count").textContent =
    `${list.length} shown · ${c.escalate || 0} escalate · ${c.work || 0} work`;
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
      lines.push(`   Link: ${it.kind === "cve" ? `${SITE}#${it.ref}` : it.link}`);
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

  const byCve = new Map(state.data.items.filter((it) => it.kind === "cve").map((it) => [it.ref, it]));
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
  render();
}
