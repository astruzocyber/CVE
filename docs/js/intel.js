// Threat-intel board: security news / advisories that have no CVE record yet
// or never will (social engineering, vendor update issues, exploited-in-the-
// wild reports). Data: data/intel.json, written by scripts/fetch_intel.py.
// Every tag shown is a deterministic keyword-rule hit on the article's own
// title/summary -- nothing is generated.
import { byId, escapeHtml, extLink, debounce } from "./dom.js";
import { findAlert } from "./state.js";

const PAGE = 24;
const state = { items: [], labels: {}, cat: "", prio: "", src: "", watchOnly: false, q: "", shown: PAGE };
const SEV_BADGE = { critical: "badge--critical", high: "badge--high", medium: "badge--medium", low: "badge--low" };

// A CVE chip jumps to the alert card when the dashboard tracks that CVE
// (deep-link format is #alert-<id>, see main.js revealHash); otherwise it
// opens the NVD record so the chip is never a dead link.
function cveLink(c) {
  const id = escapeHtml(c);
  if (findAlert(c)) return `<a class="tag" href="#alert-${encodeURIComponent(c)}" title="Jump to this CVE on the dashboard">${id}</a>`;
  return `<a class="tag tag--ext" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}" target="_blank" rel="noopener noreferrer" title="Not on the dashboard yet (no NVD match or filtered) - open NVD record">${id} ↗</a>`;
}

// Vendor advisory: per-CVE table copied from the vendor bulletin (severity
// and CVSS as the vendor rated them; blank where the bulletin didn't say).
function renderAdvisory(adv) {
  if (!adv || !adv.length) return "";
  const rows = adv.map((a) => `<tr>
      <td>${cveLink(a.cve)}</td>
      <td>${a.severity ? `<span class="badge ${SEV_BADGE[a.severity] || ""}">${escapeHtml(a.severity)}</span>` : "-"}</td>
      <td class="num">${a.cvss != null ? escapeHtml(String(a.cvss)) + (a.cvss_version ? `<span class="adv__ver"> v${escapeHtml(a.cvss_version)}</span>` : "") : "-"}</td>
      <td>${escapeHtml(a.description || "")}${a.fixed_in ? `<div class="adv__fix">Fixed in: ${escapeHtml(a.fixed_in)}</div>` : ""}</td>
    </tr>`).join("");
  return `<details class="adv"><summary>${adv.length} CVE${adv.length === 1 ? "" : "s"} in this bulletin (vendor ratings)</summary>
    <div class="table-wrap"><table class="adv__table">
      <thead><tr><th scope="col">CVE</th><th scope="col">Vendor severity</th><th scope="col" class="num">CVSS</th><th scope="col">Issue / fix</th></tr></thead>
      <tbody>${rows}</tbody></table></div></details>`;
}

const CAT_BADGE = {
  exploited: "badge--overdue",
  social_engineering: "badge--kev",
  vendor_issue: "badge--due-soon",
  ransomware: "badge--ransomware",
  identity: "badge--new",
  patch: "badge--fix",
  vulnerability: "badge--medium",
};
const PRIO_BADGE = { high: "badge--critical", medium: "badge--high", low: "badge--low" };

function fmtDate(iso) {
  if (!iso) return "date unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "date unknown";
  const hours = (Date.now() - d.getTime()) / 36e5;
  const rel = hours < 1 ? "<1h ago" : hours < 48 ? `${Math.round(hours)}h ago` : `${Math.round(hours / 24)}d ago`;
  return `${d.toISOString().slice(0, 10)} · ${rel}`;
}

function matches(it) {
  if (state.cat && !(it.categories || []).includes(state.cat)) return false;
  if (state.prio && it.priority !== state.prio) return false;
  if (state.src && it.source !== state.src) return false;
  if (state.watchOnly && !(it.watch_matches || []).length) return false;
  if (state.q) {
    const adv = (it.advisory || []).map((a) => `${a.description || ""} ${a.fixed_in || ""}`).join(" ");
    const hay = `${it.title} ${it.summary} ${it.source} ${(it.cve_ids || []).join(" ")} ${(it.watch_matches || []).join(" ")} ${adv}`.toLowerCase();
    if (!state.q.split(/\s+/).every((w) => hay.includes(w))) return false;
  }
  return true;
}

function renderItem(it) {
  const cats = (it.categories || [])
    .map((c) => `<span class="badge ${CAT_BADGE[c] || ""}">${escapeHtml(state.labels[c] || c)}</span>`)
    .join("");
  const isAdv = it.kind === "advisory";
  const advBadge = isAdv
    ? `<span class="badge badge--advisory" title="Official vendor security bulletin">Vendor advisory</span>` +
      (it.advisory_severity ? `<span class="badge ${SEV_BADGE[it.advisory_severity] || ""}" title="Highest vendor-rated severity in this bulletin">max ${escapeHtml(it.advisory_severity)}</span>` : "")
    : "";
  // advisory CVEs are listed in the table instead of as loose chips
  const cves = (isAdv && (it.advisory || []).length ? [] : it.cve_ids || []).map(cveLink).join("");
  const watch = (it.watch_matches || []).length
    ? `<p class="card__affected">Matches your watchlist: ${escapeHtml(it.watch_matches.slice(0, 6).join(", "))}</p>`
    : "";
  const also = (it.also_reported_by || []).length
    ? ` · also: ${escapeHtml(it.also_reported_by.join(", "))}`
    : "";
  return `<article class="card intel-card card--${it.priority === "high" ? "critical" : it.priority === "medium" ? "high" : "low"}">
    <div class="card__head">
      <h3 class="intel-card__title">${extLink(it.link, it.title) || escapeHtml(it.title)}</h3>
      <span class="badge ${PRIO_BADGE[it.priority] || ""}" title="Rule score ${Number(it.score) || 0}/100">${escapeHtml(it.priority)}</span>
    </div>
    <p class="card__affected">${escapeHtml(it.source)}${also} · ${escapeHtml(fmtDate(it.published || it.first_seen))}</p>
    <div class="card__badges">${advBadge}${cats}</div>
    ${it.summary ? `<p class="card__desc">${escapeHtml(it.summary)}</p>` : ""}
    ${isAdv ? renderAdvisory(it.advisory) : ""}
    ${watch}
    ${cves ? `<div class="card__tags">${cves}</div>` : ""}
  </article>`;
}

function render() {
  const list = state.items.filter(matches);
  const grid = byId("intel-grid");
  grid.innerHTML = list.slice(0, state.shown).map(renderItem).join("");
  byId("intel-count").textContent = `${list.length} of ${state.items.length} items`;
  const more = byId("intel-more");
  more.hidden = list.length <= state.shown;
  byId("intel-empty").hidden = list.length > 0;
}

function renderCatChips() {
  const counts = {};
  for (const it of state.items) for (const c of it.categories || []) counts[c] = (counts[c] || 0) + 1;
  const order = ["exploited", "social_engineering", "vendor_issue", "identity", "ransomware", "patch", "vulnerability"];
  const sel = byId("intel-cat");
  sel.innerHTML = `<option value="">All categories</option>` + order
    .filter((c) => counts[c])
    .map((c) => `<option value="${c}">${escapeHtml(state.labels[c] || c)} (${counts[c]})</option>`)
    .join("");
}

function renderSourceSelect() {
  const counts = {};
  for (const it of state.items) counts[it.source] = (counts[it.source] || 0) + 1;
  const adv = new Set(state.items.filter((i) => i.kind === "advisory").map((i) => i.source));
  // vendor advisory sources first, then news by volume
  const names = Object.keys(counts).sort((a, b) => (adv.has(b) - adv.has(a)) || counts[b] - counts[a] || a.localeCompare(b));
  byId("intel-src").innerHTML = `<option value="">All sources</option>` +
    names.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)} (${counts[n]})</option>`).join("");
}

function renderFeedHealth(feeds, generatedAt) {
  const ok = (feeds || []).filter((f) => f.ok).length;
  const bad = (feeds || []).filter((f) => !f.ok).map((f) => f.name);
  byId("intel-hint").textContent =
    `${ok}/${(feeds || []).length} feeds OK · updated ${fmtDate(generatedAt)}` + (bad.length ? ` · unavailable: ${bad.join(", ")}` : "");
}

export async function initIntel() {
  const section = byId("intel-section");
  if (!section) return;
  let data;
  try {
    const res = await fetch("data/intel.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch {
    return; // board stays hidden; CVE dashboard unaffected
  }
  if (!data || !Array.isArray(data.items)) return;
  state.items = data.items;
  state.labels = data.category_labels || {};
  section.hidden = false;
  renderCatChips();
  renderSourceSelect();
  renderFeedHealth(data.feeds, data.generated_at);

  const reset = () => { state.shown = PAGE; render(); };
  byId("intel-cat").addEventListener("change", (e) => { state.cat = e.target.value; reset(); });
  byId("intel-prio").addEventListener("change", (e) => { state.prio = e.target.value; reset(); });
  byId("intel-src").addEventListener("change", (e) => { state.src = e.target.value; reset(); });
  byId("intel-watch").addEventListener("change", (e) => { state.watchOnly = e.target.checked; reset(); });
  byId("intel-q").addEventListener("input", debounce((e) => { state.q = e.target.value.trim().toLowerCase(); reset(); }, 150));
  byId("intel-more").addEventListener("click", () => { state.shown += PAGE; render(); });
  render();
}
