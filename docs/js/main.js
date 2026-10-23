// Entry point: loads data, wires every control, and renders.
// All rendering goes through render(); all events are delegated where the
// target set is dynamic (cards, rows, chips), so nothing is re-bound per paint.

import { byId, debounce, toast, copyText, prefersReducedMotion, storage } from "./dom.js";
import { state, PAGE_SIZE, buildSearchIndex, findAlert } from "./state.js";
import {
  readFilters, setFilter, resetFilters, applyQueryString, toQueryString, syncUrl, countAdvanced, activeFilterChips,
  filterAndSort, SORT_IS_ASCENDING, dropFromResults,
} from "./filters.js";
import { toggleReviewed, markReviewed, countReviewed, exportReviewedState, importReviewedState, isReviewed } from "./reviewed.js";
import { readDependencies } from "./deps.js";
import { renderCard } from "./render-card.js";
import { renderRow } from "./render-table.js";
import { renderOverview, renderBreakdowns, renderFreshness } from "./overview.js";
import { exportCsv, exportJson, exportMarkdown, alertToMarkdown, suppressionSnippet } from "./export.js";
import { initTheme } from "./theme.js";
import { initTrend, refreshTrendTheme } from "./trend.js";
import { saveView, deleteView, findView, renderViewsSelect } from "./saved-views.js";
import { initIntel } from "./intel.js";
import { initEscalations } from "./escalations.js";
import { alertIdFromHash, deepLinkOffTarget } from "./format.js";

const VIEW_KEY = "viewMode";

/* ---------- rendering ---------- */

function renderActiveFilters(values) {
  const list = byId("active-filters");
  const chips = activeFilterChips(values);
  list.replaceChildren(...chips.map(({ key, text }) => {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "filter-chip";
    btn.dataset.clear = key;
    btn.setAttribute("aria-label", `Remove filter: ${text}`);
    btn.textContent = `${text} ×`;
    li.append(btn);
    return li;
  }));
  list.hidden = chips.length === 0;
  const n = countAdvanced(values);
  const badge = byId("filters-badge");
  badge.textContent = String(n);
  badge.hidden = n === 0;
}

function renderSortIndicators(sort) {
  for (const btn of document.querySelectorAll(".th-sort")) {
    const active = btn.dataset.sort === sort;
    btn.closest("th").setAttribute("aria-sort", active ? (SORT_IS_ASCENDING.has(sort) ? "ascending" : "descending") : "none");
  }
}

function paint() {
  const { filtered, alerts, view } = state;
  const shown = Math.min(state.visible, filtered.length);
  const slice = filtered.slice(0, shown);
  const isTable = view === "table";

  byId("card-grid").hidden = isTable;
  byId("table-view-wrapper").hidden = !isTable;
  if (isTable) {
    byId("alerts-table-body").innerHTML = slice.map(renderRow).join("");
    byId("card-grid").replaceChildren();
  } else {
    byId("card-grid").innerHTML = slice.map(renderCard).join("");
    byId("alerts-table-body").replaceChildren();
  }

  byId("result-count").textContent = `${filtered.length} of ${alerts.length} alerts`;
  byId("empty-state").hidden = filtered.length > 0;
  const pager = byId("pager");
  pager.hidden = shown >= filtered.length;
  byId("pager-status").textContent = `Showing ${shown} of ${filtered.length}`;

  const reviewed = countReviewed(alerts);
  byId("reviewed-progress").textContent = alerts.length ? `Reviewed ${reviewed} of ${alerts.length} (${Math.round((reviewed / alerts.length) * 100)}%)` : "";

  const toggle = byId("view-toggle");
  toggle.textContent = isTable ? "Card view" : "Table view";
  toggle.setAttribute("aria-pressed", String(isTable));
}

/** Re-filter + re-sort, reset paging, sync URL, paint. */
function render() {
  const values = readFilters();
  state.filtered = filterAndSort(values);
  state.visible = PAGE_SIZE[state.view];
  syncUrl(values);
  renderActiveFilters(values);
  renderSortIndicators(values.sort);
  paint();
}

/** Repaint without re-filtering (reviewed toggles, paging, view switch). */
function repaintKeepingScroll() {
  const y = window.scrollY;
  paint();
  window.scrollTo(0, y);
}

/* ---------- deep links (#alert-CVE-…) ---------- */

function revealHash() {
  const cve = alertIdFromHash(location.hash);
  if (!cve) return;
  const id = `alert-${cve}`;
  const hashNow = location.hash;
  const index = state.filtered.findIndex((a) => a.cve_id === cve);
  if (index === -1) {
    if (findAlert(cve)) toast(`${cve} is hidden by the current filters`);
    return;
  }
  if (state.view !== "cards") setView("cards", false);
  if (index >= state.visible) {
    state.visible = index + 1;
    paint();
  }
  const card = document.getElementById(id);
  if (!card) return;
  card.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
  // Trend chart / intel / escalation panels above the board finish loading
  // after this and push the card down; re-aim once layout has settled.
  for (const ms of [800, 2000, 4000]) {
    setTimeout(() => {
      if (location.hash !== hashNow) return;
      const r = card.getBoundingClientRect();
      if (deepLinkOffTarget(r.top)) card.scrollIntoView({ behavior: "auto", block: "start" });
    }, ms);
  }
  card.classList.add("is-highlighted");
  setTimeout(() => card.classList.remove("is-highlighted"), 2500);
}

/* ---------- view ---------- */

function setView(view, persist = true) {
  state.view = view === "table" ? "table" : "cards";
  state.visible = Math.max(state.visible, PAGE_SIZE[state.view]);
  if (persist) storage.set(VIEW_KEY, state.view);
  paint();
}

/* ---------- events ---------- */

const KPI_FILTERS = {
  total: () => {},
  critical: () => setFilter("sev", "critical"),
  kev: () => setFilter("kev", "kev"),
  overdue: () => setFilter("kev", "overdue"),
  "due-soon": () => setFilter("kev", "due-soon"),
  ransomware: () => setFilter("kev", "ransomware"),
  new: () => setFilter("newOnly", true),
  rejected: () => setFilter("hideRejected", true),
};

function closeMenus(except) {
  for (const m of document.querySelectorAll("details.menu[open]")) if (m !== except) m.open = false;
}

function scrollToResults() {
  byId("alerts-title").scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
}

async function handleCardAction(btn) {
  const cve = btn.dataset.cve || btn.closest("[data-cve]")?.dataset.cve;
  const alert = cve ? findAlert(cve) : null;
  switch (btn.dataset.action) {
    case "toggle-reviewed": {
      if (!alert) return;
      const now = toggleReviewed(cve);
      let focusId = cve;
      if (readFilters().hideReviewed && now) {
        // Drop just this alert and keep the analyst's place: a full re-filter
        // reset paging to page 1, so marking card #120 jumped the page and
        // un-rendered the next card to review.
        const { list, nextId } = dropFromResults(state.filtered, cve);
        state.filtered = list;
        focusId = nextId;
      }
      repaintKeepingScroll();
      if (focusId) document.querySelector(`[data-action="toggle-reviewed"][data-cve="${CSS.escape(focusId)}"]`)?.focus({ preventScroll: true });
      break;
    }
    case "copy-link":
      await copyText(`${location.origin}${location.pathname}#alert-${cve}`, "Link copied");
      break;
    case "copy-md":
      if (alert) await copyText(alertToMarkdown(alert), "Markdown copied");
      break;
    case "copy-yaml":
      if (alert) await copyText(suppressionSnippet(alert), "Suppression entry copied");
      break;
    case "toggle-breakdown": {
      const panel = document.getElementById(btn.getAttribute("aria-controls"));
      if (!panel) return;
      const open = btn.getAttribute("aria-expanded") !== "true";
      btn.setAttribute("aria-expanded", String(open));
      panel.hidden = !open;
      break;
    }
    default:
      break;
  }
}

function applyDependencies(text) {
  const { names, message } = readDependencies(text, Boolean(state.depPackages));
  byId("dep-status").textContent = message;
  if (!names) return;
  state.depPackages = names;
  render();
}

function clearDependencies() {
  state.depPackages = null;
  byId("dep-file-input").value = "";
  byId("dep-text-input").value = "";
  byId("dep-status").textContent = "";
}

function resetAll() {
  resetFilters();
  clearDependencies();
  renderViewsSelect();
  render();
}

function openShortcuts() {
  const modal = byId("shortcuts-modal");
  modal.hidden = false;
  byId("shortcuts-modal-close").focus();
}

function closeShortcuts() {
  const modal = byId("shortcuts-modal");
  if (modal.hidden) return false;
  modal.hidden = true;
  byId("kbd-hint-btn").focus();
  return true;
}

function bindEvents() {
  const debounced = debounce(render, 200);
  byId("search").addEventListener("input", debounced);
  for (const id of ["kev-filter", "severity-filter", "source-filter", "sort-by", "new-only", "has-fix-only", "hide-reviewed", "hide-rejected"]) {
    byId(id).addEventListener("change", render);
  }
  for (const id of ["min-risk", "min-epss"]) byId(id).addEventListener("input", debounced);

  byId("stats-bar").addEventListener("click", (e) => {
    const tile = e.target.closest("[data-kpi]");
    if (!tile) return;
    resetFilters();
    clearDependencies();
    KPI_FILTERS[tile.dataset.kpi]?.();
    render();
    scrollToResults();
  });

  byId("main").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-filter]");
    if (chip) {
      setFilter(chip.dataset.filter, chip.dataset.value);
      render();
      scrollToResults();
      return;
    }
    const clear = e.target.closest("[data-clear]");
    if (clear) {
      if (clear.dataset.clear === "deps") clearDependencies();
      else setFilter(clear.dataset.clear, undefined); // undefined resets the control to its default
      render();
      return;
    }
    const action = e.target.closest("[data-action]");
    if (action) {
      handleCardAction(action);
      return;
    }
    const sortBtn = e.target.closest(".th-sort");
    if (sortBtn) {
      setFilter("sort", sortBtn.dataset.sort);
      render();
    }
  });

  byId("show-more").addEventListener("click", () => {
    state.visible += PAGE_SIZE[state.view];
    repaintKeepingScroll();
  });
  byId("show-all").addEventListener("click", () => {
    state.visible = state.filtered.length;
    repaintKeepingScroll();
  });

  byId("view-toggle").addEventListener("click", () => setView(state.view === "table" ? "cards" : "table"));
  byId("reset-filters").addEventListener("click", resetAll);
  byId("empty-reset").addEventListener("click", resetAll);

  const panel = byId("filters-panel");
  byId("filters-toggle").addEventListener("click", (e) => {
    panel.hidden = !panel.hidden;
    e.currentTarget.setAttribute("aria-expanded", String(!panel.hidden));
  });

  // Menus: one open at a time, close on outside click, close after choosing.
  for (const menu of document.querySelectorAll("details.menu")) {
    menu.addEventListener("toggle", () => menu.open && closeMenus(menu));
    menu.addEventListener("click", (e) => {
      if (e.target.closest("button.menu__item")) menu.open = false;
    });
  }
  document.addEventListener("click", (e) => {
    if (!e.target.closest("details.menu")) closeMenus();
  });

  byId("export-csv").addEventListener("click", () => exportCsv(state.filtered));
  byId("export-json").addEventListener("click", () => exportJson(state.filtered));
  byId("export-md-report").addEventListener("click", () => exportMarkdown(state.filtered));
  byId("print-view").addEventListener("click", () => {
    state.visible = state.filtered.length;
    paint();
    window.print();
  });

  byId("mark-filtered-reviewed").addEventListener("click", () => {
    const pending = state.filtered.filter((a) => !isReviewed(a.cve_id));
    if (!pending.length) {
      toast("Everything in this view is already reviewed");
      return;
    }
    if (!window.confirm(`Mark ${pending.length} alert(s) as reviewed?`)) return;
    markReviewed(pending.map((a) => a.cve_id));
    render();
    toast(`Marked ${pending.length} alert(s) as reviewed`);
  });
  byId("export-reviewed").addEventListener("click", exportReviewedState);
  byId("import-reviewed-input").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    const status = byId("import-reviewed-status");
    if (!file) return;
    closeMenus();
    try {
      status.textContent = await importReviewedState(file);
    } catch (err) {
      status.textContent = err.message;
    }
    status.hidden = false;
    e.target.value = "";
    render();
  });

  const views = byId("saved-views-select");
  views.addEventListener("change", () => {
    const view = findView(views.value);
    byId("delete-view-btn").disabled = !view;
    if (!view) return;
    applyQueryString(view.qs);
    render();
  });
  byId("save-view-btn").addEventListener("click", () => {
    const name = window.prompt("Name this view:", views.value || "");
    if (name === null) return;
    if (!saveView(name, toQueryString())) {
      toast("A view needs a name");
      return;
    }
    renderViewsSelect(name.trim().slice(0, 60));
    toast("View saved");
  });
  byId("delete-view-btn").addEventListener("click", () => {
    if (!views.value) return;
    deleteView(views.value);
    renderViewsSelect();
    toast("View deleted");
  });

  byId("dep-apply-btn").addEventListener("click", async () => {
    const file = byId("dep-file-input").files?.[0];
    const text = file ? await file.text() : byId("dep-text-input").value;
    applyDependencies(text);
  });
  byId("dep-clear-btn").addEventListener("click", () => {
    clearDependencies();
    render();
  });

  byId("kbd-hint-btn").addEventListener("click", openShortcuts);
  byId("shortcuts-modal-close").addEventListener("click", closeShortcuts);
  byId("shortcuts-modal").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeShortcuts();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (closeShortcuts()) return;
      closeMenus();
      if (document.activeElement instanceof HTMLElement && document.activeElement.matches("input, select, textarea")) {
        document.activeElement.blur();
      }
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target instanceof HTMLElement && e.target.matches("input, select, textarea, [contenteditable]")) return;
    switch (e.key) {
      case "/":
        e.preventDefault();
        byId("search").focus();
        break;
      case "r":
        resetAll();
        break;
      case "t":
        byId("theme-toggle").click();
        break;
      case "v":
        byId("view-toggle").click();
        break;
      case "?":
        if (!closeShortcuts()) openShortcuts();
        break;
      default:
        break;
    }
  });

  window.addEventListener("hashchange", revealHash);
}

/* ---------- boot ---------- */

async function fetchJson(url) {
  const res = await fetch(url, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

function showLoadError(err) {
  byId("last-updated").textContent = "Could not load alert data.";
  const empty = byId("empty-state");
  empty.querySelector(".empty-state__title").textContent = `Alert data failed to load (${err.message}). Reload the page or try again later.`;
  empty.hidden = false;
  byId("result-count").textContent = "";
}

async function main() {
  initTheme(refreshTrendTheme);
  state.view = storage.get(VIEW_KEY) === "table" ? "table" : "cards";
  applyQueryString(location.search);
  renderViewsSelect();
  bindEvents();

  let alerts;
  try {
    alerts = await fetchJson("data/alerts.json");
    if (!Array.isArray(alerts)) throw new Error("data/alerts.json is not a list");
  } catch (err) {
    showLoadError(err);
    return;
  }
  state.stats = await fetchJson("data/stats.json").catch(() => null);
  // stats.json is regenerated with alerts.json; if the two disagree, derive from alerts instead.
  if (state.stats && state.stats.total_alerts !== alerts.length) state.stats = null;

  state.alerts = alerts;
  state.searchIndex = buildSearchIndex(alerts);

  renderFreshness(state.stats?.generated_at, alerts.length);
  renderOverview(alerts, state.stats);
  renderBreakdowns(alerts, state.stats);
  render();
  revealHash();
  initTrend();
  initIntel();
  // initEscalations re-renders once its data arrives, and render() resets
  // paging to page 1 -- which un-rendered a deep-linked card past page 1
  // (#alert-CVE-… from a shared link or a news-card CVE chip). Re-apply the
  // hash after that re-render.
  initEscalations(alerts, () => { render(); revealHash(); });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  }
}

main();
