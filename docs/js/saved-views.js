// Named filter presets stored in localStorage. Each view is { name, qs } where
// qs is the same query string a shared link uses (key unchanged from v1).

import { byId, storage } from "./dom.js";

const KEY = "cve_dashboard_saved_views_v1";
const MAX_VIEWS = 30;

export function loadViews() {
  const views = storage.getJson(KEY, []);
  return Array.isArray(views) ? views.filter((v) => v && typeof v.name === "string" && typeof v.qs === "string") : [];
}

const persist = (views) => storage.setJson(KEY, views);

export function saveView(name, qs) {
  const clean = name.trim().slice(0, 60);
  if (!clean) return false;
  const views = loadViews().filter((v) => v.name !== clean);
  views.unshift({ name: clean, qs });
  persist(views.slice(0, MAX_VIEWS));
  return true;
}

export function deleteView(name) {
  persist(loadViews().filter((v) => v.name !== name));
}

export const findView = (name) => loadViews().find((v) => v.name === name) ?? null;

export function renderViewsSelect(selected = "") {
  const select = byId("saved-views-select");
  select.replaceChildren(new Option("Saved views…", ""));
  for (const v of loadViews()) select.add(new Option(v.name, v.name));
  select.value = findView(selected) ? selected : "";
  byId("delete-view-btn").disabled = !select.value;
}
