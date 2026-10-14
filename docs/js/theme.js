// Light/dark theme toggle. The initial theme is applied before first paint by
// theme-init.js (same "theme" storage key); this module only handles changes.

import { byId, storage } from "./dom.js";

const THEME_COLORS = { light: "#f5f7fa", dark: "#0b0f14" };

export const currentTheme = () => (document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");

function syncButton(theme) {
  const btn = byId("theme-toggle");
  const next = theme === "light" ? "dark" : "light";
  btn.setAttribute("aria-pressed", String(theme === "light"));
  btn.title = `Switch to ${next} theme (shortcut: t)`;
  btn.textContent = next === "light" ? "Light theme" : "Dark theme";
}

export function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLORS[theme]);
  storage.set("theme", theme);
  syncButton(theme);
}

export function initTheme(onChange) {
  syncButton(currentTheme());
  byId("theme-toggle").addEventListener("click", () => {
    setTheme(currentTheme() === "light" ? "dark" : "light");
    onChange?.();
  });
}
