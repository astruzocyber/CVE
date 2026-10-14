// Small, dependency-free DOM and browser utilities shared by every module.

/** document.getElementById shorthand. scripts/validate_data.py checks every
 *  byId("...") literal against index.html, so keep ids as string literals. */
export const byId = (id) => document.getElementById(id);

const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape any value for safe interpolation into HTML text or a quoted attribute. */
export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/** Return an escaped http(s) URL, or null for anything else (javascript:, data:, junk). */
export function safeUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === "https:" || url.protocol === "http:" ? escapeHtml(url.href) : null;
  } catch {
    return null;
  }
}

/** External link markup with consistent rel/target; empty string if the URL is unsafe. */
export function extLink(url, label, title = "") {
  const href = safeUrl(url);
  if (!href) return "";
  const t = title ? ` title="${escapeHtml(title)}"` : "";
  return `<a href="${href}" target="_blank" rel="noopener noreferrer"${t}>${escapeHtml(label)}</a>`;
}

export function debounce(fn, ms) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/** localStorage wrapper that never throws (private mode, quota, corrupted JSON). */
export const storage = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? fallback : raw;
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* storage unavailable: feature degrades to session-only */
    }
  },
  getJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch {
      return fallback;
    }
  },
  setJson(key, value) {
    this.set(key, JSON.stringify(value));
  },
};

export function downloadBlob(content, type, filename) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next task so every browser has started the download.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export const todayStamp = () => new Date().toISOString().slice(0, 10);

let toastTimer = null;
/** Brief, screen-reader-announced status message. */
export function toast(message) {
  const el = byId("toast");
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 2600);
}

/** Copy text to the clipboard and always tell the user whether it worked. */
export async function copyText(text, successMessage = "Copied to clipboard") {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard API unavailable");
    await navigator.clipboard.writeText(text);
    toast(successMessage);
    return true;
  } catch {
    toast("Copy failed. Your browser blocked clipboard access.");
    return false;
  }
}

export const prefersReducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
