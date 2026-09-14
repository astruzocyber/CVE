// Pre-paint theme init, extracted from an inline <script> in index.html so a
// strict Content-Security-Policy (script-src 'self' ...) can be enforced
// without an 'unsafe-inline' carve-out. Must stay tiny and synchronous
// (loaded via a blocking <script src> in <head>, before <link rel=stylesheet>)
// to avoid a flash of the wrong theme -- identical behavior to the inline
// version it replaces, just moved to a same-origin file.
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (!t) {
      t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    // localStorage/matchMedia unavailable (e.g. privacy mode) -- fall back to
    // the CSS default theme rather than breaking page load.
  }
})();
