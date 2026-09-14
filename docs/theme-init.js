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
    // Keep the browser chrome (address bar / task-switcher) color in sync
    // with the actual page theme on first paint -- the meta tag previously
    // had a single hardcoded dark value, so a light-theme visitor (explicit
    // choice or prefers-color-scheme: light) got a dark browser UI framing
    // a light page. #f5f7fa matches --bg in the light CSS block.
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute("content", t === "light" ? "#f5f7fa" : "#0b0f14");
  } catch (e) {
    // localStorage/matchMedia unavailable (e.g. privacy mode) -- fall back to
    // the CSS default theme rather than breaking page load.
  }
})();
