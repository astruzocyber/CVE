// Minimal service worker for the CVE/KEV/Dependabot Alert Dashboard PWA.
//
// Why: manifest.webmanifest has existed since an early cycle (display:
// standalone, icons, start_url) but a manifest alone does NOT make a site
// installable/offline-capable in any browser that implements the PWA
// installability checklist (Chrome/Edge/Android require a registered
// service worker with a fetch handler; Firefox/Safari treat it as a
// prerequisite for "add to home screen" reliability) -- so the existing
// manifest was inert scaffolding. This closes that gap with the smallest
// safe implementation for a data-freshness-sensitive dashboard.
//
// Strategy, deliberately conservative given this site's nature (vulnerability
// data that must never be silently served stale from a cache without the
// user knowing):
//   - docs/data/*.json, feed.json, feed.xml: NETWORK-ONLY, never cached.
//     These change every ~4h and staleness is already surfaced via the
//     stale-data banner (cycle 9) which reads a live fetch of stats.json --
//     caching them here would defeat that mechanism and could show a visitor
//     confidently-wrong vulnerability data while offline with no warning.
//   - Static shell (index.html, app.js, style.css, theme-init.js,
//     manifest.webmanifest, icons): NETWORK-FIRST with a versioned cache
//     fallback. A visitor with a live connection always gets the current
//     file (never stuck on a stale cached JS bug fix); only when the network
//     request fails entirely (offline) does the cache serve as a fallback,
//     so the shell still loads for a repeat visitor with no connectivity,
//     just without fresh vulnerability data (data fetches will simply fail,
//     which the existing frontend already handles as an empty/error state).
//   - Cache versioned by CACHE_NAME; activate() purges any old-version
//     caches so a deploy never accumulates stale shell files indefinitely.
const CACHE_NAME = "cve-dashboard-shell-v1";
const SHELL_ASSETS = [
  "./",
  "./index.html",
  "./app.js",
  "./style.css",
  "./theme-init.js",
  "./manifest.webmanifest",
];

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS).catch(() => {}))
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // never intercept cross-origin (CDN, links)

  // Never cache data endpoints -- always hit the network so vulnerability
  // data is never served stale without the existing staleness banner logic
  // (which itself depends on a live fetch) getting a chance to evaluate it.
  if (url.pathname.includes("/data/") || url.pathname.endsWith("feed.json") || url.pathname.endsWith("feed.xml")) {
    event.respondWith(fetch(req).catch(() => new Response("", { status: 503 })));
    return;
  }

  // Network-first for the static shell, falling back to cache only when
  // fully offline (fetch throws) -- never serves a stale shell file over a
  // live connection.
  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(req).then((cached) => cached || Response.error()))
  );
});
