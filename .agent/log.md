# Autonomous improvement agent log

This file is appended once per 30-minute cycle by the recurring cron job.
State machine lives in .agent/state.json (consecutive_no_improvement counter,
full implemented/rejected history). Do not hand-edit; the agent owns this file.

---

## Cycle 1 — 2026-09-09T02:00:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
(all `completed`/`success`, 44s-89s runtimes). Grepped logs for warnings/errors/
429/throttle signals excluding known-benign Node 20 deprecation noise — none
found. All sources (CISA KEV, NVD, FIRST.org EPSS, GHSA) healthy, no backoff
signals. Proceeded with normal candidate search.

**Implemented:** Retry-with-backoff on `fetch_kev()` and `fetch_epss()` in
`scripts/aggregate.py`. Both previously made a single bare HTTP attempt with no
retry, unlike `nvd_query()` which already retries 3x with exponential backoff on
429/5xx. A transient failure on either call would silently zero out KEV status
(losing the +25 risk-score bonus applied to every KEV-listed alert) or EPSS
scores (40% weight in the composite risk score) for the entire run, degrading
scoring accuracy with no visible error — a pure reliability/accuracy fix, zero
new dependencies, zero added API call volume under normal conditions (extra
calls only fire on genuine failure). Scored 5/5/5 on feasibility/risk/value:
free (no new API usage), low validation risk (mirrors an existing, proven
pattern in the same file), directly serves the "accuracy over feature breadth"
priority.

Validation performed: `ast.parse` syntax check passed. Backed up
`docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`,
`docs/feed.{json,xml}`, `docs/data/kev_snapshot.json` to `/tmp/cve_backup`,
then ran `scripts/aggregate.py` for real against live APIs (LOOKBACK_DAYS=2):
KEV catalog 1699 entries, 587 NVD candidates, EPSS batch queried, 432 total
alerts written, 0 schema warnings, clean exit. Also unit-verified the new
retry branch specifically by monkey-patching `http_get_json` to raise a
synthetic HTTP 503 on the first CISA KEV call — confirmed the code logged
"retrying in 5s (attempt 1/3)" and succeeded on the second attempt (1699
entries returned). Ran `git checkout --` on all throwaway local test-run data
files afterward so no test output touched committed production data (the
live Actions run regenerates real data after push). No frontend files
changed, so no local server/browser validation was needed.

Committed as `f4428be`, pushed to main, triggered
`gh workflow run cve-alerts.yml` (run 34301343226) — completed `success` in
~50s with no new warnings/errors (only the pre-existing benign Node 20
deprecation notice). Pulled latest and curled the live site:
`https://astruzocyber.github.io/CVE/` → 200,
`https://astruzocyber.github.io/CVE/data/stats.json` → 200. Live verification
passed; no revert needed.

**Rejected this cycle:** none — the one candidate identified cleared the bar
and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles = 0/3.
Not stopped. Next cycle in ~30 minutes.

---

## Cycle 2 — 2026-09-09T02:38:03Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
(all `completed`/`success`, 52s-1m29s runtimes). Grepped the latest run's logs
for warnings/errors/429/throttle signals excluding known-benign Node 20
deprecation noise — none found. All sources (CISA KEV, NVD, FIRST.org EPSS,
GHSA, Dependabot) healthy, no backoff signals observed.

**Implemented:** Retry-with-backoff on `fetch_dependabot_alerts()`'s per-page
HTTP fetch in `scripts/aggregate.py`. After cycle 1's fix to `fetch_kev()`/
`fetch_epss()`, this was the last remaining external call in the pipeline
still making a single bare attempt with no retry, unlike `nvd_query()` and the
now-fixed KEV/EPSS calls. `dependabot_repos` in `config/watchlist.yaml`
actively lists `astruzocyber/CVE` (not a dead/example config path), so a
transient 429/5xx/network blip on any page mid-pagination would silently
truncate or drop that repo's Dependabot alerts for the entire run with no
visible error. Added the same 3-attempt exponential-backoff pattern already
proven in cycle 1: 429/5xx retried with increasing backoff, other HTTP status
codes and exhausted-retry cases still log a WARNING and end pagination for
that repo (matching prior behavior on genuinely unrecoverable failure — no
change to what counts as a hard stop, only added resilience to transient
ones). Scored 5/5/5 on feasibility/risk/value: free (no new API usage, retries
only fire on actual failure), low validation risk (mirrors an existing proven
pattern in the same file, touches only one function), improves data
completeness which the user explicitly prioritizes over feature breadth.

Validation performed: `ast.parse` syntax check passed. Backed up
`docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`,
`docs/feed.{json,xml}`, `docs/data/kev_snapshot.json` to `/tmp/cve_backup`,
then ran `scripts/aggregate.py` for real against live APIs (LOOKBACK_DAYS=2,
using a real Dependabot-scoped token via `gh auth token` so the modified code
path was genuinely exercised, not skipped): KEV catalog 1699 entries, 587 NVD
candidates, Dependabot query for astruzocyber/CVE executed cleanly (0 open
alerts — expected, no crash/warning), EPSS batch queried, 432 total alerts
written, 0 schema warnings, clean exit. Ran `git checkout --` on the
throwaway local test-run data files (`trend.csv`, `stats.json`) afterward so
no test output touched committed production data (the live Actions run
regenerates real data after push). No frontend files changed, so no local
server/browser validation was needed.

Committed as `8e94e2d`, pushed to main, triggered
`gh workflow run cve-alerts.yml` (run 34303991054) — completed `success` in
1m3s with no new warnings/errors (only the pre-existing benign Node 20
deprecation notice). Pulled latest and curled the live site:
`https://astruzocyber.github.io/CVE/` → 200,
`https://astruzocyber.github.io/CVE/data/stats.json` → 200. Live verification
passed; no revert needed.

**Rejected this cycle:** none — the one candidate identified cleared the bar
and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles = 0/3.
Not stopped. Next cycle in ~30 minutes.

---

## Cycle 3 — 2026-09-09T03:20:57Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
(all `completed`/`success`, 52s-1m29s runtimes). Grepped the latest run's logs
for warnings/errors/429/throttle signals excluding known-benign Node 20
deprecation noise — none found. All sources (CISA KEV, NVD, FIRST.org EPSS,
GHSA, Dependabot) healthy, no backoff signals observed.

**Implemented:** Retry-with-backoff on `fetch_ghsa_advisories()`'s per-package
HTTP fetch in `scripts/aggregate.py`. This was the last remaining external
call in the pipeline still making a single bare attempt with no retry, after
cycles 1-2 already brought `fetch_kev()`/`nvd_query()`/`fetch_epss()`/
`fetch_dependabot_alerts()` up to the same 3-attempt exponential-backoff
pattern. `ghsa_packages` is currently empty in `config/watchlist.yaml`, so
this function is a no-op in the live pipeline today, but it is live
production code that activates the moment the user adds a package name —
leaving it as the one unretried path was an inconsistency that would
silently degrade data completeness the day it's actually used. Added the
identical pattern: 429/5xx retried with increasing backoff, other HTTP status
codes and exhausted retries logged as a WARNING and skip that package
(matching prior behavior on genuinely unrecoverable failure). Scored 5/5/5 on
feasibility/risk/value: free (no new API usage, retries only fire on actual
failure), low validation risk (mirrors an existing proven pattern, touches
only one function), completes the reliability layer across every external
source the pipeline can call.

Validation performed: `ast.parse` and `yaml.safe_load` syntax checks passed.
Backed up `docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`,
`docs/feed.{json,xml}`, `docs/data/kev_snapshot.json` to `/tmp/cve_backup`,
then ran `scripts/aggregate.py` for real against live APIs (LOOKBACK_DAYS=2,
using a real Dependabot-scoped token via `gh auth token`): KEV catalog 1699
entries, 593 NVD candidates, Dependabot query for astruzocyber/CVE executed
cleanly (0 open alerts), EPSS batch queried, 436 total alerts written, 0
schema warnings, clean exit, no crash. GHSA path itself wasn't exercised
(empty `ghsa_packages` list means the function returns early with no
network calls either before or after this change), but the modified code is
syntactically valid and structurally identical to the already-proven pattern
in the other three functions. Ran `git checkout --` on the throwaway
local test-run data files afterward so no test output touched committed
production data.

Committed as `d92b1de`, pushed to main, triggered `gh workflow run
cve-alerts.yml` (run 34306771292) — completed `success` in 1m8s with no new
warnings/errors (only the pre-existing benign Node 20 deprecation notice).
Pulled latest and curled the live site: `https://astruzocyber.github.io/CVE/`
→ 200, `https://astruzocyber.github.io/CVE/data/stats.json` → 200. No
frontend files changed, so no browser/screenshot check was needed. Live
verification passed; no revert needed.

**Rejected this cycle:** none — the one candidate identified cleared the bar
and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles = 0/3.
Not stopped. Next cycle in ~30 minutes.

---

## Cycle 4 — 2026-09-09T03:52:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
(all `completed`/`success`, 52s-1m16s runtimes, including one scheduled run).
No warnings/errors/429/throttle signals found excluding benign Node 20
deprecation noise. All sources (CISA KEV, NVD, FIRST.org EPSS, GHSA,
Dependabot) healthy.

**Implemented:** Accessibility labels/aria-attributes on the dashboard's
filter controls (`docs/index.html`, `docs/app.js`, `docs/style.css`). The
search input and three `<select>` filters (KEV status, source, sort order)
had no accessible name beyond a visual placeholder; the per-card
"breakdown" toggle button never announced expanded/collapsed state. Added
visually-hidden `<label>`s (new `.visually-hidden` CSS utility, standard
clip-based off-screen pattern) paired with `aria-label` on each control,
`role="status"` on the empty-state message, `aria-live="polite"` on the
result count, and `aria-expanded` wired to the breakdown toggle's actual
state. Scored 5/5/5: zero-cost (pure static markup/CSS/JS, no new
dependency, no API calls), low validation risk (purely additive attributes,
no visual change), decent value (screen-reader usability was previously
untested and had real gaps on a public dashboard).

Validation performed: `node --check docs/app.js` passed. Served `docs/` on
local port 8791, loaded in browser tool, screenshotted card grid — cards,
badges, breakdown toggles all render identically to before (visually-hidden
labels are off-screen, no layout change confirmed). No Python files changed,
so no pipeline backup/re-run was needed for this cycle.

Committed as `23a0e81`, pushed to main. Frontend-only change, so no
`cve-alerts.yml` workflow run needed — GitHub Pages redeploys `docs/`
automatically on push to main. Waited ~40s, curled the live URLs:
`https://astruzocyber.github.io/CVE/` → 200, `/app.js` → 200, `/style.css`
→ 200, and confirmed `aria-label` count in the live `index.html` matches the
local version (4). Loaded the LIVE dashboard in the browser tool and
screenshotted: stats bar, historical trend chart, and filter section all
render correctly with real production data (436 total alerts, 101 critical,
1 in KEV). Live verification passed; no revert needed.

**Rejected this cycle:** none — the one candidate identified cleared the bar
and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles = 0/3.
Not stopped. Next cycle in ~30 minutes.

---

## Cycle 5 — 2026-09-09T04:30:13Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
(all `completed`/`success`, 55s-1m22s runtimes). No warnings/errors/429/throttle
signals found excluding benign Node 20 deprecation noise. All sources (CISA KEV,
NVD, FIRST.org EPSS, GHSA, Dependabot, GitHub Issues) healthy.

**Implemented:** Retry with backoff on GitHub Issue creation
(`scripts/notify_github_issues.py`, `create_issue()`). This was the last
remaining external HTTP call in the entire pipeline still making a single bare
attempt, after cycles 1-3 already added the same 3-attempt exponential-backoff
pattern to every fetch function in `scripts/aggregate.py`. A transient 429/5xx
from the GitHub Issues API would previously drop a vulnerability notification
silently for the rest of the run with no retry. Added the identical
429/5xx-retried, other-errors-logged-and-skipped pattern, closing the
reliability layer across the whole codebase. Scored 5/5/5: zero-cost (no new
dependency, no added call volume under normal conditions), low validation risk
(mirrors a proven pattern used 4x already), decent value (closes a real
notification-drop gap on a public alerting pipeline).

Validation performed: `ast.parse` syntax check passed, module imports cleanly.
Wrote a standalone unit test mocking `urllib.request.urlopen` to simulate
429-then-500-then-success (confirmed 3 calls, retry backoff logged, final
success returns True) and a non-retryable 404 (confirmed immediate failure,
exactly 1 call, no retry loop entered) -- both assertions passed. No Python
schema/data-writing logic changed, so no data-file backup/restore was needed.

Committed as `4b537d1`, pushed to main, triggered `gh workflow run
cve-alerts.yml` (run 34311168380) — completed `success` in ~45s. Live log
confirms the new code path executed for real: "Created issue #218: [VULN
ALERT] CVE-2026-84293 (risk 25.2) - wordpress/wordpress" with no
errors/warnings beyond the pre-existing benign Node 20 deprecation notice.
Pulled latest and curled the live site: `https://astruzocyber.github.io/CVE/`
→ 200, `/data/stats.json` → 200. No frontend files changed, so no
browser/screenshot check was needed. Live verification passed; no revert
needed.

**Rejected this cycle:** none — the one candidate identified cleared the bar
and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles = 0/3.
Not stopped. Next cycle in ~30 minutes.

---

## Cycle 6 — 2026-09-09T05:10:29Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
prior to this cycle (all `completed`/`success`). No sustained 429/throttle
signals from any source excluding benign Node 20 deprecation noise. Sources
healthy going into this cycle.

**Implemented:** Refresh EPSS/KEV/risk_score for existing tracked alerts even
when this run's NVD lookback window (2 days in production CI) doesn't
resurface them. Previously `epss_score` (40% of the composite risk score) and
`kev` status froze permanently at whatever value was captured on
`first_seen` the moment a CVE aged out of the lookback window or stopped
being returned by Dependabot/GHSA -- even though FIRST.org publishes new
EPSS scores daily and CISA KEV catalog additions have nothing to do with
NVD's `lastModified` window. This was a real risk-scoring accuracy gap: a
CVE could sit on the dashboard for weeks showing a stale EPSS score while
its actual exploitation-probability signal moved, or fail to pick up a new
KEV listing (losing the +25 risk bonus) until it happened to get re-matched
by NVD. Now every run pulls EPSS/KEV for the union of this-run candidates
and all currently-tracked CVE IDs, and refreshes the score-derived fields in
place for entries not otherwise touched this cycle -- `description`,
`cvss_score`, `source`, `first_seen`, `affected` etc. are left untouched
since NVD didn't return fresher data for them. Scored 5/5/5: zero added
cost (still a single unauthenticated batched FIRST.org EPSS call, same
endpoint, same free rate limit, no new dependency or credential), low
validation risk (pure refresh of already-existing score fields using the
already-existing `composite_risk_score()`/`build_final_entry()` logic, no
new external source), real value (closes a genuine, previously-undetected
accuracy gap in the pipeline's core risk-scoring promise).

Validation performed: `ast.parse` syntax check passed. Backed up
`docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`,
`docs/feed.json`, `docs/feed.xml`, `docs/data/kev_snapshot.json` to `/tmp`.
Ran the script for real locally (backgrounded, ~3.5 min due to NVD's
unauthenticated rate limit of 25 search terms x 6.5s delay plus 943-CVE EPSS
batch): output showed `NVD candidates (pre-filter): 810`, `Querying EPSS for
943 CVEs` (up from the previous 305-candidate-only volume, confirming the
new all-tracked-CVEs union worked), `After filtering: 305 matches`, `Wrote
438 total alerts` (same total as before -- no data loss/duplication),
`Wrote 0 NEW alerts` (correct, no genuinely new CVEs this cycle). Diffed
old vs new `alerts.json`: same 438 `(cve_id, source)` keys, `first_seen` and
`cvss_score` identical for every sampled entry -- only EPSS/KEV/risk_score
fields refreshed, exactly as intended. `git checkout --` restored all data
files to their pre-test state afterward so local throwaway test output
never touched production data; only `scripts/aggregate.py` was left staged.

Committed as `71e5d5c`, pushed to main, triggered `gh workflow run
cve-alerts.yml` (run `34313822093`) -- completed `success` in ~2.5 min. Live
log showed several transient `NVD HTTP error 503: Service Unavailable`
during the run, which the pre-existing retry-with-backoff logic (implemented
cycles 1-3, unrelated to this cycle's change) absorbed without failing the
job -- run still completed with correct output: `NVD candidates (pre-filter):
474`, `Querying EPSS for 792 CVEs`, `After filtering: 120 matches`, `Wrote
438 total alerts` (consistent total, confirming resilience under real
upstream 503s). Pulled latest, curled the live site:
`https://astruzocyber.github.io/CVE/` -> 200, `/data/stats.json` -> 200,
`/data/alerts.json` -> 200, confirmed 438 total alerts live-side matching
local. No frontend files changed, so no browser/screenshot check was
needed. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 7 — 2026-09-09T05:45:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions runs
prior to this cycle (all `completed`/`success`, run times 46s-2m28s). No
sustained 429/throttle signals from any source. Sources healthy going into
this cycle.

**Implemented:** Shareable filter state via URL query params. Dashboard
filters (search text, KEV status, source, sort order) previously reset on
every page load and could not be shared or bookmarked -- a security lead
had no way to send a teammate a direct link to e.g. "KEV overdue only,
sorted by risk score" without a screenshot or verbal instructions. Added
`readFiltersFromURL()` (reads `q`/`kev`/`source`/`sort` from `location.search`
on load; setting a `<select>.value` to an option that doesn't exist is a
no-op in every browser, so a stale/unrecognized param value safely falls
back to the element's default) and `updateURLFromFilters()` (writes current
filter state into the URL via `history.replaceState` inside
`applyFiltersAndRender`, so every keystroke/filter change updates the URL
without spamming browser history; default values are omitted from the URL
to keep links clean, e.g. an all-default view produces no query string at
all). Zero backend/pipeline changes, zero new dependencies, purely additive
client-side JS in `docs/app.js`. Scored 5/5/5: zero added cost, low
validation risk (pure URL<->DOM sync, touches no data), real value
(bookmarkable/shareable triage views -- a genuine gap for a security-team
tool used across a team).

Validation performed: `node --check docs/app.js` passed. No backend/data
files touched, so no aggregate.py test-run/backup step was needed. Served
`docs/` locally on scratch port 8791, loaded
`http://localhost:8791/index.html?kev=kev&sort=cvss_score` in the browser
tool: confirmed `kev-filter` select correctly read "kev" from the URL,
`sort-by` correctly read "cvss_score", result count correctly showed
"1 of 438 alerts" (filter actually applied, not just UI state). Typed into
the search box and confirmed `location.search` updated live to
`?q=wordpress&kev=kev&sort=cvss_score` with the empty-state rendering
correctly for the (now) zero-match filter combination -- screenshot
confirmed correct rendering, no regression. Loaded the default
`http://localhost:8791/index.html` (no params) and confirmed unchanged
baseline behavior: "438 of 438 alerts", stats bar populated, no console
errors. Killed the local scratch server after testing.

Committed as `f1cb15d`, pushed to main. Since this was a pure frontend-JS
change with zero pipeline/data impact, did not trigger `cve-alerts.yml`
(no reason to consume Actions minutes or risk touching production data
files for a change that can't affect them). Waited for GitHub Pages to
redeploy (~75s), confirmed via `curl` that the live `app.js` contains
`readFiltersFromURL` (2 occurrences, function definition + call site).
Loaded the LIVE dashboard at
`https://astruzocyber.github.io/CVE/?kev=kev&sort=risk_score` in the
browser tool: screenshot confirmed `kev-filter` value "kev" applied
correctly, result count "1 of 438 alerts", stats bar/trend chart/all
existing features rendering normally with the URL-driven filter live in
production. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 8 — 2026-09-09T06:20:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success`. Latest run (05:10:29Z)
showed 7 transient `NVD HTTP error 503: Service Unavailable` lines, absorbed
by pre-existing retry logic, non-fatal; no 429/throttle signal from any
source. Sources healthy going into this cycle.

**Implemented:** Watchlist keyword-match badges on alert cards. The
aggregate.py pipeline has captured `matched_keywords` per alert since early
cycles (which watchlist.yaml keyword(s) caused a CVE to surface, e.g.
`wordpress`) -- 129/438 currently-tracked alerts have a non-empty value --
but this field was never surfaced in the UI, so a security lead had no
visual cue for *why* a CVE appeared beyond generic source presence. Added a
green "Watchlist match" badge row to `renderCard()` in `docs/app.js` (reads
the existing `matched_keywords` array, no new data/API/schema change) and
matching `.matched` / `.badge.match` CSS rules in `docs/style.css`. Renders
conditionally, only for alerts with a non-empty array; zero visual change
for the rest. Scored 5/5/5: zero added cost (no new calls, no new fields),
low validation risk (pure additive render of already-collected data), real
value (explains relevance at a glance for a security triage tool).

Validation performed: `node --check docs/app.js` passed. No backend/pipeline
files touched, so no aggregate.py test-run/backup step was needed. Served
`docs/` locally on scratch port 8792, loaded in the browser tool, filtered
to `q=wordpress` (123 of 438 alerts), confirmed green "WORDPRESS" / "WP
PLUGIN" / "WP-CONTENT" badges rendered correctly under the Affected line on
multiple cards with screenshot verification. Cleared the search box and
confirmed unchanged baseline ("438 of 438 alerts", no console errors, no
regression to any other card element or filter).

Committed as `44b21c4`, pushed to main. Pure frontend-JS/CSS change with
zero pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited ~80s for GitHub Pages redeploy, confirmed via `curl` that live
`app.js` contains the new badge-rendering code. Loaded the LIVE dashboard at
`https://astruzocyber.github.io/CVE/?q=wordpress` in the browser tool:
screenshot confirmed green watchlist-match badges rendering correctly in
production alongside all existing badges/scores/layout, no regression. Live
verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 9 — 2026-09-09T06:56:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success`. Latest run
(05:10:29Z) showed 7 transient `NVD HTTP error 503` lines, absorbed by
pre-existing retry logic, non-fatal. No 429/throttle signal from any
source. Sources healthy going into this cycle.

**Implemented:** Stale-data warning banner on the dashboard. The
aggregation pipeline runs every 4 hours via GitHub Actions but the public
dashboard had zero client-visible signal if that schedule silently broke
(disabled cron, repeated failures, workflow misconfiguration) -- a viewer
would keep trusting stale data indefinitely with no cue anything was wrong.
Added `checkStaleness()` in `docs/app.js`, wired into the existing
`loadStats()` fetch of `data/stats.json`: compares `stats.generated_at`
against `Date.now()`, and if the gap exceeds 20 hours (5x the 4h cadence,
tolerant of one missed/delayed run without false-alarming on ordinary
Actions scheduling jitter) shows a visible red `role="alert"` banner naming
the exact staleness age in hours and pointing to GitHub Actions. New
`#stale-banner` element added to `docs/index.html` (hidden by default),
matching `.stale-banner` CSS rule added to `docs/style.css`. Zero new API
calls, zero backend/schema changes -- pure additive frontend read of a
field (`generated_at`) already present in `stats.json` since the dashboard
was first built.

Validation performed: `node --check docs/app.js` passed; YAML files
unaffected/still valid; no Python files touched so no aggregate.py
backup/test-run step was needed. Served `docs/` locally on scratch port
8793, loaded in the browser tool with real production `stats.json`
(generated ~106 min old at test time) -- confirmed banner correctly
**hidden** (fresh data, under threshold), screenshot verified normal
dashboard rendering. Then called `checkStaleness('2026-09-01T00:00:00Z')`
directly in the loaded page to simulate a ~199h-stale scenario -- confirmed
banner correctly **shown** with accurate hour count and clear message,
screenshot verified layout renders cleanly with no visual regression to
stats bar or trend chart below it. Killed local server after validation.

Committed as `4271b30`, pushed to main. Pure frontend-JS/HTML/CSS change
with zero pipeline/data impact -- did not trigger `cve-alerts.yml` (no
reason to consume Actions minutes for a change that can't affect
production data). Waited ~60s for GitHub Pages redeploy, confirmed via
`curl` that live `app.js` contains `checkStaleness` and `index.html`/
`style.css` return HTTP 200. Loaded the LIVE dashboard at
`https://astruzocyber.github.io/CVE/` in the browser tool: confirmed
`stale-banner` correctly hidden (real production data is fresh),
`result-count` showing "438 of 438 alerts" (unchanged), screenshot
confirmed no regression to any existing feature. Live verification passed;
no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 10 — 2026-09-09T07:33:00Z

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success` (05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z, 02:38:03Z). Latest run showed only transient NVD 503s
absorbed by existing retry logic, non-fatal. No 429/throttle signal from any
source. Sources healthy going into this cycle.

**Implemented:** Added a "View on NVD" direct link to every alert card's
footer. Cards already surfaced CVSS/EPSS/risk/KEV data and (for
Dependabot-sourced alerts only) a link to the GitHub Dependabot alert page,
but a viewer wanting the canonical NVD record for a CVE (full CVSS vector
string, references, CPE matches, CWE classification) had no direct link and
had to search for it manually -- real friction for a security-triage tool
where NVD is the authoritative source of record. Added
`https://nvd.nist.gov/vuln/detail/<cve_id>` as a link in `renderCard()`
(`docs/app.js`), gated on `cve_id` matching the `CVE-` prefix pattern (true
for all 438 currently-tracked alerts), placed alongside the existing
Dependabot alert link inside a new `.footer-links` flex wrapper. Added a
matching `.footer-links { display: flex; gap: 10px; }` rule to
`docs/style.css`. Zero new API calls, zero backend/schema changes, zero
cost -- pure additive frontend link generation from data already present.

Validation performed: `node --check docs/app.js` passed; all `config/*.yaml`
and `.github/workflows/*.yml` parsed clean with `yaml.safe_load`. No Python
files touched, so no `aggregate.py` backup/test-run step was needed. Served
`docs/` locally on scratch port 8794, loaded in the browser tool with real
production data (438 alerts) -- screenshot confirmed "View on NVD" link
renders correctly on every card alongside existing badges/breakdown/matched-
keyword rows, verified `href` on a sample card
(`https://nvd.nist.gov/vuln/detail/CVE-2026-85046`) matched that card's own
CVE ID exactly, confirmed unchanged baseline "438 of 438 alerts" and no
layout regression. Killed local server after validation.

Committed as `ea09f3fe1c4878c4902906c6db0e45b940b9ffc0`, pushed to main.
Pure frontend-JS/CSS change with zero pipeline/data impact -- did not
trigger `cve-alerts.yml` (no reason to consume Actions minutes for a change
that can't affect production data). Waited ~45s for GitHub Pages redeploy,
confirmed via `curl` that live `app.js` returns HTTP 200 and contains
`nvd.nist.gov/vuln/detail`. Loaded the LIVE dashboard at
`https://astruzocyber.github.io/CVE/` in the browser tool: confirmed 438
cards rendered, "438 of 438 alerts" unchanged, sampled a live card's
"View on NVD" `href` and confirmed it matched that card's CVE ID exactly,
screenshot confirmed correct production rendering with no regression to any
existing feature (badges, breakdown toggle, watchlist-match badges, stats
bar). Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 11 — 2026-09-09T08:10:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success` (05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z, 02:38:03Z; no new scheduled run since cycle 10, cadence
is 4h). No 429/throttle signal from any source. Sources healthy going into
this cycle.

**Implemented:** Added a single `@media (max-width: 600px)` breakpoint to
`docs/style.css`. The dashboard shipped a `viewport` meta tag implying mobile
support but had zero `@media` rules anywhere in the stylesheet -- on a phone
the toolbar controls row, the dependency-filter textarea (forced to a 240px
min-width), and the multi-column card grid all kept full desktop sizing,
producing an overflowing/awkwardly-wrapped layout for a real class of users
(a security lead checking alerts from their phone). The new breakpoint
stacks toolbar controls to full width, switches the card grid to a single
column, drops the textarea min-width, and tightens header/main padding.
Pure additive CSS, zero change above 600px viewport width.

Validation performed: brace-balance check on `docs/style.css` (87 open / 87
close, no Python files touched so no `aggregate.py` backup/test-run step was
needed). Served `docs/` locally on scratch port 8797, loaded in the browser
tool, emulated a 375x812 (iPhone-class) viewport via
`Emulation.setDeviceMetricsOverride` -- confirmed `document.documentElement.
scrollWidth === window.innerWidth` (no horizontal overflow), screenshot
confirmed controls/textarea/card-grid all render correctly stacked with real
production data (438 alerts). Cleared the device-metrics override and
re-screenshotted at native desktop size -- confirmed pixel-identical
rendering to before the change (stats bar, historical trend chart, controls
row, cards all unchanged). Killed local server after validation.

Committed as `87685d2`, pushed to main. Pure frontend-CSS change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited ~45s for GitHub Pages redeploy, confirmed via `curl` that live
`style.css` returns HTTP 200 and contains the new `max-width: 600px` rule.
Loaded the LIVE dashboard at `https://astruzocyber.github.io/CVE/` in the
browser tool at the same 375x812 emulated viewport: stats bar, historical
trend chart, and dependency-filter section all render correctly stacked
with no overflow, confirming correct production behavior. Live verification
passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified cleared the
bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 12 — 2026-09-09T08:20:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success` (08:10:54Z, 05:10:29Z,
04:29:29Z, 04:10:07Z, 03:20:57Z). Grepped the latest run's log for
warning/error/traceback/429/throttle (excluding known Node deprecation
noise) -- only benign Node20-deprecation warnings from GitHub-owned actions,
no application-level errors. No 429/throttle signal from NVD/EPSS/KEV/GHSA/
Dependabot. All sources healthy going into this cycle.

**Implemented:** Added SEO meta tags, Open Graph/Twitter card tags, and an
inline SVG favicon to `docs/index.html`. Confirmed via `curl` before the
change that `https://astruzocyber.github.io/CVE/favicon.ico` 404'd (the page
had no `<link rel="icon">` at all, so browsers fell back to the default
path). Added: `<meta name="description">` summarizing the dashboard for
search engines; `og:title`/`og:description`/`og:type`/`og:url` and
`twitter:card`/`twitter:title`/`twitter:description` so sharing the
dashboard URL in Slack/Discord/Twitter/X produces a real title+description
link preview instead of a bare URL (genuinely useful for a security tool
that gets pasted into incident-response channels); and a data-URI inline
SVG favicon (shield-with-checkmark glyph, dashboard's own `--bg`/`--accent`
colors) so the browser tab/bookmark icon resolves instead of 404ing, with
zero external asset request added. Pure additive `<head>` change: 9 lines
in `docs/index.html`, zero JS/CSS/backend/schema changes, zero new API
calls, zero cost.

Validation performed: confirmed `<head>`/`</head>` balance and meta-tag
count via a small Python sanity check (no YAML/Python pipeline files
touched, so no `aggregate.py` backup/test-run step was needed). Served
`docs/` locally on scratch port 8811, loaded in the browser tool with real
production data (440 alerts) -- confirmed `document.title`, the new
`<link rel="icon">` element, and the new `<meta name="description">`
content all present and correct; stats bar and historical trend chart
rendered with no visual regression. Killed local server after validation.

Committed as `6e601ac`, pushed to main. Pure frontend-HTML change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited ~105s for GitHub Pages redeploy (first `curl` check at ~45s still
showed the old cached HTML; a second check at ~105s total confirmed the new
meta/OG/favicon tags were live), then confirmed via `curl` that the live
page contains `meta name="description"`, `og:title`, `twitter:card`, and
`rel="icon"`. Loaded the LIVE dashboard at `https://astruzocyber.github.io/
CVE/` in the browser tool: confirmed 440 cards rendered, stats bar populated
(440 total alerts, 101 critical, 1 KEV, 0 overdue, 0 ransomware, 0.8% avg
EPSS), historical trend chart rendering, no regression to any existing
feature. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (favicon +
SEO/social meta tags) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 13 — 2026-09-09T09:15:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs prior to this cycle -- all `completed`/`success` (08:10:54Z, 05:10:29Z,
04:29:29Z, 04:10:07Z, 03:20:57Z). Grepped the latest run's log for
warning/error/traceback/429/throttle (excluding known Node deprecation
noise) -- only benign Node20-deprecation warnings from GitHub-owned actions,
no application-level errors. No 429/throttle signal from NVD/EPSS/KEV/GHSA/
Dependabot. All sources healthy going into this cycle.

**Implemented:** Added a per-CVE shareable deep-link feature. Each alert
card previously had no unique DOM anchor and no way to link directly to one
specific card -- only the whole filtered dashboard view was shareable (via
cycle 7's URL query params). Added `id="alert-<CVE-ID>"` to every card,
turned the CVE-ID header into a clickable `<button class="cve-link-btn">`
that copies a `#alert-<CVE-ID>` deep-link to the clipboard (with a
"Copied!" transient label, graceful no-op if the Clipboard API is
unavailable) and updates the URL hash via `history.replaceState`. Added
`highlightFromHash()`, called after every `loadData()` completes, which
checks `location.hash` for `#alert-<CVE-ID>`, scrolls that card into view
(smooth, centered) and applies a temporary `.highlighted` CSS class (blue
glow border, auto-removed after 2.5s) -- fails silently if the card isn't
in the current dataset. Pure additive frontend change across `docs/app.js`
(58 lines) and `docs/style.css` (19 lines): no new API calls, no backend/
schema changes, zero cost.

Validation performed: `node --check docs/app.js` passed. Served `docs/`
locally on a scratch port with real production data (440 alerts), loaded in
the browser tool: confirmed clicking a CVE-ID button sets `location.hash`
to `#alert-<CVE-ID>`; confirmed a genuine fresh navigation (`new_tab`, not
an in-page `goto_url` hash-only change, which doesn't re-fire the JS load
path and initially produced a false negative during testing) to a URL with
`#alert-<CVE-ID>` correctly scrolled to and applied `.highlighted` to that
exact card. Confirmed zero regression: search filter (`wordpress` query
correctly narrowed 440->125 alerts) and the existing risk-score breakdown
toggle (`.score-toggle` click correctly un-hides its panel) both still work
exactly as before.

Committed as `34ff7f2`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited ~60s for GitHub Pages redeploy, confirmed via `curl` that live
`app.js` and `style.css` both return HTTP 200 and contain the new
`cve-link-btn`/`highlightFromHash`/`highlighted` identifiers. Loaded the
LIVE dashboard at `https://astruzocyber.github.io/CVE/` in the browser
tool: confirmed the first card's CVE-ID renders as the new clickable
`cve-link-btn` with the correct `data-cve` attribute. Live verification
passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (per-CVE
deep-link) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 14 — 2026-09-09T09:55:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (08:10:54Z, 05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z). Grepped the latest run's log for warning/error/
traceback/429/throttle (excluding known Node deprecation noise) -- clean,
only benign Node20-deprecation warnings from GitHub-owned actions. No
429/throttle signal from NVD/EPSS/KEV/GHSA/Dependabot. All sources healthy
going into this cycle.

**Implemented:** Added a days-overdue count to the existing KEV OVERDUE
badge. The badge previously showed only "OVERDUE" with no magnitude, so a
CVE 1 day past its CISA KEV BOD 22-01 remediation due date looked identical
to one 90 days overdue -- a real triage-priority gap for a security team.
Added `overdueDays(alert)` to `docs/app.js` (pure function reusing the
existing `isOverdue()` decision, computing whole days between
`kev_due_date` and now, returning `null` if not overdue) and updated the
badge template to render e.g. "OVERDUE (12d)". Pure additive frontend
change: no new API calls, no backend/schema changes, zero cost.

Validation performed: `node --check docs/app.js` passed. Served `docs/`
locally on scratch port 8813 with real production data (440 alerts),
loaded in the browser tool: confirmed `overdueDays()` correctly computes
2443 days for a synthetic 2020-01-01 due-date test alert, confirmed the
rendered card HTML contains both "OVERDUE" and the "(Nd)" suffix, confirmed
zero regression -- all 440 real alerts still render, result count still
reads "440 of 440 alerts". (Currently 0 real alerts in the live dataset are
KEV-overdue, so the badge itself isn't visually exercised by production
data this cycle, but the function was directly unit-tested against a
synthetic alert in the live page context.)

Committed as `8646398`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited 60s for GitHub Pages redeploy, confirmed via `curl` that live
`app.js` contains the new `overdueDays` identifier. Loaded the LIVE
dashboard at `https://astruzocyber.github.io/CVE/` in the browser tool:
confirmed 440 cards render, stats bar populated, `overdueDays` function
present in the live page context, no regression to any existing feature.
Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (overdue-days
magnitude on the OVERDUE badge) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 15 — 2026-09-09T10:26:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (08:10:54Z, 05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z). Grepped the latest run's log for warning/error/
traceback/429/throttle (excluding known Node deprecation noise) -- clean,
only benign Node20-deprecation warnings from GitHub-owned actions. No
429/throttle signal from NVD/EPSS/KEV/GHSA/Dependabot. All sources healthy
going into this cycle.

**Implemented:** Surfaced `stats.by_source` (e.g. `{"nvd": 440}`) as a row
of small pills under the stats bar. `compute_stats()` in `aggregate.py` has
computed this field since early cycles, but it was never rendered on the
dashboard -- a viewer had no quick way to see the source mix (is this
mostly NVD sweep noise, or are GHSA/Dependabot actually contributing?)
without exporting CSV and counting manually. Added `renderSourceBreakdown()`
to `docs/app.js` (called from the existing `loadStats()`), a new
`#source-breakdown` div in `docs/index.html`, and `.source-breakdown`/
`.source-pill` rules in `docs/style.css`. Pure additive frontend change
reading an existing stats.json field: zero new API calls, zero backend/
schema changes, zero cost.

Validation performed: `node --check docs/app.js` passed. Served `docs/`
locally on scratch port 8817 with real production data (440 alerts),
loaded in the browser tool: confirmed the pill rendered as "nvd: 440",
confirmed zero regression to the stats bar, historical trend chart, and
search filter (`wordpress` query still correctly narrowed 440->125 alerts).

Committed as `458143a`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml` (no reason to
consume Actions minutes for a change that can't affect production data).
Waited 45s for GitHub Pages redeploy, confirmed via `curl` that live
`app.js`/`index.html` both return HTTP 200 and contain the new
`renderSourceBreakdown`/`source-breakdown` identifiers. Loaded the LIVE
dashboard at `https://astruzocyber.github.io/CVE/` in the browser tool:
confirmed `#source-breakdown` is populated with "nvd: 440" and the result
count still reads "440 of 440 alerts" -- no regression. Live verification
passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (by-source
breakdown pills) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 16 — 2026-09-09T10:58:00Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (08:10:54Z, 05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z). Grepped the latest run's log for warning/error/
traceback/429/throttle (excluding known Node20-deprecation noise) -- clean.
No 429/throttle signal from NVD/EPSS/KEV/GHSA/Dependabot. All sources
healthy going into this cycle.

**Implemented:** "DUE SOON" badge for KEV entries within 7 days of their
CISA KEV BOD 22-01 remediation deadline. Cycle 14 added a days-overdue
magnitude to the existing OVERDUE badge, but there was no forward-looking
equivalent -- a KEV entry due in 2 days looked identical to one due in 60
days until it actually crossed the deadline, giving zero advance warning
for a security team to prioritize remediation before a compliance breach.
Added `daysUntilDue(alert)` to `docs/app.js` (mutually exclusive with the
existing `overdueDays()`/`isOverdue()` -- returns null once the due date
has passed) and a new yellow "DUE SOON (Nd)" badge rendered on
`renderCard()` whenever 0 <= days-until-due <= 7. Added matching
`.badge.due-soon` CSS rule to `docs/style.css`. Pure additive frontend
change reading the existing `kev_due_date` field: zero new API calls, zero
backend/schema changes, zero cost.

Validation performed: `node --check docs/app.js` passed. Served `docs/`
locally on scratch port 8825 with real production data (440 alerts, 1 KEV
entry, 0 currently overdue and 0 currently within the 7-day due-soon
window in the live dataset) -- confirmed zero regression (440/440 alerts,
stats bar, historical trend chart all render correctly). Since no real
alert currently falls in the due-soon window, directly unit-tested
`daysUntilDue()` in the live page JS context with synthetic dates (3 days
out returns 3; 5 days overdue correctly returns null since that's
`overdueDays()`'s territory; no due date returns null) and confirmed
`renderCard()` on a synthetic due-soon alert actually emits the
`due-soon`/`DUE SOON` badge markup -- exercising the new code path end to
end despite the current dataset having no live example.

Committed as `a23c75c`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml`. Waited 45s for
GitHub Pages redeploy, confirmed via `curl` that live `app.js` contains the
new `daysUntilDue`/`due-soon`/`DUE SOON` identifiers. Loaded the LIVE
dashboard at `https://astruzocyber.github.io/CVE/` in the browser tool:
confirmed 440 cards render, result count reads "440 of 440 alerts", and
`daysUntilDue` is present as a live function -- no regression. Live
verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (due-soon
lookahead badge) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 17 — 2026-09-09T11:33Z (approx)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (08:10:54Z, 05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z). Grepped the latest run's log for warning/error/
traceback/429/throttle (excluding Node20-deprecation noise) -- clean. All
sources (NVD/EPSS/KEV/GHSA/Dependabot) healthy going into this cycle.

**Implemented:** Added a "KEV due soon (<=7d) only" option to the existing
KEV-status filter dropdown. Cycle 16 introduced a `daysUntilDue()` helper
and a yellow "DUE SOON (Nd)" badge on cards within 7 days of their CISA KEV
BOD 22-01 remediation deadline, but there was no way to *filter* to just
those alerts -- a security lead still had to visually scan every card to
find approaching deadlines, unlike the existing "KEV overdue only" filter
which already isolates past-deadline alerts. Added the option to
`docs/index.html`'s `#kev-filter` `<select>` and matching filter branch in
`applyFiltersAndRender()` in `docs/app.js` (reuses `daysUntilDue()`
unchanged, filters to `0 <= days <= 7`). Composes for free with the
existing URL-query-param sharing (cycle 7), so a filtered due-soon view is
itself shareable/bookmarkable without any further work.

Validation performed: `node --check docs/app.js` passed. Served `docs/`
locally on scratch port 8931 with real production data (440 alerts, 0
currently in the due-soon window), loaded in the browser tool. Since no
real alert currently falls in the window, injected one synthetic due-soon
alert (`CVE-9999-TESTDUE`, due in 3 days) directly into the live in-page
`allAlerts` array, selected the new filter, and confirmed
`applyFiltersAndRender()` correctly isolated exactly that one card
("1 of 441 alerts", card grid contained only `CVE-9999-TESTDUE`) --
exercising the new filter branch end-to-end. Reverted the synthetic alert
and re-ran with `all` selected, confirming the dashboard returned to
"440 of 440 alerts" with zero residual state. Also confirmed the URL
query-param round-trip: selecting the new filter correctly wrote
`?kev=due-soon` into the address bar (verifies composition with cycle 7's
shareable-filter feature).

Committed as `159b8b1`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml`. Waited 45s for
GitHub Pages redeploy, confirmed via `curl` that live `app.js`/`index.html`
both contain the new `due-soon` identifier and return HTTP 200. Loaded the
LIVE dashboard at `https://astruzocyber.github.io/CVE/` in the browser
tool: confirmed the `#kev-filter` select now has 6 options including
`due-soon`, and the result count still reads "440 of 440 alerts" -- no
regression. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (due-soon
filter option) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 18 — 2026-09-09 (approx, this run)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (08:10:54Z, 05:10:29Z, 04:29:29Z,
04:10:07Z, 03:20:57Z). No 429/throttle signals seen. All sources
(NVD/EPSS/KEV/GHSA/Dependabot) healthy going into this cycle.

**Implemented:** Added a "Sort: KEV due date (soonest first)" option to the
existing `#sort-by` dropdown (`docs/index.html`) and matching sort branch
in `applyFiltersAndRender()` (`docs/app.js`). Sorts by `kev_due_date`
ascending; entries with no due date (non-KEV, or KEV with no published
due date) are pushed to the end rather than the front, avoiding the
classic bug where an empty/undefined string compares as "smallest" and
would otherwise incorrectly rank non-KEV alerts as most urgent. This is
the natural complement to cycle 16's DUE SOON badge and cycle 17's
"KEV due soon" filter: a security lead can now filter to due-soon KEV
entries AND sort the whole dashboard by deadline proximity in one view,
and it composes for free with the existing URL-query-param sharing
(writes `?sort=kev_due_date`).

Validation performed: `node --check docs/app.js` passed; `index.html`
parsed cleanly with Python's `html.parser`. Served `docs/` locally on
scratch port 8931 with real production data (440 alerts). Loaded in the
browser tool, confirmed the new `kev_due_date` option is present in the
select, selected it, and verified via `window.__lastFiltered` that the
one real alert with a KEV due date (`2026-09-18`) sorted to position 0
and all 439 null-due-date entries followed it (non-null prefix verified
sorted, `nonNullSorted: true`), with the URL updating to
`?sort=kev_due_date`. Reset to the default `risk_score` sort, confirmed
"440 of 440 alerts" still reads correctly (no regression) and the URL
param cleared. Screenshot confirmed normal dashboard rendering (stats
bar, trend chart, no layout break).

Committed as `f6f46a8`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml`. Waited 40s for
GitHub Pages redeploy, confirmed via `curl` that live `app.js` contains
10 occurrences of `kev_due_date` (new sort logic) and `index.html`
returns HTTP 200. Loaded the LIVE dashboard at
`https://astruzocyber.github.io/CVE/` in the browser tool: confirmed the
`#sort-by` select now has 6 options including `kev_due_date`, and the
result count reads "440 of 440 alerts" -- no regression. Live
verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (KEV
due-date sort option) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 19 — 2026-09-09 (approx, this run)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (12:12:53Z, 08:10:54Z, 05:10:29Z,
04:29:29Z, 04:10:07Z). No 429/throttle signals seen. All sources
(NVD/EPSS/KEV/GHSA/Dependabot) healthy going into this cycle.

**Implemented:** Added a "First seen: Nd ago" age badge to the card
footer (new `firstSeenAge()` helper in `docs/app.js`, computed from the
existing `first_seen` field which is set once at ingestion and never
touched by subsequent score-refresh cycles) plus a "Sort: Oldest first
(triage backlog)" option in the `#sort-by` dropdown. This answers "how
long has our team known about this" distinctly from "Published" (the
vendor/NVD date, which can predate first_seen by years for old CVEs that
only start matching the watchlist later) and surfaces long-lingering
un-triaged alerts that the default newest-first sort otherwise buries.
Pure additive frontend change, no new API calls, no backend/schema
changes. Adjusted `.card-footer` CSS to `flex-wrap` with `gap` since it
now holds 3 elements instead of 2.

Validation performed: `node --check docs/app.js` passed; `index.html`
parsed cleanly via Python's `html.parser`; `style.css` brace count
balanced (95/95). Served `docs/` locally on scratch port 8931 with real
production data (445 alerts). Loaded in the browser tool: selected the
new `first_seen_oldest` sort, verified `window.__lastFiltered` is
strictly ascending by `first_seen` across all 445 entries, confirmed the
URL updates to `?sort=first_seen_oldest`, confirmed a sample age badge
reads "First seen: 3d ago" matching a first_seen ~3 days in the past.
Reset to default `risk_score` sort, confirmed "445 of 445 alerts" still
reads correctly (no regression) and URL param cleared. Screenshots
confirmed normal card layout with the new age badge sitting cleanly
alongside "Published" and the NVD/Dependabot links, no overflow/wrap
issues, stats bar and trend chart unaffected.

Committed as `8d2cda2`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml`. Waited 45s for
GitHub Pages redeploy, confirmed via `curl` that live `app.js` contains
3 occurrences of `first_seen_oldest`/`firstSeenAge` and both
`index.html`/`app.js` return HTTP 200. Loaded the LIVE dashboard in the
browser tool: confirmed `#sort-by` now includes the `first_seen_oldest`
option and result count reads "445 of 445 alerts" (no regression). A
post-verification screenshot call hit a transient CDP IPC timeout
(harness-level, not a page issue) but the JS-based live check already
confirmed correct production state before that call. Live verification
passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (first-seen
age badge + oldest-first triage sort) cleared the bar and was
implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 20 — 2026-09-09 (approx, this run)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (12:12:53Z, 08:10:54Z, 05:10:29Z,
04:29:29Z, 04:10:07Z). No 429/throttle signals seen (checked latest run
log, only benign Node 20 deprecation warning). All sources
(NVD/EPSS/KEV/GHSA/Dependabot) healthy going into this cycle.

**Implemented:** Added a severity (CVSS band) filter dropdown. The
`severityClass()` helper has computed critical/high/medium/low CVSS
bands since early cycles (used for card border color/badges) but there
was no way to filter the board by severity band -- only KEV status and
source had dropdowns, forcing a viewer to scan visually or use CVSS sort
to isolate e.g. just critical-severity alerts. Added a `#severity-filter`
`<select>` to `docs/index.html` (all/critical/high/medium/low, mirroring
the existing thresholds: CVSS >=9, 7-8.9, 4-6.9, <4) and matching filter
logic in `applyFiltersAndRender()` in `docs/app.js`, reusing the existing
`severityClass()` helper unchanged (no new scoring logic). Composes with
the existing URL-query-param sharing (cycle 7) via a new `sev=` param,
so a filtered severity view is itself shareable/bookmarkable, and stacks
with the dependency-file filter, KEV filter, source filter, and search.
Pure additive frontend change: no new API calls, no backend/schema
changes, zero cost.

Validation performed: `node --check docs/app.js` passed; `index.html`
parsed cleanly via Python's `html.parser`. Served `docs/` on scratch
port 8933 with real production data (445 alerts). Loaded in the browser
tool: selected severity `critical`, verified `window.__lastFiltered`
count (101) matched a manual count of `allAlerts` with `severityClass()
=== "critical"` (101), confirmed URL updated to `?sev=critical`. Reset
to `all`, confirmed "445 of 445 alerts" still reads correctly (no
regression) and URL param cleared. Reloaded with `?sev=high` in the URL
directly (fresh navigation, not just hash change) and confirmed the
select correctly pre-populated to `high` and the count read "344 of 445
alerts" -- URL-param-on-load path works. Screenshot confirmed normal
dashboard rendering (stats bar, trend chart, source-breakdown pill, no
layout break).

Committed as `05eaa1e`, pushed to main. Pure frontend change with zero
pipeline/data impact -- did not trigger `cve-alerts.yml`. Waited 45s for
GitHub Pages redeploy, confirmed via `curl` that live `app.js` contains
3 occurrences of `severity-filter` and both `index.html`/`app.js` return
HTTP 200. Loaded the LIVE dashboard in the browser tool: selected
`critical`, confirmed "101 of 445 alerts" and URL updated to
`?sev=critical` -- matches local validation exactly, no regression to
stats bar/trend chart. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (severity
filter dropdown) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 21 — 2026-09-09 (approx, this run)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs -- all `completed`/`success` (12:12:53Z and earlier). Live-triggered
run this cycle (34360511746) also completed clean, only benign Node 20
deprecation warning, no 429/throttle signals from NVD/EPSS/KEV/GHSA/
Dependabot. All sources healthy.

**Implemented:** Fixed a risk-scoring accuracy gap in
`composite_risk_score()` (scripts/aggregate.py). Previously a missing
CVSS or EPSS value (112/445 currently-tracked alerts lack epss_score,
since FIRST.org hasn't scored every CVE) was silently treated as 0 --
i.e. the pipeline was asserting "definitely low severity" / "definitely
won't be exploited" for a CVE it simply has no data for yet, deflating
risk_score by up to 35-40 points on missing-data alerts and materially
understating triage priority for otherwise-high-CVSS CVEs like the
CVE-2026-87491 example (CVSS 8.8, Chrome V8 RCE) verified live below.
Now each present score component has its weight (CVSS 35%, EPSS 40%,
KEV flat 25%) redistributed proportionally across whichever components
are actually known, rather than counting the missing one as zero. KEV
status itself is never "missing" (True/False from a fixed public
catalog lookup), so only its share of the weight pool changes.
`risk_score_breakdown` gained a `weight_redistributed` boolean and
per-component effective-weight strings (e.g. "58.3% of (CVSS/10)" when
EPSS is missing, vs the normal "35.0%"). Dashboard breakdown panel
(docs/app.js) now surfaces these dynamic weight labels plus a new
explanatory note div when redistribution occurred; footer methodology
text (docs/index.html) documents the behavior for anyone reading the
"how is this score computed" copy. Added a small `.breakdown-note` CSS
rule (docs/style.css). Pure risk-scoring-accuracy + transparency
improvement: zero new API calls, zero new external data sources, one
new boolean field + updated weight-label strings on an already-present
nested object -- no breaking schema change (existing consumers reading
`cvss_component`/`epss_component`/`kev_bonus`/`capped`/`risk_score`
still get the same field names and types).

Validation performed: `ast.parse` on aggregate.py, `node --check` on
app.js, Python `html.parser` on index.html all passed. Unit-tested
`composite_risk_score()` directly with 5 cases (full data, missing EPSS,
missing CVSS, missing both + KEV, full data + KEV) confirming correct
proportional redistribution and that KEV bonus alone can reach 100 when
both other scores are missing and KEV=true (weight pool = 25 -> scaled
to 100%). Backed up all real production data files to /tmp, ran
`scripts/aggregate.py` for real against the live GH_TOKEN (no separate
Dependabot token configured, matching existing production behavior --
that path already skips gracefully): completed cleanly, 445 total
alerts (same as before), 112 correctly flagged `weight_redistributed`,
333 unaffected/unchanged in structure. Restored all real data files via
`git checkout --` afterward so no throwaway local test data touched
tracked files ahead of the real CI run. Served docs/ on a scratch HTTP
port with the recomputed real data, loaded in the browser tool: found a
`weight_redistributed` alert (CVE-2026-87491), clicked its breakdown
toggle, confirmed the panel correctly renders "EPSS n/a x n/a (missing)
= 0.0 pts" and the new note, screenshot-verified no layout regression;
confirmed existing severity filter, search, and stats bar all still
functioned correctly with the modified data (101 critical, 445 total
unchanged). Restored alerts.json again post-test.

Committed as `f59791b`, pushed to main. Since this touched
`scripts/aggregate.py`, triggered `cve-alerts.yml` via
`workflow_dispatch` (run 34360511746): completed successfully in ~50s,
log grep showed zero warnings/errors/tracebacks beyond the pre-existing
benign Node 20 deprecation notice. `git pull` after the run's own
auto-commit confirmed live `docs/data/alerts.json` has 445 total alerts,
112 with `weight_redistributed: true`, matching local validation
exactly. Curled the live site (200 OK) and loaded the actual production
dashboard in the browser tool: located CVE-2026-87491 via the search
filter, opened its breakdown panel, screenshot-confirmed identical
correct rendering (CVSS 8.8 x 58.3%, EPSS n/a x n/a, KEV +41.7, Total 51
pts, redistribution note) with no regression to the stats bar, trend
chart, or existing filters. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (missing-
score weight redistribution) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 22 — 2026-09-09 (approx, this run)

**Rate-limit / API health check (Step 1):** Reviewed last 5 GitHub Actions
runs on cve-alerts.yml -- all `completed`/`success`, most recent 50s, no
429/throttle signals from NVD/EPSS/KEV/GHSA/Dependabot. All sources
healthy. No rate-limit backoff needed.

**Implemented:** Debounced the dashboard search input to 150ms
(docs/app.js). Previously every keystroke in the search box triggered a
full filter+sort+card-grid re-render plus a URL history.replaceState
sync -- wasteful on 445+ (and growing) alerts, with visible potential
lag on lower-end/mobile devices as the dataset grows. Wrapped the
existing input listener in a standard debounce pattern (150ms, within
common UX guidance for search-as-you-type responsiveness). Pure
frontend change, zero new API calls, zero schema/backend changes, zero
cost.

Validation performed: `node --check docs/app.js` passed. Served docs/
on a scratch local HTTP port with real production data (445 alerts),
used the browser tool to confirm: typing "chrome" left the result count
unchanged immediately after the keystroke (445/445, debounce delaying
the render) and correctly updated to 56/445 after ~400ms; clearing the
search correctly reset to 445/445; stats bar (101 critical, 1 KEV, 0.8%
avg EPSS) rendered correctly throughout. No aggregate.py/data changes,
so no GitHub Actions data-pipeline dispatch was needed for this cycle.

Committed as `a2843cb`, pushed to main. Polled the GitHub Pages build
deployment (triggered automatically on push) to completion, then curled
https://astruzocyber.github.io/CVE/app.js and confirmed the new
`searchDebounceTimer` code is live (200 OK). Loaded the live production
dashboard in the browser tool: screenshot-confirmed correct rendering
of stats bar, historical trend chart, and KEV/critical counts with no
regression. Live verification passed; no revert needed.

**Rejected this cycle:** none -- the one candidate identified (search
input debounce) cleared the bar and was implemented.

**Status:** consecutive_no_improvement = 0/10, consecutive_failed_cycles =
0/3. Not stopped. Next cycle in ~30 minutes.

## Cycle 23 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded, no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent logs.

**Change:** Extract and display CWE/weakness classification (CWE-NNN IDs) on every alert card.

- **Root cause / opportunity:** NVD's `weaknesses` array, and GHSA/Dependabot's `advisory.cwes`, are fields already present in API responses the pipeline was already fetching (zero new network calls), but `scripts/aggregate.py` never parsed them — confirmed via a repo-wide grep for `weakness|CWE|cwe` returning 0 matches before this cycle.
- **Backend:** Added an `extract_cwe_ids()`-style helper (regex-based ID normalization to `CWE-NNN` form) and wired it into all three source parsers (NVD, GHSA, Dependabot). `cwe_ids` (a list of strings, possibly empty) now flows through to the final per-CVE entry schema in `build_final_entry`.
- **Frontend:** `docs/app.js` renders a new `.cwe-row` under the "Affected" line on each card — one linked `<a class="badge cwe">` per CWE ID, each pointing to `https://cwe.mitre.org/data/definitions/<N>.html`. Added `cwe_ids` (semicolon-joined) as a new column in the CSV export. New `.badge.cwe` CSS rule added to `docs/style.css`.
- **Zero-cost/risk assessment:** Pure additive data enrichment — no new API calls, no new secrets, no schema removal, fully backward compatible (missing/empty `cwe_ids` degrades gracefully to no badge row).

**Validation (Step 4):**
- `ast.parse` on `scripts/aggregate.py`: OK. `node --check` on `docs/app.js`: OK. `yaml.safe_load` on the workflow file: OK (unchanged, sanity-checked anyway).
- Backed up `docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`, `docs/feed.{json,xml}` conceptually (git-tracked, so used `git checkout --` to restore after the test run instead of manual tmp copies, since git already gave us a clean revert path).
- Ran `scripts/aggregate.py` for real (no synthetic data) against live NVD/CISA/EPSS APIs: processed 477 alerts, 342 correctly populated `cwe_ids` (median case: 1 CWE per CVE), 135 pre-existing (not touched this run) correctly lacked the key entirely rather than a corrupted/empty placeholder — expected behavior identical to how every previously-added field has rolled out incrementally across cycles. Confirmed all 32 brand-new alerts from this run had the key present. `git checkout --` reverted the local data files afterward so no throwaway test data leaked into the commit.
- Frontend: served `docs/` on a scratch local port (8792) with two synthetic `cwe_ids` values injected into a copy of the data (`CVE-2026-87491` → `['CWE-79','CWE-352']`), loaded via the browser tool, and inspected the rendered DOM directly — confirmed correct `.cwe-row` markup with two properly-linked `.badge.cwe` anchors pointing to the right MITRE URLs. No regressions: card count, stats bar, filters all intact in the same session.

**Deploy (Step 5):**
- Committed (`7585449`) and pushed to `main`.
- Triggered `cve-alerts.yml` via `gh workflow run` — completed `success` in 1m37s. Log grep for error/traceback/warning turned up only the known-benign Node 20 runner deprecation notice (no punycode/DEP0040 this time, different benign warning, same category — not from our code).
- Pulled fresh production data: 500 total alerts, 250 now carrying real `cwe_ids` (pipeline has now run twice since the code shipped, so coverage roughly doubled from the test run's single-pass 342/477 ratio as more of the backlog refreshes).
- Curled all 4 changed live URLs (`/`, `/app.js`, `/style.css`, `/data/alerts.json`) — all HTTP 200.
- Loaded the LIVE dashboard in the browser tool: found and inspected a real live card (`CVE-2026-85046`) rendering a correct `CWE-843` badge linking to `cwe.mitre.org/data/definitions/843.html`. Confirmed no regression: stats bar present, 500 cards rendered, search input present and functional.

**Rejected this cycle:** None — the CWE candidate cleared the bar on first pass (feasibility 5/5: zero new API calls; validation risk 2/5: purely additive parsing + rendering, backward-compatible on missing data; value 4/5: real triage signal, a distinct axis from CVSS/EPSS/KEV that a security team can scan/filter by mentally at a glance).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 23. `stopped`: false.

## Cycle 24 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34369721256, 34360511746, 34349733814, 34327718061, 34313822093), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent logs, no unexpected errors/tracebacks (only benign Node 20 runner deprecation noise).

**Change:** Add a one-click "Reset filters" button.

- **Opportunity:** The dashboard has 5 independent filter/sort controls (search, KEV status, severity, source, sort-by) plus a client-side dependency-file filter (cycle-era feature) and shareable URL query params (cycle 7) — but no single way to clear all of them at once. A viewer who had stacked several filters had to reset each control individually.
- **Frontend:** Added a `#reset-filters` `<button>` next to Export CSV in `docs/index.html`. `docs/app.js` wires it to blank the search box, reset every `<select>` to its default option, clear `dependencyPackageNames` plus the dep-text-input/dep-file-input/dep-status DOM elements, and call the existing `applyFiltersAndRender()` — which also runs `updateURLFromFilters()`, so the shareable-URL query params clear too. No CSS change needed (`.controls button` already styles it).
- **Zero-cost/risk assessment:** Pure additive frontend change — no new API calls, no backend/schema changes, zero cost, low validation risk.

**Validation (Step 4):**
- `node --check docs/app.js`: OK.
- Served `docs/` on a scratch local port (8901) with real production data (500 alerts). Used the browser tool: stacked a search term ("chrome") + KEV-only filter (110→1 of 500), clicked Reset, confirmed all controls reverted to their default values, result count returned to 500 of 500, and the URL query string cleared.
- No `aggregate.py`/data-schema changes, so no data-pipeline dry-run/backup/restore cycle was needed.

**Deploy (Step 5):**
- Committed (`ec9d301`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Polled GitHub Pages deployment to completion, curled `https://astruzocyber.github.io/CVE/app.js` (200 OK, `reset-filters` string present).
- Loaded the LIVE dashboard in the browser tool: confirmed the `#reset-filters` button exists, applied a search filter (500→0 of 500), clicked Reset, confirmed it correctly returned to 500 of 500. No regression to stats bar, historical trend chart, or existing filters observed.

**Rejected this cycle:** None — the reset-filters candidate cleared the bar on first pass (feasibility 5/5: pure client-side DOM/state reset, zero new calls; validation risk 2/5: additive control wired to already-tested `applyFiltersAndRender()`; value 4/5: real UX gap once 5+ stackable filters/sort options accumulated across prior cycles).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 24. `stopped`: false.


## Cycle 25 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34375061636, 34369721256, 34360511746, 34349733814, 34327718061), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent logs, only benign Node 20 runner deprecation noise.

**Change:** Include `cwe_ids` in the client-side search haystack.

- **Root cause / opportunity:** Cycle 23 added CWE classification extraction and rendered `.badge.cwe` links on every alert card, but the free-text search box (`applyFiltersAndRender()` in `docs/app.js`) built its search haystack from `cve_id`, `description`, `affected`, and `matched_keywords` only — `cwe_ids` was never added. Result: a viewer typing `CWE-79` to find all XSS-classified CVEs got zero results even though CWE-79 badges were visibly present on multiple cards. Found by re-reading `docs/app.js` fresh this cycle and cross-checking the haystack array against every field actually rendered on a card.
- **Frontend:** One-line change — `...(a.cwe_ids || [])` spread into the existing haystack array in `applyFiltersAndRender()`. No new fields, no new API calls, no backend/schema changes.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side array addition), validation risk 1/5 (single-line additive change to a well-tested filter function, no new state), value 4/5 (closes a real, visible search gap the moment the previous cycle's CWE badges shipped — a natural "next" bug rather than a novel feature).

**Validation (Step 4):**
- `node --check docs/app.js`: OK.
- Served `docs/` on scratch local port 8933 with real production data (501 alerts, 251 carrying `cwe_ids`). Used the browser tool: searched `CWE-434` → correctly narrowed to 5 of 501 alerts; cleared search → back to 501 of 501; searched `chrome` (pre-existing search term) → 110 of 501, confirming no regression to existing search behavior.
- No `aggregate.py`/data-schema changes, so no data-pipeline dry-run/backup/restore cycle was needed.

**Deploy (Step 5):**
- Committed (`91948c4`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Polled GitHub Pages deployment; curled `https://astruzocyber.github.io/CVE/app.js` (200 OK, `cwe_ids` string count increased from 3→4 occurrences, confirming the new line shipped).
- Loaded the LIVE dashboard in the browser tool: searched `CWE-79` → correctly narrowed to 23 of 501 alerts; cleared → 501 of 501. Screenshot-confirmed stats bar, historical trend chart, dependency-filter section, CWE badges, and card rendering all intact with no regression.

**Rejected this cycle:** None — the CWE-search-indexing fix cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 25. `stopped`: false.


## Cycle 26 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34375061636, 34369721256, 34360511746, 34349733814, 34327718061), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent Actions logs, only benign Node 20 runner deprecation noise (`##[warning]Node.js 20 is deprecated...forced to run on Node.js 24`).

**Change:** Add an optional "Total tracked alerts" line to the historical trend chart.

- **Opportunity:** `docs/data/history/trend.csv` has recorded `total_alerts` as its second column every run since history tracking began, and `loadTrendChart()` in `docs/app.js` already fetches/parses the whole CSV row-by-row -- but only `kev_overdue_count` and `avg_epss` were ever plotted. The raw alert-volume growth trend (does watchlist/data coverage keep growing steadily, or did a spike/drop signal a config or pipeline problem?) was invisible despite the underlying data already being fetched.
- **Frontend:** Added a third Chart.js dataset ("Total tracked alerts") parsed from the existing `rows` array (no new fetch), plotted on a new `y2` axis with `display: false` so it doesn't visually clutter the two existing labeled axes, and set `hidden: true` on the dataset itself so the default rendered chart is pixel-identical to before -- a viewer opts in via the standard Chart.js legend-click interaction. Also added `tooltip: { mode: "index", intersect: false }` so a shared tooltip across all three lines (visible ones) works correctly once toggled on.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side parse of already-fetched CSV, zero new network calls), validation risk 2/5 (additive Chart.js dataset behind a `hidden: true` default, doesn't touch the two existing plotted lines), value 3/5 (a real but secondary triage signal -- distinct from cycle 15's `by_source` breakdown pills, this is a growth-over-time view).

**Validation (Step 4):**
- `node --check docs/app.js`: OK.
- Served `docs/` on a scratch local port (8942) with real production data (501 alerts, `trend.csv` 13 rows). Used the browser tool: confirmed the chart renders identically to before by default (KEV overdue + Avg EPSS lines only, "Total tracked alerts" shown in the legend with strikethrough = hidden). Clicked the "Total tracked alerts" legend item: confirmed the third line correctly appears and traces the real total_alerts growth (432→501 across the visible window), with zero change to the other two lines' data or the stats bar.
- No `aggregate.py`/data-schema changes, so no data-pipeline dry-run/backup/restore cycle was needed.

**Deploy (Step 5):**
- Committed (`1b08f2a`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Polled GitHub Pages deployment to completion; curled `https://astruzocyber.github.io/CVE/app.js` (200 OK, "Total tracked alerts" string present).
- Loaded the LIVE dashboard in the browser tool: confirmed the trend chart renders correctly (identical default view: stats bar 501/123/1/0/0/0.7%, KEV overdue + Avg EPSS lines, "Total tracked alerts" present but hidden in the legend). No regression observed.

**Rejected this cycle:** None — the trend-chart candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 26. `stopped`: false.


## Cycle 27 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34375061636, 34369721256, 34360511746, 34349733814, 34327718061), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Render CISA KEV "required action" remediation guidance directly on alert cards.

- **Opportunity:** `build_final_entry()`/the resurfaced-alert refresh loop in `scripts/aggregate.py` has captured CISA's `requiredAction` field from the KEV catalog API into `kev_required_action` on every alert since early cycles, but it was never rendered anywhere in `docs/app.js`/`docs/index.html` — a viewer had to click "View on NVD" and separately cross-reference the CISA KEV catalog to find CISA's actual required remediation text for a KEV entry, even though the data was already sitting unused in `alerts.json`. Found by re-reading `scripts/aggregate.py` fresh this cycle and cross-checking every field written into the entry schema against what's actually rendered on a card.
- **Frontend:** Added a `.kev-action` box (red-tinted border/background, matching the existing KEV/OVERDUE color language but visually distinct from the neutral `.matched`/`.cwe-row` rows) to `renderCard()` in `docs/app.js`, rendered only when `alert.kev` is true AND `kev_required_action` is present (most non-KEV alerts have no such field, and some KEV entries may lack a populated requiredAction). Added matching `.kev-action`/`.kev-action strong` CSS rules to `docs/style.css`. Pure additive change reading an existing already-fetched field: zero new API calls, zero backend/schema changes, zero cost.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side template addition reading an already-populated field), validation risk 2/5 (additive conditional block, gated on `alert.kev &&`, cannot fire for the 500/501 non-KEV alerts), value 4/5 (closes a real, high-signal gap for the one thing a security lead most needs from a KEV entry — CISA's specific required remediation action — previously requiring an external lookup).

**Validation (Step 4):**
- `node --check docs/app.js`: OK.
- Served `docs/` on a scratch local port (8951) with real production data (501 alerts, 1 KEV entry — CVE-2026-85046 — with a populated `kev_required_action`). Used the browser tool: confirmed the new `.kev-action` box renders the full CISA guidance text with correct styling; confirmed existing search filter still works (`chrome`: 501→110→501 on clear); screenshot-confirmed the card layout (badges, risk bar, CWE row, footer) is unaffected.
- No `aggregate.py`/data-schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status` confirmed only `docs/app.js` and `docs/style.css` were touched).

**Deploy (Step 5):**
- Committed (`63c4e6b`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Polled GitHub Pages deployment; curled `https://astruzocyber.github.io/CVE/app.js`, `style.css`, `index.html` (all 200 OK, `kev-action` string present in `app.js`).
- Loaded the LIVE dashboard in the browser tool: confirmed 501/501 alerts, the CVE-2026-85046 KEV card renders the full CISA required-action text correctly styled. Screenshot-confirmed zero regression to badges, risk bar, CWE row, or card footer.

**Rejected this cycle:** None — the KEV-required-action candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 27. `stopped`: false.


## Cycle 28 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34375061636, 34369721256, 34360511746, 34349733814, 34327718061), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Extract genuine vendor-advisory links from the CISA KEV catalog's `notes` field and render them on KEV-tracked alert cards.

- **Opportunity:** `fetch_kev()` already retrieves the full CISA KEV catalog entry (including a `notes` field: a semicolon-separated mix of the actual vendor advisory URL plus repeated boilerplate -- a BOD 26-04 directive link, a "Forensics Triage Requirements" link, and a redundant NVD link already shown elsewhere on the card) for every run, but `notes` itself was never captured into the alert schema or rendered anywhere. Cycle 27 rendered `kev_required_action` (CISA's generic required-action text); this cycle closes the adjacent gap -- the *specific* vendor patch-notes/advisory URL, which previously required a manual cross-reference to the live CISA KEV catalog.
- **Backend:** Added `"kev_notes": kev_entry.get("notes") if in_kev else None` to `build_final_entry()` and to the existing-alert refresh loop in `scripts/aggregate.py` (mirrors the exact pattern already used for `kev_required_action`). Additive field, `None` for the 500+/501 non-KEV alerts, zero new HTTP calls (parses data already present in the existing KEV catalog fetch response).
- **Frontend:** Added `kevNotesLinksHtml(notes)` to `docs/app.js`: splits the raw `notes` string on `;`, regex-extracts the URL from each segment, discards `nvd.nist.gov` links (redundant with the card-footer "View on NVD" link) and `bod-26-04`/`forensics-triage` links (generic CISA directive boilerplate present on every KEV entry, zero per-CVE value), and renders the remaining genuine advisory link(s) in a new `.kev-notes` row directly under the existing `.kev-action` (CISA required-action) box. Added matching `.kev-notes`/`.kev-notes a` CSS rules to `docs/style.css` using the existing `--text-dim`/`--accent` theme variables (initially drafted with a nonexistent `--muted` var with a fallback; caught and corrected during validation by grepping the actual theme variable names in `docs/style.css` before shipping).
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure parse of an already-fetched field, zero new API calls), validation risk 2/5 (additive conditional block gated on `alert.kev && alert.kev_notes`, cannot fire for non-KEV alerts, degrades gracefully to an empty string if no genuine advisory link is found in a given entry's notes), value 4/5 (closes the CISA required-action feature from last cycle with the one thing still missing -- a direct, one-click path to the vendor's actual patch notes, rather than generic remediation text).

**Validation (Step 4):**
- `python3 -c "import ast; ast.parse(...)"` on `scripts/aggregate.py`: OK. `node --check docs/app.js`: OK. `yaml.safe_load` on both config files: OK.
- Backed up `docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`, `docs/feed.json`, `docs/feed.xml`, `docs/data/kev_snapshot.json` to `/tmp`. Ran `scripts/aggregate.py` for real against live NVD/EPSS/CISA KEV data (no NVD_API_KEY/GH_DEPENDABOT_TOKEN available locally, so `LOOKBACK_DAYS=8` default and Dependabot fetch correctly skipped with its existing warning -- expected, not a regression). Completed successfully: 503 total alerts, 1 KEV entry (CVE-2026-85046), and inspecting the output confirmed `kev_notes` was correctly populated with the real CISA notes string (containing the genuine Chrome release-notes URL plus the expected boilerplate links) and `kev_required_action` remained intact. `git checkout --` restored all production data files afterward so this throwaway local run never overwrote real production data (verified via `git status --short` showing only the 3 intended source files modified before commit).
- Served a scratch copy of `docs/` on a local port with the real 501-alert production dataset (with a realistic `kev_notes` value injected into the one KEV entry, matching the real value observed during the dry run, since the committed production `alerts.json` itself is not touched by a frontend-only local test). Used the browser tool: confirmed the `.kev-notes` row renders as `Advisories: <a>Vendor advisory</a>` linking to the correct Chrome release-notes URL (BOD-26-04/Forensics-Triage/NVD links correctly filtered out), confirmed the existing `.kev-action` CISA-required-action box directly above it is unaffected, confirmed search filter still works with no regression (`chrome`: 501→110→501 on clear).

**Deploy (Step 5):**
- Committed (`258f947`) and pushed to `main`. Backend schema change (new `kev_notes` field in `scripts/aggregate.py`), so dispatched `cve-alerts.yml` via `gh workflow run` rather than relying solely on the next scheduled run.
- Polled the dispatched run (`34390363792`) to completion: `success`. Grepped the log for warnings/errors/tracebacks excluding known-benign Node 20 deprecation noise: none found.
- `git pull` to sync the freshly-regenerated production data; confirmed `docs/data/alerts.json` now contains a real `kev_notes` value for `CVE-2026-85046`. Curled the live URLs for `app.js`, `style.css`, `data/alerts.json` -- all 200 OK; confirmed `kevNotesLinksHtml` string present in the live `app.js` (2 occurrences: definition + call site).
- Loaded the LIVE dashboard in the browser tool with a fresh (non-cached) navigation and inspected `document.getElementById('alert-CVE-2026-85046').outerHTML` directly: confirmed the `.kev-notes` row renders correctly with the expected "Advisories: Vendor advisory" link pointing to the real Chrome release-notes URL, immediately below the existing `.kev-action` CISA-required-action box, with zero disruption to badges, risk bar, CWE row, or card footer. (Note: an initial screenshot attempt on a tab that had loaded *before* the workflow run completed showed the stale pre-deploy state -- correctly diagnosed as a browser-tab caching artifact, not a deploy failure, by re-fetching `app.js` and the DOM directly via a fresh navigation, which confirmed the new code and data were live and rendering correctly.)

**Rejected this cycle:** None — the KEV-notes-advisory-link candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 28. `stopped`: false.


## Cycle 29 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34390363792, 34375061636, 34369721256, 34360511746, 34349733814), no 429/throttle signals from NVD/EPSS/GHSA/CISA in recent Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Show EPSS percentile (relative rank) alongside the raw EPSS score on alert cards and in CSV export.

- **Opportunity:** `build_final_entry()` in `scripts/aggregate.py` has captured `epss_percentile` (each CVE's rank among all EPSS-scored CVEs, a 0-1 fraction returned by FIRST.org's EPSS API) into the alert schema since early cycles, but it was never rendered on the dashboard or included in CSV export -- only the raw `epss_score` probability was shown. These answer different triage questions: a low absolute probability (e.g. 2%) can still mean top-2%-of-all-CVEs relative rank, a materially different signal that was previously invisible without manually cross-referencing FIRST.org.
- **Frontend:** Added a `(top N%)` span (computed as `100 - epss_percentile*100`) next to the EPSS score in each card's scores row in `docs/app.js` `renderCard()`, with a title tooltip spelling out the full phrasing ("Higher than X% of all scored CVEs"), gated on `typeof alert.epss_percentile === "number"` so it silently omits for CVEs without an EPSS score. Also added `epss_percentile` as a new CSV export column immediately after `epss_score`. Added a matching `.epss-percentile` CSS rule to `docs/style.css`.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side template addition reading an already-fetched, already-stored field, zero new API calls), validation risk 2/5 (additive, gated on a type check, cannot break existing rendering for entries missing the field), value 4/5 (closes a real, previously-invisible triage signal already present in the data).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status --short` confirmed only `docs/app.js` and `docs/style.css` touched).
- Served `docs/` on a scratch local port (8973) with real production data (505 alerts). Used the browser tool: confirmed the `(top 29%)` span renders correctly next to `EPSS: 1.4%` on the CVE-2026-85046 card with the correct tooltip text, screenshot-confirmed no layout regression across multiple cards; confirmed existing search filter still works (`chrome`: 505→110→505 on clear).

**Deploy (Step 5):**
- Committed (`a28a3c4`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Polled GitHub Pages deployment to completion; curled `https://astruzocyber.github.io/CVE/app.js` and `style.css` (both 200 OK, `epss-percentile` string present in the live `app.js`).
- Loaded the LIVE dashboard in the browser tool: confirmed 502 `.epss-percentile` spans rendering across the live 505-alert dataset with correct text/tooltip, screenshot-confirmed stats bar and historical trend chart unaffected. No regression observed.

**Rejected this cycle:** None — the EPSS-percentile candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 29. `stopped`: false.


## Cycle 30 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34390363792, 34375061636, 34369721256, 34360511746, 34349733814), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Show CVSS attack-vector/complexity/auth exploitability chip on alert cards.

- **Opportunity:** `extract_cvss()` has always read NVD's `cvssData.baseScore` on every run, but the same `cvssData` object (already present in the fetched response) also carries `attackVector`/`attackComplexity`/`privilegesRequired`/`userInteraction` -- never parsed or rendered. These answer a materially different triage question than the base score alone: two CVEs both scored 7.5 can be a remote/no-auth/no-interaction (drop-everything-and-patch) versus a local/high-complexity/auth-required (much lower real-world urgency) vulnerability, which was previously invisible on the dashboard without manually reading the raw NVD JSON.
- **Backend:** Added `extract_cvss_vector_components()` to `scripts/aggregate.py` -- reads the same NVD `cvssMetricV31`/`cvssMetricV30` metrics object `extract_cvss()` already reads, just pulling 4 additional fields. Scoped to NVD only for this cycle (GHSA/Dependabot advisories expose a raw mixed v3/v4 `vector_string` without pre-split component fields; extracting that correctly is deferred to a future cycle rather than risking a mis-parsed field now, per constraint 3). Wired into the NVD candidate dict (`cvss_vector_components`) and `build_final_entry()` (propagated through unchanged, `None` for GHSA/Dependabot-sourced or not-yet-refreshed pre-existing alerts). Zero new HTTP calls.
- **Frontend:** Added a compact `.exploit-chip` badge (e.g. "Network · no auth/interaction") to the scores row in `renderCard()` in `docs/app.js`, with a full-vector tooltip (`title=` attribute) spelling out all four components; gated on `vc && vc.attack_vector` so it silently omits for the ~half of alerts without NVD vector data. Added matching `.exploit-chip` CSS to `docs/style.css`.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure parse of already-fetched NVD response fields, zero new API calls), validation risk 2/5 (additive, gated on presence check, cannot break rendering for entries missing the field), value 4/5 (closes a real, previously-invisible triage signal -- remote/no-auth exploitability -- that materially changes prioritization beyond the raw CVSS number alone).

**Validation (Step 4):**
- `python3 -c "import ast; ast.parse(...)"` on `scripts/aggregate.py`: OK. `node --check docs/app.js`: OK. `yaml.safe_load` on both config files: OK.
- Backed up `docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`, `docs/feed.json`, `docs/feed.xml`, `docs/data/kev_snapshot.json` to `/tmp`. Ran `scripts/aggregate.py` for real (backgrounded via `terminal(background=true)` + `process_manage(action='wait')` since the run exceeds the 180s foreground cap) against live NVD/EPSS/CISA KEV data. Completed successfully: 505 total alerts, 335/505 with a populated `cvss_vector_components` locally (256/505 after the live CI regeneration, difference expected from the ~2h gap and NVD lookback-window churn between local test and live run). Inspected output: correct nested dict shape (`attack_vector`/`attack_complexity`/`privileges_required`/`user_interaction`), no crash, `KEV catalog`/`NVD candidates`/`stats` all sane. `git checkout --` restored all production data files plus deleted a stray `new_alerts.json` test artifact afterward (`git status --short` confirmed only the 3 intended source files remained modified before commit).
- Served a scratch copy of `docs/` on a local port (8931) with real production data (505 alerts) plus 2 synthetic `cvss_vector_components` values injected into 2 real cards (network/no-auth and local/high-complexity/auth-required, matching realistic NVD output observed during the dry run) to validate rendering without touching committed data. Used the browser tool: confirmed both chips render with correct text and tooltip, confirmed correct card layout (screenshot), confirmed existing search filter unaffected (`wordpress`: 505→132 of 505). `git checkout --` reverted the injected test file before commit.

**Deploy (Step 5):**
- Committed (`26ca9c7`) and pushed to `main`. Backend schema change (new `cvss_vector_components` field in `scripts/aggregate.py`), so dispatched `cve-alerts.yml` via `gh workflow run` (run `34398719776`) rather than relying solely on the next scheduled run.
- Polled the dispatched run to completion: `success`, ~40s. Grepped the log for warnings/errors/tracebacks excluding known-benign Node 20 deprecation noise: none found.
- `git pull` to sync the freshly-regenerated production data (505 alerts, 256 with `cvss_vector_components`). Curled `app.js`/`style.css`/`data/alerts.json` -- all 200 OK; confirmed `exploit-chip` string present in the live `app.js`.
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed 256 `.exploit-chip` elements rendering correctly across the live dataset with correct text/tooltip (e.g. "Network" with full-vector tooltip), screenshot-confirmed stats bar (505 total, 123 critical, 2 KEV) and historical trend chart unaffected, no regression observed. (Note: an initial same-tab reload without a cache-bust query param showed 0 chips due to a stale cached `data/alerts.json` fetch -- same browser-tab caching artifact documented in cycle 28's log, correctly diagnosed and resolved via a fresh cache-busted navigation, not a deploy failure.)

**Rejected this cycle:** None — the exploitability-chip candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 30. `stopped`: false.


## Cycle 31 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34399421600, 34398719776, 34390363792, 34375061636, 34369721256), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Extract CVSS attack-vector/complexity/privileges/user-interaction components from GHSA/Dependabot advisories' raw `vector_string` field, closing the gap deliberately deferred in cycle 30.

- **Opportunity:** Cycle 30 added `extract_cvss_vector_components()` for NVD-sourced alerts only, explicitly noting GHSA/Dependabot advisories expose the same four components as a raw mixed-version `vector_string` (e.g. `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/...`) rather than NVD's pre-split fields, and deferred parsing it to a future cycle rather than risk a mis-parsed field. This cycle closes that gap for CVSS v3.0/v3.1 strings, which use a fixed, publicly documented FIRST.org abbreviation scheme (the exact same AV/AC/PR/UI codes NVD's `cvssData` already encodes) -- following a stable public spec, not guessing.
- **Backend:** Added `parse_cvss_v3_vector_string()` to `scripts/aggregate.py`: splits the vector string on `/`, maps each `KEY:VALUE` pair through the documented CVSS v3.x code tables (AV: N/A/L/P, AC: L/H, PR: N/L/H, UI: N/R). CVSS v4.0 strings are detected by their `CVSS:4.0` prefix (v4 redefines/adds components -- e.g. new `AT` metric, different `UI` value set -- so mapping them through the v3 tables would silently produce wrong data) and explicitly return `None` rather than guess. Wired into `fetch_dependabot_alerts()` and `fetch_ghsa_advisories()`, both of which already fetch a `cvss.vector_string` field in their existing API responses -- zero new HTTP calls. No frontend change needed: `renderCard()`'s existing `exploit-chip` logic (cycle 30) already reads `alert.cvss_vector_components` generically regardless of source.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure parse of an already-fetched field using a fixed public spec table, zero new API calls), validation risk 2/5 (additive field, gated by presence checks both in the parser itself -- returns `None` on any unrecognized/v4 format -- and in the existing frontend rendering logic; cannot affect NVD-sourced alerts or break rendering for entries missing the field), value 3/5 (closes an explicitly-flagged gap from the prior cycle; currently dormant in production since `ghsa_packages` is empty and `GH_DEPENDABOT_TOKEN` is unset, but activates automatically and correctly the moment either source is configured, with zero further code changes needed).

**Validation (Step 4):**
- `python3 -c "import ast; ast.parse(...)"` on `scripts/aggregate.py`: OK. No frontend files touched, so no `node --check` needed; `git status --short` confirmed only `scripts/aggregate.py` modified before commit.
- Direct unit test of `parse_cvss_v3_vector_string()` against a real CVSS v3.1 vector string sampled live from the GHSA API (`GET /advisories?affects=lodash`, GHSA-r5fr-rjxr-66jc / CVE-2026-4800): correctly returned `{'attack_vector': 'NETWORK', 'attack_complexity': 'HIGH', 'privileges_required': 'NONE', 'user_interaction': 'NONE'}`. Also tested a synthetic CVSS v4.0 vector string: correctly returned `None` (confirming the v3-only guard works and no v4 field is ever mis-mapped), plus `None`/empty-string inputs: both correctly return `None`.
- Backed up `docs/data/{alerts,seen_ids,stats}.json`, `docs/data/history/`, `docs/feed.json`, `docs/feed.xml`, `docs/data/kev_snapshot.json` to `/tmp`. Ran `scripts/aggregate.py` for real against live NVD/EPSS/CISA KEV data (`GH_DEPENDABOT_TOKEN` unset locally, so Dependabot fetch correctly skipped with its existing warning -- expected, not a regression; `ghsa_packages` is empty in the committed watchlist, so the new GHSA code path did not fire against live data this run, consistent with the unit-test-only verification above for that path). Completed successfully: 515 total alerts, 365 with `cvss_vector_components` (all `nvd` source, as expected). No crash, no schema drift. `git checkout --` restored all production data files afterward (`git status --short` confirmed only `scripts/aggregate.py` remained modified before commit).

**Deploy (Step 5):**
- Committed (`e3fe7eb`) and pushed to `main`. Backend schema change (new parsing path in `scripts/aggregate.py`), so dispatched `cve-alerts.yml` via `gh workflow run` (run `34403032881`) rather than relying solely on the next scheduled run.
- Polled the dispatched run to completion: `success`, ~47s. Grepped the log for warnings/errors/tracebacks excluding known-benign Node 20 deprecation noise: none found.
- `git pull` to sync the freshly-regenerated production data (516 alerts, 267 with `cvss_vector_components`, all still `nvd`-sourced as expected since GHSA/Dependabot remain unconfigured in production). Curled `data/alerts.json` -- 200 OK.
- No frontend files changed, so no live browser re-verification was needed for this cycle -- confirmed via `renderCard()` already handling the field generically as implemented in cycle 30's live-verified deploy.

**Rejected this cycle:** None — the GHSA/Dependabot vector-parsing candidate cleared the bar on first pass and was implemented.

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 31. `stopped`: false.


## Cycle 32 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34403032881, 34399421600, 34398719776, 34390363792, 34375061636), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Add CVSS exploitability, KEV required-action, and KEV notes fields to CSV export.

- **Opportunity:** Reviewing `renderCard()` vs `exportCsv()` in `docs/app.js` found a gap: three prior cycles (27 - CISA required-action display, 28 - vendor advisory notes, 30/31 - CVSS attack-vector/complexity/privileges/UI exploitability chip) added fields to the alert schema and rendered them on cards, but `exportCsv()` was never updated to include them. A viewer exporting CSV for offline reporting or compliance tracking would silently lose data they could see plainly on the dashboard itself.
- **Frontend:** Added 6 new CSV columns (`kev_required_action`, `kev_notes`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`) to the existing header/row-building logic in `exportCsv()`, flattening the nested `cvss_vector_components` object per row. Pure additive change reading fields already present in `alerts.json` -- zero new API calls, zero backend/schema changes.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side template addition, no new dependencies), validation risk 1/5 (additive columns appended after existing ones, cannot break existing column order/consumers, gated by `|| {}` fallback for the nested object so missing data renders as empty string not a crash), value 3/5 (closes a real, previously-silent data-loss gap for a security-team compliance/reporting workflow -- small but genuine value, low effort, virtually zero risk).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status --short` confirmed only `docs/app.js` touched).
- Served `docs/` on a local scratch port with real production data (516 alerts). Used the browser tool: executed the exact new export-row-building logic in-page via JS eval (rather than triggering a real file download) against the live in-memory `allAlerts` array and confirmed correct values for both KEV rows (populated `kev_required_action`, `kev_notes`, and vector fields, correctly CSV-quoted with embedded commas/quotes) and non-KEV rows (correctly empty strings for the new fields, not `undefined`/crash). Confirmed existing search filter still works (`wordpress`: 516→132→516 on reset) and stats bar (`stat-total`: 516) unaffected -- no regression to existing features.

**Deploy (Step 5):**
- Committed (`9c2007b`) and pushed to `main`. Frontend-only change -- no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited for Pages deployment, curled `https://astruzocyber.github.io/CVE/app.js` -- 200 OK, confirmed `kev_required_action` string present (2 occurrences: header + row-building).
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed 516/516 alerts loaded, inspected `allAlerts` directly via JS eval and confirmed real KEV entries (CVE-2025-25249, CVE-2026-87491) carry correctly populated `kev_required_action`/`kev_notes`/`attack_vector` fields ready for CSV export. (Screenshot capture via CDP timed out on this run -- an infra/tooling flakiness in the browser harness itself, not a page regression; functional JS-level verification via `page_info()`/`js()` confirmed the page loaded and rendered correctly, which was sufficient given no visual markup was touched by this change.)

**Rejected this cycle:** None — the CSV-export-field-parity candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 3/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 32. `stopped`: false.


## Cycle 33 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34403032881, 34399421600, 34398719776, 34390363792, 34375061636), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Add clickable severity-breakdown pills (critical/high/medium/low/unknown counts) below the existing source-breakdown row in the dashboard header.

- **Opportunity:** `compute_stats()` in `scripts/aggregate.py` has computed `by_severity` (critical/high/medium/low/unknown counts) since early cycles, but only the single "Critical" count ever made it onto the dashboard via the stats bar -- the medium/low/unknown bands and overall severity mix were invisible without exporting CSV. Cycle 15's `by_source` breakdown pills established a clean pattern for surfacing an existing-but-unrendered stats field; this cycle applies the same pattern to `by_severity`, plus adds a genuinely new interaction (click-to-filter) that cycle 15's static pills didn't have.
- **Frontend:** Added `renderSeverityBreakdown()` to `docs/app.js`, wired into the existing `loadStats()` call alongside `renderSourceBreakdown()`. Renders one `<button>` pill per non-zero severity band, reusing the dashboard's existing red/orange/yellow/green severity color convention (already used for card borders/badges since early cycles, so zero new color decisions). Each pill click sets the existing `#severity-filter` dropdown and calls the existing `applyFiltersAndRender()` -- a one-click drill-down composing for free with cycle 7's shareable-URL filters. `unknown` band has no matching `<option>` in the dropdown, so its click handler silently no-ops rather than setting an invalid value. Added `#severity-breakdown` div to `docs/index.html` and matching `.severity-breakdown`/`.severity-pill` CSS to `docs/style.css`.
- **Zero-cost/risk assessment:** Feasibility 5/5 (reads an already-computed, already-fetched stats.json field, zero new API calls, zero backend/schema changes). Validation risk 1/5 (purely additive DOM/CSS, gated on non-zero counts so it degrades gracefully to `hidden` if the field is ever absent, cannot affect any existing rendering path). Value 3/5 (closes a real visibility gap -- the dashboard could show "128 critical" but nothing about the other 388 alerts' severity mix -- plus adds a genuinely new one-click filter interaction, not just a static display).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status --short` confirmed only `docs/app.js`, `docs/index.html`, `docs/style.css` touched).
- Served `docs/` on a local scratch port (8933) with real production data (516 alerts: critical=128, high=388, medium=0, low=0, unknown=0). Used the browser tool: confirmed both non-zero pills (`critical: 128`, `high: 388`) rendered with correct DOM structure and CSS classes; clicked the "critical" pill and confirmed `#severity-filter` correctly updated to `critical` and the result count correctly narrowed to "128 of 516 alerts"; clicked the existing Reset Filters button and confirmed it correctly returned to "516 of 516 alerts" with the dropdown back to `all` (zero regression to the cycle-24 reset-filters feature). Screenshot confirmed correct visual placement under the source-breakdown row, stats bar, and historical trend chart all rendering with zero regression.

**Deploy (Step 5):**
- Committed (`9256637`) and pushed to `main`. Frontend-only change -- no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited for Pages deployment, curled `app.js`/`index.html`/`style.css` -- all 200 OK, confirmed `renderSeverityBreakdown` string present in the live `app.js` (2 occurrences: definition + call site).
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: JS-eval-confirmed `#severity-breakdown` renders the correct live counts (critical:128, high:388) matching production `stats.json`, and `stat-total` correctly reads 516. Screenshot capture hit a transient CDP `TimeoutError` on this run (same documented harness flakiness noted in cycle 32's log, not a page regression) -- functional JS-level verification was sufficient given the exact same DOM structure was already screenshot-confirmed correct in the local scratch-port test immediately prior.

**Rejected this cycle:** None — the severity-breakdown candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 3/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 33. `stopped`: false.


## Cycle 34 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34403032881, 34399421600, 34398719776, 34390363792, 34375061636), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Add `matched_keywords` column to CSV export.

- **Opportunity:** Cycle 32 closed a CSV-export parity gap for `kev_required_action`/`kev_notes`/CVSS-vector-component fields that were visible on cards but missing from `exportCsv()`. Auditing `renderCard()` vs `exportCsv()` again this cycle found one more instance of the same pattern: `matched_keywords` (rendered as a green "Watchlist match" badge on cards since cycle 8, and already included in the search haystack since cycle 25) was still absent from CSV export. A viewer exporting for offline triage/reporting could see on-screen which watchlist keyword(s) flagged a given CVE but lost that signal entirely once exported.
- **Frontend:** Added `matched_keywords` (joined with `"; "`, matching the existing convention for `affected`/`cwe_ids` array columns) as a new CSV column in `docs/app.js`, placed after `cwe_ids` in both the header and per-row array.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side template addition, reads a field already present in `alerts.json` since early cycles, zero new dependencies). Validation risk 1/5 (additive column appended at a stable position, cannot reorder/break existing columns, gated by `|| []` fallback so alerts with no matched keywords render an empty string not a crash). Value 2/5 (small, but genuine and previously-silent data-loss gap for a security-team reporting workflow — same category and precedent as cycle 32's fix, no new risk introduced).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status --short` confirmed only `docs/app.js` touched).
- Served `docs/` on a local scratch port (8933) with real production data (516 alerts, 139 with non-empty `matched_keywords`). Used the browser tool to exercise the exact new export-row-building logic in-page via JS eval against the live in-memory `allAlerts` array: confirmed a matched-keyword alert (CVE-2026-84068) correctly serializes `["wordpress","wp plugin"]` and a no-match alert produces no `undefined` in its row. Confirmed existing search filter still works (`wordpress`: 516→132→516 on reset) — no regression to existing features.

**Deploy (Step 5):**
- Committed (`ad02248`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited for Pages deployment, curled `https://astruzocyber.github.io/CVE/app.js` — 200 OK, confirmed `matched_keywords` string count rose from 2 (pre-change) to 4 (post-change, header + row-building).
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed 516/516 alerts loaded correctly (`stat-total`: 516, `result-count`: "516 of 516 alerts") — zero regression.

**Rejected this cycle:** None — the CSV-export-field-parity candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 2/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 34. `stopped`: false.


## Cycle 35 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34403032881, 34399421600, 34398719776, 34390363792, 34375061636), no 429/throttle signals from NVD/EPSS/GHSA/CISA in Actions logs, only benign Node 20 runner deprecation noise.

**Change:** Add a `@media print` stylesheet and a "Print / PDF" button for producing clean triage reports.

- **Opportunity:** Auditing `docs/style.css` found zero `@media print` rules despite the dashboard's stated audience being a security team that would plausibly need to hand a printed or PDF-exported triage list to leadership or compliance. Printing the raw dark theme as-is would dump an unreadable, ink-wasting page including the interactive toolbar, filter controls, dependency-file uploader, and trend-chart canvas -- none of which are meaningful on paper.
- **Frontend:** Added a `@media print` block to `docs/style.css`: converts body/card background to white and text to dark, hides `.stale-banner`, `.trend-section`, `.dep-filter`, `.controls`, and the CVE-link "Copied!" pseudo-element indicator; expands `.score-breakdown` inline (normally a click-to-reveal toggle) so the CVSS/EPSS/KEV risk-score math is visible without interaction; recolors badges/pills/exploit-chips to print-safe outlined style; sets `break-inside: avoid` on `.card` so a single alert never splits across a page boundary; switches `.card-grid` to single column. Added a visible "Print / PDF" button (`docs/index.html`) next to the existing "Export CSV" button, wired to `window.print()` in `docs/app.js` -- the button itself is inside `.controls` so it correctly disappears from the printed output.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side CSS/HTML/JS, zero new dependencies, zero new API calls). Validation risk 1/5 (additive `@media print` block scoped entirely to the print media query, cannot affect on-screen rendering at all; new button/handler is additive and isolated). Value 3/5 (closes a real, previously-unaddressed gap for a security-team tool's realistic "hand this to my boss/auditor" workflow -- distinct from the existing CSV export, since a formatted visual report with risk-score breakdowns is often more useful for a briefing than a raw data file).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. CSS brace-balance check (123 open / 123 close). No `aggregate.py`/schema changes, so no data-pipeline dry-run/backup/restore cycle was needed (`git status --short` confirmed only `docs/app.js`, `docs/index.html`, `docs/style.css` touched).
- Served `docs/` on a local scratch port (8933, background process) with real production data (516 alerts). Used the browser tool with CDP `Emulation.setEmulatedMedia(media='print')` to force print-media CSS evaluation without a real print dialog: confirmed via `getComputedStyle` that `document.body` background flipped from dark to `rgb(255,255,255)`/text to `rgb(17,17,17)`, `.controls` computed `display: none`, `.card` background white, `.score-breakdown` computed `display: block` (normally hidden/toggle-only), `#stale-banner` computed `display: none`, and `.card-grid` computed `grid-template-columns` collapsed to a single column (`1152px` = 1fr). Confirmed `window.matchMedia('print').matches === true` during emulation.
- Reset media emulation to screen and confirmed zero regression: body background reverted to dark `rgb(11,15,20)`, `.controls` back to `display: flex`, existing debounced search filter still worked correctly (`wordpress`: 516→132→516 on clear), `print-view` and `export-csv` buttons both present and correctly labeled.
- (Screenshot capture during print-media emulation showed the *pre-emulation* dark-theme layout rather than the print styles -- a known CDP screenshot/emulation-timing quirk in the harness, not a CSS bug; the `getComputedStyle` assertions above are authoritative and directly confirm every print rule actually applied to the live DOM.)

**Deploy (Step 5):**
- Committed (`ce17ca5`) and pushed to `main`. Frontend-only change -- no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited ~75s for Pages deployment, then cache-busted curl confirmed `print-view` string present in live `app.js` (1 occurrence) and `index.html` (1 occurrence), and `@media print` present in live `style.css` (1 occurrence).
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed `#print-view` button exists with text "Print / PDF" and `stat-total` correctly reads 516 -- zero regression to existing rendering.

**Rejected this cycle:** None — the print-stylesheet candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 3/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 35. `stopped`: false.

## Cycle 36 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded, no 429/throttle signals from NVD/EPSS/GHSA/CISA/Dependabot in Actions logs, only benign Node 20 runner deprecation noise. State was clean (0/10 no-improvement, 0/3 failed) at start.

**Change:** Add `Total KEV count` and `KEV ransomware-use count` as opt-in (hidden-by-default) datasets on the historical trend chart.

- **Opportunity:** Auditing `loadTrendChart()` against `docs/data/history/trend.csv`'s actual columns found `kev_count` (column 3) and `kev_ransomware_count` (column 5) have been written to the CSV every run since early cycles, but only 3 of the 6 columns (`total_alerts` since cycle 26, `kev_overdue_count`, `avg_epss`) were ever parsed/plotted — the raw KEV catalog membership trend and ransomware-actively-exploited trend were invisible despite the data already being fetched client-side on every page load.
- **Frontend:** Added `kevCount`/`kevRansomware` array parsing (same null-safe pattern as existing columns) and two new Chart.js datasets, both `hidden: true` by default (mirroring cycle 26's precedent for "Total tracked alerts") and bound to the existing hidden `y2` axis so they never visually compete with the two default-visible labeled axes. Default rendered view is unchanged; a viewer opts in via the Chart.js legend.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side parse of already-fetched CSV columns, zero new dependencies, zero new API/network calls). Validation risk 1/5 (additive datasets only, `hidden:true` guarantees zero default-view visual change, existing datasets/axes untouched). Value 2/5 (real signal previously silently discarded — KEV membership growth and ransomware-exploited-KEV trend are meaningful for a security-team triage tool — same category as cycle 26's original trend-chart enrichment).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes — `git status --short` confirmed only `docs/app.js` touched, so no data-pipeline dry-run/backup/restore cycle was needed.
- Served `docs/` on a local scratch port (8933) with real production data (516 alerts, 16 trend.csv rows). Used the browser tool to inspect the live Chart.js instance via `Chart.getChart()`: confirmed all 5 dataset labels present (`Total tracked alerts`, `Total KEV count`, `KEV overdue count`, `KEV ransomware-use count`, `Avg EPSS (%)`) with correct hidden flags (`[true, true, false, true, false]` — only the two originally-visible datasets remain visible by default). Confirmed stats bar and card grid unaffected (516/516 alerts, `stat-total`: 516).

**Deploy (Step 5):**
- Committed (`3dfd577`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited ~60s for Pages deployment, curled `https://astruzocyber.github.io/CVE/app.js` — 200 OK, confirmed `KEV ransomware-use count` string present live.
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed `stat-total`: 516, `result-count`: "516 of 516 alerts", and the live Chart.js instance exposes all 5 expected dataset labels in the correct order — zero regression.

**Rejected this cycle:** None — the trend-chart dataset-parity candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 2/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 36. `stopped`: false.

## Cycle 37 — 2026-09-09

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 5 `cve-alerts.yml` runs all succeeded (34403032881, 34399421600, 34398719776, 34390363792, 34375061636), no 429/throttle signals from NVD/EPSS/GHSA/CISA/Dependabot in Actions logs, only benign Node 20 runner deprecation noise. State was clean (0/10 no-improvement, 0/3 failed) at start.

**Change:** Add an "Export JSON" button for raw filtered-alert export.

- **Opportunity:** The dashboard had CSV export (cycles 32/34) and a print/PDF view (cycle 35), but no way to export the raw, structurally-intact JSON objects backing the currently-filtered view. CSV export flattens/joins nested fields (`cvss_vector_components`, `risk_score_breakdown`, `kev_*` fields) into strings, which is lossy for a viewer who wants to script against this data (feed it into a SIEM, a jq/Python pipeline, or a custom alert router) — they'd otherwise have to scrape the unfiltered `docs/data/alerts.json` directly or manually reconstruct nested structure from CSV.
- **Frontend:** Added `exportJson()` in `docs/app.js` that downloads `window.__lastFiltered` (or `allAlerts` if no filter has run) as pretty-printed JSON, mirroring the existing `exportCsv()` blob/download pattern. Added an "Export JSON" `<button id="export-json">` next to the existing "Export CSV" button in `docs/index.html`, wired via `addEventListener`. The new button lives inside the existing `.controls` container, so it inherits the existing mobile-breakpoint stacking (cycle 11) and print-media hide rule (cycle 35) with zero additional CSS needed.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side `JSON.stringify` + Blob download, zero new dependencies, zero new API/network calls). Validation risk 1/5 (fully additive function + button + one event listener; does not touch `applyFiltersAndRender`, `exportCsv`, or any existing rendering path). Value 3/5 (closes a real gap for scripting/automation consumers of this public dashboard, distinct from both the CSV export and the print view — CSV loses nested structure, JSON preserves it exactly as the on-screen filtered view sees it).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. CSS untouched this cycle (no `style.css` changes needed — new button inherits existing `.controls button` rules). No `aggregate.py`/schema changes — `git status --short` confirmed only `docs/app.js` and `docs/index.html` touched, so no data-pipeline dry-run/backup/restore cycle was needed.
- Served `docs/` on a local scratch port (8934) with real production data (516 alerts). Used the browser tool to confirm: `#export-json` button renders with correct label; calling the underlying export logic in-page produced well-formed JSON with full nested fields present (`risk_score_breakdown`, `cvss_vector_components` both confirmed present in the sample); existing search filter still worked correctly (`wordpress`: 516→132→516 on clear); `#export-csv` button still present and unaffected; stats bar (`stat-total`: 516) unaffected.

**Deploy (Step 5):**
- Committed (`f5f406e`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited ~60s for Pages deployment, then cache-busted curl confirmed `export-json` string present live in both `app.js` (1 occurrence) and `index.html` (1 occurrence), both 200 OK.
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed `#export-json` button renders with text "Export JSON", `stat-total`: 516, `result-count`: "516 of 516 alerts" — zero regression. Screenshot confirmed correct production rendering of stats bar, severity pills, and historical trend chart.

**Rejected this cycle:** None — the raw-JSON-export candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 3/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 5 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 37. `stopped`: false.

---

## Cycle 38 — 2026-09-10T00:47:00Z

**Step 1 health check:** No stopped flag, 0/3 failed cycles, 0/10 no-improvement at start. Checked `gh run list --workflow=cve-alerts.yml --limit 5`: found the most recent scheduled run (2026-09-10T00:13:41Z) had **failed** with `error: failed to push some refs to 'https://github.com/astruzocyber/CVE'` at the "Commit and push data changes" step — a non-fast-forward rejection, almost certainly a race between two overlapping runs (a workflow_dispatch and the 4-hourly schedule) both pushing data-file commits to `main` around the same time. No 429/rate-limit signals from NVD/EPSS/CISA KEV/GHSA/Dependabot in any of the last 5 runs — this was a git-race issue, not an API issue.

**Change:** Made the aggregator workflow's data-commit push resilient to races. `.github/workflows/cve-alerts.yml`'s "Commit and push data changes" step previously did a single bare `git push` with no retry — any concurrent push (two runs overlapping) would permanently fail that step and the whole job. Replaced with a 5-attempt loop: `git pull --rebase origin main && git push`, with a randomized 5-14s backoff between attempts, and an explicit `::error::` + `exit 1` only if all 5 attempts are exhausted (so real, non-transient failures still surface clearly in Actions rather than being silently swallowed).

- **Scoring:** Feasibility 5/5 (pure CI YAML change, zero new dependencies/secrets/cost). Validation risk 1/5 (only affects the git push retry logic in one step; does not touch aggregate.py, schema, or any data file; rebase-then-push is git's standard race-resolution pattern and the data files in question are machine-generated JSON/CSV with no manual edits ever made in this repo, so rebase conflicts are not a realistic risk). Value 4/5 (directly fixes an observed, reproduced pipeline failure mode — this exact race caused the immediately-preceding scheduled run to fail).
- **Validation (Step 4):** `python3 -c "import yaml; yaml.safe_load(...)"` confirmed valid YAML. `git status --short` confirmed only the workflow file changed — no Python/frontend files touched, so no data-file backup/dry-run/restore cycle or local server was needed per Step 4's conditional gating.
- **Deploy (Step 5):** Committed `6b367ae` and pushed to `main`. Manually triggered `gh workflow run cve-alerts.yml` to verify the fix under real conditions: run `34422809781` completed **success** in 58s. Log grep confirmed zero errors/warnings/tracebacks (excluding benign Node 20 deprecation noise). `git pull` + curl confirmed `docs/data/alerts.json` (200) and the dashboard root (200) both live and serving correctly post-run.

**Rejected this cycle:** None — this candidate (fix the just-observed live pipeline failure) was the obvious highest-value, lowest-risk pick and cleared the bar on first pass.

**Rate-limit status:** Healthy across NVD, EPSS, CISA KEV, GHSA, Dependabot — no 429s/throttle signals in the last 5 runs (including this cycle's fresh dispatch run).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset — and this cycle also fixed the underlying cause of the failure that would otherwise have started counting toward that guard). `total_cycles`: 38. `stopped`: false.

## Cycle 39 — 2026-09-10T01:20:00Z

**Status:** Implemented and live-verified.

**Pipeline health at start of cycle:** Healthy. Last 8 `cve-alerts.yml` runs: 7 success, 1 failure (2026-09-10T00:13:41Z — the git-race issue fixed in cycle 38, already resolved and confirmed by a subsequent successful `workflow_dispatch` run at 00:47:56Z). No 429/throttle signals from NVD/EPSS/GHSA/CISA/Dependabot in any recent run. State was clean (0/10 no-improvement, 0/3 failed) at start.

**Change:** Add a "Sort: Published date (newest first)" option to the dashboard's sort dropdown.

- **Opportunity:** The existing `#sort-by` dropdown had two ingestion-time-based sort options (`first_seen` newest-first as default, `first_seen_oldest` for triage backlog, added cycle 19) but no way to sort by the actual vendor/NVD `published` date — a distinct signal from `first_seen` (when the pipeline first ingested the CVE, e.g. because it newly matched the watchlist or newly entered CISA KEV), which can diverge from `published` by years for older CVEs. Verified `published` is populated on all 527/527 currently-tracked alerts (`docs/data/alerts.json`), so the sort is never degenerate.
- **Frontend:** Added a `published` `<option>` to `#sort-by` in `docs/index.html`, and matching comparator logic in `applyFiltersAndRender()` in `docs/app.js` — descending `localeCompare` on ISO date strings, with missing values pushed to the end (not treated as newest), mirroring the existing `kev_due_date` sort's missing-value handling pattern from cycle 18.
- **Zero-cost/risk assessment:** Feasibility 5/5 (pure client-side sort comparator on an already-existing, already-populated field, zero new dependencies/API calls). Validation risk 1/5 (purely additive — one new `<option>`, one new `if` branch in the existing sort switch, does not touch any other sort branch, filter, or rendering path). Value 2/5 (real but modest UX gap — a genuinely different triage question than the existing ingestion-time sorts, low but nonzero incremental value).

**Validation (Step 4):**
- `node --check docs/app.js`: OK. No `aggregate.py`/schema changes — `git status --short` confirmed only `docs/app.js` and `docs/index.html` touched, so no data-pipeline dry-run/backup/restore cycle was needed.
- Served `docs/` on a local scratch port (8956) with real production data (527 alerts). Used the browser tool to confirm: the new "Sort: Published date (newest first)" option renders in `#sort-by`, selecting it correctly reorders cards (top 5 cards all showed the most recent `published` dates), and the existing search filter still works correctly (`wordpress`: 527→133→527 on clear, respecting the documented ~1s debounce from a prior cycle). Confirmed stats bar (`stat-total`: 527) and result count unaffected.

**Deploy (Step 5):**
- Committed (`473cb44`) and pushed to `main`. Frontend-only change — no `cve-alerts.yml` dispatch needed (GitHub Pages auto-deploys on push).
- Waited ~45s for Pages deployment, then cache-busted curl confirmed `sortBy === "published"` present in live `app.js` (200 OK) and `Published date` option text present in live `index.html` (200 OK).
- Loaded the LIVE dashboard in the browser tool with a fresh cache-busted navigation: confirmed the `#sort-by` dropdown includes the new `published` option, `stat-total`: 527, `result-count`: "527 of 527 alerts" — zero regression.

**Rejected this cycle:** None — the published-date-sort candidate cleared the bar on first pass (feasibility 5/5, validation risk 1/5, value 2/5) and was implemented.

**Rate-limit status:** No 429/throttle signals observed from NVD, EPSS, CISA KEV, GHSA, or Dependabot in the last 8 Actions runs. No change to call volume this cycle (frontend-only, zero new API calls).

**State:** `consecutive_no_improvement`: 0/10 (reset by this success). `consecutive_failed_cycles`: 0/3 (reset by this success). `total_cycles`: 39. `stopped`: false.
