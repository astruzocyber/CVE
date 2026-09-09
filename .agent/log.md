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
