# CVE / KEV / Dependabot Alert Dashboard

A fully automated, zero-cost vulnerability alert system. Runs entirely on free
tiers: GitHub Actions (scheduled cron), free public security APIs, and GitHub
Pages for the dashboard. No database, no server, no paid services.

## What it does

Every 4 hours (and on-demand via `workflow_dispatch`), a GitHub Actions job:

1. Fetches the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
2. Queries [NVD](https://nvd.nist.gov/) for CVEs matching the vendors/products/keywords in `config/watchlist.yaml`
3. Enriches matches with [FIRST.org EPSS](https://www.first.org/epss/) exploit-probability scores
4. Pulls open [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) for the repos listed in the watchlist
5. Filters everything against the watchlist (CVSS floor, optional KEV/high-EPSS-only mode)
6. Deduplicates against `docs/data/seen_ids.json` so nothing alerts twice
7. Writes results to `docs/data/alerts.json` (read directly by the dashboard)
8. Commits the updated data files back to the repo
9. Opens a GitHub Issue per new match, with a triage checklist

The dashboard (`docs/index.html`) is a plain HTML/CSS/JS static site with no
build step, deployed via GitHub Pages from the `docs/` folder.

## Setup

### 1. Enable GitHub Pages

Repo Settings -> Pages -> Source: "Deploy from a branch" -> Branch: `main`,
folder: `/docs`. Save. The dashboard will be live at
`https://astruzocyber.github.io/CVE/` within a minute or two.

### 2. Add repo secrets

Repo Settings -> Secrets and variables -> Actions -> New repository secret:

| Secret | Required? | Notes |
|---|---|---|
| `NVD_API_KEY` | Recommended | Free key from https://nvd.nist.gov/developers/request-an-api-key -- raises the NVD rate limit from 5 to 50 requests/30s. Without it the script still works, just slower/more likely to be rate-limited. |
| `GH_DEPENDABOT_TOKEN` | Required if `dependabot_repos` is non-empty | Personal Access Token with `security_events` read scope (classic PAT, or fine-grained with "Dependabot alerts: Read-only") for each repo listed under `dependabot_repos` in `config/watchlist.yaml`. |

`GITHUB_TOKEN` for opening issues is provided automatically by Actions --
nothing to add for that.

### 3. Tune the watchlist

Edit `config/watchlist.yaml`:

- `cvss_minimum` -- floor score to alert on (currently 7.0)
- `vendors_products` -- vendor/product pairs to search for in NVD
- `keywords` -- free-text terms matched against CVE descriptions
- `dependabot_repos` -- `owner/repo` list to check for Dependabot alerts
- `require_kev_or_high_epss` -- if `true`, only alerts on CVEs that are in KEV
  or have EPSS >= `epss_high_threshold` (cuts noise a lot); currently `false`

The initial vendor/product/keyword list is a broad starting set covering major
widely-deployed software (OS, web server, CMS, browsers, cloud, networking)
since specifics of GFR Media's actual stack weren't provided. **Narrow this
down** once you see real results -- add exact CPE vendor/product pairs for
what you actually run, and remove anything irrelevant.

### 4. Run it

Actions tab -> "CVE/KEV/Dependabot Alert Aggregation" -> "Run workflow" to
trigger manually, or just wait for the next scheduled run (every 4 hours).

## Notifications

Currently wired: **GitHub Issues** -- one issue per new alert with a triage
checklist, labeled `vulnerability-alert` plus a severity label and `kev` if
applicable. No extra secret needed.

Other channels (ntfy.sh, Discord, Telegram) are stubbed out as commented-out
steps in `.github/workflows/cve-alerts.yml` -- to enable one, write the
corresponding `scripts/notify_*.py` (POST to the webhook/API), add the
required secret(s), and uncomment its workflow step.

## Files

```
config/watchlist.yaml            watchlist config (vendors, keywords, CVSS floor, repos)
scripts/aggregate.py             pulls KEV/NVD/EPSS/Dependabot, filters, writes data files
scripts/notify_github_issues.py  opens a GitHub Issue per new alert
.github/workflows/cve-alerts.yml scheduled + manual workflow
docs/index.html, style.css, app.js   static dashboard (GitHub Pages root)
docs/data/alerts.json            cumulative matched alerts (dashboard reads this)
docs/data/seen_ids.json          dedup ledger, prevents repeat notifications
docs/data/new_alerts.json        transient, only new-this-run alerts (gitignored)
```

## Local testing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
NVD_API_KEY=... GH_DEPENDABOT_TOKEN=... python scripts/aggregate.py
python -m http.server -d docs 8080   # then open http://localhost:8080
```
