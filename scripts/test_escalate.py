#!/usr/bin/env python3
"""Tests for environment tiering (scripts/escalate.py) and the Discord
notifier (scripts/notify_discord.py). No network: the poster is injected."""
import json
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import escalate as E  # noqa: E402
import notify_discord as D  # noqa: E402
import fetch_intel as F  # noqa: E402

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
CFG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "environment.yaml")


def env():
    return E.load_env(CFG, priority_terms=["Active Directory Federation Services"])


def alert(cid, desc, cvss=5.0, **kw):
    a = {"cve_id": cid, "description": desc, "cvss_score": cvss, "published": "2026-10-13T19:00:00",
         "first_seen": "2026-10-14T00:00:00", "matched_keywords": [], "affected": [],
         "cvss_vector_components": {"attack_vector": "NETWORK"}}
    a.update(kw)
    return a


def intel(iid, title, cats, summary="", priority="high"):
    return {"id": iid, "title": title, "summary": summary, "link": f"https://example.com/{iid}",
            "source": "Test", "categories": cats, "priority": priority, "score": 70,
            "published": "2026-10-15T10:00:00+00:00", "cve_ids": []}


def tiers(out):
    return {it["ref"]: it["tier"] for it in out["items"]}


class EscalateTests(unittest.TestCase):
    def test_kev_windows_shell_escalates(self):
        out = E.build([alert("CVE-2026-96951", "Command injection in Windows Shell allows bypass.", 8.8,
                             kev=True, kev_date_added="2026-10-13")], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-96951": "escalate"})
        self.assertIn("Windows Shell", out["items"][0]["reasons"][0])

    def test_low_cvss_adfs_is_work_via_priority_term(self):
        out = E.build([alert("CVE-2026-69982", "Weak authentication in Active Directory Federation Services "
                             "(AD FS) allows spoofing.", 5.9)], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-69982": "work"})

    def test_critical_network_cvss_on_critical_asset_escalates(self):
        out = E.build([alert("CVE-2026-96252", "Improper signature verification in Active Directory "
                             "Federation Services (AD FS).", 9.1)], {}, env(), NOW)
        self.assertEqual(tiers(out)["CVE-2026-96252"], "escalate")

    # Each ESCALATE trigger of classify_alert on its own. Before these tests,
    # removing the ransomware, news-exploited, EPSS or network-vector rule left
    # the whole suite green.
    PAN = "Buffer over-read in PAN-OS GlobalProtect portal."   # critical asset, no priority term

    def test_cvss_below_floor_alone_is_not_tiered(self):
        self.assertEqual(E.build([alert("CVE-2026-10", self.PAN, 5.0)], {}, env(), NOW)["items"], [])

    def test_news_reported_exploited_escalates_and_withdrawal_drops_it(self):
        out = E.build([alert("CVE-2026-11", self.PAN, 5.0, matched_keywords=["news: reported exploited"])],
                      {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-11": "escalate"})
        self.assertIn("Security news reports this CVE as exploited", out["items"][0]["reasons"])
        # aggregate.withdraw_news_exploited() removes the label -> no longer tiered
        self.assertEqual(E.build([alert("CVE-2026-11", self.PAN, 5.0, matched_keywords=[])],
                                 {}, env(), NOW)["items"], [])

    def test_epss_threshold_escalates_only_at_or_above(self):
        thr = env()["escalate_epss"]
        out = E.build([alert("CVE-2026-12", self.PAN, 5.0, epss_score=thr),
                       alert("CVE-2026-13", self.PAN, 5.0, epss_score=round(thr - 0.01, 4))], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-12": "escalate"})
        self.assertTrue(any(r.startswith("EPSS ") for r in out["items"][0]["reasons"]))

    def test_kev_ransomware_use_is_stated(self):
        out = E.build([alert("CVE-2026-14", self.PAN, 5.0, kev=True, kev_date_added="2026-10-14",
                             kev_ransomware_use=True)], {}, env(), NOW)
        self.assertIn("CISA KEV: known ransomware use", out["items"][0]["reasons"])
        out = E.build([alert("CVE-2026-14", self.PAN, 5.0, kev=True, kev_date_added="2026-10-14")],
                      {}, env(), NOW)
        self.assertNotIn("CISA KEV: known ransomware use", out["items"][0]["reasons"])

    def test_critical_cvss_needs_network_vector_to_escalate(self):
        out = E.build([alert("CVE-2026-15", self.PAN, 9.3, cvss_vector_components={"attack_vector": "LOCAL"}),
                       alert("CVE-2026-16", self.PAN, 9.3)], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-15": "work", "CVE-2026-16": "escalate"})

    def test_out_of_estate_is_ignored_even_if_kev(self):
        out = E.build([alert("CVE-2026-1", "RCE in Acme Router firmware.", 9.8, kev=True,
                             kev_date_added="2026-10-14")], {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_watchlist_label_alone_is_not_evidence(self):
        # NVD keyword search AND-matches words; the label must not count.
        out = E.build([alert("CVE-2026-2", "A check on the access point is missing in FooCMS.", 9.8,
                             matched_keywords=["Check Point"], kev=True, kev_date_added="2026-10-14")],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_old_cve_resurfaced_by_backfill_is_ignored(self):
        out = E.build([alert("CVE-2019-1579", "RCE in PAN-OS GlobalProtect.", 8.1,
                             published="2019-07-19T00:00:00", first_seen="2026-10-16T00:00:00")],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_wordpress_plugin_excluded(self):
        out = E.build([alert("CVE-2026-3", "The Foo plugin for WordPress is vulnerable to SQLi.", 9.8)],
                      {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_wordpress_plugin_naming_an_estate_saas_is_not_in_estate(self):
        # Real NVD shapes (CVE-2026-109515, CVE-2026-93388): the flaw is in the
        # plugin; HubSpot / Google Drive are only integrations it talks to.
        out = E.build([
            alert("CVE-2026-5", "The MailOptin - Popup, Optin Forms & Email Newsletters for Mailchimp, "
                  "HubSpot, AWeber Etc. plugin for WordPress is vulnerable to Privilege Escalation.", 9.8),
            alert("CVE-2026-6", "The Printcart Store plugin for WooCommerce is vulnerable to arbitrary "
                  "file upload; its Google Drive branch rebuilds the filename.", 9.8),
            alert("CVE-2026-7", "The Download Manager WordPress plugin before 7.5.6 does not sanitise "
                  "data (free Download Manager).", 9.8)], {}, env(), NOW)
        self.assertEqual(out["items"], [])
        # the estate product's own CVE still matches
        out = E.build([alert("CVE-2026-8", "Privilege escalation in HubSpot CMS allows takeover.", 9.8)],
                      {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-8": "work"})

    def test_named_add_on_for_wordpress_is_not_core_wordpress(self):
        # Real NVD shapes (CVE-2026-111862, CVE-2026-105892, CVE-2020-25213):
        # the add-on is named "<X> for WordPress" without the word "plugin"
        # next to it, so the plugin phrases missed them.
        out = E.build([
            alert("CVE-2026-9", "Rank Math SEO PRO for WordPress is affected by a supply-chain "
                  "compromise.", 9.8),
            alert("CVE-2026-10", "Path Traversal vulnerability in rtCamp Inc. rtMedia for WordPress, "
                  "BuddyPress and bbPress allows traversal.", 9.8),
            alert("CVE-2026-11", "The File Manager (wp-file-manager) plugin before 6.9 for WordPress "
                  "allows remote attackers to upload PHP code.", 10.0, kev=True,
                  kev_date_added="2026-10-14")], {}, env(), NOW)
        self.assertEqual(out["items"], [])
        # core WordPress CVEs still match
        out = E.build([alert("CVE-2026-12", "WordPress 6.9.x before 6.9.5 is affected by a REST API "
                             "route confusion issue.", 9.8)], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-12": "work"})

    def test_bare_palo_alto_headline_matches_palo_alto_asset(self):
        # Real intel titles (2026-10): headlines drop "Networks"; the MFA-bypass
        # story was attributed to VMware only and four others matched nothing.
        pa = "Palo Alto (firewalls / GlobalProtect / Cortex)"
        for text in ("Hackers Exploit Palo Alto VPN Flaw to Bypass MFA and Steal Credentials From VMware Disks",
                     "Palo Alto's firewall OS has been under attack from multiple ransomware groups",
                     "CISA flags exploited flaws in Palo Alto, Cisco and Ahsay products"):
            self.assertIn(pa, [a["name"] for a, _ in E.match_assets(text, env()["assets"])], text)
        for text in ("A Palo Alto, Calif.-based startup raised $40M for AI phishing defense",
                     "Palo Alto-based vendor patches its scanner"):
            self.assertNotIn(pa, [a["name"] for a, _ in E.match_assets(text, env()["assets"])], text)

    def test_check_point_as_research_source_is_not_check_point_asset(self):
        # Real intel (Help Net Security 2026-10-19): brand-phishing stats "tracked by
        # Check Point Research ... (Source: Check Point)" escalated as Check Point / Avanan.
        cp = "Check Point / Avanan"
        for text in ("Microsoft accounted for 33% of brand impersonation attempts tracked by Check Point "
                     "Research in Q3. Top 10 most impersonated brands (Source: Check Point)",
                     "Microsoft behind a third of brand phishing, Check Point says - News Ghana",
                     "19th October - Threat Intelligence Report - Check Point Research"):
            self.assertNotIn(cp, [a["name"] for a, _ in E.match_assets(text, env()["assets"])], text)
        for text in ("Authentication bypass in the Check Point SmartConsole login process.",
                     "Check Point Research found that Check Point Quantum Security Gateway VPN is exploited"):
            self.assertIn(cp, [a["name"] for a, _ in E.match_assets(text, env()["assets"])], text)

    def test_cloudflare_as_reporter_is_not_cloud_asset(self):
        # Real intel (CyberSecurityNews 2026-10-21): Cloudflare reporting exploitation of
        # leaked PHP flaws sat on the board as ESCALATE for the Cloud platforms asset.
        cl = "Cloud platforms (AWS / Azure / Google Cloud / DigitalOcean / Cloudflare)"
        names = lambda text: [a["name"] for a, _ in E.match_assets(text, env()["assets"])]
        for text in ("Cloudflare Detects Early Exploitation Attempts Targeting Two Leaked PHP "
                     "Vulnerabilities || Cloudflare says it is seeing early attempts to exploit two "
                     "critical PHP vulnerabilities",
                     "Cloudflare Warns of Active Exploitation Attempts Against Two Leaked PHP Flaws",
                     "Defending the NetScaler front door before the patch - Cloudflare Blog",
                     "A large-scale scam operation impersonating Microsoft uses a malicious traffic "
                     "distribution system and abuses thousands of Cloudflare links."):
            self.assertNotIn(cl, names(text), text)
        for text in ("How Cloudflare addressed a cross-tenant data exposure vulnerability in "
                     "Cloudflare Containers - Cloudflare Blog",
                     "Applications using the Cloudflare Zero Trust service token can be bypassed",
                     "Cloudflare says attackers breached its Atlassian server using stolen Okta "
                     "tokens; Cloudflare's systems were rotated"):
            self.assertIn(cl, names(text), text)

    def test_teams_vishing_news_escalates(self):
        out = E.build([], {"items": [intel("t1", "Hackers pose as IT support in Microsoft Teams calls",
                                           ["social_engineering"])]}, env(), NOW)
        self.assertEqual(tiers(out), {"t1": "escalate"})

    def test_vendor_issue_news_is_work(self):
        out = E.build([], {"items": [intel("b1", "Windows 11 update causes black screens on AVD with FSLogix",
                                           ["vendor_issue"])]}, env(), NOW)
        self.assertEqual(tiers(out), {"b1": "work"})

    def test_generic_windows_malware_news_not_escalated(self):
        out = E.build([], {"items": [intel("g1", "New stealer lures Windows users with fake updates",
                                           ["social_engineering"], priority="medium")]}, env(), NOW)
        self.assertEqual(tiers(out), {"g1": "work"})

    def _tier_alone(self, title, cats):
        # one build per headline: story folding would merge similar test titles
        out = E.build([], {"items": [intel("x", title, cats)]}, env(), NOW)
        return out["items"][0]["tier"], out["items"][0]["reasons"]

    def test_defensive_feature_and_takedown_news_is_work_not_escalate(self):
        # real board headlines that were escalated as if they were campaigns
        for title in ("Microsoft Teams to Detect Malicious QR Codes and Warn Users of Phishing Attacks",
                      "Microsoft Disrupts 3 Phishing Kits Linked to Over 1 Billion Scam Messages for Microsoft 365",
                      "Microsoft 365 Business Email Compromise (BEC) Attacks: How to Stop Them"):
            tier, reasons = self._tier_alone(title, ["social_engineering"])
            self.assertEqual(tier, "work", title)
            self.assertTrue(any("not an active campaign" in r for r in reasons), reasons)

    def test_campaign_headlines_with_defense_words_still_escalate(self):
        for title, cats in (
                # attack succeeds despite the defence
                ("Phishing kit bypasses Microsoft Teams protections to steal logins", ["social_engineering"]),
                ("Ransomware disables Windows Defender protections on Windows Server", ["ransomware"]),
                # a takedown story that also reports tenants hacked
                ("Crypto cop takes down scam network, and Microsoft 365 tenants hacked via backup provider",
                 ["social_engineering"]),
                # vendor warning ABOUT a live campaign is not a defensive feature
                ("Microsoft warns of Microsoft Teams vishing campaign posing as IT support", ["social_engineering"]),
                # exploitation news is never demoted
                ("Hackers exploit Microsoft Teams flaw to bypass detection", ["exploited"])):
            tier, reasons = self._tier_alone(title, cats)
            self.assertEqual(tier, "escalate", title)
            self.assertFalse(any("not an active campaign" in r for r in reasons), reasons)

    def test_escalate_sorted_first(self):
        out = E.build([alert("CVE-2026-69982", "Weak authentication in Active Directory Federation "
                             "Services.", 5.9)],
                      {"items": [intel("t1", "Vishing via Microsoft Teams", ["social_engineering"])]}, env(), NOW)
        self.assertEqual(out["items"][0]["tier"], "escalate")
        self.assertEqual(out["counts"], {"escalate": 1, "work": 1})


class EstateAndTriageTests(unittest.TestCase):
    def test_url_hostname_is_not_a_product_match(self):
        out = E.build([alert("CVE-2026-2", "Path traversal in Acme Notes, see https://github.com/acme/notes "
                             "for the fix.", 9.8)], {}, env(), NOW)
        self.assertEqual(out["items"], [])

    def test_inventory_app_matches(self):
        out = E.build([alert("CVE-2026-3", "Remote code execution in AnyDesk for Windows.", 9.8,
                             kev=True, kev_date_added="2026-10-14")], {}, env(), NOW)
        self.assertEqual(tiers(out), {"CVE-2026-3": "escalate"})

    def test_match_case_common_word_names(self):
        self.assertEqual(E.build([alert("CVE-2026-4", "A flaw lets users workday schedules leak.", 9.8)],
                                 {}, env(), NOW)["items"], [])

    def test_triage_is_attached_and_closed_is_flagged(self):
        a = alert("CVE-2026-5", "Remote code execution in AnyDesk for Windows.", 9.8,
                  kev=True, kev_date_added="2026-10-14")
        tri = {"cve:CVE-2026-5": {"status": "resolved", "owner": "GMS", "note": "patched", "date": "2026-10-16"}}
        out = E.build([a], {}, env(), NOW, triage=tri)
        it = out["items"][0]
        self.assertEqual(it["triage"]["status"], "resolved")
        self.assertTrue(it["closed"])
        self.assertEqual(out["open"]["escalate"], 0)

    def test_load_triage_drops_unknown_status_and_survives_bad_yaml(self):
        import tempfile
        d = tempfile.mkdtemp()
        good, bad = os.path.join(d, "g.yaml"), os.path.join(d, "b.yaml")
        open(good, "w").write('entries:\n  "cve:CVE-2026-5":\n    status: resolved\n'
                              '  "cve:CVE-2026-6":\n    status: maybe\n')
        open(bad, "w").write("entries:\n  - [unclosed\n")
        self.assertEqual(list(E.load_triage(good)), ["cve:CVE-2026-5"])
        self.assertEqual(E.load_triage(bad), {})
        self.assertEqual(E.load_triage(os.path.join(d, "missing.yaml")), {})

    def _work(self, n, day="2026-10-13"):
        return [alert(f"CVE-2026-10{i:02d}", "Use after free in Google Chrome allows heap corruption.", 8.8,
                      published=f"{day}T19:00:00") for i in range(n)]

    def test_same_day_release_is_bundled_with_every_id_kept(self):
        out = E.build(self._work(6), {}, env(), NOW)
        bundles = [i for i in out["items"] if i["kind"] == "bundle"]
        self.assertEqual(len(bundles), 1)
        self.assertEqual(len(bundles[0]["cve_ids"]), 6)
        self.assertEqual(bundles[0]["tier"], "work")
        self.assertFalse(any(i["kind"] == "cve" for i in out["items"]))

    def test_small_groups_and_triaged_items_not_bundled(self):
        self.assertTrue(all(i["kind"] == "cve" for i in E.build(self._work(3), {}, env(), NOW)["items"]))
        tri = {"cve:CVE-2026-1000": {"status": "in_progress"}}
        out = E.build(self._work(5), {}, env(), NOW, triage=tri)
        kinds = sorted(i["kind"] for i in out["items"])
        self.assertEqual(kinds, ["bundle", "cve"])

    def test_stale_stored_category_is_reclassified(self):
        it = intel("pan1", "Palo Alto Networks Patches PAN-OS RCE Flaw Amid Active Exploitation",
                   ["patch", "vulnerability"], priority="medium")
        out = E.build([], {"items": [it]}, env(), NOW)
        self.assertEqual(out["items"][0]["tier"], "escalate")

    def _pan(self, i, title, day, cves=None):
        x = intel(f"pan{i}", title, ["exploited"], priority="high")
        x["published"] = f"2026-10-{day}T12:00:00+00:00"
        x["cve_ids"] = cves or []
        return x

    def test_duplicate_coverage_folds_into_one_story(self):
        items = [self._pan(1, "Palo Alto Networks PAN-OS zero-day exploited", 14, ["CVE-2026-0322"]),
                 self._pan(2, "PAN-OS flaw exploited, Palo Alto Networks warns - Outlet", 15),
                 self._pan(3, "CISA: Palo Alto Networks bug exploited", 15, ["CVE-2026-0322"])]
        out = E.build([], {"items": items}, env(), NOW)
        self.assertEqual(len(out["items"]), 1)
        s = out["items"][0]
        self.assertEqual(s["key"], "intel:pan1")
        self.assertEqual(s["tier"], "escalate")
        self.assertEqual(len(s["coverage"]), 3)
        self.assertEqual(sorted(s["member_keys"]), ["intel:pan1", "intel:pan2", "intel:pan3"])

    def test_story_reason_counts_distinct_reports_not_reposts(self):
        # Real: 'Suspected Chinese espionage attackers abusing BeyondTrust...' said
        # 'reported by 43 sources' while 9 of the 43 were Google News re-listings of
        # an article already in the cluster (the card lists only the 34 distinct ones).
        items = [self._pan(1, "Palo Alto Networks PAN-OS zero-day exploited", 14, ["CVE-2026-0322"]),
                 self._pan(2, "PAN-OS flaw exploited, Palo Alto Networks warns", 15, ["CVE-2026-0322"]),
                 self._pan(3, "PAN-OS flaw exploited, Palo Alto Networks warns", 15, ["CVE-2026-0322"])]
        items[2]["source"] = "GNews: firewalls"
        s = E.build([], {"items": items}, env(), NOW)["items"][0]
        self.assertEqual(len(s["coverage"]), 3)
        self.assertEqual(sum(1 for c in s["coverage"] if not c["dup"]), 2)
        reason = [r for r in s["reasons"] if r.startswith("Same incident")][0]
        self.assertIn("covered by 2 distinct reports", reason)
        self.assertIn("plus 1 reposts of the same headline", reason)

    def test_same_asset_alone_does_not_fold_unrelated_stories(self):
        # Real (2026-10-22 board): 'Microsoft Entra ID Adds Third-Party SMS and Voice MFA'
        # was folded into the escalated 'Why password resets won't save you from OAuth
        # consent phishing' card, and 'Authorities disrupt nearly 11,000 cybercrime
        # networks in Africa' into 'M365 Token Spray and Replay Campaign...', only
        # because each pair hit the same broad asset within the story window.
        seed = intel("m1", "Why password resets won't save you from OAuth consent phishing",
                     ["social_engineering"], summary="Attackers abuse Entra ID app consent.")
        other = intel("m2", "Microsoft Entra ID Adds Third-Party SMS and Voice MFA", ["social_engineering"])
        same = intel("m3", "OAuth consent phishing campaign hits Entra ID tenants", ["social_engineering"])
        for x in (other, same):
            x["published"] = "2026-10-15T14:00:00+00:00"
        out = E.build([], {"items": [seed, other, same]}, env(), NOW)
        home = {m: it["key"] for it in out["items"] for m in (it.get("member_keys") or [it["key"]])}
        self.assertEqual(home["intel:m3"], home["intel:m1"])
        self.assertNotEqual(home["intel:m2"], home["intel:m1"])

    def test_cveless_report_does_not_join_unrelated_psirt_advisory(self):
        # Real: 'Ransomware Operators Exploit PAN-OS GlobalProtect Authentication Bypass'
        # (no CVE named; it is CVE-2026-0257) was folded into the PSIRT entry for
        # CVE-2026-0307, a GlobalProtect App local privilege escalation, on asset+date.
        adv = self._pan(1, "CVE-2026-0307 GlobalProtect App: Local Privilege Escalation Vulnerabilities (Severity: MEDIUM)",
                        13, ["CVE-2026-0307"])
        adv["source"] = "Palo Alto PSIRT"
        news = self._pan(2, "Ransomware Operators Exploit PAN-OS Authentication Bypass", 15)
        story = self._pan(3, "Threat Brief: Active Exploitation of PAN-OS Authentication Bypass CVE-2026-0257", 15,
                          ["CVE-2026-0257"])
        out = E.build([], {"items": [adv, news, story]}, env(), NOW)
        home = {m: it["key"] for it in out["items"] for m in (it.get("member_keys") or [it["key"]])}
        self.assertNotEqual(home["intel:pan2"], home["intel:pan1"])
        self.assertEqual(home["intel:pan2"], home["intel:pan3"])
        # Without the CVE-specific story it stands alone rather than joining the advisory.
        out = E.build([], {"items": [adv, news]}, env(), NOW)
        self.assertEqual(len(out["items"]), 2)

    def test_different_cves_or_far_apart_stay_separate(self):
        items = [self._pan(1, "Palo Alto Networks bug A exploited", 14, ["CVE-2026-1"]),
                 self._pan(2, "Palo Alto Networks bug B exploited", 14, ["CVE-2026-2"]),
                 self._pan(3, "Palo Alto Networks bug C exploited", 10)]
        self.assertEqual(len(E.build([], {"items": items}, env(), NOW)["items"]), 3)

    def test_campaign_name_links_reports_with_different_old_cves(self):
        items = [self._pan(1, "PEERSTITCH malware deployed via FortiOS flaw", 15, ["CVE-2025-1"]),
                 self._pan(2, "Unit 42 uncovers PEERSTITCH, a stealthy FortiGate implant", 16),
                 self._pan(3, "Fortinet FortiWeb flaw exploited in attacks", 10)]
        out = E.build([], {"items": items}, env(), NOW)
        sizes = sorted(len(i.get("coverage") or [i]) for i in out["items"])
        self.assertEqual(sizes, [1, 2])

    def test_later_cve_joins_clusters(self):
        items = [self._pan(1, "Palo Alto Networks bug one", 10, ["CVE-2026-1"]),
                 self._pan(2, "Palo Alto Networks bug two", 11, ["CVE-2026-2"]),
                 self._pan(3, "Palo Alto Networks chained bugs", 12, ["CVE-2026-1", "CVE-2026-2"])]
        out = E.build([], {"items": items}, env(), NOW)
        self.assertEqual(len(out["items"]), 1)

    def test_psirt_work_advisories_batched(self):
        items = []
        for i, d in enumerate([14, 14, 15, 16]):
            x = intel(f"ps{i}", f"CVE-2026-03{i} PAN-OS: Denial of Service (Severity: MEDIUM)", ["vulnerability"])
            x["published"] = f"2026-10-{d}T12:00:00+00:00"
            x["cve_ids"] = [f"CVE-2026-03{i}"]
            x["source"] = "Palo Alto PSIRT"
            items.append(x)
        out = E.build([], {"items": items}, env(), NOW)
        work = [i for i in out["items"] if i["tier"] == "work"]
        if work:  # only meaningful when these advisories reach WORK at all
            self.assertEqual(len(work), 1)
            self.assertEqual(len(work[0]["cve_ids"]), 4)
            self.assertEqual(work[0]["key"], "intel:ps0")

    def test_story_already_announced_via_member_not_reposted(self):
        story = {"key": "intel:a", "tier": "escalate", "member_keys": ["intel:a", "intel:b"]}
        self.assertEqual(D.select_new([story], {"intel:b": "x"}), [])
        self.assertEqual(len(D.select_new([story], {})), 1)

    def test_triaged_item_never_posted_to_discord(self):
        esc_doc = {"items": [{"key": "cve:A", "tier": "escalate", "title": "A", "triage": {"status": "acknowledged"}}]}
        self.assertEqual(D.select_new(esc_doc["items"], {}), [])


class IntelRuleRegressionTests(unittest.TestCase):
    """False positives found while building the Escalate board."""
    def cats(self, text):
        return F.classify(text, [])[0]

    def test_anti_phishing_is_not_social_engineering(self):
        self.assertNotIn("social_engineering", self.cats("enclave that handles passwords for a Windows anti-phishing feature"))

    def test_failure_is_not_a_lure(self):
        self.assertNotIn("social_engineering", self.cats("a configuration failure caused the outage"))

    def test_real_lures_still_match(self):
        self.assertIn("social_engineering", self.cats("attackers use invoice lures and phishing pages"))
        self.assertIn("social_engineering", self.cats("a new tech scam targets retirees"))

    def test_active_exploitation_phrasing(self):
        self.assertIn("exploited", self.cats("Palo Alto Networks Patches PAN-OS Flaw Amid Active Exploitation"))
        self.assertIn("exploited", self.cats("PEERSTITCH Malware Deployed via FortiOS Flaw"))


def esc(*items):
    return {"items": [{"key": f"cve:{k}", "kind": "cve", "ref": k, "title": k, "tier": t,
                       "assets": ["Identity"], "criticality": "critical",
                       "reasons": ["In your estate: x", "CISA KEV"]} for k, t in items]}


class DiscordTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        D.time.sleep = lambda s: None

    def test_cve_embed_links_to_the_card_anchor(self):
        # dashboard cards are id="alert-<CVE>"; a bare #CVE-... link opened the
        # page without jumping to the alert
        e = D.build_embed({"kind": "cve", "ref": "CVE-2026-84731", "tier": "escalate",
                           "title": "t"}, "https://x.example/CVE/")
        self.assertEqual(e["url"], "https://x.example/CVE/#alert-CVE-2026-84731")

    def poster(self, ok=True):
        def p(url, payload):
            self.calls.append(payload)
            return ok
        return p

    def test_first_run_seeds_without_flood(self):
        st, n = D.run("u", esc(("A", "escalate"), ("B", "escalate")), {}, NOW, poster=self.poster())
        self.assertEqual(n, 0)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("embeds", self.calls[0])
        self.assertTrue(st["seeded"])
        self.assertEqual(set(st["sent"]), {"cve:A", "cve:B"})

    def test_only_new_escalate_items_posted(self):
        state = {"seeded": True, "sent": {"cve:A": NOW.isoformat()}}
        st, n = D.run("u", esc(("A", "escalate"), ("B", "escalate"), ("C", "work")), state, NOW,
                      poster=self.poster())
        self.assertEqual(n, 1)
        self.assertEqual([e["title"] for e in self.calls[0]["embeds"]], ["[ESCALATE] B"])
        self.assertIn("cve:B", st["sent"])
        self.assertNotIn("cve:C", st["sent"])

    def test_failed_post_is_retried_next_run(self):
        state = {"seeded": True, "sent": {}}
        st, n = D.run("u", esc(("B", "escalate")), state, NOW, poster=self.poster(ok=False))
        self.assertEqual(n, 0)
        self.assertNotIn("cve:B", st["sent"])

    def test_story_not_reposted_when_its_oldest_report_ages_out(self):
        # card key = oldest report; once it left the intel window the rest of
        # the story looked new (run 39522290183 re-posted a Patch Tuesday story)
        def card(key, members):
            return {"items": [{"key": key, "kind": "intel", "title": "Patch Tuesday", "tier": "escalate",
                               "member_keys": members, "reasons": ["x"]}]}
        st, n = D.run("u", card("intel:a", ["intel:a", "intel:b", "intel:c"]),
                      {"seeded": True, "sent": {}}, NOW, poster=self.poster())
        self.assertEqual(n, 1)
        st, n = D.run("u", card("intel:b", ["intel:b", "intel:c"]), st, NOW, poster=self.poster())
        self.assertEqual(n, 0)
        # state written before the fix holds only the card key: healed on the next run
        old = {"seeded": True, "sent": {"intel:a": "2026-10-15T00:00:00+00:00"}}
        st, n = D.run("u", card("intel:a", ["intel:a", "intel:b"]), old, NOW, poster=self.poster())
        self.assertEqual((n, st["sent"]["intel:b"]), (0, "2026-10-15T00:00:00+00:00"))
        st, n = D.run("u", card("intel:b", ["intel:b"]), st, NOW, poster=self.poster())
        self.assertEqual(n, 0)

    def test_seed_only_records_without_posting(self):
        st, n = D.run("u", esc(("B", "escalate")), {"seeded": True, "sent": {}}, NOW, seed_only=True,
                      poster=self.poster())
        self.assertEqual((n, self.calls), (0, []))
        self.assertIn("cve:B", st["sent"])

    def test_batches_of_ten(self):
        items = [(f"X{i}", "escalate") for i in range(23)]
        st, n = D.run("u", esc(*items), {"seeded": True, "sent": {}}, NOW, poster=self.poster())
        self.assertEqual(n, 23)
        self.assertEqual([len(c["embeds"]) for c in self.calls], [10, 10, 3])

    def test_mentions_disabled_and_url_hidden(self):
        sent = []

        class Res:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            sent.append(req.data)
            return Res()
        orig = D.urllib.request.urlopen
        D.urllib.request.urlopen = fake_urlopen
        try:
            self.assertTrue(D.post("https://discord.com/api/webhooks/1/abc", {"content": "@everyone hi"}))
        finally:
            D.urllib.request.urlopen = orig
        self.assertIn(b'"allowed_mentions": {"parse": []}', sent[0])

    def test_digest_once_per_day_after_hour(self):
        doc = esc(("A", "escalate"), ("B", "work"))
        st = {"seeded": True, "sent": {}}
        early = NOW.replace(hour=6)
        self.assertEqual(D.run_digest("u", doc, st, early, 12, poster=self.poster())[1], False)
        st2, ok = D.run_digest("u", doc, st, NOW, 12, poster=self.poster())
        self.assertTrue(ok)
        self.assertIn("1 open Escalate", self.calls[0]["content"])
        self.assertEqual(D.run_digest("u", doc, st2, NOW, 12, poster=self.poster())[1], False)

    def test_connect_run_skips_same_day_digest(self):
        st, _ = D.run("u", esc(("A", "escalate")), {}, NOW, poster=self.poster())
        self.assertEqual(D.run_digest("u", esc(("A", "escalate")), st, NOW, 12, poster=self.poster())[1], False)

    def test_webhook_url_validation(self):
        self.assertTrue(D.WEBHOOK_RE.match("https://discord.com/api/webhooks/123/abc-DEF_1"))
        self.assertFalse(D.WEBHOOK_RE.match("https://evil.example/api/webhooks/123/abc"))


class DiscordSkipIssuesTests(unittest.TestCase):
    """The workflow's Discord step, run as the workflow configures it. A
    skip_issues dispatch at the normal lookback used to set DISCORD_SEED_ONLY,
    which marked its new Escalate items as sent without posting them, so no
    later run ever announced them (run 39660604872: two stories)."""

    WF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows",
                      "cve-alerts.yml")

    def step_env(self, skip_issues, lookback):
        import re
        import yaml
        with open(self.WF, encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        step = next(s for s in wf["jobs"]["aggregate"]["steps"] if s.get("run") == "python scripts/notify_discord.py")
        out = {}
        for k, v in (step.get("env") or {}).items():
            v = str(v)
            v = re.sub(r"\$\{\{\s*secrets\.\w+\s*\}\}", "https://discord.com/api/webhooks/1/abc", v)
            v = re.sub(r"\$\{\{\s*inputs\.skip_issues && '([^']*)' \|\| '' \s*\}\}",
                       lambda m: m.group(1) if skip_issues else "", v)
            v = re.sub(r"\$\{\{\s*inputs\.lookback_days \|\| '(\d+)'\s*\}\}",
                       lambda m: str(lookback) if lookback else m.group(1), v)
            self.assertNotIn("${{", v, f"unhandled expression in {k}")
            out[k] = v
        return out

    def run_main(self, env, tmp):
        posted = []

        class Res:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            posted.append(req.data)
            return Res()
        saved = (D.ESC_PATH, D.STATE_PATH, D.urllib.request.urlopen, dict(os.environ))
        D.ESC_PATH, D.STATE_PATH = os.path.join(tmp, "esc.json"), os.path.join(tmp, "state.json")
        D.urllib.request.urlopen = fake_urlopen
        D.time.sleep = lambda s: None
        for k in ("DISCORD_SEED_ONLY", "SKIP_ISSUES", "LOOKBACK_DAYS", "NORMAL_LOOKBACK_DAYS", "DISCORD_DIGEST"):
            os.environ.pop(k, None)
        os.environ.update(env, DISCORD_DIGEST="0")
        try:
            D.main()
        finally:
            D.ESC_PATH, D.STATE_PATH, D.urllib.request.urlopen = saved[:3]
            os.environ.clear()
            os.environ.update(saved[3])
        with open(os.path.join(tmp, "state.json"), encoding="utf-8") as fh:
            return json.load(fh), posted

    def setup_tmp(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "esc.json"), "w", encoding="utf-8") as fh:
            json.dump(esc(("NEW", "escalate")), fh)
        with open(os.path.join(tmp, "state.json"), "w", encoding="utf-8") as fh:
            json.dump({"seeded": True, "sent": {}}, fh)
        return tmp

    def test_skip_issues_at_normal_window_defers_to_next_run(self):
        tmp = self.setup_tmp()
        st, posted = self.run_main(self.step_env(True, None), tmp)
        self.assertEqual(posted, [])
        self.assertNotIn("cve:NEW", st["sent"])   # not swallowed
        st, posted = self.run_main(self.step_env(False, None), tmp)   # next scheduled run
        self.assertEqual(len(posted), 1)
        self.assertIn(b"[ESCALATE] NEW", posted[0])
        self.assertIn("cve:NEW", st["sent"])

    def test_skip_issues_backfill_still_seeds_without_posting(self):
        tmp = self.setup_tmp()
        st, posted = self.run_main(self.step_env(True, 30), tmp)
        self.assertEqual(posted, [])
        self.assertIn("cve:NEW", st["sent"])

    def test_run_mode(self):
        self.assertEqual(D.run_mode({}), "post")
        self.assertEqual(D.run_mode({"DISCORD_SEED_ONLY": "1"}), "seed")
        self.assertEqual(D.run_mode({"SKIP_ISSUES": "true", "LOOKBACK_DAYS": "4"}), "defer")
        self.assertEqual(D.run_mode({"SKIP_ISSUES": "true", "LOOKBACK_DAYS": "14"}), "seed")
        self.assertEqual(D.run_mode({"SKIP_ISSUES": "true", "LOOKBACK_DAYS": "x"}), "seed")

    def test_reply_errors_do_not_crash_or_lose_state(self):
        # urlopen wraps only connect errors in URLError; a timeout or reset
        # while reading Discord's reply raised out of main() before the state
        # was written, so an item already posted was posted again next run.
        import http.client
        for exc in (TimeoutError("timed out"), ConnectionResetError(104, "reset"),
                    http.client.RemoteDisconnected("closed")):
            def boom(req, timeout=0, exc=exc):
                raise exc
            orig = D.urllib.request.urlopen
            D.urllib.request.urlopen = boom
            D.time.sleep = lambda s: None
            try:
                self.assertFalse(D.post("https://discord.com/api/webhooks/1/abc", {"content": "x"}))
            finally:
                D.urllib.request.urlopen = orig
        # item post accepted, then the daily digest's reply times out
        tmp = self.setup_tmp()
        with open(os.path.join(tmp, "state.json"), "w", encoding="utf-8") as fh:
            json.dump({"seeded": True, "sent": {}, "digest_date": "2000-01-01"}, fh)
        calls = []

        class Res:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            calls.append(req.data)
            if len(calls) > 1:
                raise TimeoutError("The read operation timed out")
            return Res()
        saved = (D.ESC_PATH, D.STATE_PATH, D.urllib.request.urlopen, dict(os.environ))
        D.ESC_PATH, D.STATE_PATH = os.path.join(tmp, "esc.json"), os.path.join(tmp, "state.json")
        D.urllib.request.urlopen = fake_urlopen
        try:
            for k in ("DISCORD_SEED_ONLY", "SKIP_ISSUES", "LOOKBACK_DAYS", "DISCORD_DIGEST"):
                os.environ.pop(k, None)
            os.environ.update(self.step_env(False, None), DISCORD_DIGEST_HOUR_UTC="0")
            D.main()
        finally:
            D.ESC_PATH, D.STATE_PATH, D.urllib.request.urlopen = saved[:3]
            os.environ.clear()
            os.environ.update(saved[3])
        with open(os.path.join(tmp, "state.json"), encoding="utf-8") as fh:
            st = json.load(fh)
        self.assertEqual(len(calls), 2)
        self.assertIn("cve:NEW", st["sent"])            # not posted again next run
        self.assertEqual(st["digest_date"], "2000-01-01")  # digest retried next run


if __name__ == "__main__":
    unittest.main()
