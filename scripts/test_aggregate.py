"""
Unit tests for the pure/deterministic logic functions in aggregate.py.

Distinct from validate_data.py (which checks the shape/consistency of
already-*committed* output data) -- this suite exercises the actual scoring
and parsing *logic* directly with synthetic inputs, so a regression in e.g.
composite_risk_score()'s weighting math or parse_cvss_v3_vector_string()'s
letter-code mapping is caught even if it happens to still produce
schema-valid (but *wrong*) output. Across 54 prior cycles this project had
zero automated coverage of its own scoring math -- every change to
composite_risk_score, CWE extraction, or the CVSS vector parser was
validated only by ad hoc manual spot checks against production data, which
catches gross breakage but not subtle math errors (e.g. wrong weight
redistribution, off-by-one severity bucket boundaries).

Deliberately stdlib-only (unittest), zero new dependencies, zero network
calls -- runs in well under a second and is wired into ci.yml so it gates
every push, same as validate_data.py.

Only functions with no I/O and no external API dependency are covered here:
composite_risk_score, parse_cvss_v3_vector_string, extract_cwe_nvd,
extract_cwe_ghsa, unique_key, compute_stats's severity bucketing (exercised
indirectly through compute_stats itself with synthetic alert dicts).
"""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aggregate import (
    composite_risk_score,
    parse_cvss_v3_vector_string,
    extract_cwe_nvd,
    extract_cwe_ghsa,
    extract_vuln_status,
    unique_key,
    compute_stats,
    build_final_entry,
    parse_osv_fixed_versions,
    extract_nvd_fix_versions,
    extract_nvd_reference_links,
    extract_cvss,
    extract_cvss_vector_components,
    append_history,
    HISTORY_CSV_HEADER,
)


class TestCompositeRiskScore(unittest.TestCase):
    def test_both_present_no_kev(self):
        total, bd = composite_risk_score(cvss=9.8, epss_score=0.5, in_kev=False)
        # cvss_component = (9.8/10)*35 = 34.3, epss_component = 0.5*40 = 20.0, kev = 0
        self.assertAlmostEqual(total, 54.3, places=1)
        self.assertFalse(bd["weight_redistributed"])
        self.assertEqual(bd["kev_bonus"], 0.0)

    def test_kev_adds_flat_bonus(self):
        total_no_kev, _ = composite_risk_score(cvss=5.0, epss_score=0.1, in_kev=False)
        total_kev, bd = composite_risk_score(cvss=5.0, epss_score=0.1, in_kev=True)
        self.assertGreater(total_kev, total_no_kev)
        self.assertAlmostEqual(total_kev - total_no_kev, 25.0, places=1)

    def test_missing_epss_redistributes_weight_not_zero(self):
        # With epss missing, cvss+kev weights should scale up to fill 100%,
        # not silently treat epss as 0 against the full 40% weight.
        total, bd = composite_risk_score(cvss=10.0, epss_score=None, in_kev=False)
        self.assertTrue(bd["weight_redistributed"])
        self.assertEqual(bd["epss_component"], 0.0)
        self.assertEqual(bd["epss_weight"], "n/a (missing)")
        # cvss weight scaled from 35 to 100*(35/(35+25))=58.33..., so
        # cvss_component = 1.0 * 58.33 = 58.3, well above the naive 35.
        self.assertGreater(bd["cvss_component"], 35.0)

    def test_missing_cvss_redistributes_weight(self):
        total, bd = composite_risk_score(cvss=None, epss_score=0.9, in_kev=True)
        self.assertTrue(bd["weight_redistributed"])
        self.assertEqual(bd["cvss_component"], 0.0)
        self.assertEqual(bd["cvss_weight"], "n/a (missing)")

    def test_both_missing_kev_only(self):
        total, bd = composite_risk_score(cvss=None, epss_score=None, in_kev=True)
        # Only KEV's 25 flat weight is available -- scaled to fill 100%.
        self.assertEqual(total, 100.0)
        self.assertTrue(bd["weight_redistributed"])

    def test_score_never_exceeds_100(self):
        total, bd = composite_risk_score(cvss=10.0, epss_score=1.0, in_kev=True)
        self.assertLessEqual(total, 100.0)

    def test_score_never_negative(self):
        total, bd = composite_risk_score(cvss=0.0, epss_score=0.0, in_kev=False)
        self.assertGreaterEqual(total, 0.0)


class TestExtractCvss(unittest.TestCase):
    def test_prefers_v31_over_v40_when_both_present(self):
        nvd_cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
                "cvssMetricV40": [{"cvssData": {"baseScore": 9.8}}],
            }
        }
        score, version = extract_cvss(nvd_cve)
        self.assertEqual(score, 7.5)
        self.assertEqual(version, "CVSS V31")

    def test_falls_back_to_v40_when_no_v3_or_v2(self):
        nvd_cve = {"metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 8.7}}]}}
        score, version = extract_cvss(nvd_cve)
        self.assertEqual(score, 8.7)
        self.assertEqual(version, "CVSS V40")

    def test_no_metrics_returns_none(self):
        self.assertEqual(extract_cvss({"metrics": {}}), (None, None))
        self.assertEqual(extract_cvss({}), (None, None))

    def test_prefers_nvd_primary_over_cna_secondary_listed_first(self):
        # Real NVD shape for CVE-2024-13342: CNA (Wordfence) 8.1 listed
        # before NVD's own Primary 9.8.
        nvd_cve = {"metrics": {"cvssMetricV31": [
            {"source": "security@wordfence.com", "type": "Secondary",
             "cvssData": {"baseScore": 8.1, "attackVector": "NETWORK", "attackComplexity": "HIGH"}},
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"baseScore": 9.8, "attackVector": "NETWORK", "attackComplexity": "LOW"}},
        ]}}
        self.assertEqual(extract_cvss(nvd_cve), (9.8, "CVSS V31"))
        self.assertEqual((extract_cvss_vector_components(nvd_cve) or {}).get("attack_complexity"), "LOW")

    def test_secondary_only_still_used(self):
        nvd_cve = {"metrics": {"cvssMetricV31": [
            {"source": "psirt@cisco.com", "type": "Secondary", "cvssData": {"baseScore": 8.6}}]}}
        self.assertEqual(extract_cvss(nvd_cve), (8.6, "CVSS V31"))


class TestExtractCvssVectorComponents(unittest.TestCase):
    def test_v31_extracted(self):
        nvd_cve = {"metrics": {"cvssMetricV31": [{"cvssData": {
            "attackVector": "NETWORK", "attackComplexity": "LOW",
            "privilegesRequired": "NONE", "userInteraction": "NONE",
        }}]}}
        result = extract_cvss_vector_components(nvd_cve)
        self.assertEqual(result, {
            "attack_vector": "NETWORK", "attack_complexity": "LOW",
            "privileges_required": "NONE", "user_interaction": "NONE",
        })

    def test_v31_preferred_over_v40_when_both_present(self):
        # regression guard: an alert that already has a v3.1 block must never
        # have its component values changed by the new v4.0 fallback.
        nvd_cve = {"metrics": {
            "cvssMetricV31": [{"cvssData": {
                "attackVector": "LOCAL", "attackComplexity": "HIGH",
                "privilegesRequired": "HIGH", "userInteraction": "REQUIRED",
            }}],
            "cvssMetricV40": [{"cvssData": {
                "attackVector": "NETWORK", "attackComplexity": "LOW",
                "privilegesRequired": "NONE", "userInteraction": "NONE",
            }}],
        }}
        result = extract_cvss_vector_components(nvd_cve)
        self.assertEqual(result["attack_vector"], "LOCAL")
        self.assertEqual(result["privileges_required"], "HIGH")

    def test_v40_fallback_when_no_v3(self):
        nvd_cve = {"metrics": {"cvssMetricV40": [{"cvssData": {
            "attackVector": "NETWORK", "attackComplexity": "LOW",
            "privilegesRequired": "LOW", "userInteraction": "NONE",
            "attackRequirements": "NONE",  # v4-only field, must be ignored
        }}]}}
        result = extract_cvss_vector_components(nvd_cve)
        self.assertEqual(result, {
            "attack_vector": "NETWORK", "attack_complexity": "LOW",
            "privileges_required": "LOW", "user_interaction": "NONE",
        })

    def test_no_metrics_returns_none(self):
        self.assertIsNone(extract_cvss_vector_components({"metrics": {}}))
        self.assertIsNone(extract_cvss_vector_components({}))


class TestParseCvssV3VectorString(unittest.TestCase):
    def test_valid_v31_vector(self):
        result = parse_cvss_v3_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result, {
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
        })

    def test_valid_v30_vector(self):
        result = parse_cvss_v3_vector_string("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(result["attack_vector"], "LOCAL")
        self.assertEqual(result["attack_complexity"], "HIGH")
        self.assertEqual(result["privileges_required"], "HIGH")
        self.assertEqual(result["user_interaction"], "REQUIRED")

    def test_v4_vector_rejected_not_guessed(self):
        # v4 redefines some letter codes (e.g. UI values differ) -- must be
        # skipped entirely rather than mis-parsed with v3 semantics.
        result = parse_cvss_v3_vector_string("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertIsNone(result)

    def test_none_input(self):
        self.assertIsNone(parse_cvss_v3_vector_string(None))

    def test_empty_string(self):
        self.assertIsNone(parse_cvss_v3_vector_string(""))

    def test_malformed_string_no_crash(self):
        self.assertIsNone(parse_cvss_v3_vector_string("not a vector"))

    def test_adjacent_network_and_physical(self):
        result = parse_cvss_v3_vector_string("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["attack_vector"], "ADJACENT_NETWORK")
        result2 = parse_cvss_v3_vector_string("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result2["attack_vector"], "PHYSICAL")


class TestExtractCweNvd(unittest.TestCase):
    def test_extracts_valid_cwe(self):
        nvd_cve = {"weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}]}
        self.assertEqual(extract_cwe_nvd(nvd_cve), ["CWE-79"])

    def test_filters_placeholder_values(self):
        nvd_cve = {"weaknesses": [
            {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
            {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
        ]}
        self.assertEqual(extract_cwe_nvd(nvd_cve), [])

    def test_dedupes(self):
        nvd_cve = {"weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "CWE-79"}]},
        ]}
        self.assertEqual(extract_cwe_nvd(nvd_cve), ["CWE-79"])

    def test_ignores_non_english(self):
        nvd_cve = {"weaknesses": [{"description": [{"lang": "es", "value": "CWE-79"}]}]}
        self.assertEqual(extract_cwe_nvd(nvd_cve), [])

    def test_empty_weaknesses(self):
        self.assertEqual(extract_cwe_nvd({}), [])
        self.assertEqual(extract_cwe_nvd({"weaknesses": []}), [])
        self.assertEqual(extract_cwe_nvd({"weaknesses": None}), [])


class TestExtractCweGhsa(unittest.TestCase):
    def test_extracts_from_cwes_list(self):
        obj = {"cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}]}
        self.assertEqual(extract_cwe_ghsa(obj), ["CWE-89"])

    def test_handles_missing_cwes_key(self):
        self.assertEqual(extract_cwe_ghsa({}), [])

    def test_skips_non_dict_entries(self):
        obj = {"cwes": ["not-a-dict", {"cwe_id": "CWE-79"}]}
        self.assertEqual(extract_cwe_ghsa(obj), ["CWE-79"])

    def test_rejects_malformed_id(self):
        obj = {"cwes": [{"cwe_id": "not-a-cwe"}]}
        self.assertEqual(extract_cwe_ghsa(obj), [])


class TestExtractVulnStatus(unittest.TestCase):
    def test_extracts_status(self):
        self.assertEqual(extract_vuln_status({"vulnStatus": "Analyzed"}), "Analyzed")

    def test_extracts_rejected(self):
        self.assertEqual(extract_vuln_status({"vulnStatus": "Rejected"}), "Rejected")

    def test_missing_status_is_none(self):
        self.assertIsNone(extract_vuln_status({}))


class TestUniqueKey(unittest.TestCase):
    def test_combines_cve_and_source(self):
        self.assertEqual(unique_key({"cve_id": "CVE-2024-1234", "source": "nvd"}),
                          "CVE-2024-1234::nvd")

    def test_same_cve_different_source_differs(self):
        k1 = unique_key({"cve_id": "CVE-2024-1234", "source": "nvd"})
        k2 = unique_key({"cve_id": "CVE-2024-1234", "source": "dependabot"})
        self.assertNotEqual(k1, k2)


class TestComputeStats(unittest.TestCase):
    def test_severity_bucket_boundaries(self):
        alerts = [
            {"cvss_score": 9.0, "kev": False},   # critical boundary (>=9.0)
            {"cvss_score": 8.9, "kev": False},   # high boundary
            {"cvss_score": 7.0, "kev": False},   # high boundary
            {"cvss_score": 6.9, "kev": False},   # medium boundary
            {"cvss_score": 4.0, "kev": False},   # medium boundary
            {"cvss_score": 3.9, "kev": False},   # low boundary
            {"cvss_score": None, "kev": False},  # unknown
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_severity"]["high"], 2)
        self.assertEqual(stats["by_severity"]["medium"], 2)
        self.assertEqual(stats["by_severity"]["low"], 1)
        self.assertEqual(stats["by_severity"]["unknown"], 1)

    def test_total_alerts_count(self):
        alerts = [{"cvss_score": 5.0, "kev": False} for _ in range(7)]
        stats = compute_stats(alerts)
        self.assertEqual(stats["total_alerts"], 7)

    def test_kev_and_ransomware_counts(self):
        alerts = [
            {"cvss_score": 5.0, "kev": True, "kev_ransomware_use": True},
            {"cvss_score": 5.0, "kev": True, "kev_ransomware_use": False},
            {"cvss_score": 5.0, "kev": False},
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["kev_count"], 2)
        self.assertEqual(stats["kev_ransomware_count"], 1)

    def test_empty_alerts_no_crash(self):
        stats = compute_stats([])
        self.assertEqual(stats["total_alerts"], 0)

    def test_by_age_bucket(self):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)

        def iso(delta_days):
            return (now - timedelta(days=delta_days)).isoformat()

        alerts = [
            {"cvss_score": 5.0, "kev": False, "first_seen": iso(0.5)},   # 0-1d
            {"cvss_score": 5.0, "kev": False, "first_seen": iso(3)},     # 1-7d
            {"cvss_score": 5.0, "kev": False, "first_seen": iso(15)},    # 7-30d
            {"cvss_score": 5.0, "kev": False, "first_seen": iso(45)},    # 30d+
            {"cvss_score": 5.0, "kev": False, "first_seen": None},       # ignored
            {"cvss_score": 5.0, "kev": False, "first_seen": "not-a-date"},  # ignored
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["by_age_bucket"]["0-1d"], 1)
        self.assertEqual(stats["by_age_bucket"]["1-7d"], 1)
        self.assertEqual(stats["by_age_bucket"]["7-30d"], 1)
        self.assertEqual(stats["by_age_bucket"]["30d+"], 1)

    def test_kev_due_soon_count_excludes_overdue_and_far_future(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc).date()
        overdue_date = (today - timedelta(days=3)).isoformat()
        due_soon_date = (today + timedelta(days=5)).isoformat()
        far_future_date = (today + timedelta(days=30)).isoformat()
        alerts = [
            {"cvss_score": 8.0, "kev": True, "kev_due_date": overdue_date},
            {"cvss_score": 8.0, "kev": True, "kev_due_date": due_soon_date},
            {"cvss_score": 8.0, "kev": True, "kev_due_date": today.isoformat()},  # due today: due-soon
            {"cvss_score": 8.0, "kev": True, "kev_due_date": far_future_date},
            {"cvss_score": 8.0, "kev": True, "kev_due_date": None},
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["kev_overdue_count"], 1)
        self.assertEqual(stats["kev_due_soon_count"], 2)

    def test_avg_cvss_score_excludes_unknown(self):
        alerts = [
            {"cvss_score": 9.0, "kev": False},
            {"cvss_score": 7.0, "kev": False},
            {"cvss_score": None, "kev": False},  # excluded from average
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["avg_cvss_score"], 8.0)

    def test_avg_cvss_score_none_when_no_scores(self):
        alerts = [{"cvss_score": None, "kev": False}]
        stats = compute_stats(alerts)
        self.assertIsNone(stats["avg_cvss_score"])

    def test_by_matched_keyword_counts_and_caps_top_10(self):
        # Mirrors the by_cwe/by_vendor_product pattern: counts occurrences of
        # each matched_keywords entry across alerts, sorted descending, capped
        # to the top 10. Alerts with no matched_keywords (or an empty list)
        # contribute nothing, matching the existing empty-list-safe `or []`
        # pattern already used for cwe_ids/affected.
        alerts = [
            {"cvss_score": 5.0, "kev": False, "matched_keywords": ["wordpress", "wp plugin"]},
            {"cvss_score": 5.0, "kev": False, "matched_keywords": ["wordpress"]},
            {"cvss_score": 5.0, "kev": False, "matched_keywords": []},
            {"cvss_score": 5.0, "kev": False},  # missing key entirely
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["by_matched_keyword"], {"wordpress": 2, "wp plugin": 1})

    def test_by_matched_keyword_empty_when_no_matches(self):
        alerts = [{"cvss_score": 5.0, "kev": False}]
        stats = compute_stats(alerts)
        self.assertEqual(stats["by_matched_keyword"], {})

    def test_risk_increasing_decreasing_counts(self):
        # Mirrors the frontend's per-card risk-delta badge logic exactly:
        # round both scores to the nearest int before comparing, so this
        # aggregate always agrees with how many badges show up/down arrows.
        alerts = [
            {"cvss_score": 5.0, "kev": False, "risk_score": 60, "risk_score_prev": 40},  # up
            {"cvss_score": 5.0, "kev": False, "risk_score": 30.4, "risk_score_prev": 30.2},  # rounds equal, no change
            {"cvss_score": 5.0, "kev": False, "risk_score": 20, "risk_score_prev": 50},  # down
            {"cvss_score": 5.0, "kev": False, "risk_score": 10, "risk_score_prev": None},  # no prior, ignored
            {"cvss_score": 5.0, "kev": False, "risk_score": 15},  # no prior key at all, ignored
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["risk_increasing_count"], 1)
        self.assertEqual(stats["risk_decreasing_count"], 1)

    def test_risk_increasing_decreasing_counts_zero_when_no_deltas(self):
        alerts = [{"cvss_score": 5.0, "kev": False, "risk_score": 50}]
        stats = compute_stats(alerts)
        self.assertEqual(stats["risk_increasing_count"], 0)
        self.assertEqual(stats["risk_decreasing_count"], 0)

    def test_rejected_count(self):
        alerts = [
            {"cvss_score": 9.0, "kev": False, "vuln_status": "Rejected"},
            {"cvss_score": 5.0, "kev": False, "vuln_status": "Analyzed"},
            {"cvss_score": 5.0, "kev": False},
        ]
        stats = compute_stats(alerts)
        self.assertEqual(stats["rejected_count"], 1)

    def test_rejected_count_zero_when_none_rejected(self):
        alerts = [{"cvss_score": 5.0, "kev": False, "vuln_status": "Analyzed"}]
        stats = compute_stats(alerts)
        self.assertEqual(stats["rejected_count"], 0)


class TestBuildFinalEntry(unittest.TestCase):
    def test_risk_score_prev_defaults_to_none_for_new_entry(self):
        # build_final_entry() always produces a fresh entry (used both for
        # genuinely-new alerts and as the scoring base before main() layers
        # first_seen/risk_score_prev back on for already-known ones) -- it
        # must not itself invent a risk_score_prev value out of nothing.
        entry = {"cve_id": "CVE-2026-00001", "source": "nvd", "cvss_score": 7.5,
                 "description": "test"}
        final = build_final_entry(entry, kev_map={}, epss_map={})
        self.assertIn("risk_score_prev", final)
        self.assertIsNone(final["risk_score_prev"])
        self.assertIsInstance(final["risk_score"], (int, float))

    def test_epss_score_prev_defaults_to_none_for_new_entry(self):
        # Mirrors test_risk_score_prev_defaults_to_none_for_new_entry above:
        # build_final_entry() must not invent an epss_score_prev value out of
        # nothing either -- main() is the only place that layers a real prior
        # value back on for already-known alerts.
        entry = {"cve_id": "CVE-2026-00003", "source": "nvd", "cvss_score": 6.0,
                 "description": "test"}
        final = build_final_entry(entry, kev_map={}, epss_map={})
        self.assertIn("epss_score_prev", final)
        self.assertIsNone(final["epss_score_prev"])

    def test_default_osv_fields_are_empty(self):
        # OSV.dev enrichment (cycle 61) is applied later in main() for NEW
        # alerts only -- build_final_entry() itself must always default these
        # fields rather than omit them, so every alert has a stable shape
        # regardless of whether OSV.dev enrichment ran this cycle.
        entry = {"cve_id": "CVE-2026-00002", "source": "nvd", "cvss_score": 5.0,
                 "description": "test"}
        final = build_final_entry(entry, kev_map={}, epss_map={})
        self.assertIn("osv_id", final)
        self.assertIsNone(final["osv_id"])
        self.assertEqual(final["osv_fixed_versions"], [])

    def test_vuln_status_propagated(self):
        entry = {"cve_id": "CVE-2026-00004", "source": "nvd", "cvss_score": 5.0,
                 "description": "test", "vuln_status": "Rejected"}
        final = build_final_entry(entry, kev_map={}, epss_map={})
        self.assertEqual(final["vuln_status"], "Rejected")

    def test_vuln_status_defaults_to_none(self):
        entry = {"cve_id": "CVE-2026-00005", "source": "dependabot", "cvss_score": 5.0,
                 "description": "test"}
        final = build_final_entry(entry, kev_map={}, epss_map={})
        self.assertIsNone(final["vuln_status"])

    def test_kev_listed_nvd_alert_without_cpe_gets_kev_vendor_product(self):
        # Real case CVE-2026-102764: surfaced from KEV as
        # 'beyondtrust/remote support', then its NVD record (keyword match, no
        # CPE pair yet) replaced it in place and the product was dropped.
        kev = {"CVE-2026-102764": {"vendorProject": "BeyondTrust", "product": "Remote Support",
                                   "dateAdded": "2026-10-16"}}
        entry = {"cve_id": "CVE-2026-102764", "source": "nvd", "cvss_score": 9.8,
                 "description": "test", "matched_vendor_product": [],
                 "matched_keywords": ["BeyondTrust"]}
        final = build_final_entry(entry, kev_map=kev, epss_map={})
        self.assertEqual(final["affected"], ["beyondtrust/remote support"])

    def test_cpe_match_kept_over_kev_vendor_product(self):
        kev = {"CVE-2026-00007": {"vendorProject": "Fortinet", "product": "FortiOS"}}
        entry = {"cve_id": "CVE-2026-00007", "source": "nvd", "cvss_score": 9.8,
                 "description": "test", "matched_vendor_product": ["fortinet/fortios"]}
        self.assertEqual(build_final_entry(entry, kev_map=kev, epss_map={})["affected"],
                         ["fortinet/fortios"])

    def test_non_kev_alert_without_cpe_stays_empty(self):
        entry = {"cve_id": "CVE-2026-00008", "source": "nvd", "cvss_score": 5.0,
                 "description": "test", "matched_vendor_product": []}
        self.assertEqual(build_final_entry(entry, kev_map={}, epss_map={})["affected"], [])

    def test_kev_listed_alert_carries_cisa_kev_label(self):
        # Real case CVE-2024-47575: ingested via the news path with
        # ['news: reported exploited'], kev=true, but no 'CISA KEV' label, so
        # the keyword chip showed 600 while the KEV tile showed 606.
        kev = {"CVE-2024-47575": {"vendorProject": "Fortinet", "product": "FortiManager"}}
        kws = ["news: reported exploited"]
        entry = {"cve_id": "CVE-2024-47575", "source": "nvd", "cvss_score": 9.8,
                 "description": "test", "matched_vendor_product": [], "matched_keywords": kws}
        final = build_final_entry(entry, kev_map=kev, epss_map={})
        self.assertEqual(final["matched_keywords"], ["news: reported exploited", "CISA KEV"])
        self.assertEqual(kws, ["news: reported exploited"])  # input not mutated
        again = build_final_entry({**entry, "matched_keywords": ["CISA KEV"]}, kev_map=kev, epss_map={})
        self.assertEqual(again["matched_keywords"], ["CISA KEV"])  # no duplicate
        self.assertEqual(build_final_entry(entry, kev_map={}, epss_map={})["matched_keywords"],
                         ["news: reported exploited"])

    def test_stored_alert_refresh_adds_cisa_kev_label(self):
        # Stored alerts not resurfaced this run are refreshed in main(); one
        # that CISA listed later (CVE-2016-7255, matched by microsoft/windows
        # only) kept kev=true with matched_keywords [].
        import inspect
        import aggregate as A
        src = inspect.getsource(A.main)
        self.assertIn('prior["matched_keywords"] = with_kev_label(prior.get("matched_keywords"), in_kev)', src)
        self.assertEqual(A.with_kev_label([], True), ["CISA KEV"])
        self.assertEqual(A.with_kev_label(None, False), [])


class TestParseOsvFixedVersions(unittest.TestCase):
    def test_extracts_fixed_versions_from_affected_ranges(self):
        osv_data = {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "affected": [
                {
                    "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [
                            {"introduced": "0"}, {"fixed": "2.3.1"},
                        ]},
                    ],
                },
            ],
        }
        result = parse_osv_fixed_versions(osv_data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["package"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(result[0]["ecosystem"], "Maven")
        self.assertEqual(result[0]["fixed"], "2.3.1")

    def test_no_fixed_event_yields_empty_list(self):
        osv_data = {"id": "X", "affected": [
            {"package": {"name": "foo", "ecosystem": "PyPI"},
             "ranges": [{"events": [{"introduced": "0"}]}]},
        ]}
        self.assertEqual(parse_osv_fixed_versions(osv_data), [])

    def test_missing_affected_key_returns_empty(self):
        self.assertEqual(parse_osv_fixed_versions({"id": "X"}), [])

    def test_malformed_input_does_not_raise(self):
        self.assertEqual(parse_osv_fixed_versions(None), [])
        self.assertEqual(parse_osv_fixed_versions({"affected": "not-a-list"}), [])
        self.assertEqual(parse_osv_fixed_versions({"affected": [{"ranges": "bad"}]}), [])

    def test_caps_at_five_entries(self):
        osv_data = {"id": "X", "affected": [
            {"package": {"name": f"pkg{i}", "ecosystem": "PyPI"},
             "ranges": [{"events": [{"fixed": f"1.{i}.0"}]}]}
            for i in range(8)
        ]}
        result = parse_osv_fixed_versions(osv_data)
        self.assertEqual(len(result), 5)


class TestExtractNvdFixVersions(unittest.TestCase):
    def test_extracts_fix_from_version_end_excluding(self):
        nvd_cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "2.3.1",
                    }],
                }],
            }],
        }
        result = extract_nvd_fix_versions(nvd_cve)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["vendor"], "apache")
        self.assertEqual(result[0]["product"], "log4j")
        self.assertEqual(result[0]["fixed"], "2.3.1")
        self.assertEqual(result[0]["fix_type"], "before")

    def test_version_end_including_sets_fix_type(self):
        nvd_cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*",
            "versionEndIncluding": "15.6",
        }]}]}]}
        result = extract_nvd_fix_versions(nvd_cve)
        self.assertEqual(result[0]["fix_type"], "up_to_and_including")

    def test_non_vulnerable_match_ignored(self):
        nvd_cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": False,
            "criteria": "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.0",
        }]}]}]}
        self.assertEqual(extract_nvd_fix_versions(nvd_cve), [])

    def test_no_version_bound_ignored(self):
        nvd_cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*",
        }]}]}]}
        self.assertEqual(extract_nvd_fix_versions(nvd_cve), [])

    def test_missing_configurations_returns_empty(self):
        self.assertEqual(extract_nvd_fix_versions({}), [])

    def test_malformed_input_does_not_raise(self):
        self.assertEqual(extract_nvd_fix_versions({"configurations": "bad"}), [])
        self.assertEqual(extract_nvd_fix_versions({"configurations": [{"nodes": "bad"}]}), [])
        self.assertEqual(extract_nvd_fix_versions(
            {"configurations": [{"nodes": [{"cpeMatch": "bad"}]}]}), [])

    def test_dedupes_and_caps_at_five(self):
        matches = [{
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:vendor{i}:product{i}:*:*:*:*:*:*:*:*",
            "versionEndExcluding": f"1.{i}.0",
        } for i in range(8)]
        # Add a duplicate of the first entry to verify dedup doesn't consume a slot twice
        matches.insert(0, dict(matches[0]))
        nvd_cve = {"configurations": [{"nodes": [{"cpeMatch": matches}]}]}
        result = extract_nvd_fix_versions(nvd_cve)
        self.assertEqual(len(result), 5)

    def test_malformed_criteria_ignored(self):
        nvd_cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "not-a-cpe-string",
            "versionEndExcluding": "1.0",
        }]}]}]}
        self.assertEqual(extract_nvd_fix_versions(nvd_cve), [])


class TestExtractNvdReferenceLinks(unittest.TestCase):
    """extract_nvd_reference_links() (cycle 79) -- parses NVD's `references`
    array for Vendor Advisory/Patch/Release Notes tagged links only."""

    def test_wanted_tags_kept(self):
        nvd_cve = {"references": [
            {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://vendor.example/patch", "tags": ["Patch"]},
            {"url": "https://vendor.example/notes", "tags": ["Release Notes"]},
        ]}
        result = extract_nvd_reference_links(nvd_cve)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["url"], "https://vendor.example/advisory")
        self.assertEqual(result[0]["tags"], ["Vendor Advisory"])

    def test_unwanted_tags_excluded(self):
        nvd_cve = {"references": [
            {"url": "https://third.example/x", "tags": ["Third Party Advisory"]},
            {"url": "https://list.example/y", "tags": ["Mailing List"]},
            {"url": "https://exploit.example/z", "tags": ["Exploit"]},
        ]}
        self.assertEqual(extract_nvd_reference_links(nvd_cve), [])

    def test_ref_with_multiple_tags_matches_if_any_wanted(self):
        nvd_cve = {"references": [
            {"url": "https://vendor.example/a", "tags": ["Exploit", "Vendor Advisory"]},
        ]}
        result = extract_nvd_reference_links(nvd_cve)
        self.assertEqual(len(result), 1)
        self.assertIn("Vendor Advisory", result[0]["tags"])

    def test_dedupes_by_url_and_caps_at_five(self):
        refs = [{"url": f"https://vendor.example/{i}", "tags": ["Patch"]} for i in range(8)]
        refs.insert(0, dict(refs[0]))  # duplicate URL should not consume an extra slot
        nvd_cve = {"references": refs}
        result = extract_nvd_reference_links(nvd_cve)
        self.assertEqual(len(result), 5)

    def test_missing_references_returns_empty(self):
        self.assertEqual(extract_nvd_reference_links({}), [])

    def test_malformed_input_does_not_raise(self):
        self.assertEqual(extract_nvd_reference_links({"references": "bad"}), [])
        self.assertEqual(extract_nvd_reference_links({"references": ["bad"]}), [])
        self.assertEqual(extract_nvd_reference_links({"references": [{"url": None, "tags": ["Patch"]}]}), [])
        self.assertEqual(extract_nvd_reference_links({"references": [{"url": "https://x", "tags": None}]}), [])


class TestAppendHistory(unittest.TestCase):
    """append_history() writes docs/data/history/trend.csv -- verify the new
    critical_count/high_count columns (added alongside the existing schema-
    drift self-heal for avg_risk_score) round-trip correctly and that old
    rows with fewer columns aren't touched/corrupted by the header upgrade.
    """

    def _run_with_tmp_paths(self, csv_path, fn):
        import aggregate
        with mock.patch.object(aggregate, "HISTORY_DIR", os.path.dirname(csv_path)), \
             mock.patch.object(aggregate, "HISTORY_CSV_PATH", csv_path):
            fn()

    def test_new_file_gets_full_header_and_row(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "trend.csv")
            stats = {
                "generated_at": "2026-01-01T00:00:00Z",
                "total_alerts": 10,
                "kev_count": 2,
                "kev_overdue_count": 1,
                "kev_ransomware_count": 0,
                "avg_epss": 0.05,
                "avg_risk_score": 42.5,
                "by_severity": {"critical": 3, "high": 4, "medium": 2, "low": 1, "unknown": 0},
                "avg_cvss_score": 6.5,
                "kev_due_soon_count": 2,
                "new_alerts_count": 4,
                "risk_increasing_count": 3,
                "risk_decreasing_count": 1,
            }
            self._run_with_tmp_paths(csv_path, lambda: append_history(stats))
            with open(csv_path) as f:
                lines = f.read().strip().split("\n")
            self.assertEqual(lines[0], HISTORY_CSV_HEADER)
            self.assertTrue(lines[0].endswith("critical_count,high_count,avg_cvss_score,kev_due_soon_count,medium_count,low_count,new_alerts_count,risk_increasing_count,risk_decreasing_count"))
            row = lines[1].split(",")
            self.assertEqual(row[-9], "3")  # critical_count
            self.assertEqual(row[-8], "4")  # high_count
            self.assertEqual(row[-7], "6.5")  # avg_cvss_score
            self.assertEqual(row[-6], "2")  # kev_due_soon_count
            self.assertEqual(row[-5], "2")  # medium_count
            self.assertEqual(row[-4], "1")  # low_count
            self.assertEqual(row[-3], "4")  # new_alerts_count
            self.assertEqual(row[-2], "3")  # risk_increasing_count
            self.assertEqual(row[-1], "1")  # risk_decreasing_count

    def test_stale_header_upgraded_without_touching_old_rows(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "trend.csv")
            old_header = "timestamp,total_alerts,kev_count,kev_overdue_count,kev_ransomware_count,avg_epss,avg_risk_score"
            old_row = "2025-12-01T00:00:00Z,5,0,0,0,0.01,10.0"
            with open(csv_path, "w") as f:
                f.write(old_header + "\n" + old_row + "\n")
            stats = {
                "generated_at": "2026-01-01T00:00:00Z",
                "total_alerts": 6, "kev_count": 0, "kev_overdue_count": 0,
                "kev_ransomware_count": 0, "avg_epss": 0.02, "avg_risk_score": 11.0,
                "by_severity": {"critical": 1, "high": 1},
                "avg_cvss_score": 7.25,
                "kev_due_soon_count": 0,
                "new_alerts_count": 6,
                "risk_increasing_count": 2,
                "risk_decreasing_count": 0,
            }
            self._run_with_tmp_paths(csv_path, lambda: append_history(stats))
            with open(csv_path) as f:
                lines = f.read().strip().split("\n")
            self.assertEqual(lines[0], HISTORY_CSV_HEADER)
            # Old row is untouched (still fewer columns -- schema-evolution record).
            self.assertEqual(lines[1], old_row)
            self.assertEqual(lines[2].split(",")[-9:], ["1", "1", "7.25", "0", "", "", "6", "2", "0"])

    def test_missing_severity_breakdown_writes_empty_columns(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "trend.csv")
            stats = {
                "generated_at": "2026-01-01T00:00:00Z",
                "total_alerts": 1, "kev_count": 0, "kev_overdue_count": 0,
                "kev_ransomware_count": 0, "avg_epss": None, "avg_risk_score": None,
            }
            self._run_with_tmp_paths(csv_path, lambda: append_history(stats))
            with open(csv_path) as f:
                row = f.read().strip().split("\n")[1].split(",")
            self.assertEqual(row[-9:], ["", "", "", "", "", "", "", "", ""])


class TestWriteSitemap(unittest.TestCase):
    """write_sitemap() must emit a <lastmod> in valid W3C Datetime format
    (no fractional seconds) per the Sitemaps protocol, even though
    generated_at_iso arrives with microsecond precision from
    datetime.isoformat() elsewhere in the pipeline (cycle 142 fix --
    previously untested, the gap that let this ship without a regression
    guard in the first place)."""

    def _run_with_tmp_path(self, sitemap_path, fn):
        import aggregate
        with mock.patch.object(aggregate, "SITEMAP_PATH", sitemap_path):
            fn()

    def test_strips_microseconds_from_generated_at(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sitemap.xml")
            self._run_with_tmp_path(
                path, lambda: aggregate.write_sitemap("2026-09-14T20:11:17.873552+00:00")
            )
            with open(path) as f:
                content = f.read()
            self.assertIn("<lastmod>2026-09-14T20:11:17+00:00</lastmod>", content)
            self.assertNotIn("873552", content)

    def test_missing_generated_at_falls_back_to_now_without_microseconds(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sitemap.xml")
            self._run_with_tmp_path(path, lambda: aggregate.write_sitemap(None))
            with open(path) as f:
                content = f.read()
            match = re.search(r"<lastmod>([^<]+)</lastmod>", content)
            self.assertIsNotNone(match)
            # Valid W3C-DTF complete-seconds form has no '.' fractional component.
            self.assertNotIn(".", match.group(1))

    def test_malformed_generated_at_left_untouched(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sitemap.xml")
            self._run_with_tmp_path(
                path, lambda: aggregate.write_sitemap("not-a-real-timestamp")
            )
            with open(path) as f:
                content = f.read()
            self.assertIn("<lastmod>not-a-real-timestamp</lastmod>", content)


class TestBuildKevFeedRss(unittest.TestCase):
    """build_kev_feed()'s RSS 2.0 mirror must emit <pubDate> in RFC 822 date
    format per the RSS 2.0 spec, even though date_published is stored as ISO
    8601 (with fractional seconds) elsewhere in the pipeline -- the same
    class of spec-compliance gap fixed for sitemap.xml's <lastmod> above,
    applied here to feed.xml's <pubDate>/<lastBuildDate>."""

    def _run_with_tmp_paths(self, snapshot_path, feed_json_path, feed_xml_path, fn):
        import aggregate
        with mock.patch.object(aggregate, "KEV_SNAPSHOT_PATH", snapshot_path), \
             mock.patch.object(aggregate, "FEED_JSON_PATH", feed_json_path), \
             mock.patch.object(aggregate, "FEED_XML_PATH", feed_xml_path):
            fn()

    def test_pubdate_is_rfc822_not_iso8601(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            snap = os.path.join(d, "kev_snapshot.json")
            feed_json = os.path.join(d, "feed.json")
            feed_xml = os.path.join(d, "feed.xml")
            with open(snap, "w") as f:
                json.dump([], f)
            kev_map = {
                "CVE-2026-99999": {
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "desc",
                    "dateAdded": "2026-09-14",
                    "dueDate": "2026-10-05",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            }
            self._run_with_tmp_paths(
                snap, feed_json, feed_xml,
                lambda: aggregate.build_kev_feed(kev_map),
            )
            with open(feed_xml) as f:
                content = f.read()
            match = re.search(r"<pubDate>([^<]+)</pubDate>", content)
            self.assertIsNotNone(match)
            pubdate = match.group(1)
            # RFC 822 format ("Day, DD Mon YYYY HH:MM:SS GMT") has no ISO 8601
            # 'T' date/time separator between the date and time components.
            # A plain substring check for "T" is unsound: RFC 822 day-name
            # abbreviations "Tue" and "Thu" legitimately contain a 'T', which
            # made this assertion flaky (only failing on those two weekdays).
            # Instead assert there is no ISO-8601-style "YYYY-MM-DDTHH:MM:SS"
            # pattern anywhere in the value.
            self.assertIsNone(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", pubdate))
            self.assertNotIn(".", pubdate)
            self.assertTrue(pubdate.endswith("GMT"))
            # Must be parseable by the standard RFC 822 parser.
            from email.utils import parsedate_to_datetime
            parsedate_to_datetime(pubdate)  # raises if invalid
            # lastBuildDate must also be present and RFC 822-valid.
            lb_match = re.search(r"<lastBuildDate>([^<]+)</lastBuildDate>", content)
            self.assertIsNotNone(lb_match)
            parsedate_to_datetime(lb_match.group(1))

    def test_malformed_date_published_left_untouched(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            snap = os.path.join(d, "kev_snapshot.json")
            feed_json = os.path.join(d, "feed.json")
            feed_xml = os.path.join(d, "feed.xml")
            with open(snap, "w") as f:
                json.dump([], f)
            with open(feed_json, "w") as f:
                json.dump({
                    "version": "https://jsonfeed.org/version/1",
                    "title": "New CISA KEV Entries",
                    "items": [{
                        "id": "CVE-2020-00000",
                        "title": "CVE-2020-00000: Old entry",
                        "content_text": "desc",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-00000",
                        "date_published": "not-a-real-timestamp",
                    }],
                }, f)
            self._run_with_tmp_paths(
                snap, feed_json, feed_xml,
                lambda: aggregate.build_kev_feed({}),
            )
            with open(feed_xml) as f:
                content = f.read()
            self.assertIn("<pubDate>not-a-real-timestamp</pubDate>", content)

    def test_existing_items_track_catalog_due_date_and_ransomware(self):
        # CISA moved CVE-2026-86950's due date 2026-10-02 -> 2026-10-13 after
        # it was added; the feed item kept the old date forever.
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            snap = os.path.join(d, "kev_snapshot.json")
            feed_json = os.path.join(d, "feed.json")
            feed_xml = os.path.join(d, "feed.xml")
            with open(snap, "w") as f:
                json.dump(["CVE-2026-86950", "CVE-2020-1", "CVE-2020-2"], f)
            old = {"id": "CVE-2026-86950", "title": "CVE-2026-86950: Apple", "content_text": "d",
                   "url": "u", "date_published": "2026-09-29T16:12:56+00:00",
                   "_kev_date_added": "2026-09-29", "_kev_due_date": "2026-10-02",
                   "_kev_vendor_project": "Apple", "_kev_product": "Multiple Products",
                   "_kev_ransomware_use": False}
            gone = dict(old, id="CVE-2020-1", _kev_due_date="2020-01-01")
            partial = dict(old, id="CVE-2020-2", _kev_due_date="2021-01-01")
            with open(feed_json, "w") as f:
                json.dump({"version": "https://jsonfeed.org/version/1", "title": "t",
                           "items": [old, gone, partial]}, f)
            kev_map = {"CVE-2026-86950": {"dateAdded": "2026-09-29", "dueDate": "2026-10-13",
                                          "knownRansomwareCampaignUse": "Known"},
                       "CVE-2020-2": {}}
            self._run_with_tmp_paths(snap, feed_json, feed_xml,
                                     lambda: aggregate.build_kev_feed(kev_map))
            with open(feed_json) as f:
                items = {i["id"]: i for i in json.load(f)["items"]}
            self.assertEqual(items["CVE-2026-86950"]["_kev_due_date"], "2026-10-13")
            self.assertTrue(items["CVE-2026-86950"]["_kev_ransomware_use"])
            self.assertEqual(items["CVE-2026-86950"]["date_published"], "2026-09-29T16:12:56+00:00")
            self.assertEqual(items["CVE-2026-86950"]["_kev_date_added"], "2026-09-29")
            self.assertEqual(items["CVE-2020-1"]["_kev_due_date"], "2020-01-01")  # delisted: untouched
            self.assertEqual(items["CVE-2020-2"]["_kev_due_date"], "2021-01-01")  # partial: not blanked
            self.assertFalse(items["CVE-2020-2"]["_kev_ransomware_use"])


class TestAdvisoryTwins(unittest.TestCase):
    def test_kev_only_twin_collapses_into_nvd_alert(self):
        by_key = {"CVE-2026-1::kev": {"cve_id": "CVE-2026-1", "source": "kev", "first_seen": "2026-10-16T00:00:00"},
                  "CVE-2026-1::nvd": {"cve_id": "CVE-2026-1", "source": "nvd", "first_seen": "2026-10-17T00:00:00"},
                  "CVE-2026-2::kev": {"cve_id": "CVE-2026-2", "source": "kev", "first_seen": "2026-10-17T00:00:00"},
                  "CVE-2026-1::dependabot": {"cve_id": "CVE-2026-1", "source": "dependabot"}}
        import aggregate
        self.assertEqual(aggregate.collapse_advisory_twins(by_key), 1)
        self.assertEqual(sorted(by_key), ["CVE-2026-1::dependabot", "CVE-2026-1::nvd", "CVE-2026-2::kev"])
        self.assertEqual(by_key["CVE-2026-1::nvd"]["first_seen"], "2026-10-16T00:00:00")


class TestSingleWordHit(unittest.TestCase):
    """NVD prefix-matches single keywords; only whole-word / CPE hits count."""

    def _cve(self, desc, cpes=()):
        return {"id": "CVE-2099-0001", "descriptions": [{"lang": "en", "value": desc}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": c} for c in cpes]}]}]}

    def test_prefix_noise_rejected(self):
        from aggregate import single_word_hit
        self.assertFalse(single_word_hit("DeepL", self._cve("libexpat stack overflow via deeply nested XML")))
        self.assertFalse(single_word_hit("Canva", self._cve("Use-after-free in the canvas component")))
        self.assertFalse(single_word_hit("Naviga", self._cve("Open redirect in navigation handler")))

    def test_whole_word_and_cpe_kept(self):
        from aggregate import single_word_hit
        self.assertTrue(single_word_hit("DeepL", self._cve("DeepL for Windows allows DLL hijacking")))
        self.assertTrue(single_word_hit("Canva", self._cve("Affinity by Canva before 3.0 ...")))
        self.assertTrue(single_word_hit("Naviga", self._cve("XSS in an editor",
                                                          ["cpe:2.3:a:naviga:writer:*:*:*:*:*:*:*:*"])))


class TestPruneSingleWord(unittest.TestCase):
    """Retroactive prune of single-word prefix noise ingested before single_word_hit()."""
    WL = {"keywords": ["Zoom", "Slack", "Vim", "wordpress", "Fortinet"], "priority_keywords": []}

    def test_prefix_noise_pruned_real_hits_kept(self):
        from aggregate import prune_loose_phrase_matches
        alerts = [
            {"cve_id": "CVE-A", "source": "nvd", "matched_keywords": ["Zoom"],
             "description": "Reflected XSS in ZoomSounds through 6.91", "affected": []},
            {"cve_id": "CVE-B", "source": "nvd", "matched_keywords": ["Slack"],
             "description": "A flaw in slackero phpwcms", "affected": []},
            {"cve_id": "CVE-C", "source": "nvd", "matched_keywords": ["wordpress", "Vim"],
             "description": "The FV Flowplayer plugin for WordPress is vulnerable", "affected": []},
            {"cve_id": "CVE-D", "source": "nvd", "matched_keywords": ["Zoom"],
             "description": "Zoom Workplace for Windows allows DLL hijacking", "affected": []},
            {"cve_id": "CVE-E", "source": "nvd", "matched_keywords": ["Zoom"],
             "description": "Buffer overflow in the meeting client", "affected": ["zoom/meetings"]},
            {"cve_id": "CVE-F", "source": "kev", "matched_keywords": ["Fortinet"],
             "description": "FortiOS heap overflow"},  # CISA-text match, not an NVD prefix hit
        ]
        kept, removed = prune_loose_phrase_matches(alerts, self.WL)
        self.assertEqual(removed, ["CVE-A", "CVE-B"])
        by = {a["cve_id"]: a for a in kept}
        self.assertEqual(by["CVE-C"]["matched_keywords"], ["wordpress"])
        self.assertEqual(by["CVE-D"]["matched_keywords"], ["Zoom"])
        self.assertEqual(by["CVE-E"]["matched_keywords"], ["Zoom"])
        self.assertEqual(by["CVE-F"]["matched_keywords"], ["Fortinet"])

    def test_affected_pair_justifies_alert(self):
        """Stored alerts keep vendor/product pairs in `affected`; a pair-matched alert
        must survive even when its only keyword turns out loose."""
        from aggregate import prune_loose_phrase_matches
        alerts = [{"cve_id": "CVE-G", "source": "nvd", "matched_keywords": ["Check Point"],
                   "description": "kernel check at point", "affected": ["mozilla/firefox"]}]
        kept, removed = prune_loose_phrase_matches(alerts, {"keywords": ["Check Point"]})
        self.assertEqual(removed, [])
        self.assertEqual(kept[0]["matched_keywords"], [])

    def test_alerts_seen_after_fetch_filter_not_rechecked(self):
        """Post-filter alerts already passed single_word_hit (maybe via CPE, which the
        stored alert can't show); re-checking them would drop CPE-only hits."""
        from aggregate import prune_loose_phrase_matches
        alerts = [{"cve_id": "CVE-H", "source": "nvd", "matched_keywords": ["Zoom"],
                   "description": "ZoomRooms installer DLL hijack", "affected": [],
                   "first_seen": "2026-10-21T08:00:00+00:00"}]
        kept, removed = prune_loose_phrase_matches(alerts, self.WL)
        self.assertEqual(removed, [])
        self.assertEqual(kept[0]["matched_keywords"], ["Zoom"])


class TestFetchPhraseBoundary(unittest.TestCase):
    """keywordExactMatch is substring-based; the fetch must reject "Check pointer"
    for "Check Point" or prune and fetch fight over the alert every run."""

    def test_substring_phrase_hit_rejected(self):
        from unittest import mock
        import aggregate as A

        def cve(i, desc):
            return {"cve": {"id": i, "descriptions": [{"lang": "en", "value": desc}]}}

        def fake(params, api_key):
            if params.get("keywordSearch") == "Check Point":
                v = [cve("CVE-1", "bpf: Check pointer type for all atomic RMW paths"),
                     cve("CVE-2", "Check Point Harmony Email allows XSS")]
                return {"vulnerabilities": v, "totalResults": 2}
            return {"vulnerabilities": [], "totalResults": 0}

        with mock.patch.object(A, "nvd_query", side_effect=fake), mock.patch.object(A.time, "sleep"):
            got = A.fetch_nvd_candidates({"keywords": ["Check Point"], "vendors_products": [],
                                          "priority_keywords": []}, None)
        self.assertEqual(sorted(got), ["CVE-2"])


class TestFetchVendorProductCpe(unittest.TestCase):
    """'php php' keywordSearch returns libxml2 / WordPress-plugin CVEs; a record
    whose CPEs name neither 'php' vendor nor product must not be tagged php/php."""

    def test_other_vendor_cpe_rejected(self):
        from unittest import mock
        import aggregate as A

        def cve(i, desc, cpes):
            confs = [{"nodes": [{"cpeMatch": [{"criteria": c, "vulnerable": True} for c in cpes]}]}] if cpes else []
            return {"cve": {"id": i, "descriptions": [{"lang": "en", "value": desc}], "configurations": confs}}

        def fake(params, api_key):
            if params.get("keywordSearch") == "php php":
                v = [cve("CVE-1", "libxml2 overflow, see php bug tracker", ["cpe:2.3:a:xmlsoft:libxml2:2.9.4:*:*:*:*:*:*:*"]),
                     cve("CVE-2", "PHP 8.3 heap overflow", ["cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"]),
                     cve("CVE-3", "PHP Object Injection in a plugin", [])]
                return {"vulnerabilities": v, "totalResults": 3}
            if params.get("keywordSearch") == "nginx nginx":
                return {"vulnerabilities": [cve("CVE-4", "nginx resolver bug", ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"])],
                        "totalResults": 1}
            return {"vulnerabilities": [], "totalResults": 0}

        with mock.patch.object(A, "nvd_query", side_effect=fake), mock.patch.object(A.time, "sleep"):
            got = A.fetch_nvd_candidates({"keywords": [], "priority_keywords": [],
                                          "vendors_products": [{"vendor": "php", "product": "php"},
                                                               {"vendor": "nginx", "product": "nginx"}]}, None)
        # CVE-3 has no CPEs yet (cannot tell, kept); CVE-4 nginx now under vendor f5
        self.assertEqual(sorted(got), ["CVE-2", "CVE-3", "CVE-4"])


class TestReadmittedKeepsFirstSeen(unittest.TestCase):
    """An alert pruned as loose-phrase noise and re-admitted in the same run by a
    CPE pair must keep its original first_seen (it was reset to 'now' and showed
    as 'New in last 24 h', e.g. CVE-2023-0286 on 2026-10-20)."""

    def test_pruned_then_readmitted(self):
        import aggregate as A
        old = "2026-10-14T22:59:41+00:00"
        alerts = [{"cve_id": "CVE-2023-0286", "source": "nvd", "matched_keywords": ["Zoom"],
                   "description": "X.400 address type confusion in OpenSSL", "affected": [],
                   "first_seen": old}]
        pruned_first_seen = {A.unique_key(a): a["first_seen"] for a in alerts}
        kept, removed = A.prune_loose_phrase_matches(alerts, {"keywords": ["Zoom"]})
        self.assertEqual(removed, ["CVE-2023-0286"])
        by_key = {A.unique_key(a): a for a in kept}
        now = "2026-10-20T16:55:32+00:00"
        self.assertEqual(A.known_first_seen("CVE-2023-0286::nvd", by_key, pruned_first_seen, now), old)
        # Genuinely unknown key still falls back to now; a live prior wins.
        self.assertEqual(A.known_first_seen("CVE-9::nvd", by_key, pruned_first_seen, now), now)
        self.assertEqual(A.known_first_seen("K", {"K": {"first_seen": "a"}}, {"K": "b"}, now), "a")

    def test_main_snapshots_before_prune(self):
        import inspect
        import aggregate as A
        src = inspect.getsource(A.main)
        self.assertLess(src.index("pruned_first_seen = "), src.index("prune_loose_phrase_matches("))
        self.assertIn("known_first_seen(key, existing_by_key, pruned_first_seen", src)


class TestKevOutageDoesNotCorruptData(unittest.TestCase):
    """A failed CISA KEV fetch returns {}. That must not wipe the KEV baseline
    (the next good run would re-announce the whole catalog as new) and must
    not let main() write alerts/stats with every KEV flag cleared."""

    def test_empty_catalog_keeps_snapshot_and_feed(self):
        import aggregate
        with tempfile.TemporaryDirectory() as d:
            snap = os.path.join(d, "kev_snapshot.json")
            feed_json = os.path.join(d, "feed.json")
            feed_xml = os.path.join(d, "feed.xml")
            real = {f"CVE-2020-{i:04d}": {"cveID": f"CVE-2020-{i:04d}"} for i in range(50)}
            with mock.patch.object(aggregate, "KEV_SNAPSHOT_PATH", snap), \
                 mock.patch.object(aggregate, "FEED_JSON_PATH", feed_json), \
                 mock.patch.object(aggregate, "FEED_XML_PATH", feed_xml):
                aggregate.build_kev_feed(real)   # seed baseline
                aggregate.build_kev_feed({})     # outage run
                with open(snap) as f:
                    self.assertEqual(len(json.load(f)), 50)
                aggregate.build_kev_feed(real)   # recovery run
                with open(feed_json) as f:
                    self.assertEqual(json.load(f)["items"], [])

    def test_main_aborts_before_writing_when_kev_unavailable(self):
        import aggregate
        with mock.patch.object(aggregate, "fetch_kev", return_value={}), \
             mock.patch.object(aggregate, "fetch_nvd_candidates") as nvd, \
             mock.patch.object(aggregate, "save_json_file") as save, \
             mock.patch.object(aggregate, "append_history") as hist:
            with self.assertRaises(SystemExit) as cm:
                aggregate.main()
            self.assertNotEqual(cm.exception.code, 0)
            nvd.assert_not_called()
            save.assert_not_called()
            hist.assert_not_called()


class TestEpssOutageKeepsPriorScores(unittest.TestCase):
    """A failed EPSS batch used to overwrite every tracked alert in it with
    epss_score=None, dropping the EPSS share of its risk score for that run."""

    def test_failed_batch_ids_reported(self):
        import aggregate
        with mock.patch.object(aggregate, "http_get_json", side_effect=OSError("down")), \
             mock.patch.object(aggregate.time, "sleep"):
            failed = set()
            out = aggregate.fetch_epss(["CVE-2024-0001", "CVE-2024-0002"], failed=failed)
        self.assertEqual(out, {})
        self.assertEqual(failed, {"CVE-2024-0001", "CVE-2024-0002"})

    def test_prior_score_kept_only_for_failed_ids(self):
        import aggregate
        existing = [
            {"cve_id": "CVE-2024-0001", "epss_score": 0.42, "epss_percentile": 0.97},
            {"cve_id": "CVE-2024-0002", "epss_score": 0.10, "epss_percentile": 0.80},
            {"cve_id": "CVE-2024-0003", "epss_score": None},
        ]
        fresh = {"CVE-2024-0002": {"epss": 0.20, "percentile": 0.90}}
        out = aggregate.keep_prior_epss_on_failure(
            fresh, {"CVE-2024-0001", "CVE-2024-0003"}, existing)
        self.assertEqual(out["CVE-2024-0001"], {"epss": 0.42, "percentile": 0.97})
        self.assertEqual(out["CVE-2024-0002"], {"epss": 0.20, "percentile": 0.90})  # fresh wins
        self.assertNotIn("CVE-2024-0003", out)  # never invent a score
        self.assertIs(aggregate.keep_prior_epss_on_failure(fresh, set(), existing), fresh)


class TestLegacyNvdBackfill(unittest.TestCase):
    """Alerts written before nvd_last_modified/vuln_status existed (124 live,
    first seen 2026-09-05) never got CWE/attack vector/status because they are
    only rebuilt when NVD edits the record again."""

    CVE = {
        "id": "CVE-2026-11325", "published": "2026-08-12T12:17:44.370",
        "lastModified": "2026-08-28T15:42:20.060", "vulnStatus": "Awaiting Analysis",
        "descriptions": [{"lang": "en", "value": "fresh text"}],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {
            "baseScore": 9.9, "attackVector": "NETWORK", "attackComplexity": "LOW",
            "privilegesRequired": "NONE", "userInteraction": "NONE"}}]},
        "references": [{"url": "https://vendor.example/adv", "tags": ["Vendor Advisory"]}],
    }

    def legacy(self):
        return {"cve_id": "CVE-2026-11325", "source": "nvd", "cvss_score": 8.8,
                "description": "old text", "first_seen": "2026-09-05T15:02:54+00:00",
                "affected": ["cloudflare/cloudflare"], "vuln_status": None,
                "nvd_fix_versions": [], "nvd_reference_links": []}

    def test_fills_missing_fields_only(self):
        import aggregate
        alerts = {"CVE-2026-11325::nvd": self.legacy(),
                  "CVE-2026-1::kev": {"cve_id": "CVE-2026-1", "source": "kev", "vuln_status": None}}
        resp = {"vulnerabilities": [{"cve": self.CVE}], "totalResults": 1}
        with mock.patch.object(aggregate, "nvd_query", return_value=resp) as q:
            n = aggregate.backfill_legacy_nvd_fields(alerts, set(), None, max_n=10, sleep=lambda s: None)
        self.assertEqual(n, 1)
        q.assert_called_once()  # KEV-only alert is not re-read
        a = alerts["CVE-2026-11325::nvd"]
        self.assertEqual(a["cwe_ids"], ["CWE-78"])
        self.assertEqual(a["vuln_status"], "Awaiting Analysis")
        self.assertEqual(a["nvd_last_modified"], "2026-08-28T15:42:20.060")
        self.assertEqual(a["cvss_vector_components"]["attack_vector"], "NETWORK")
        self.assertEqual(a["nvd_reference_links"][0]["url"] if isinstance(a["nvd_reference_links"][0], dict)
                         else a["nvd_reference_links"][0], "https://vendor.example/adv")
        # score, text, first_seen and matching untouched
        self.assertEqual((a["cvss_score"], a["description"], a["first_seen"], a["affected"]),
                         (8.8, "old text", "2026-09-05T15:02:54+00:00", ["cloudflare/cloudflare"]))
        self.assertFalse(aggregate.needs_legacy_nvd_backfill(a))  # converges

    def test_failed_lookup_and_skip_keys_leave_alert_unchanged(self):
        import aggregate
        before = self.legacy()
        alerts = {"CVE-2026-11325::nvd": dict(before)}
        with mock.patch.object(aggregate, "nvd_query", return_value=None):
            self.assertEqual(aggregate.backfill_legacy_nvd_fields(alerts, set(), None, max_n=10,
                                                                  sleep=lambda s: None), 0)
        self.assertEqual(alerts["CVE-2026-11325::nvd"], before)
        with mock.patch.object(aggregate, "nvd_query") as q:
            aggregate.backfill_legacy_nvd_fields(alerts, {"CVE-2026-11325::nvd"}, None, max_n=10,
                                                 sleep=lambda s: None)
        q.assert_not_called()

    def test_cap(self):
        import aggregate
        alerts = {f"CVE-2026-{i}::nvd": {"cve_id": f"CVE-2026-{i}", "source": "nvd"} for i in range(5)}
        with mock.patch.object(aggregate, "nvd_query", return_value=None) as q:
            aggregate.backfill_legacy_nvd_fields(alerts, set(), None, max_n=2, sleep=lambda s: None)
        self.assertEqual(q.call_count, 2)


class TestRevalidateAffectedPairs(unittest.TestCase):
    """557 live alerts were justified only by 'php/php', stored before the fetch
    checked CPEs (60ea6b7); e.g. CVE-2026-62052 'PHP Object Injection in Tipsy'."""

    WL = {"vendors_products": [{"vendor": "php", "product": "php"},
                               {"vendor": "wordpress", "product": "wordpress"}]}

    @staticmethod
    def resp(cve_id, cpes):
        nodes = [{"cpeMatch": [{"criteria": c} for c in cpes]}] if cpes else []
        return {"vulnerabilities": [{"cve": {"id": cve_id, "configurations": [{"nodes": nodes}] if nodes else []}}]}

    def alerts(self):
        return {
            "CVE-1::nvd": {"cve_id": "CVE-1", "source": "nvd", "affected": ["php/php"], "matched_keywords": []},
            "CVE-2::nvd": {"cve_id": "CVE-2", "source": "nvd", "affected": ["php/php"], "matched_keywords": []},
            "CVE-3::nvd": {"cve_id": "CVE-3", "source": "nvd", "affected": ["php/php", "wordpress/wordpress"],
                           "matched_keywords": ["WordPress"]},
            "CVE-4::nvd": {"cve_id": "CVE-4", "source": "nvd", "affected": ["php/php"], "matched_keywords": []},
            "CVE-5::kev": {"cve_id": "CVE-5", "source": "kev", "kev": True, "affected": ["php/php"]},
        }

    def run_it(self, alerts, responses, **kw):
        import aggregate
        with mock.patch.object(aggregate, "nvd_query", side_effect=lambda p, k: responses.get(p["cveId"])) as q:
            removed = aggregate.revalidate_affected_pairs(alerts, set(), self.WL, None, sleep=lambda s: None,
                                                          today=__import__("datetime").date(2026, 10, 21), **kw)
        return removed, q

    def test_drops_pair_and_unjustified_alert(self):
        alerts = self.alerts()
        responses = {
            "CVE-1": self.resp("CVE-1", ["cpe:2.3:a:tipsy:tipsy:*:*:*:*:*:wordpress:*:*"]),  # other vendor
            "CVE-2": self.resp("CVE-2", ["cpe:2.3:a:php:php:8.3.0:*:*:*:*:*:*:*"]),  # real PHP bug
            "CVE-3": self.resp("CVE-3", ["cpe:2.3:a:foo:bar:*:*:*:*:*:wordpress:*:*"]),
            "CVE-4": self.resp("CVE-4", []),  # NVD has not analysed it yet
        }
        removed, q = self.run_it(alerts, responses, max_n=10)
        self.assertEqual(removed, ["CVE-1"])
        self.assertNotIn("CVE-1::nvd", alerts)
        self.assertEqual(alerts["CVE-2::nvd"]["affected"], ["php/php"])
        # plugin CPE: the pair goes (as in the live fetch) but the WordPress keyword keeps the alert
        self.assertEqual(alerts["CVE-3::nvd"]["affected"], [])
        self.assertEqual(alerts["CVE-3::nvd"]["matched_keywords"], ["WordPress"])
        self.assertEqual(alerts["CVE-4::nvd"]["affected"], ["php/php"])
        self.assertEqual(alerts["CVE-4::nvd"]["affected_cpe_check"], "no_cpes:2026-10-21")
        self.assertEqual(q.call_count, 4)  # KEV alert never re-read
        # converges: checked alerts are not re-read; no-CPE ones wait 14 days
        _, q2 = self.run_it(alerts, responses, max_n=10)
        self.assertEqual(q2.call_count, 0)

    def test_failed_lookup_and_cap(self):
        alerts = self.alerts()
        before = {k: dict(v) for k, v in alerts.items()}
        removed, q = self.run_it(alerts, {}, max_n=2)
        self.assertEqual((removed, q.call_count), ([], 2))
        self.assertEqual(alerts, before)


class TestResurfacedAlertKeepsStoredEnrichment(unittest.TestCase):
    """OSV.dev enrichment runs only for NEW alerts, but every NVD alert is re-read
    while it sits in the lookback window and the 'already known' merge rebuilt it
    from build_final_entry() (osv_id None, osv_fixed_versions []): CVE-2026-56095
    got its OSV record at e463957 and lost it on the next run (7f00d88)."""

    STORED = {"cve_id": "CVE-2026-56095", "source": "nvd", "first_seen": "2026-09-17T08:12:06+00:00",
              "cvss_score": 8.1, "risk_score": 30.0, "epss_score": 0.01, "matched_keywords": ["Linux"],
              "description": "Linux bug",
              "affected": [], "osv_id": "CVE-2026-56095",
              "osv_fixed_versions": [{"package": None, "ecosystem": None, "fixed": "722363e5"}],
              "affected_cpe_check": "ok"}

    def run_main(self, stored, candidates, kev_candidates=(), osv_result=None):
        import aggregate as A
        files = {A.ALERTS_PATH: [dict(a) for a in stored],
                 A.SEEN_PATH: [A.unique_key(a) for a in stored]}
        saved = {}
        wl = {"cvss_minimum": 7.0, "vendors_products": [], "keywords": ["Linux"], "priority_keywords": [],
              "dependabot_repos": [], "ghsa_packages": [], "require_kev_or_high_epss": False,
              "epss_high_threshold": 0.5}
        with mock.patch.object(A, "load_watchlist", return_value=wl), \
             mock.patch.object(A, "load_suppressions", return_value={}), \
             mock.patch.object(A, "fetch_kev", return_value={"CVE-2000-0001": {"cveID": "CVE-2000-0001"}}), \
             mock.patch.object(A, "fetch_nvd_candidates", return_value={c["cve_id"]: c for c in candidates}), \
             mock.patch.object(A, "fetch_dependabot_alerts", return_value=[]), \
             mock.patch.object(A, "fetch_ghsa_advisories", return_value=[]), \
             mock.patch.object(A, "fetch_kev_candidates", return_value=list(kev_candidates)), \
             mock.patch.object(A, "fetch_epss", return_value={}), \
             mock.patch.object(A, "fetch_osv_fix_info", return_value=osv_result) as osv, \
             mock.patch.object(A, "backfill_legacy_nvd_fields"), \
             mock.patch.object(A, "revalidate_affected_pairs"), \
             mock.patch.object(A, "load_json_file", side_effect=lambda p, d: files.get(p, d)), \
             mock.patch.object(A, "save_json_file", side_effect=lambda p, o: saved.__setitem__(p, o)), \
             mock.patch.object(A, "append_history"), mock.patch.object(A, "build_kev_feed"), \
             mock.patch.object(A, "write_sitemap"), mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}):
            A.main()
        return {A.unique_key(a): a for a in saved[A.ALERTS_PATH]}, saved[A.NEW_ALERTS_PATH], osv

    def candidate(self, source="nvd"):
        return {"cve_id": "CVE-2026-56095", "source": source, "cvss_score": 8.1, "description": "Linux bug",
                "matched_keywords": ["Linux"], "matched_vendor_product": []}

    def test_resurfaced_alert_keeps_osv_and_recheck_mark(self):
        out, new, osv = self.run_main([self.STORED], [self.candidate()])
        a = out["CVE-2026-56095::nvd"]
        self.assertEqual(new, [])
        osv.assert_not_called()
        self.assertEqual(a["osv_id"], "CVE-2026-56095")
        self.assertEqual(a["osv_fixed_versions"], self.STORED["osv_fixed_versions"])
        self.assertEqual(a["affected_cpe_check"], "ok")
        self.assertEqual(a["first_seen"], self.STORED["first_seen"])

    def test_kev_twin_upgrade_keeps_osv(self):
        kev = {**self.STORED, "source": "kev"}
        del kev["affected_cpe_check"]
        out, new, _ = self.run_main([kev], [self.candidate()])
        self.assertEqual(list(out), ["CVE-2026-56095::nvd"])
        self.assertEqual(out["CVE-2026-56095::nvd"]["osv_id"], "CVE-2026-56095")

    def test_never_invents_enrichment(self):
        bare = {k: v for k, v in self.STORED.items() if k not in A_STORED_ONLY}
        out, _, _ = self.run_main([bare], [self.candidate()])
        a = out["CVE-2026-56095::nvd"]
        self.assertIsNone(a["osv_id"])
        self.assertEqual(a["osv_fixed_versions"], [])
        self.assertNotIn("affected_cpe_check", a)

    def test_helper_fresh_value_wins(self):
        import aggregate as A
        merged = A.keep_stored_enrichment({"osv_id": "GHSA-new", "osv_fixed_versions": []},
                                          {"osv_id": "OLD", "osv_fixed_versions": [{"fixed": "1"}]})
        # a fresh OSV id is never paired with the old record's fixed versions
        self.assertEqual(merged, {"osv_id": "GHSA-new", "osv_fixed_versions": []})


A_STORED_ONLY = ("osv_id", "osv_fixed_versions", "osv_checked", "affected_cpe_check")


class TestRecheckOsv(unittest.TestCase):
    """OSV.dev used to be queried once, when an alert was first seen, so alerts
    whose OSV data was wiped (pre-5a8d6c7 merge) or that OSV had not ingested yet
    stayed without a fix line forever (13 of 80 sampled board alerts without
    osv_id had an OSV record on 2026-10-22)."""

    from datetime import date as _date
    TODAY = _date(2026, 10, 22)
    REC = {"osv_id": "CVE-2026-1", "osv_fixed_versions": [{"package": "p", "ecosystem": "PyPI", "fixed": "1.2"}]}

    def alerts(self):
        return {
            "a::nvd": {"cve_id": "CVE-2026-1", "risk_score": 50},                              # never checked
            "b::nvd": {"cve_id": "CVE-2026-2", "risk_score": 90},                              # never checked, riskier
            "c::nvd": {"cve_id": "CVE-2026-3", "osv_checked": "2026-10-20"},                   # checked recently
            "d::nvd": {"cve_id": "CVE-2026-4", "osv_checked": "2026-09-01"},                   # check is stale
            "e::nvd": {"cve_id": "CVE-2026-5", "osv_id": "GHSA-x", "osv_fixed_versions": []},  # has a record
        }

    def run_recheck(self, by_key, results, **kw):
        import aggregate as A
        calls = []

        def fetch(cid):
            calls.append(cid)
            return results.get(cid)
        kw.setdefault("max_lookups", 10)
        kw.setdefault("recheck_days", 14)
        kw.setdefault("time_budget_s", 60)
        out = A.recheck_osv(by_key, today=self.TODAY, fetch=fetch, **kw)
        return calls, out

    def test_due_alerts_only_never_checked_first_by_risk(self):
        by = self.alerts()
        calls, (looked, found) = self.run_recheck(by, {"CVE-2026-1": self.REC})
        self.assertEqual(calls, ["CVE-2026-2", "CVE-2026-1", "CVE-2026-4"])
        self.assertEqual((looked, found), (3, 1))
        self.assertEqual(by["a::nvd"]["osv_id"], "CVE-2026-1")
        self.assertEqual(by["a::nvd"]["osv_fixed_versions"], self.REC["osv_fixed_versions"])
        self.assertEqual(by["a::nvd"]["osv_checked"], "2026-10-22")
        # a 404 records the check but invents nothing
        self.assertNotIn("osv_id", by["b::nvd"])
        self.assertEqual(by["b::nvd"]["osv_checked"], "2026-10-22")
        self.assertEqual(by["d::nvd"]["osv_checked"], "2026-10-22")
        self.assertEqual(by["c::nvd"]["osv_checked"], "2026-10-20")
        self.assertEqual(by["e::nvd"], self.alerts()["e::nvd"])

    def test_failed_lookup_is_not_recorded_and_outage_stops_the_pass(self):
        import aggregate as A
        by = {f"k{i}::nvd": {"cve_id": f"CVE-2026-{i}"} for i in range(10)}
        calls, (looked, _) = self.run_recheck(by, {f"CVE-2026-{i}": A.OSV_LOOKUP_FAILED for i in range(10)})
        self.assertEqual(len(calls), 3)           # stops after max_failures
        self.assertEqual(looked, 0)
        self.assertFalse(any("osv_checked" in a for a in by.values()))

    def test_cap_and_skip_keys(self):
        by = self.alerts()
        calls, _ = self.run_recheck(by, {}, max_lookups=1, skip_keys={"b::nvd"})
        self.assertEqual(calls, ["CVE-2026-1"])

    def test_main_restores_osv_for_a_stored_alert_not_resurfaced(self):
        # A board alert whose OSV data was lost and that NVD no longer resurfaces
        lost = {k: v for k, v in TestResurfacedAlertKeepsStoredEnrichment.STORED.items()
                if k not in A_STORED_ONLY}
        lost.update(osv_id=None, osv_fixed_versions=[])
        t = TestResurfacedAlertKeepsStoredEnrichment()
        rec = {"osv_id": "CVE-2026-56095", "osv_fixed_versions": [{"package": None, "ecosystem": None, "fixed": "722363e5"}]}
        out, new, osv = t.run_main([lost], [], osv_result=rec)
        a = out["CVE-2026-56095::nvd"]
        self.assertEqual(new, [])
        osv.assert_called_once_with("CVE-2026-56095")
        self.assertEqual(a["osv_id"], "CVE-2026-56095")
        self.assertEqual(a["osv_fixed_versions"], rec["osv_fixed_versions"])
        self.assertTrue(a["osv_checked"])

    def test_main_new_alert_lookup_is_recorded_once(self):
        t = TestResurfacedAlertKeepsStoredEnrichment()
        out, new, osv = t.run_main([], [t.candidate()], osv_result=None)
        self.assertEqual(len(new), 1)
        osv.assert_called_once_with("CVE-2026-56095")   # not re-queried by the recheck pass
        self.assertTrue(out["CVE-2026-56095::nvd"]["osv_checked"])
        self.assertIsNone(out["CVE-2026-56095::nvd"]["osv_id"])

    def test_resurfaced_alert_keeps_its_check_date(self):
        t = TestResurfacedAlertKeepsStoredEnrichment()
        stored = {k: v for k, v in t.STORED.items() if k not in A_STORED_ONLY}
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date().isoformat()
        stored.update(osv_id=None, osv_fixed_versions=[], osv_checked=today)
        out, _, osv = t.run_main([stored], [t.candidate()])
        osv.assert_not_called()
        self.assertEqual(out["CVE-2026-56095::nvd"]["osv_checked"], today)


class TestNvdTimeBudget(unittest.TestCase):
    """During an NVD brownout every lookup times out (3 x 45 s). Without a
    run-wide budget the watchlist search alone ran ~606 requests / ~487 min,
    so GitHub cancelled the job at its 30-minute timeout before the data
    commit and the whole run (KEV, EPSS, OSV, intel) was lost."""

    def setUp(self):
        import aggregate
        self.A = aggregate
        self.sim = {"t": 0.0, "calls": 0}
        self._saved = (aggregate._nvd_deadline, dict(aggregate._nvd_budget_note))
        self.clock = mock.patch.object(aggregate, "_nvd_clock", lambda: self.sim["t"])
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.A._nvd_deadline, note = self._saved
        self.A._nvd_budget_note.update(note)

    def hang(self, url, headers=None, timeout=30):
        self.sim["calls"] += 1
        self.sim["t"] += timeout
        raise TimeoutError("The read operation timed out")

    def slp(self, s):
        self.sim["t"] += s

    def test_brownout_search_stops_at_budget(self):
        A = self.A
        wl = A.load_watchlist()
        A.start_nvd_budget(1080)
        with mock.patch.dict(os.environ, {"LOOKBACK_DAYS": "4"}), \
             mock.patch.object(A, "http_get_json", side_effect=self.hang), \
             mock.patch.object(A.time, "sleep", side_effect=self.slp), \
             mock.patch("builtins.print"):
            cands = A.fetch_nvd_candidates(wl, "k")
        self.assertEqual(cands, {})
        # the budget can be overrun by at most one in-flight request + retry sleep
        self.assertLessEqual(self.sim["t"], 1080 + 45 + 60)
        self.assertLess(self.sim["calls"], 30)

    def test_budget_reads_env_and_zero_disables(self):
        A = self.A
        with mock.patch.dict(os.environ, {"NVD_TIME_BUDGET_S": "60"}):
            A.start_nvd_budget()
        self.assertFalse(A.nvd_budget_exhausted())
        self.sim["t"] = 61
        with mock.patch("builtins.print"):
            self.assertTrue(A.nvd_budget_exhausted())
        A.start_nvd_budget(0)
        self.sim["t"] = 10 ** 9
        self.assertFalse(A.nvd_budget_exhausted())

    def test_spent_budget_skips_recheck_without_removing(self):
        A = self.A
        alerts = TestRevalidateAffectedPairs().alerts()
        before = {k: dict(v) for k, v in alerts.items()}
        A.start_nvd_budget(1)
        self.sim["t"] = 5
        with mock.patch.object(A, "nvd_query") as q, mock.patch("builtins.print"):
            removed = A.revalidate_affected_pairs(alerts, set(), TestRevalidateAffectedPairs.WL, None,
                                                  sleep=lambda s: None,
                                                  today=__import__("datetime").date(2026, 10, 21), max_n=10)
        q.assert_not_called()
        self.assertFalse(removed)
        self.assertEqual(alerts, before)  # nothing dropped, nothing marked checked


if __name__ == "__main__":
    unittest.main()
