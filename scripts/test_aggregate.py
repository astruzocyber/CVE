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
import os
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


if __name__ == "__main__":
    unittest.main()
