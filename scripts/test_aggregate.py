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
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aggregate import (
    composite_risk_score,
    parse_cvss_v3_vector_string,
    extract_cwe_nvd,
    extract_cwe_ghsa,
    unique_key,
    compute_stats,
    build_final_entry,
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


if __name__ == "__main__":
    unittest.main()
