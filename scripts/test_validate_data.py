"""
Unit tests for validate_data.py -- the sole automated CI regression guard
protecting this project's live dashboard (see validate_data.py's own module
docstring). Across 68 prior cycles this file itself had zero test coverage:
every change to its check_*() functions (including this cycle's own
by_severity/by_source partition cross-check) was validated only by ad hoc
manual runs against real production data, meaning a subtle logic bug in the
validator itself (e.g. an inverted condition that always passes, or a
mismatch check that silently no-ops on the wrong key) could ship completely
unnoticed and defeat the very safety net it exists to provide.

Deliberately stdlib-only (unittest + tempfile), zero network calls, exercises
each check_*() function against synthetic docs/ trees built in a temp
directory so real production data is never required or touched. Wired into
the same `python3 -m unittest discover -s scripts -p 'test_*.py'` invocation
already gating every cycle's validation step -- no new CI config needed.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _make_docs_tree(root, alerts=None, stats=None, trend_lines=None,
                     app_js="", index_html="", feed_json='{}', feed_xml="<?xml version='1.0'?><rss></rss>"):
    docs = Path(root) / "docs"
    (docs / "data" / "history").mkdir(parents=True, exist_ok=True)
    if alerts is not None:
        (docs / "data" / "alerts.json").write_text(json.dumps(alerts))
    if stats is not None:
        (docs / "data" / "stats.json").write_text(json.dumps(stats))
    if trend_lines is not None:
        (docs / "data" / "history" / "trend.csv").write_text("\n".join(trend_lines))
    (docs / "app.js").write_text(app_js)
    (docs / "index.html").write_text(index_html)
    (docs / "feed.json").write_text(feed_json)
    (docs / "feed.xml").write_text(feed_xml)
    return docs


class ValidateDataTestBase(unittest.TestCase):
    """Reloads validate_data.py's module-level ROOT/DOCS + error/warning
    lists against a fresh temp docs/ tree per test, since the real module
    resolves paths relative to its own file location at import time and
    accumulates errors/warnings in module-level lists across calls."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # scripts/ subdir so `from aggregate import HISTORY_CSV_HEADER` (used by
        # check_trend_csv) still resolves via the real sys.path insert below.
        (Path(self.tmpdir) / "scripts").mkdir(exist_ok=True)
        import shutil
        shutil.copy(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "aggregate.py"),
            os.path.join(self.tmpdir, "scripts", "aggregate.py"),
        )
        import importlib
        global validate_data
        if "validate_data" in sys.modules:
            del sys.modules["validate_data"]
        import validate_data as vd
        validate_data = vd
        validate_data.ROOT = Path(self.tmpdir)
        validate_data.DOCS = Path(self.tmpdir) / "docs"
        sys.path.insert(0, str(Path(self.tmpdir) / "scripts"))
        validate_data.errors.clear()
        validate_data.warnings.clear()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestCheckAlertsJson(ValidateDataTestBase):
    def _valid_alert(self, **overrides):
        a = {
            "cve_id": "CVE-2026-1234", "description": "test", "cvss_score": 5.0,
            "risk_score": 50, "epss_score": 0.1, "kev": False, "source": "nvd",
            "first_seen": "2026-01-01T00:00:00Z", "severity": None,
        }
        a.update(overrides)
        return a

    def test_valid_alerts_pass(self):
        _make_docs_tree(self.tmpdir, alerts=[self._valid_alert()])
        validate_data.check_alerts_json()
        self.assertEqual(validate_data.errors, [])

    def test_duplicate_cve_id_fails(self):
        _make_docs_tree(self.tmpdir, alerts=[self._valid_alert(), self._valid_alert()])
        validate_data.check_alerts_json()
        self.assertTrue(any("duplicate cve_id" in e for e in validate_data.errors))

    def test_risk_score_out_of_range_fails(self):
        _make_docs_tree(self.tmpdir, alerts=[self._valid_alert(risk_score=150)])
        validate_data.check_alerts_json()
        self.assertTrue(any("out of expected 0-100 range" in e for e in validate_data.errors))

    def test_epss_out_of_range_fails(self):
        _make_docs_tree(self.tmpdir, alerts=[self._valid_alert(epss_score=1.5)])
        validate_data.check_alerts_json()
        self.assertTrue(any("out of expected 0-1 range" in e for e in validate_data.errors))

    def test_missing_required_key_fails(self):
        alert = self._valid_alert()
        del alert["kev"]
        _make_docs_tree(self.tmpdir, alerts=[alert])
        validate_data.check_alerts_json()
        self.assertTrue(any("missing required keys" in e for e in validate_data.errors))

    def test_non_list_root_fails(self):
        _make_docs_tree(self.tmpdir, alerts={"not": "a list"})
        validate_data.check_alerts_json()
        self.assertTrue(any("must be a list" in e for e in validate_data.errors))


class TestCheckStatsJson(ValidateDataTestBase):
    def _base_stats(self, **overrides):
        s = {
            "generated_at": "2026-01-01T00:00:00Z",
            "total_alerts": 3,
            "kev_count": 0,
            "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "unknown": 0},
            "by_source": {"nvd": 3},
        }
        s.update(overrides)
        return s

    def test_valid_stats_pass(self):
        alerts = [{"cve_id": f"CVE-2026-{i}"} for i in range(3)]
        _make_docs_tree(self.tmpdir, alerts=alerts, stats=self._base_stats())
        validate_data.check_stats_json()
        self.assertEqual(validate_data.errors, [])

    def test_missing_required_key_fails(self):
        stats = self._base_stats()
        del stats["by_source"]
        _make_docs_tree(self.tmpdir, alerts=[], stats=stats)
        validate_data.check_stats_json()
        self.assertTrue(any("missing required keys" in e for e in validate_data.errors))

    def test_total_alerts_mismatch_with_alerts_json_fails(self):
        alerts = [{"cve_id": "CVE-2026-1"}]
        _make_docs_tree(self.tmpdir, alerts=alerts, stats=self._base_stats(total_alerts=99))
        validate_data.check_stats_json()
        self.assertTrue(any("total_alerts" in e and "!=" in e for e in validate_data.errors))

    def test_by_severity_sum_mismatch_fails(self):
        alerts = [{"cve_id": f"CVE-2026-{i}"} for i in range(3)]
        stats = self._base_stats(by_severity={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0})
        _make_docs_tree(self.tmpdir, alerts=alerts, stats=stats)
        validate_data.check_stats_json()
        self.assertTrue(any("sum(by_severity.values())" in e for e in validate_data.errors))

    def test_by_source_sum_mismatch_fails(self):
        alerts = [{"cve_id": f"CVE-2026-{i}"} for i in range(3)]
        stats = self._base_stats(by_source={"nvd": 1, "ghsa": 1})
        _make_docs_tree(self.tmpdir, alerts=alerts, stats=stats)
        validate_data.check_stats_json()
        self.assertTrue(any("sum(by_source.values())" in e for e in validate_data.errors))

    def test_partition_checks_tolerate_missing_maps(self):
        # Missing by_severity/by_source already fails the required-keys check;
        # this test just confirms the new partition logic doesn't crash if
        # one is present but malformed (not a dict) instead of raising.
        alerts = [{"cve_id": "CVE-2026-1"}]
        stats = self._base_stats(total_alerts=1, by_severity="not-a-dict")
        _make_docs_tree(self.tmpdir, alerts=alerts, stats=stats)
        validate_data.check_stats_json()  # must not raise


class TestCheckTrendCsv(ValidateDataTestBase):
    def test_missing_file_warns_not_fails(self):
        _make_docs_tree(self.tmpdir)
        validate_data.check_trend_csv()
        self.assertEqual(validate_data.errors, [])
        self.assertTrue(any("missing" in w for w in validate_data.warnings))

    def test_correct_header_passes(self):
        from aggregate import HISTORY_CSV_HEADER
        _make_docs_tree(self.tmpdir, trend_lines=[HISTORY_CSV_HEADER, "2026-01-01,1,0,0,0,0.1,10,0,1"])
        validate_data.check_trend_csv()
        self.assertEqual(validate_data.errors, [])

    def test_wrong_header_fails(self):
        _make_docs_tree(self.tmpdir, trend_lines=["totally,wrong,header", "1,2,3"])
        validate_data.check_trend_csv()
        self.assertTrue(any("header mismatch" in e for e in validate_data.errors))

    def test_row_with_more_columns_than_header_fails(self):
        from aggregate import HISTORY_CSV_HEADER
        extra_row = "2026-01-01," + ",".join(["x"] * (len(HISTORY_CSV_HEADER.split(",")) + 2))
        _make_docs_tree(self.tmpdir, trend_lines=[HISTORY_CSV_HEADER, extra_row])
        validate_data.check_trend_csv()
        self.assertTrue(any("more than header's" in e for e in validate_data.errors))

    def test_row_with_fewer_columns_is_tolerated(self):
        from aggregate import HISTORY_CSV_HEADER
        _make_docs_tree(self.tmpdir, trend_lines=[HISTORY_CSV_HEADER, "2026-01-01,1,0,0"])
        validate_data.check_trend_csv()
        self.assertEqual(validate_data.errors, [])


class TestCheckJsHtmlConsistency(ValidateDataTestBase):
    def test_all_ids_resolve_passes(self):
        _make_docs_tree(
            self.tmpdir,
            app_js='document.getElementById("search"); document.getElementById("kev-filter");',
            index_html='<input id="search"><select id="kev-filter"></select>',
        )
        validate_data.check_js_html_consistency()
        self.assertEqual(validate_data.errors, [])

    def test_missing_id_fails(self):
        _make_docs_tree(
            self.tmpdir,
            app_js='document.getElementById("does-not-exist");',
            index_html='<input id="search">',
        )
        validate_data.check_js_html_consistency()
        self.assertTrue(any("does-not-exist" in e for e in validate_data.errors))


class TestCheckFeeds(ValidateDataTestBase):
    def test_valid_feeds_pass(self):
        _make_docs_tree(self.tmpdir, feed_json="[]", feed_xml="<?xml version='1.0'?><rss></rss>")
        validate_data.check_feeds()
        self.assertEqual(validate_data.errors, [])

    def test_invalid_feed_json_fails(self):
        _make_docs_tree(self.tmpdir, feed_json="{not valid json")
        validate_data.check_feeds()
        self.assertTrue(any("invalid JSON" in e for e in validate_data.errors))

    def test_missing_xml_declaration_fails(self):
        _make_docs_tree(self.tmpdir, feed_xml="<rss>no declaration</rss>")
        validate_data.check_feeds()
        self.assertTrue(any("does not look like valid XML" in e for e in validate_data.errors))


if __name__ == "__main__":
    unittest.main()
