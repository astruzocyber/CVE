#!/usr/bin/env python3
"""Unit tests for scripts/close_suppressed_issues.py.

Mocks urllib.request.urlopen entirely -- no real network calls, no GitHub
token required. Focuses on the core decision logic: which open issues get
closed given a suppressions map, and that non-matching issues are left alone.
"""
import json
import os
import sys
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import close_suppressed_issues as csi  # noqa: E402


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestCloseSuppressedIssues(unittest.TestCase):
    def test_no_suppressions_no_api_calls(self):
        with mock.patch.object(csi, "load_suppressions", return_value={}), \
             mock.patch("urllib.request.urlopen") as mock_urlopen:
            os.environ["GITHUB_TOKEN"] = "x"
            os.environ["GITHUB_REPOSITORY"] = "astruzocyber/CVE"
            csi.main()
            mock_urlopen.assert_not_called()

    def test_matching_open_issue_is_closed(self):
        suppressions = {"CVE-2099-99999": {"reason": "not applicable", "expires": None}}
        open_issues = [
            {"number": 42, "title": "[VULN ALERT] CVE-2099-99999 (risk 30.0) - wordpress/wordpress"},
            {"number": 43, "title": "[VULN ALERT] CVE-2099-11111 (risk 20.0) - php/php"},
        ]

        call_log = []

        def fake_urlopen(req, timeout=30):
            url = req.full_url
            method = req.get_method()
            call_log.append((method, url))
            if "issues?state=open" in url:
                return FakeResponse(open_issues if "page=1" in url else [])
            if method == "POST" and "/comments" in url:
                return FakeResponse({"id": 1})
            if method == "PATCH":
                return FakeResponse({"state": "closed"})
            return FakeResponse({})

        with mock.patch.object(csi, "load_suppressions", return_value=suppressions), \
             mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            os.environ["GITHUB_TOKEN"] = "x"
            os.environ["GITHUB_REPOSITORY"] = "astruzocyber/CVE"
            csi.main()

        patched = [c for c in call_log if c[0] == "PATCH"]
        self.assertEqual(len(patched), 1)
        self.assertIn("issues/42", patched[0][1])
        # Issue 43 (no matching suppression) must never be PATCHed.
        self.assertFalse(any("issues/43" in c[1] for c in patched))

    def test_shorter_id_does_not_close_longer_id_issue(self):
        # Real collision on the board: CVE-2025-5949 vs CVE-2025-59494.
        suppressions = {"CVE-2025-5949": {"reason": "n/a", "expires": None}}
        open_issues = [
            {"number": 50, "title": "[VULN ALERT] CVE-2025-59494 (risk 40.0) - microsoft/azure"},
            {"number": 51, "title": "[VULN ALERT] CVE-2025-5949 [KEV] (risk 60.0) - foo/bar"},
        ]
        patched = []

        def fake_urlopen(req, timeout=30):
            url = req.full_url
            if "issues?state=open" in url:
                return FakeResponse(open_issues if "page=1" in url else [])
            if req.get_method() == "PATCH":
                patched.append(url)
                return FakeResponse({"state": "closed"})
            return FakeResponse({"id": 1})

        with mock.patch.object(csi, "load_suppressions", return_value=suppressions), \
             mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            os.environ["GITHUB_TOKEN"] = "x"
            os.environ["GITHUB_REPOSITORY"] = "astruzocyber/CVE"
            csi.main()

        self.assertEqual(len(patched), 1)
        self.assertTrue(patched[0].endswith("issues/51"))

    def test_issue_beyond_2000_open_is_still_closed(self):
        # 2399 open vulnerability-alert issues (Oct 2026): the oldest ones sit
        # past page 20 of the newest-first listing and must still be checked.
        import re as _re
        suppressions = {"CVE-2099-77777": {"reason": "n/a", "expires": None}}
        patched = []

        def fake_urlopen(req, timeout=30):
            url = req.full_url
            if "issues?state=open" in url:
                page = int(_re.search(r"[?&]page=(\d+)", url).group(1))
                if page <= 24:
                    return FakeResponse([{"number": page * 1000 + i,
                                          "title": f"[VULN ALERT] CVE-2098-{page:02d}{i:03d}"}
                                         for i in range(100)])
                return FakeResponse([{"number": 7, "title": "[VULN ALERT] CVE-2099-77777 (risk 9)"}])
            if req.get_method() == "PATCH":
                patched.append(url)
                return FakeResponse({"state": "closed"})
            return FakeResponse({"id": 1})

        with mock.patch.object(csi, "load_suppressions", return_value=suppressions), \
             mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            os.environ["GITHUB_TOKEN"] = "x"
            os.environ["GITHUB_REPOSITORY"] = "astruzocyber/CVE"
            csi.main()

        self.assertEqual(len(patched), 1)
        self.assertTrue(patched[0].endswith("issues/7"))

    def test_id_in_title_token_boundaries(self):
        self.assertTrue(csi.id_in_title("CVE-2025-5949", "[VULN ALERT] CVE-2025-5949 - x"))
        self.assertTrue(csi.id_in_title("CVE-2025-5949", "[VULN ALERT] CVE-2025-5949"))
        self.assertFalse(csi.id_in_title("CVE-2025-5949", "[VULN ALERT] CVE-2025-59494 - x"))
        self.assertFalse(csi.id_in_title("CVE-2025-1281", "[VULN ALERT] CVE-2025-12813 (risk 1)"))
        self.assertTrue(csi.id_in_title("GHSA-abcd-efgh-ijkl", "[VULN ALERT] GHSA-abcd-efgh-ijkl - pip/x"))


if __name__ == "__main__":
    unittest.main()
