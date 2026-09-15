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


if __name__ == "__main__":
    unittest.main()
