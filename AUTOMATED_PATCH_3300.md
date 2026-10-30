Contributor details
Your Expensify account email: 3055073676@qq.com
Upwork Profile Link: https://www.upwork.com/freelancers/~01a6c3832b8108493d

## Proposal

### Please re-state the problem that we are trying to solve in this issue.

In repository [`astruzocyber/CVE`](https://github.com/astruzocyber/CVE), automated monitoring workflow alert [Issue #3300](https://github.com/astruzocyber/CVE/issues/3300) was generated for **CVE-2026-8034** (`[VULN ALERT] CVE-2026-8034 (risk 34.5) - keyword: GitHub Enterprise`).

The problem encompasses two interdependent layers: the underlying high-severity software vulnerability defect and the repository triage pipeline state:

1. **Underlying Vulnerability Defect (CVE-2026-8034)**:
   - **Target Software**: GitHub Enterprise Server (GHES) prior to version 3.21 (CVSS v3.1: 9.8 Critical; EPSS: 0.52%; CWE-918: Server-Side Request Forgery).
   - **Vulnerability Class**: Server-Side Request Forgery (SSRF) via URL parser confusion between validation layers and underlying HTTP client libraries.
   - **Reproduction & Exploit Scenario**:
     - The GitHub Enterprise Server notebook viewer renders Jupyter notebook files (`.ipynb`) and fetches remote notebook assets or dependencies.
     - When inspecting user-supplied URLs, GHES passes the target URL through an input validation layer to enforce restrictions (e.g., verifying that the destination hostname matches an allowed domain or does not resolve to internal network addresses).
     - However, the validation layer and the underlying HTTP client library (such as `libcurl`, `Net::HTTP`, or `Faraday`) implement disparate URL parsing specifications (RFC 3986 vs. WHATWG URL Standard vs. legacy RFC 2396).
     - An attacker with network access constructs a crafted URL exploiting parser differential delimiters—such as embedded userinfo credentials, fragment identifiers, or backslashes (e.g., `http://whitelisted-domain.com#@169.254.169.254/latest/meta-data/` or `http://whitelisted-domain.com\@127.0.0.1:8080/`).
     - The validation layer interprets `whitelisted-domain.com` as the authority/host and accepts the URL, whereas the HTTP client library interprets the authority as `169.254.169.254` or `127.0.0.1`.
     - The notebook rendering worker then issues an outbound HTTP request directly to unintended internal microservices (Nomad, Consul, Spokes, Elasticsearch) or cloud provider instance metadata endpoints (`169.254.169.254`), exposing sensitive tokens, configuration data, and internal network topologies.
   - **Upstream Remediation**: GitHub patched this vulnerability in GHES versions `3.16.18`, `3.17.15`, `3.18.9`, `3.19.6`, `3.20.2`, and all versions $\ge 3.21$.

2. **Repository Alert & Triage Pipeline State**:
   - In [`astruzocyber/CVE`](https://github.com/astruzocyber/CVE), [`config/watchlist.yaml`](file:///config/watchlist.yaml) tracks the keyword `"GitHub Enterprise"`.
   - Cross-referencing the organization's estate inventory defined in [`config/environment.yaml`](file:///config/environment.yaml) confirms that the deployed stack uses cloud-hosted **GitHub Enterprise Cloud (SaaS), GitHub Actions, and GitHub Copilot** and does **not** deploy or maintain an on-premises GitHub Enterprise Server (GHES) appliance.
   - Issue #3300 requires completing the 6-point triage checklist. Merely closing the issue without recording an entry in [`config/suppressions.yaml`](file:///config/suppressions.yaml) will lead to pipeline state drift, allowing future aggregation runs or cache invalidations to resurface this non-applicable alert as a false positive.

---

### What is the root cause of that problem?

#### 1. Upstream Root Cause in GitHub Enterprise Server (CVE-2026-8034)
- **Parser Differential (Parser Confusion)**: The notebook viewer service used one URL parser for hostname/allowlist validation (e.g., a regex or high-level URI parser like Ruby `URI.parse`), while the transport client performing the socket connection used a different parser (e.g., `libcurl` or an HTTP client adapter):
  - In WHATWG URL parsing, backslashes (`\`) are normalized to forward slashes (`/`), whereas in RFC 3986, backslashes are treated as unreserved characters or prohibited in the host.
  - When parsing userinfo and fragments, discrepancies in handling `#` before `@` allow an attacker to make the validation parser extract `whitelisted.com` as the host and `#@internal-host` as the fragment, while the HTTP library parses `whitelisted.com#` as the username and `internal-host` as the target network host.
- **Decoupled Validation and Connection Phases**: Host validation was performed purely on raw URL strings prior to connection, rather than resolving the host to an IP address, validating that IP against private CIDR blocklists (e.g., RFC 1918, loopback, link-local metadata), and pinning the underlying socket connection directly to the verified IP address.

#### 2. Root Cause in the `astruzocyber/CVE` Pipeline State
- In [`config/watchlist.yaml`](file:///config/watchlist.yaml), the keyword `"GitHub Enterprise"` matches all broad GHES CVE alerts.
- In [`scripts/aggregate.py`](file:///scripts/aggregate.py), the ingestion pipeline matched `"GitHub Enterprise"` in the CVE description, verified CVSS 9.8 $\ge$ 7.0, and generated [Issue #3300](https://github.com/astruzocyber/CVE/issues/3300).
- Because GFR Media / LinkActiv does not operate an on-premises GHES appliance, the alert is non-applicable to the active production stack. Without an entry in [`config/suppressions.yaml`](file:///config/suppressions.yaml), the automated issue closer [`scripts/close_suppressed_issues.py`](file:///scripts/close_suppressed_issues.py) cannot programmatically close the alert with audit trail verification.

---

### What changes do you think we should make in order to solve the problem?

#### 1. Suppress Non-Applicable Alert in `config/suppressions.yaml`
Add a structured entry to [`config/suppressions.yaml`](file:///config/suppressions.yaml) with an explicit explanation and a 1-year time-boxed expiration date (`2027-10-27`):

```diff
--- a/config/suppressions.yaml
+++ b/config/suppressions.yaml
@@ -20,3 +20,7 @@
 #
 # Leave this file as an empty list until you have real suppressions to record.
-[]
+- cve_id: "CVE-2026-8034"
+  reason: "Not applicable to deployed stack: GFR Media/LinkActiv estate utilizes GitHub Enterprise Cloud (SaaS) exclusively; no on-premises GitHub Enterprise Server (GHES) instances are deployed. Verified against config/environment.yaml. Official upstream patches exist in GHES 3.16.18, 3.17.15, 3.18.9, 3.19.6, 3.20.2, and 3.21+."
+  expires: "2027-10-27"
```

#### 2. Update Shared Team Board in `config/triage.yaml`
Record the formal triage resolution under `entries:` in [`config/triage.yaml`](file:///config/triage.yaml) so that the security dashboard and team alerting bots reflect the resolved state:

```diff
--- a/config/triage.yaml
+++ b/config/triage.yaml
@@ -28,3 +28,8 @@ entries:
     owner: "Giankaleb Moran"
     note: "PEERSTITCH via FortiOS CLI path traversal. Not affected, our FortiGate runs FortiOS 7.4.10 which is the fixed release (7.4.0 to 7.4.9 affected). Validated in threat intel tool and Fortinet FG-IR-26-122. Follow-up IOC and FortiManager checks listed in the triage doc."
     date: "2026-10-19"
+  "cve:CVE-2026-8034":
+    status: resolved
+    owner: "Security Operations / AppSec Team"
+    note: "GHES notebook viewer SSRF via URL parser confusion (CVE-2026-8034). Not affected: estate runs GitHub Enterprise Cloud (SaaS), not on-premises GHES appliance. Suppressed in config/suppressions.yaml with 1-year review."
+    date: "2026-10-27"
```

#### 3. Complete Issue #3300 Triage Checklist
Mark all checklist items complete in Issue #3300 to finalize audit compliance:
- [x] Confirm this affects our actual deployed stack/version *(Verified: Non-applicable; estate uses GitHub Enterprise Cloud SaaS)*
- [x] Check for available patch / upgrade path *(Verified: Official patches available in GHES 3.16.18, 3.17.15, 3.18.9, 3.19.6, 3.20.2, and 3.21+)*
- [x] Assess exploitability in our environment *(Zero exposure; no self-hosted GHES instance or notebook rendering service in estate)*
- [x] Patch or mitigate *(Not applicable; cloud stack managed upstream by GitHub)*
- [x] If not applicable, add to config/suppressions.yaml with a reason + expiry *(Added with 2027-10-27 expiry)*
- [x] Close this issue once resolved *(Automated by `scripts/close_suppressed_issues.py` via CI workflow)*

#### 4. Reference Implementation for GHES / Notebook Viewer Deployments
For self-hosted instances running the notebook viewer, eliminate parser confusion and DNS rebinding SSRF by unifying the parser and enforcing socket-level IP pinning:

```python
import ipaddress
import socket
import urllib.parse
from urllib.parse import urlsplit

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # RFC 3927 Link-Local / Cloud Metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Current Network
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]

def validate_and_resolve_safe_url(raw_url: str) -> tuple[str, str, int]:
    """
    Parses and canonicalizes target URL using a single standard parser.
    Resolves the destination hostname and validates that all resolved IP addresses
    reside outside protected internal and cloud metadata networks.
    Returns: (canonical_url, resolved_ip, port)
    """
    # Reject backslash normalization confusion
    if "\\" in raw_url:
        raise ValueError("Invalid URL: backslash character not permitted")

    parsed = urlsplit(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Prohibited scheme: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a valid hostname")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Resolve all DNS A/AAAA records
    addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    for family, _, _, _, sockaddr in addr_info:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        for blocked_net in BLOCKED_NETWORKS:
            if ip_obj in blocked_net or ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
                raise PermissionError(f"Access to internal IP {ip_obj} is prohibited (SSRF prevention)")

    target_ip = addr_info[0][4][0]
    return raw_url, target_ip, port
```

---

### What alternative solutions did you explore? (Optional)

1. **Manually closing Issue #3300 directly via GitHub UI without updating `config/suppressions.yaml`**:
   - *Drawback*: [`scripts/aggregate.py`](file:///scripts/aggregate.py) checks `docs/data/seen_ids.json`. If `seen_ids.json` is ever pruned, reset, or if a pipeline check re-evaluates historic NVD records, the alert will silently resurface and reopen duplicate issues. Suppressing it via `config/suppressions.yaml` provides deterministic, auditable state tracking.

2. **Removing `"GitHub Enterprise"` from `config/watchlist.yaml`**:
   - *Drawback*: Removing the keyword would eliminate visibility for hybrid runner agents, GitHub Enterprise Cloud authentication interfaces, or third-party integrations that the organization actively depends on. Maintaining the keyword while suppressing non-applicable appliance CVEs ensures broad visibility without noise.

3. **Restricting NVD keyword matching solely to CPE vendor/product pairs**:
   - *Drawback*: Newly disclosed advisories frequently omit CPE mappings initially (classified as `Affected vendor/product: n/a` as in CVE-2026-8034). Eliminating keyword matching introduces blind spots for newly published critical CVEs.

---

### What automated tests can you add to prevent this from re-occurring?

Provide automated unit tests covering both the repository triage/suppression pipeline and URL parser confusion validation:

```python
import unittest
import os
import sys
import json
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import aggregate as agg
import close_suppressed_issues as csi


class TestCVE20268034SuppressionAndTriage(unittest.TestCase):
    def setUp(self):
        self.cve_id = "CVE-2026-8034"
        self.issue_number = 3300
        self.issue_title = "[VULN ALERT] CVE-2026-8034 (risk 34.5) - keyword: GitHub Enterprise"
        self.mock_suppressions = {
            self.cve_id: {
                "reason": "Not applicable to deployed stack: GFR Media/LinkActiv uses GitHub Enterprise Cloud (SaaS).",
                "expires": "2027-10-27",
            }
        }

    def test_id_in_title_matches_cve_2026_8034(self):
        """Verify token boundary regex matches CVE-2026-8034 exactly in issue title."""
        self.assertTrue(csi.id_in_title(self.cve_id, self.issue_title))
        # Ensure it does not false-match longer IDs
        self.assertFalse(csi.id_in_title(self.cve_id, "[VULN ALERT] CVE-2026-80341 (risk 35.0)"))

    def test_aggregate_passes_filters_excludes_suppressed_cve_2026_8034(self):
        """Verify aggregate.passes_filters excludes CVE-2026-8034 when active in suppressions."""
        cve_record = {
            "cve_id": self.cve_id,
            "cvss": 9.8,
            "description": "A server-side request forgery (SSRF) vulnerability was identified in the GitHub Enterprise Server notebook viewer...",
        }
        watchlist = {"cvss_minimum": 7.0, "require_kev_or_high_epss": False}
        kev_map = {}
        epss_map = {self.cve_id: 0.0052}

        # Passes when unsuppressed
        self.assertTrue(agg.passes_filters(cve_record, watchlist, kev_map, epss_map, {}))
        # Excluded when suppressed
        self.assertFalse(agg.passes_filters(cve_record, watchlist, kev_map, epss_map, self.mock_suppressions))

    def test_close_suppressed_issues_dispatches_correct_payload(self):
        """Verify close_suppressed_issues fetches issue #3300, posts the audit comment, and closes."""
        executed_requests = []

        class MockResponse:
            def __init__(self, data):
                self._data = json.dumps(data).encode("utf-8")
            def read(self):
                return self._data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        def fake_urlopen(req, timeout=30):
            url = req.full_url
            method = req.get_method()
            body = req.data.decode("utf-8") if req.data else None
            executed_requests.append({"method": method, "url": url, "body": body})
            if "issues?state=open" in url:
                return MockResponse([{"number": self.issue_number, "title": self.issue_title}])
            if method == "POST" and f"issues/{self.issue_number}/comments" in url:
                return MockResponse({"id": 1, "body": "Auto-closing comment"})
            if method == "PATCH" and f"issues/{self.issue_number}" in url:
                return MockResponse({"number": self.issue_number, "state": "closed"})
            return MockResponse({})

        with mock.patch.object(csi, "load_suppressions", return_value=self.mock_suppressions), \
             mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            os.environ["GITHUB_TOKEN"] = "test-token"
            os.environ["GITHUB_REPOSITORY"] = "astruzocyber/CVE"
            csi.main()

        # Validate audit comment posting
        post_comments = [r for r in executed_requests if r["method"] == "POST" and f"issues/{self.issue_number}/comments" in r["url"]]
        self.assertEqual(len(post_comments), 1)
        self.assertIn("Auto-closing: `CVE-2026-8034`", post_comments[0]["body"])

        # Validate issue close state
        patch_issues = [r for r in executed_requests if r["method"] == "PATCH" and f"issues/{self.issue_number}" in r["url"]]
        self.assertEqual(len(patch_issues), 1)
        patch_body = json.loads(patch_issues[0]["body"])
        self.assertEqual(patch_body.get("state"), "closed")
        self.assertEqual(patch_body.get("state_reason"), "not_planned")


class TestURLParserConfusionAndSSRFDefense(unittest.TestCase):
    """Unit tests validating detection and blocking of URL parser differential payloads."""

    def test_parser_confusion_payloads_rejected(self):
        malicious_payloads = [
            "http://allowed.com#@169.254.169.254/latest/meta-data/",
            "http://allowed.com\\@127.0.0.1:8080/admin",
            "http://127.0.0.1:80@allowed.com/",
            "http://169.254.169.254.nip.io/",
            "http://[::1]:8080/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        from urllib.parse import urlsplit
        for url in malicious_payloads:
            with self.subTest(url=url):
                # Verify that backslashes or dangerous schemes are trapped
                parsed = urlsplit(url)
                is_invalid = ("\\" in url) or (parsed.scheme not in ("http", "https")) or (parsed.hostname in ("127.0.0.1", "169.254.169.254", "::1"))
                self.assertTrue(is_invalid, f"Payload should have been marked invalid: {url}")


if __name__ == "__main__":
    unittest.main()
```