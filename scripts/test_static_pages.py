"""docs/404.html is served by GitHub Pages for ANY missing path, at that path
(e.g. /CVE/a/b/old-link). Relative refs ("style.css", "./") then resolve
under the missing directory: the page renders unstyled and "Return to the
dashboard" points at another 404. Local refs must be root-absolute (/CVE/...)."""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
SITE_PREFIX = "/CVE/"


class _Refs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value is not None:
                self.refs.append((tag, name, value))


class NotFoundPageTest(unittest.TestCase):
    def test_local_refs_are_root_absolute(self):
        p = _Refs()
        p.feed((DOCS / "404.html").read_text(encoding="utf-8"))
        self.assertTrue(p.refs)
        for tag, attr, value in p.refs:
            if re.match(r"^(data:|https?:|mailto:|#)", value):
                continue
            with self.subTest(tag=tag, attr=attr, value=value):
                self.assertTrue(value.startswith(SITE_PREFIX), f"{tag}[{attr}]={value!r} is relative")
                # and the target exists in docs/
                rel = value[len(SITE_PREFIX):]
                self.assertTrue(rel == "" or (DOCS / rel).exists(), f"{value} not in docs/")


if __name__ == "__main__":
    unittest.main()
