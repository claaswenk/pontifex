import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The frontend and the backend both call their package "app", so the frontend is
# exercised in its own interpreter with only its own paths on sys.path.
_SCRIPT = r"""
import json, os, sys
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "frontend")]
os.environ["BACKEND_FRONTEND_SECRET"] = "f" * 40
from app import create_app

client = create_app().test_client()
out = {}
for path in ("/", "/devices", "/account", "/health", "/does-not-exist"):
    r = client.get(path)
    out[path] = {
        "status": r.status_code,
        "location": r.headers.get("Location"),
        "csp": r.headers.get("Content-Security-Policy"),
        "body": r.get_data(as_text=True),
    }
print(json.dumps(out))
"""


class FrontendPagesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            [sys.executable, "-c", f"ROOT = {ROOT!r}\n{_SCRIPT}"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr[-2000:])
        cls.pages = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_root_redirects_to_devices(self):
        self.assertEqual(self.pages["/"]["status"], 302)
        self.assertTrue(self.pages["/"]["location"].endswith("/devices"))

    def test_devices_page_shows_status_in_words_not_only_colour(self):
        body = self.pages["/devices"]["body"]
        self.assertEqual(self.pages["/devices"]["status"], 200)
        self.assertIn("status--online", body)
        self.assertIn("status--offline", body)
        self.assertIn("Online", body)
        self.assertIn("Offline", body)

    def test_pages_are_marked_as_preview(self):
        for path in ("/devices", "/account"):
            self.assertIn("Preview.", self.pages[path]["body"], path)

    def test_navigation_marks_the_current_page(self):
        self.assertIn('href="/devices" aria-current="page"', self.pages["/devices"]["body"])
        self.assertIn('href="/account" aria-current="page"', self.pages["/account"]["body"])

    def test_no_inline_styles_or_scripts_that_the_csp_would_block(self):
        for path in ("/devices", "/account"):
            body = self.pages[path]["body"].lower()
            self.assertNotIn("<script", body, path)
            self.assertNotIn("style=", body, path)
            self.assertNotIn("onclick", body, path)

    def test_security_headers_stay_on_every_page(self):
        for path, page in self.pages.items():
            self.assertIn("default-src 'none'", page["csp"] or "", path)

    def test_health_is_unchanged(self):
        self.assertEqual(json.loads(self.pages["/health"]["body"]),
                         {"status": "healthy", "service": "pontifex-frontend"})


if __name__ == "__main__":
    unittest.main()
