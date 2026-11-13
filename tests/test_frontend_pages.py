"""
Runs tests/frontend_cases.py in its own interpreter.

The frontend and the backend both call their package "app", and the test
runner imports the backend's first. The frontend cases therefore get a fresh
process with only the frontend on sys.path. Their output is shown on failure.
"""

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FrontendCasesTest(unittest.TestCase):
    def test_frontend_cases_pass(self):
        proc = subprocess.run(
            [sys.executable, "-W", "error::UserWarning", "-m", "unittest", "tests.frontend_cases"],
            cwd=ROOT, capture_output=True, text=True, timeout=240, check=False,
        )
        output = proc.stderr[-6000:]
        self.assertEqual(proc.returncode, 0, output)
        ran = re.search(r"Ran (\d+) tests?", proc.stderr)
        self.assertIsNotNone(ran, output)
        self.assertGreater(int(ran.group(1)), 50, output)
        self.assertNotIn("skipped", proc.stderr, output)


if __name__ == "__main__":
    unittest.main()
