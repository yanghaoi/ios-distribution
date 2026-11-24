import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import check_agent_layout


class TokenListTests(unittest.TestCase):
    def test_tokens_cover_both_layouts(self):
        tokens = check_agent_layout.TOKENS
        self.assertIn(b"frida-1.0", tokens)
        self.assertIn(b"/usr/lib/frida", tokens)
        self.assertIn(b"frida-agent.dylib", tokens)

    def test_tokens_cover_both_protocols(self):
        tokens = check_agent_layout.TOKENS
        self.assertIn(b"re.frida.", tokens)
        self.assertIn(b"re.frnda.", tokens)

    def test_tokens_are_ascii(self):
        for token in check_agent_layout.TOKENS:
            token.decode("ascii")

    def test_layout_tokens_are_mutually_distinct(self):
        tokens = check_agent_layout.TOKENS
        self.assertEqual(len(tokens), len(set(tokens)))


class ScanBehaviourTests(unittest.TestCase):
    def test_scan_rejects_non_deb_input(self):
        with self.assertRaises(ValueError):
            check_agent_layout.scan(os.devnull)


if __name__ == "__main__":
    unittest.main(verbosity=2)