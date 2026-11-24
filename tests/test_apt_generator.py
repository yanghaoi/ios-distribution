import hashlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import apt_generator


SAMPLE_CONTROL = """Package: re.frida.server
Version: 17.24.3+roothide1
Architecture: iphoneos-arm64e
Maintainer: Ole André Vadla Ravnås <oleavr@nowsecure.com>
Pre-Depends: rootless-compat (>= 0.9)
Conflicts: re.frida.server64
Section: Development
Priority: optional
Homepage: https://frida.re/
Description: Observe and reprogram running programs.
"""


class PoolPathTests(unittest.TestCase):
    def test_prefix_uses_first_letter(self):
        prefix, name = apt_generator.pool_path(
            "re.frida.server", "17.24.3", "iphoneos-arm64e"
        )
        self.assertEqual(prefix, "pool/main/r/re.frida.server")
        self.assertEqual(name, "re.frida.server_17.24.3_iphoneos-arm64e.deb")


class StanzaTests(unittest.TestCase):
    def test_stanza_contains_required_fields(self):
        stanza = apt_generator.build_packages_stanza(
            SAMPLE_CONTROL,
            "pool/main/r/re.frida.server/re.frida.server_17.24.3+roothide1_iphoneos-arm64e.deb",
            23469928,
            "d6eb27643fcb49be16b1ab7bd5c2b4807591e1f58f3b5f2f24fcfae60ab96907",
            "e024614f36b52aa0f4b5bc06f6a30397",
            "acb08fe8b642a4f024782b177055e84596f2bb2b",
        )
        fields = dict(apt_generator.parse_stanza(stanza))
        self.assertEqual(fields["Package"], "re.frida.server")
        self.assertEqual(fields["Architecture"], "iphoneos-arm64e")
        self.assertEqual(fields["Size"], "23469928")
        self.assertEqual(
            fields["Filename"],
            "pool/main/r/re.frida.server/re.frida.server_17.24.3+roothide1_iphoneos-arm64e.deb",
        )
        self.assertEqual(
            fields["SHA256"],
            "d6eb27643fcb49be16b1ab7bd5c2b4807591e1f58f3b5f2f24fcfae60ab96907",
        )

    def test_filename_is_repo_relative_not_absolute(self):
        stanza = apt_generator.build_packages_stanza(
            SAMPLE_CONTROL, "pool/main/r/x.deb", 1, "a" * 64, "b" * 32, "c" * 40
        )
        filename = dict(apt_generator.parse_stanza(stanza))["Filename"]
        self.assertFalse(filename.startswith("/"))
        self.assertFalse(filename.startswith("http"))


class ReleaseTests(unittest.TestCase):
    def test_release_lists_architectures(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "dists", "stable", "main", "binary-iphoneos-arm64e")
            os.makedirs(base)
            with open(os.path.join(base, "Packages"), "wb") as f:
                f.write(b"Package: x\n")
            cfg = {
                "apt": {
                    "origin": "O",
                    "label": "L",
                    "description": "D",
                }
            }
            text = apt_generator.render_release(tmp, "stable", "main", cfg)
            self.assertIn("Architectures: iphoneos-arm64e", text)
            self.assertIn("main/binary-iphoneos-arm64e/Packages", text)
            self.assertNotIn("Architectures: iphoneos-arm64 \n", text)

    def test_release_hashes_match_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "dists", "stable", "main", "binary-iphoneos-arm64")
            os.makedirs(base)
            payload = b"Package: x\nVersion: 1\n"
            target = os.path.join(base, "Packages")
            with open(target, "wb") as f:
                f.write(payload)

            cfg = {"apt": {"origin": "O", "label": "L", "description": "D"}}
            text = apt_generator.render_release(tmp, "stable", "main", cfg)

            expected = hashlib.sha256(payload).hexdigest()
            self.assertIn(expected, text)
            size = str(len(payload))
            self.assertIn(size, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)