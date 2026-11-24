import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import deb_builder


class RoothidePostinstTests(unittest.TestCase):
    def test_entitlements_contains_all_required_keys(self):
        for key in (
            "com.apple.private.security.no-sandbox",
            "com.apple.private.security.storage.AppBundles",
            "com.apple.private.security.storage.AppDataContainers",
            "platform-application",
        ):
            self.assertIn(key, deb_builder.ROOTHIDE_ENTITLEMENTS)

    def test_entitlements_is_valid_plist(self):
        import plistlib

        data = deb_builder.ROOTHIDE_ENTITLEMENTS.encode("utf-8")
        parsed = plistlib.loads(data)
        self.assertTrue(parsed["com.apple.private.security.no-sandbox"])
        self.assertTrue(parsed["platform-application"])

    def test_postinst_references_ldid_and_patches(self):
        text = deb_builder.ROOTHIDE_POSTINST
        self.assertIn("/usr/bin/ldid", text)
        self.assertIn("/usr/lib/DynamicPatches/AutoPatches.dylib", text)
        self.assertIn("$SERVER_BIN.roothidepatch", text)
        self.assertIn("$AGENT.roothidepatch", text)
        self.assertIn("SERVER_BIN=/usr/sbin/frida-server", text)
        self.assertIn("AGENT=/usr/lib/frida-1.0/frida-agent.dylib", text)

    def test_postinst_does_not_abort_without_ldid(self):
        text = deb_builder.ROOTHIDE_POSTINST
        self.assertIn('if [ -z "$LDID" ]', text)
        self.assertIn("skipping", text)

    def test_postinst_restarts_daemon(self):
        text = deb_builder.ROOTHIDE_POSTINST
        self.assertIn("launchctl unload", text)
        self.assertIn("launchctl load", text)

    def test_postinst_embeds_entitlements(self):
        text = deb_builder.ROOTHIDE_POSTINST
        self.assertIn("com.apple.private.security.no-sandbox", text)
        self.assertIn("PLIST", text)


class BuildVariantsTests(unittest.TestCase):
    def test_roothide_full_differs_from_roothide_plain(self):
        import io
        import tarfile

        buf = io.BytesIO()
        tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
        info = tarfile.TarInfo("./control")
        payload = b"Package: x\nVersion: 1\nArchitecture: arm64\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        tf.close()

        plain = deb_builder.transform_control(buf.getvalue(), "1", "iphoneos-arm64e", None)
        full = deb_builder.transform_control(
            buf.getvalue(), "1", "iphoneos-arm64e", None, inject_postinst=True
        )

        plain_names = {m.name for m, _ in deb_builder.iter_tar(plain)}
        full_names = {m.name for m, _ in deb_builder.iter_tar(full)}

        self.assertNotIn("./postinst", plain_names)
        self.assertIn("./postinst", full_names)

    def test_postinst_mode_is_executable(self):
        import io
        import tarfile

        buf = io.BytesIO()
        tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
        info = tarfile.TarInfo("./control")
        payload = b"Package: x\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        tf.close()

        out = deb_builder.transform_control(
            buf.getvalue(), "1", "iphoneos-arm64e", None, inject_postinst=True
        )
        for member, _body in deb_builder.iter_tar(out):
            if member.name.lstrip("./") == "postinst":
                self.assertEqual(member.mode, 0o755)
                return
        self.fail("postinst not found")


if __name__ == "__main__":
    unittest.main(verbosity=2)