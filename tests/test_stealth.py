import io
import os
import sys
import tarfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import deb_builder


class StealthPatchTests(unittest.TestCase):
    def test_patch_renames_dbus_interfaces(self):
        payload = b"re.frida.AgentSession re.frida.HostSession /re/frida/Agent"
        out, n = deb_builder.apply_stealth_patch(payload)
        self.assertNotIn(b"re.frida.", out)
        self.assertIn(b"re.frnda.AgentSession", out)
        self.assertIn(b"/re/frnda/Agent", out)
        self.assertEqual(n, 3)

    def test_patch_renames_rpc_prefix(self):
        out, n = deb_builder.apply_stealth_patch(b"'frida:rpc'")
        self.assertEqual(out, b"'frnda:rpc'")
        self.assertEqual(n, 1)

    def test_patch_preserves_length(self):
        payload = b"x" * 100 + b"re.frida.AgentSession" + b"y" * 50
        out, _ = deb_builder.apply_stealth_patch(payload)
        self.assertEqual(len(out), len(payload))

    def test_patch_is_idempotent_safe(self):
        payload = b"re.frida.BusSession"
        once, _ = deb_builder.apply_stealth_patch(payload)
        twice, n = deb_builder.apply_stealth_patch(once)
        self.assertEqual(once, twice)
        self.assertEqual(n, 0)

    def test_no_frida_prefix_left(self):
        payload = b"re.frida.AgentController re.frida.AgentMessageSink frida:rpc"
        out, _ = deb_builder.apply_stealth_patch(payload)
        self.assertEqual(out.count(b"re.frida."), 0)
        self.assertEqual(out.count(b"frida:rpc"), 0)


class PlistTests(unittest.TestCase):
    def test_plist_has_label_and_port(self):
        text = deb_builder.render_launchd_plist(
            "re.frida.stealth", "/usr/sbin/frida-server-stealth", 27043
        )
        import plistlib

        d = plistlib.loads(text.encode("utf-8"))
        self.assertEqual(d["Label"], "re.frida.stealth")
        self.assertEqual(
            d["ProgramArguments"],
            ["/usr/sbin/frida-server-stealth", "-l", "127.0.0.1:27043"],
        )

    def test_plist_omits_program_key_when_arguments_used(self):
        text = deb_builder.render_launchd_plist("x", "/usr/sbin/y", 1234)
        self.assertNotIn("<key>Program</key>", text)

    def test_plist_is_valid_xml(self):
        import plistlib

        text = deb_builder.render_launchd_plist("a", "/b", 1)
        plistlib.loads(text.encode("utf-8"))


class PostinstTests(unittest.TestCase):
    def test_default_postinst_targets_server_paths(self):
        text = deb_builder.ROOTHIDE_POSTINST
        self.assertIn("SERVER=/usr/sbin/frida-server", text)
        self.assertIn("AGENT=/usr/lib/frida-1.0/frida-agent.dylib", text)
        self.assertIn("LABEL=re.frida.server", text)

    def test_custom_postinst_targets_stealth_paths(self):
        text = deb_builder.make_postinst(
            server="/usr/sbin/frida-server-stealth",
            agent="/usr/lib/frida/frida-agent.dylib",
            plist="/Library/LaunchDaemons/re.frida.stealth.plist",
            label="re.frida.stealth",
        )
        self.assertIn("SERVER=/usr/sbin/frida-server-stealth", text)
        self.assertIn("AGENT=/usr/lib/frida/frida-agent.dylib", text)
        self.assertIn("LABEL=re.frida.stealth", text)
        self.assertIn("re.frida.stealth", text)
        self.assertNotIn("frida-server-stealth-stealth", text)

    def test_postinst_rewrites_plist_twice(self):
        text = deb_builder.make_postinst(label="re.frida.stealth", server="/usr/sbin/frida-server-stealth")
        self.assertEqual(text.count("PLISTEOF"), 4)
        self.assertIn("sleep 5", text)

    def test_postinst_does_not_double_suffix(self):
        text = deb_builder.make_postinst(server="/usr/sbin/frida-server-stealth")
        self.assertNotIn("-stealth-stealth", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)