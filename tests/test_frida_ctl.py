import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import frida_ctl


class ServiceRegistryTests(unittest.TestCase):
    def test_known_services_have_required_keys(self):
        required = {"package", "binary", "label", "plist", "args", "defaultPort", "protocol"}
        for name, spec in frida_ctl.KNOWN_SERVICES.items():
            missing = required - set(spec)
            self.assertFalse(missing, "%s missing %s" % (name, missing))

    def test_ports_do_not_collide(self):
        ports = [s["defaultPort"] for s in frida_ctl.KNOWN_SERVICES.values()]
        self.assertEqual(len(ports), len(set(ports)), "default ports must be unique")

    def test_args_files_do_not_collide(self):
        files = [s["args"] for s in frida_ctl.KNOWN_SERVICES.values()]
        self.assertEqual(len(files), len(set(files)))

    def test_stealth_uses_frnda_protocol(self):
        self.assertEqual(frida_ctl.KNOWN_SERVICES["frida-stealth"]["protocol"], "frnda")

    def test_standard_uses_standard_protocol(self):
        self.assertEqual(frida_ctl.KNOWN_SERVICES["frida-server"]["protocol"], "standard")

    def test_binaries_differ(self):
        bins = [s["binary"] for s in frida_ctl.KNOWN_SERVICES.values()]
        self.assertEqual(len(bins), len(set(bins)))


class PlistScriptTests(unittest.TestCase):
    def test_script_targets_correct_service(self):
        script = frida_ctl.build_plist_cmd("frida-stealth")
        self.assertIn("/usr/sbin/frida-server-stealth", script)
        self.assertIn("re.frida.stealth.plist", script)
        self.assertIn("re.frida.stealth.args", script)

    def test_script_reads_args_file(self):
        script = frida_ctl.build_plist_cmd("frida-server")
        self.assertIn('while IFS= read -r line', script)
        self.assertIn('done < "$ARGS_FILE"', script)

    def test_script_skips_comments_and_blanks(self):
        script = frida_ctl.build_plist_cmd("frida-server")
        self.assertIn("''|'#'*", script)

    def test_script_escapes_xml_entities(self):
        script = frida_ctl.build_plist_cmd("frida-server")
        self.assertIn("&amp;", script)
        self.assertIn("&lt;", script)
        self.assertIn("&gt;", script)

    def test_script_preserves_shell_printf(self):
        script = frida_ctl.build_plist_cmd("frida-server")
        self.assertIn("printf '%s'", script)

    def test_no_unreplaced_placeholders(self):
        for service in frida_ctl.KNOWN_SERVICES:
            script = frida_ctl.build_plist_cmd(service)
            self.assertNotIn("@ARGS@", script)
            self.assertNotIn("@PLIST@", script)
            self.assertNotIn("@LABEL@", script)
            self.assertNotIn("@BINARY@", script)

    def test_script_has_launchd_keys(self):
        script = frida_ctl.build_plist_cmd("frida-stealth")
        for key in ("Label", "ProgramArguments", "RunAtLoad", "KeepAlive"):
            self.assertIn(key, script)


class ReloadScriptTests(unittest.TestCase):
    def test_reload_script_contains_plist_build_and_launchctl(self):
        spec = frida_ctl.KNOWN_SERVICES["frida-stealth"]
        script = frida_ctl.build_plist_cmd("frida-stealth")
        combined = script + """
launchctl unload %s >/dev/null 2>&1 || true
sleep 1
launchctl load %s
""" % (spec["plist"], spec["plist"])
        self.assertIn("launchctl unload", combined)
        self.assertIn("launchctl load", combined)
        self.assertIn("chmod 644", script)


class ArgParsingTests(unittest.TestCase):
    def test_set_requires_flags(self):
        with self.assertRaises(SystemExit):
            frida_ctl.main(["set", "frida-stealth"])

    def test_unknown_service_rejected(self):
        with self.assertRaises(SystemExit):
            frida_ctl.main(["show", "not-a-service"])


if __name__ == "__main__":
    unittest.main(verbosity=2)