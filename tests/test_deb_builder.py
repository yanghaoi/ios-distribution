import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import deb_builder


class ArTests(unittest.TestCase):
    def test_roundtrip_preserves_members(self):
        members = [("debian-binary", b"2.0\n"), ("control.tar.xz", b"abc"), ("data.tar.xz", b"de")]
        tmp = os.path.join(ROOT, "artifacts", "_test_ar.deb")
        os.makedirs(os.path.dirname(tmp), exist_ok=True)
        deb_builder.write_ar(tmp, members)
        with open(tmp, "rb") as f:
            parsed = deb_builder.read_ar(f.read())
        os.remove(tmp)
        self.assertEqual([m[0] for m in parsed], [m[0] for m in members])
        self.assertEqual(parsed[0][1], b"2.0\n")
        self.assertEqual(parsed[2][1], b"de")

    def test_rejects_non_ar(self):
        with self.assertRaises(ValueError):
            deb_builder.read_ar(b"not an archive")


class ControlTests(unittest.TestCase):
    def test_parse_multiline_description(self):
        text = "Package: foo\nVersion: 1.0\nDescription: short\n long line\n"
        fields = deb_builder.parse_control_text(text.encode("utf-8"))
        self.assertEqual(deb_builder.control_get(fields, "Package"), "foo")
        self.assertIn("long line", deb_builder.control_get(fields, "Description"))

    def test_set_replaces_not_duplicates(self):
        fields = deb_builder.parse_control_text(b"Package: foo\nVersion: 1.0\n")
        fields = deb_builder.control_set(fields, "Version", "2.0")
        versions = [f for f in fields if f.lower().startswith("version:")]
        self.assertEqual(len(versions), 1)
        self.assertEqual(deb_builder.control_get(fields, "Version"), "2.0")

    def test_set_appends_when_missing(self):
        fields = deb_builder.parse_control_text(b"Package: foo\n")
        fields = deb_builder.control_set(fields, "Pre-Depends", "rootless-compat (>= 0.9)")
        self.assertEqual(
            deb_builder.control_get(fields, "Pre-Depends"), "rootless-compat (>= 0.9)"
        )

    def test_del_removes_field(self):
        fields = deb_builder.parse_control_text(b"Package: foo\nSize: 123\n")
        fields = deb_builder.control_del(fields, "Size")
        self.assertIsNone(deb_builder.control_get(fields, "Size"))


class TarTests(unittest.TestCase):
    def test_flatten_removes_var_jb_prefix(self):
        import io
        import tarfile

        buf = io.BytesIO()
        tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
        for name in ("./var", "./var/jb", "./var/jb/usr", "./var/jb/usr/sbin/frida-server"):
            info = tarfile.TarInfo(name)
            if name.endswith("frida-server"):
                payload = b"binary"
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            else:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
        tf.close()

        out = deb_builder.transform_data(buf.getvalue(), flatten=True)
        names = [m.name for m, _ in deb_builder.iter_tar(out)]
        self.assertNotIn("./var/jb", names)
        self.assertIn("./usr/sbin/frida-server", names)


class CompressionTests(unittest.TestCase):
    def test_unsupported_compression_raises(self):
        with self.assertRaises(ValueError):
            deb_builder.decompress_member("data.tar.zst", b"\x00")

    def test_xz_detected(self):
        import lzma

        raw = lzma.compress(b"hello")
        self.assertEqual(deb_builder.decompress_member("data.tar.xz", raw), b"hello")


if __name__ == "__main__":
    unittest.main(verbosity=2)