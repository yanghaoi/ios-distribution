import io
import lzma
import os
import json
import hashlib
import urllib.request

FORMAT_VERSION = "2.0"
VAR_JB = "./var/jb/"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_ar(data):
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    off = 8
    members = []
    while off + 60 <= len(data):
        hdr = data[off : off + 60]
        raw_name = hdr[0:16].decode("ascii", "replace").strip()
        name = raw_name.rstrip("/")
        if not name:
            break
        size_field = hdr[48:58].decode("ascii", "replace").strip()
        if not size_field.isdigit():
            raise ValueError("bad ar member size for %r" % raw_name)
        size = int(size_field)
        if off + 60 + size > len(data):
            raise ValueError("truncated ar member %r" % name)
        members.append((name, data[off + 60 : off + 60 + size]))
        off += 60 + size
        if off % 2:
            off += 1
    return members


def write_ar(path, members):
    out = bytearray(b"!<arch>\n")
    for name, body in members:
        hdr = (
            ("%s/" % name).ljust(16)
            + "0".ljust(12)
            + "0".ljust(6)
            + "0".ljust(6)
            + "100644".ljust(8)
            + str(len(body)).ljust(10)
            + "`\n"
        ).encode("ascii")
        if len(hdr) != 60:
            raise ValueError("ar header must be 60 bytes, got %d" % len(hdr))
        out += hdr
        out += body
        if len(body) % 2:
            out += b"\n"
    with open(path, "wb") as f:
        f.write(bytes(out))


def decompress_member(name, body):
    kind = name.rsplit(".", 1)[-1]
    if kind == "xz":
        return lzma.decompress(body)
    raise ValueError("unsupported compression for %s: %s" % (name, kind))


def read_control(members):
    for name, body in members:
        if name.startswith("control.tar"):
            return name, decompress_member(name, body)
    raise ValueError("control.tar.* not found")


def read_data(members):
    for name, body in members:
        if name.startswith("data.tar"):
            return name, decompress_member(name, body)
    raise ValueError("data.tar.* not found")


def parse_control_text(raw):
    fields = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        if line[0] in " \t" and fields:
            fields[-1] = fields[-1] + "\n" + line
            continue
        if ":" not in line:
            raise ValueError("malformed control line: %r" % line)
        key, value = line.split(":", 1)
        fields.append("%s:%s" % (key.strip(), value))
    return fields


def control_get(fields, key):
    for item in fields:
        name, value = item.split(":", 1)
        if name.lower() == key.lower():
            return value.strip()
    return None


def control_set(fields, key, value):
    out = []
    replaced = False
    for item in fields:
        name = item.split(":", 1)[0]
        if name.lower() == key.lower():
            if not replaced:
                out.append("%s: %s" % (name, value))
                replaced = True
            continue
        out.append(item)
    if not replaced:
        out.append("%s: %s" % (key, value))
    return out


def control_del(fields, key):
    return [i for i in fields if i.split(":", 1)[0].lower() != key.lower()]


def render_control(fields):
    return ("\n".join(fields) + "\n").encode("utf-8")


def iter_tar(raw):
    import tarfile

    tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    try:
        for member in tf.getmembers():
            body = tf.extractfile(member).read() if member.isfile() else None
            yield member, body
    finally:
        tf.close()


def build_tar(entries):
    import tarfile

    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    for member, name, body in entries:
        info = tarfile.TarInfo(name)
        info.mode = member.mode
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = member.mtime
        if body is None:
            info.type = tarfile.DIRTYPE
            tf.addfile(info)
        else:
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    tf.close()
    return buf.getvalue()


ROOTHIDE_ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>com.apple.private.security.no-sandbox</key>
\t<true/>
\t<key>com.apple.private.security.storage.AppBundles</key>
\t<true/>
\t<key>com.apple.private.security.storage.AppDataContainers</key>
\t<true/>
\t<key>platform-application</key>
\t<true/>
</dict>
</plist>
"""

ROOTHIDE_POSTINST = """#!/bin/bash
set -u

ENT=/var/mobile/Library/roothide-frida.entitlements
PATCHES=/usr/lib/DynamicPatches/AutoPatches.dylib
SERVER=/usr/sbin/frida-server
AGENT=/usr/lib/frida-1.0/frida-agent.dylib
PLIST=/Library/LaunchDaemons/re.frida.server.plist

LDID=""
for c in /usr/bin/ldid /var/jb/usr/bin/ldid; do
  if [ -x "$c" ]; then LDID="$c"; break; fi
done

if [ -z "$LDID" ]; then
  echo "roothide-frida: ldid not found, skipping entitlement patch" >&2
else
  cat > "$ENT" <<'PLIST'
%s
PLIST
  chmod 644 "$ENT"
  if [ -f "$SERVER" ]; then "$LDID" -M -S"$ENT" "$SERVER" || echo "roothide-frida: server resign failed" >&2; fi
  if [ -f "$AGENT" ]; then "$LDID" -S "$AGENT" || echo "roothide-frida: agent resign failed" >&2; fi
fi

if [ -f "$PATCHES" ]; then
  ln -sf "$PATCHES" "$SERVER.roothidepatch" 2>/dev/null || true
  ln -sf "$PATCHES" "$AGENT.roothidepatch" 2>/dev/null || true
fi

if [ -f "$PLIST" ]; then
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  sleep 1
  launchctl load "$PLIST" >/dev/null 2>&1 || true
fi

exit 0
""" % ROOTHIDE_ENTITLEMENTS


def transform_control(raw, version, arch, pre_depends, inject_postinst=False):
    control_body = None
    for member, body in iter_tar(raw):
        if member.name.lstrip("./") == "control":
            control_body = body
            break
    if control_body is None:
        raise ValueError("control file not found inside control.tar")

    fields = parse_control_text(control_body)
    fields = control_set(fields, "Version", version)
    fields = control_set(fields, "Architecture", arch)
    fields = control_del(fields, "Size")
    fields = control_del(fields, "Installed-Size")
    fields = control_del(fields, "Pre-Depends")
    if pre_depends:
        fields = control_set(fields, "Pre-Depends", pre_depends)
    new_control = render_control(fields)

    entries = []
    for member, body in iter_tar(raw):
        name = member.name
        if name.lstrip("./") == "control":
            body = new_control
        entries.append((member, name, body))

    if inject_postinst:
        names = {m.name.lstrip("./") for m, _, _ in entries}
        if "postinst" not in names:
            import tarfile as _tf

            info = _tf.TarInfo("./postinst")
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            entries.append((info, "./postinst", ROOTHIDE_POSTINST.encode("utf-8")))

    return build_tar(entries)


def transform_data(raw, flatten):
    entries = []
    for member, body in iter_tar(raw):
        name = member.name
        if flatten:
            if name in ("./var", "./var/jb", "var", "var/jb"):
                continue
            if name.startswith(VAR_JB):
                name = "./" + name[len(VAR_JB) :]
            elif name.startswith(VAR_JB.lstrip("./")):
                name = "./" + name[len(VAR_JB.lstrip("./")) :]
        entries.append((member, name, body))
    return build_tar(entries)


def repack_deb(source_bytes, version, arch, pre_depends, flatten, inject_postinst=False,
               compress_preset=6):
    members = read_ar(source_bytes)
    control_name, control_raw = read_control(members)
    data_name, data_raw = read_data(members)

    new_control = transform_control(
        control_raw, version, arch, pre_depends, inject_postinst=inject_postinst
    )
    new_data = transform_data(data_raw, flatten)

    out_members = [("debian-binary", b"2.0\n")]
    out_members.append((control_name, lzma.compress(new_control, preset=compress_preset)))
    out_members.append((data_name, lzma.compress(new_data, preset=compress_preset)))

    buf = io.BytesIO()
    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "_repack_%s" % os.getpid())
    write_ar(tmp, out_members)
    with open(tmp, "rb") as f:
        buf.write(f.read())
    os.remove(tmp)
    return buf.getvalue()


def fetch(url, expected_size=None, expected_sha256=None, cache_dir=None):
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        name = url.rsplit("/", 1)[-1]
        cached = os.path.join(cache_dir, name)
        if os.path.exists(cached):
            data = open(cached, "rb").read()
            if expected_sha256 and sha256_bytes(data) != expected_sha256:
                raise ValueError("cached file hash mismatch: %s" % cached)
            return data
    req = urllib.request.Request(url, headers={"User-Agent": "ios-distribution-build"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    if expected_size is not None and len(data) != expected_size:
        raise ValueError(
            "size mismatch for %s: got %d expected %d" % (url, len(data), expected_size)
        )
    if expected_sha256 is not None:
        actual = sha256_bytes(data)
        if actual != expected_sha256:
            raise ValueError(
                "sha256 mismatch for %s: got %s expected %s"
                % (url, actual, expected_sha256)
            )
    if cache_dir:
        with open(cached, "wb") as f:
            f.write(data)
    return data


def load_config(repo_root):
    with open(os.path.join(repo_root, "config", "frida.json"), "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def build_variants(repo_root, cache_dir, out_dir):
    cfg = load_config(repo_root)
    version = cfg["upstream"]["version"]
    assets = cfg["upstream"]["assets"]

    sources = {}
    for arch, meta in assets.items():
        sources[arch] = fetch(
            meta["url"],
            expected_size=meta.get("size"),
            expected_sha256=meta["sha256"],
            cache_dir=cache_dir,
        )

    os.makedirs(out_dir, exist_ok=True)
    built = []
    for variant in cfg["variants"]:
        src = sources[variant["sourceArch"]]
        transform = variant["transform"]
        effective_version = version + variant["versionSuffix"]
        if transform == "none":
            payload = src
        elif transform == "roothide":
            payload = repack_deb(
                src,
                version=effective_version,
                arch=variant["architecture"],
                pre_depends=variant["preDepends"],
                flatten=True,
                inject_postinst=variant.get("injectRoothidePostinst", False),
            )
        elif transform == "roothide-full":
            payload = repack_deb(
                src,
                version=effective_version,
                arch=variant["architecture"],
                pre_depends=variant["preDepends"],
                flatten=True,
                inject_postinst=True,
            )
        else:
            raise ValueError("unknown transform: %s" % transform)

        name = variant["outputName"].format(version=effective_version)
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(payload)

        built.append(
            {
                "variantId": variant["id"],
                "name": name,
                "path": path,
                "size": len(payload),
                "sha256": sha256_bytes(payload),
                "version": effective_version,
                "architecture": variant["architecture"],
                "upstreamVersion": version,
                "notes": variant["notes"],
            }
        )
    return built


if __name__ == "__main__":
    import sys

    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    cache = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, ".cache", "upstream")
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(root, "dist", "out")
    for item in build_variants(root, cache, out):
        print(json.dumps({k: v for k, v in item.items() if k != "path"}, ensure_ascii=False))