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


def normalize_multiline(value):
    """Debian control continuation lines must start with a single space."""
    lines = value.splitlines()
    if not lines:
        return value
    out = [lines[0]]
    for line in lines[1:]:
        if not line.strip():
            out.append(" .")
        else:
            out.append(" " + line.lstrip())
    return "\n".join(out)


def control_set(fields, key, value):
    if "\n" in value:
        value = normalize_multiline(value)
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

ROOTHIDE_POSTINST_TEMPLATE = """#!/bin/bash
set -u

ENT=/var/mobile/Library/roothide-frida.entitlements
PATCHES=/usr/lib/DynamicPatches/AutoPatches.dylib
AGENT=%(agent)s
CONFIG_DIR=/var/mobile/Library/frida-config
ARGS_FILE=%(args_file)s
PLIST_PATH=%(plist)s
LABEL_NAME=%(label)s
SERVER_BIN=%(server)s

LDID=""
for c in /usr/bin/ldid /var/jb/usr/bin/ldid; do
  if [ -x "$c" ]; then LDID="$c"; break; fi
done

if [ -z "$LDID" ]; then
  echo "roothide-frida: ldid not found, skipping entitlement patch" >&2
else
  cat > "$ENT" <<'ENTEOF'
%(entitlements)s
ENTEOF
  chmod 644 "$ENT"
  if [ -f "$SERVER_BIN" ]; then "$LDID" -M -S"$ENT" "$SERVER_BIN" || echo "roothide-frida: server resign failed" >&2; fi
  if [ -f "$AGENT" ]; then "$LDID" -S "$AGENT" || echo "roothide-frida: agent resign failed" >&2; fi
fi

if [ -f "$PATCHES" ]; then
  ln -sf "$PATCHES" "$SERVER_BIN.roothidepatch" 2>/dev/null || true
  ln -sf "$PATCHES" "$AGENT.roothidepatch" 2>/dev/null || true
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
if [ ! -f "$ARGS_FILE" ]; then
  : > "$ARGS_FILE"
  chmod 600 "$ARGS_FILE"
fi

build_plist() {
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
    echo '<dict>'
    echo '	<key>Label</key>'
    echo "	<string>$LABEL_NAME</string>"
    echo '	<key>ProgramArguments</key>'
    echo '	<array>'
    echo "		<string>$SERVER_BIN</string>"
    while IFS= read -r line; do
      case "$line" in
        ''|'#'*) continue ;;
      esac
      esc=$(printf '%%s' "$line" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
      echo "		<string>$esc</string>"
    done < "$ARGS_FILE"
    echo '	</array>'
    echo '	<key>UserName</key>'
    echo '	<string>root</string>'
    echo '	<key>POSIXSpawnType</key>'
    echo '	<string>Interactive</string>'
    echo '	<key>RunAtLoad</key>'
    echo '	<true/>'
    echo '	<key>KeepAlive</key>'
    echo '	<true/>'
    echo '	<key>ThrottleInterval</key>'
    echo '	<integer>5</integer>'
    echo '	<key>ExecuteAllowed</key>'
    echo '	<true/>'
    echo '</dict>'
    echo '</plist>'
  } > "$PLIST_PATH"
  chmod 644 "$PLIST_PATH"
}

reload() {
  launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
  sleep 1
  launchctl load "$PLIST_PATH" >/dev/null 2>&1 || true
}

build_plist
reload

# roothide rewrites launchd plists during dpkg, pointing Program at a jbroot
# container. Redo it once the installer has finished.
(
  sleep 5
  build_plist
  reload
) >/dev/null 2>&1 &

exit 0
"""


def render_launchd_plist(label, program, port):
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-l</string>
		<string>127.0.0.1:%d</string>
	</array>
	<key>UserName</key>
	<string>root</string>
	<key>POSIXSpawnType</key>
	<string>Interactive</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ExecuteAllowed</key>
	<true/>
</dict>
</plist>
""" % (label, program, port)


def make_postinst(server="/usr/sbin/frida-server",
                  agent="/usr/lib/frida-1.0/frida-agent.dylib",
                  plist="/Library/LaunchDaemons/re.frida.server.plist",
                  label="re.frida.server",
                  args_file="/var/mobile/Library/frida-config/re.frida.server.args",
                  default_args=None):
    default_args = default_args or []
    body = ROOTHIDE_POSTINST_TEMPLATE % {
        "server": server,
        "agent": agent,
        "plist": plist,
        "label": label,
        "args_file": args_file,
        "entitlements": ROOTHIDE_ENTITLEMENTS,
    }
    if default_args:
        seed = "\n".join(default_args)
        body = body.replace(
            '  : > "$ARGS_FILE"\n',
            "  cat > \"$ARGS_FILE\" <<'ARGSEOF'\n%s\nARGSEOF\n" % seed,
        )
    return body


ROOTHIDE_POSTINST = make_postinst()


def transform_control(raw, version, arch, pre_depends, inject_postinst=False,
                      postinst_body=None, overrides=None):
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
    for key, value in (overrides or {}).items():
        if value:
            fields = control_set(fields, key, value)
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
            body_bytes = (postinst_body or ROOTHIDE_POSTINST).encode("utf-8")
            entries.append((info, "./postinst", body_bytes))

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


STEALTH_PAIRS = [
    (b"re.frida.BusSession", b"re.frnda.BusSession"),
    (b"re.frida.AgentSession", b"re.frnda.AgentSession"),
    (b"re.frida.HostSession", b"re.frnda.HostSession"),
    (b"re.frida.AgentController", b"re.frnda.AgentController"),
    (b"re.frida.AgentMessageSink", b"re.frnda.AgentMessageSink"),
    (b"re.frida.AgentSessionProvider", b"re.frnda.AgentSessionProvider"),
    (b"/re/frida/", b"/re/frnda/"),
    (b"re.frida.", b"re.frnda."),
    (b"frida:rpc", b"frnda:rpc"),
]


def apply_stealth_patch(data):
    out = data
    total = 0
    for src, dst in STEALTH_PAIRS:
        if len(src) != len(dst):
            raise ValueError("stealth replacement length differs: %r" % src)
        n = out.count(src)
        if n:
            out = out.replace(src, dst)
            total += n
    if len(out) != len(data):
        raise ValueError("stealth patch changed binary size")
    return out, total


def transform_data_stealth(raw, flatten):
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
        if body is not None and (
            name.endswith("frida-server") or name.endswith("frida-agent.dylib")
        ):
            body, _n = apply_stealth_patch(body)
        entries.append((member, name, body))
    return build_tar(entries)


def repack_deb(source_bytes, version, arch, pre_depends, flatten, inject_postinst=False,
               stealth=False, postinst_body=None, overrides=None, compress_preset=6):
    members = read_ar(source_bytes)
    control_name, control_raw = read_control(members)
    data_name, data_raw = read_data(members)

    new_control = transform_control(
        control_raw, version, arch, pre_depends, inject_postinst=inject_postinst,
        postinst_body=postinst_body, overrides=overrides,
    )
    if stealth:
        new_data = transform_data_stealth(data_raw, flatten)
    else:
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


def rename_package(deb_bytes, new_name):
    members = read_ar(deb_bytes)
    control_name, control_raw = read_control(members)
    data_name, data_raw = read_data(members)

    control_body = None
    for member, body in iter_tar(control_raw):
        if member.name.lstrip("./") == "control":
            control_body = body
    if control_body is None:
        raise ValueError("control missing")

    fields = parse_control_text(control_body)
    fields = control_set(fields, "Package", new_name)
    new_control = render_control(fields)

    entries = []
    for member, body in iter_tar(control_raw):
        if member.name.lstrip("./") == "control":
            body = new_control
        entries.append((member, member.name, body))
    new_control_raw = build_tar(entries)

    out = [
        ("debian-binary", b"2.0\n"),
        (control_name, lzma.compress(new_control_raw, preset=6)),
        (data_name, lzma.compress(data_raw, preset=6)),
    ]
    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "_rename_%s.deb" % os.getpid())
    write_ar(tmp, out)
    data = open(tmp, "rb").read()
    os.remove(tmp)
    return data


def relocate_stealth_files(deb_bytes, server_path="/usr/sbin/frida-server-stealth",
                           agent_path="/usr/lib/frida/frida-agent.dylib"):
    """Move the server binary aside so it coexists with re.frida.server.

    The agent must stay at /usr/lib/frida/frida-agent.dylib because the
    frida-server binary has that path compiled in; it is shared with any
    other 16.x server already installed.
    """
    members = read_ar(deb_bytes)
    control_name, control_raw = read_control(members)
    data_name, data_raw = read_data(members)

    server_rel = "./" + server_path.lstrip("/")
    agent_rel = "./" + agent_path.lstrip("/")

    src_server = None
    src_agent = None
    for member, body in iter_tar(data_raw):
        if body is None:
            continue
        if member.name.endswith("usr/sbin/frida-server"):
            src_server = member.name
        elif member.name.endswith("frida-agent.dylib"):
            src_agent = member.name
    if not src_server or not src_agent:
        raise ValueError("cannot locate frida-server or frida-agent in package")

    entries = []
    for member, body in iter_tar(data_raw):
        name = member.name
        if body is None:
            continue
        if name == src_server:
            entries.append((member, server_rel, body))
            continue
        if name == src_agent:
            entries.append((member, agent_rel, body))
            continue
        if name.endswith(".plist") and "LaunchDaemons" in name:
            entries.append((member, "./Library/LaunchDaemons/re.frida.stealth.plist", body))
            continue

    needed_dirs = [
        "./usr", "./usr/sbin", "./usr/lib", "./usr/lib/frida",
        "./Library", "./Library/LaunchDaemons",
    ]
    import tarfile as _tf

    dir_entries = []
    for d in needed_dirs:
        info = _tf.TarInfo(d)
        info.type = _tf.DIRTYPE
        info.mode = 0o755
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = 0
        dir_entries.append((info, d, None))

    patched_data = build_tar(dir_entries + entries)

    control_entries = []
    for member, body in iter_tar(control_raw):
        if body is not None and member.name.lstrip("./") in ("extrainst_", "postinst", "prerm"):
            text = body.decode("utf-8")
            text = text.replace("/usr/lib/frida-1.0/frida-agent.dylib",
                                "/usr/lib/frida/frida-agent.dylib")
            body = text.encode("utf-8")
        control_entries.append((member, member.name, body))
    patched_control = build_tar(control_entries)

    out = [
        ("debian-binary", b"2.0\n"),
        (control_name, lzma.compress(patched_control, preset=6)),
        (data_name, lzma.compress(patched_data, preset=6)),
    ]
    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "_relocate_%s.deb" % os.getpid())
    write_ar(tmp, out)
    data = open(tmp, "rb").read()
    os.remove(tmp)
    return data


def set_listen_port(deb_bytes, port, label="re.frida.stealth",
                    program="/usr/sbin/frida-server-stealth",
                    plist_name="re.frida.stealth.plist"):
    """Ship a placeholder plist; the postinst regenerates it from the
    device-local args file, so the port here only matters for first boot."""
    members = read_ar(deb_bytes)
    control_name, control_raw = read_control(members)
    data_name, data_raw = read_data(members)

    new_plist = render_launchd_plist(label, program, port).encode("utf-8")

    data_entries = []
    replaced = 0
    for member, body in iter_tar(data_raw):
        name = member.name
        if body is not None and name.endswith(".plist") and "LaunchDaemons" in name:
            data_entries.append((member, "./Library/LaunchDaemons/%s" % plist_name, new_plist))
            replaced += 1
            continue
        entry_name = name.replace("re.frida.server.plist", plist_name)
        data_entries.append((member, entry_name, body))
    if replaced == 0:
        raise ValueError("no launchd plist found in package")
    patched_data = build_tar(data_entries)

    control_entries = []
    for member, body in iter_tar(control_raw):
        if body is not None and member.name.lstrip("./") in ("extrainst_", "postinst", "prerm"):
            text = body.decode("utf-8")
            text = text.replace("/var/jb/Library/LaunchDaemons/re.frida.server.plist",
                                "/Library/LaunchDaemons/%s" % plist_name)
            text = text.replace("re.frida.server.plist", plist_name)
            body = text.encode("utf-8")
        control_entries.append((member, member.name, body))
    patched_control = build_tar(control_entries)

    out = [
        ("debian-binary", b"2.0\n"),
        (control_name, lzma.compress(patched_control, preset=6)),
        (data_name, lzma.compress(patched_data, preset=6)),
    ]
    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "_port_%s.deb" % os.getpid())
    write_ar(tmp, out)
    data = open(tmp, "rb").read()
    os.remove(tmp)
    return data


def build_variants(repo_root, cache_dir, out_dir):
    cfg = load_config(repo_root)

    groups = []
    if "versions" in cfg:
        for entry in cfg["versions"]:
            groups.append((entry["id"], entry["upstream"], entry["variants"]))
    else:
        groups.append(("default", cfg["upstream"], cfg["variants"]))

    os.makedirs(out_dir, exist_ok=True)
    built = []
    for group_id, upstream, variants in groups:
        version = upstream["version"]
        assets = upstream["assets"]

        sources = {}
        for arch, meta in assets.items():
            sources[arch] = fetch(
                meta["url"],
                expected_size=meta.get("size"),
                expected_sha256=meta["sha256"],
                cache_dir=cache_dir,
            )

        for variant in variants:
            src = sources[variant["sourceArch"]]
            transform = variant["transform"]
            effective_version = version + variant["versionSuffix"]
            overrides = {
                "Description": variant.get("description"),
                "Maintainer": variant.get("maintainer"),
                "Section": variant.get("section"),
                "Homepage": variant.get("homepage"),
            }
            if transform == "none":
                if any(v for v in overrides.values()):
                    # still byte-exact in payload, only the control text changes
                    payload = repack_deb(
                        src,
                        version=effective_version,
                        arch=variant["architecture"],
                        pre_depends=variant["preDepends"],
                        flatten=False,
                        inject_postinst=False,
                        overrides=overrides,
                    )
                else:
                    payload = src
            elif transform == "roothide":
                payload = repack_deb(
                    src,
                    version=effective_version,
                    arch=variant["architecture"],
                    pre_depends=variant["preDepends"],
                    flatten=True,
                    inject_postinst=variant.get("injectRoothidePostinst", False),
                    overrides=overrides,
                )
            elif transform == "roothide-full":
                payload = repack_deb(
                    src,
                    version=effective_version,
                    arch=variant["architecture"],
                    pre_depends=variant["preDepends"],
                    flatten=True,
                    inject_postinst=True,
                    overrides=overrides,
                )
            elif transform == "roothide-stealth":
                payload = repack_deb(
                    src,
                    version=effective_version,
                    arch=variant["architecture"],
                    pre_depends=variant["preDepends"],
                    flatten=True,
                    inject_postinst=True,
                    stealth=True,
                    postinst_body=make_postinst(
                        server="/usr/sbin/frida-server-stealth",
                        agent="/usr/lib/frida/frida-agent.dylib",
                        plist="/Library/LaunchDaemons/re.frida.stealth.plist",
                        label="re.frida.stealth",
                        args_file="/var/mobile/Library/frida-config/re.frida.stealth.args",
                        default_args=[
                            "-l",
                            "127.0.0.1:%d" % variant.get("listenPort", 27043),
                        ],
                    ),
                    overrides=overrides,
                )
                payload = relocate_stealth_files(payload)
                if variant.get("packageName"):
                    payload = rename_package(payload, variant["packageName"])
                if variant.get("listenPort"):
                    payload = set_listen_port(payload, variant["listenPort"])
            elif transform == "stealth-plain":
                payload = repack_deb(
                    src,
                    version=effective_version,
                    arch=variant["architecture"],
                    pre_depends=variant["preDepends"],
                    flatten=False,
                    inject_postinst=False,
                    stealth=True,
                    overrides=overrides,
                )
                if variant.get("packageName"):
                    payload = rename_package(payload, variant["packageName"])
                if variant.get("listenPort"):
                    payload = set_listen_port(payload, variant["listenPort"])
            else:
                raise ValueError("unknown transform: %s" % transform)

            name = variant["outputName"].format(version=effective_version)
            path = os.path.join(out_dir, name)
            with open(path, "wb") as f:
                f.write(payload)

            built.append(
                {
                    "variantId": variant["id"],
                    "group": group_id,
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