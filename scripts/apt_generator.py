import bz2
import gzip
import hashlib
import lzma
import os
import re


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_deb_control(path):
    import io
    import tarfile

    data = open(path, "rb").read()
    if data[:8] != b"!<arch>\n":
        raise ValueError("%s is not a Debian archive" % path)
    off = 8
    control_raw = None
    while off + 60 <= len(data):
        hdr = data[off : off + 60]
        name = hdr[0:16].decode("ascii", "replace").strip().rstrip("/")
        if not name:
            break
        size = int(hdr[48:58].decode("ascii", "replace").strip())
        body = data[off + 60 : off + 60 + size]
        if name.startswith("control.tar"):
            kind = name.rsplit(".", 1)[-1]
            if kind == "xz":
                control_raw = lzma.decompress(body)
            elif kind == "gz":
                control_raw = gzip.decompress(body)
            else:
                raise ValueError("unsupported control archive: %s" % name)
        off += 60 + size
        if off % 2:
            off += 1
    if control_raw is None:
        raise ValueError("%s has no control.tar" % path)

    tf = tarfile.open(fileobj=io.BytesIO(control_raw), mode="r:")
    try:
        for member in tf.getmembers():
            if member.name.lstrip("./") == "control":
                return tf.extractfile(member).read().decode("utf-8")
    finally:
        tf.close()
    raise ValueError("%s control file missing" % path)


def parse_stanza(text):
    fields = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t" and fields:
            fields[-1] = fields[-1] + "\n" + line
            continue
        if ":" not in line:
            raise ValueError("malformed control line: %r" % line)
        key, value = line.split(":", 1)
        fields.append((key.strip(), value.strip()))
    return fields


def stanza_get(fields, key):
    for name, value in fields:
        if name.lower() == key.lower():
            return value
    return None


def pool_path(package, version, architecture):
    safe = re.sub(r"[^A-Za-z0-9.+~:-]", "_", package)
    prefix = "pool/main/%s/%s" % (safe[0].lower() if safe else "x", safe)
    filename = "%s_%s_%s.deb" % (safe, version, architecture)
    return prefix, filename


def build_packages_stanza(control_text, repo_relative_path, size, sha256, md5, sha1):
    fields = parse_stanza(control_text)
    wanted_order = [
        "Package",
        "Version",
        "Architecture",
        "Maintainer",
        "Installed-Size",
        "Depends",
        "Pre-Depends",
        "Conflicts",
        "Breaks",
        "Replaces",
        "Provides",
        "Section",
        "Priority",
        "Homepage",
        "Description",
    ]
    lines = []
    used = set()
    for key in wanted_order:
        for name, value in fields:
            if name.lower() == key.lower():
                lines.append((name, value))
                used.add(name.lower())
                break
    for name, value in fields:
        if name.lower() in used:
            continue
        if name.lower() in ("size", "filename", "sha256", "sha1", "md5sum"):
            continue
        lines.append((name, value))

    out = []
    for name, value in lines:
        out.append("%s: %s" % (name, value))
    out.append("Filename: %s" % repo_relative_path)
    out.append("Size: %d" % size)
    out.append("MD5sum: %s" % md5)
    out.append("SHA1: %s" % sha1)
    out.append("SHA256: %s" % sha256)
    return "\n".join(out)


def build_apt_tree(apt_dir, debs, site_cfg):
    os.makedirs(apt_dir, exist_ok=True)

    dist = site_cfg["apt"]["distribution"]
    component = site_cfg["apt"]["component"]

    index_targets = {}
    pooled = []

    for item in debs:
        control_text = read_deb_control(item["path"])
        fields = parse_stanza(control_text)
        package = stanza_get(fields, "Package")
        version = stanza_get(fields, "Version")
        architecture = stanza_get(fields, "Architecture")
        if not package or not version or not architecture:
            raise ValueError("incomplete control in %s" % item["path"])

        prefix, filename = pool_path(package, version, architecture)
        if item.get("expectedArchitecture") and item["expectedArchitecture"] != architecture:
            raise ValueError(
                "architecture mismatch for %s: control says %s expected %s"
                % (item["path"], architecture, item["expectedArchitecture"])
            )

        dest_dir = os.path.join(apt_dir, prefix)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, filename)
        with open(item["path"], "rb") as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)

        rel = "%s/%s" % (prefix, filename)
        size = os.path.getsize(dest)
        sha256 = sha256_file(dest)
        if item.get("sha256") and item["sha256"] != sha256:
            raise ValueError("sha256 drift for %s" % rel)

        stanza = build_packages_stanza(
            control_text, rel, size, sha256, md5_file(dest), sha1_file(dest)
        )
        index_targets.setdefault(architecture, []).append((package, version, stanza))
        pooled.append(
            {
                "package": package,
                "version": version,
                "architecture": architecture,
                "filename": rel,
                "size": size,
                "sha256": sha256,
                "control": control_text,
            }
        )

    for arch, entries in index_targets.items():
        entries.sort(key=lambda e: (e[0], e[1]))
        body = "\n\n".join(e[2] for e in entries) + "\n"
        binary_dir = os.path.join(
            apt_dir, "dists", dist, component, "binary-%s" % arch
        )
        os.makedirs(binary_dir, exist_ok=True)
        plain = os.path.join(binary_dir, "Packages")
        with open(plain, "wb") as f:
            f.write(body.encode("utf-8"))
        with open(plain + ".gz", "wb") as f:
            f.write(gzip.compress(body.encode("utf-8"), compresslevel=9, mtime=0))
        with open(plain + ".bz2", "wb") as f:
            f.write(bz2.compress(body.encode("utf-8"), compresslevel=9))

    release_path = os.path.join(apt_dir, "dists", dist, "Release")
    release_text = render_release(apt_dir, dist, component, site_cfg)
    os.makedirs(os.path.dirname(release_path), exist_ok=True)
    with open(release_path, "wb") as f:
        f.write(release_text.encode("utf-8"))

    return {
        "releasePath": release_path,
        "architectures": sorted(index_targets.keys()),
        "packages": pooled,
        "releaseText": release_text,
    }


def render_release(apt_dir, dist, component, site_cfg):
    apt = site_cfg["apt"]
    entries = []
    base = os.path.join(apt_dir, "dists", dist)
    for root, _dirs, files in os.walk(base):
        for name in sorted(files):
            if name in ("Release", "Release.gpg", "InRelease"):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            entries.append((rel, os.path.getsize(full)))
    entries.sort(key=lambda e: e[0])

    arches = sorted(
        set(
            re.match(r"^%s/binary-(.+?)/Packages" % re.escape(component), rel).group(1)
            for rel, _ in entries
            if re.match(r"^%s/binary-(.+?)/Packages" % re.escape(component), rel)
        )
    )

    lines = []
    lines.append("Origin: %s" % apt["origin"])
    lines.append("Label: %s" % apt["label"])
    lines.append("Suite: %s" % dist)
    lines.append("Codename: %s" % dist)
    lines.append("Version: 1.0")
    if arches:
        lines.append("Architectures: %s" % " ".join(arches))
    lines.append("Components: %s" % component)
    lines.append("Description: %s" % apt.get("description", apt["label"]))
    lines.append("Date: %s" % _rfc822_now())
    lines.append("MD5Sum:")
    for rel, size in entries:
        lines.append(" %s %16d %s" % (md5_file(os.path.join(base, rel)), size, rel))
    lines.append("SHA1:")
    for rel, size in entries:
        lines.append(" %s %16d %s" % (sha1_file(os.path.join(base, rel)), size, rel))
    lines.append("SHA256:")
    for rel, size in entries:
        lines.append(" %s %16d %s" % (sha256_file(os.path.join(base, rel)), size, rel))
    return "\n".join(lines) + "\n"


def _rfc822_now():
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%a, %d %b %Y %H:%M:%S UTC")