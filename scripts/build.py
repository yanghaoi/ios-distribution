import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apt_generator
import catalog as catalog_mod
import deb_builder
import gpg_signer


class BuildError(RuntimeError):
    pass


def _load(p):
    import json as j

    with open(p, "rb") as f:
        return j.loads(f.read().decode("utf-8"))


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")


def _dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def _human(n):
    units = ["B", "KB", "MB", "GB"]
    value = float(n)
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return "%.2f %s" % (value, units[idx])


def _render_index(template_path, out_path, site_cfg, apt_meta):
    tpl = open(template_path, "rb").read().decode("utf-8")
    archs = " ".join(apt_meta["architectures"]) if apt_meta["architectures"] else "-"
    replacements = {
        "__SITE_NAME__": site_cfg["siteName"],
        "__SITE_SUBTITLE__": site_cfg.get("siteSubtitle", ""),
        "__APT_BASE_URL__": site_cfg["baseUrl"] + "apt/",
        "__APT_PUBLIC_KEY_PATH__": "apt/public.gpg",
        "__APT_DIST__": site_cfg["apt"]["distribution"],
        "__APT_COMP__": site_cfg["apt"]["component"],
        "__APT_ARCHS__": archs,
        "__FOOTER__": "%s · %s" % (site_cfg["owner"], site_cfg["repository"]),
    }
    for key, value in replacements.items():
        tpl = tpl.replace(key, value)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(tpl)


def build(repo_root, dist_dir, debs_dir, sign_key=None, sign_passphrase=None,
          allow_unsigned=False):
    site_cfg = _load(os.path.join(repo_root, "config", "site.json"))
    frida_cfg = _load(os.path.join(repo_root, "config", "frida.json"))

    if not site_cfg["channels"]["apt"]:
        raise BuildError("channels.apt is disabled in config/site.json")

    if os.path.isdir(dist_dir):
        try:
            shutil.rmtree(dist_dir)
        except PermissionError as exc:
            raise BuildError(
                "cannot clear %s (%s); close any process holding files in it, "
                "for example a local preview server" % (dist_dir, exc)
            )
    os.makedirs(dist_dir, exist_ok=True)

    site_root = os.path.join(dist_dir, "site")
    os.makedirs(site_root, exist_ok=True)

    deb_specs = []
    groups = frida_cfg.get("versions")
    if groups is None:
        groups = [frida_cfg]
    for entry in groups:
        upstream = entry["upstream"]
        for variant in entry["variants"]:
            version = upstream["version"] + variant["versionSuffix"]
            name = variant["outputName"].format(version=version)
            path = os.path.join(debs_dir, name)
            if not os.path.exists(path):
                raise BuildError("missing built deb: %s" % path)
            deb_specs.append(
                {
                    "path": path,
                    "expectedArchitecture": variant["architecture"],
                }
            )

    apt_dir = os.path.join(site_root, "apt")
    apt_meta = apt_generator.build_apt_tree(apt_dir, deb_specs, site_cfg)

    signature = None
    if sign_key:
        try:
            signature = gpg_signer.sign_apt_release(
                apt_dir, site_cfg["apt"]["distribution"], sign_key, sign_passphrase
            )
            gpg_signer.verify_apt_release(apt_dir, site_cfg["apt"]["distribution"])
        except gpg_signer.SigningError as exc:
            raise BuildError("APT signing failed: %s" % exc)
    elif site_cfg.get("publish", {}).get("requireGpgSignature") and not allow_unsigned:
        raise BuildError(
            "config requires a GPG signature but no APT_GPG_PRIVATE_KEY was supplied; "
            "refusing to produce an unsigned repository"
        )

    cat = catalog_mod.build_catalog(apt_meta["packages"], site_cfg, frida_cfg)
    _write_json(os.path.join(site_root, "catalog.json"), cat)

    web = os.path.join(repo_root, "website")
    for item in ("css", "js", "assets"):
        src = os.path.join(web, item)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(site_root, item))
    _render_index(
        os.path.join(web, "index.html"),
        os.path.join(site_root, "index.html"),
        site_cfg,
        apt_meta,
    )

    total = _dir_size(site_root)
    limit = site_cfg.get("publish", {}).get("maxPagesBytes", 1073741824)
    if total > limit:
        raise BuildError(
            "dist size %s exceeds Pages limit %s" % (_human(total), _human(limit))
        )

    summary = {
        "siteRoot": site_root,
        "totalBytes": total,
        "totalHuman": _human(total),
        "architectures": apt_meta["architectures"],
        "signed": signature is not None,
        "keyid": signature["keyid"] if signature else None,
        "packages": [
            {
                "package": p["package"],
                "version": p["version"],
                "architecture": p["architecture"],
                "size": p["size"],
                "sha256": p["sha256"],
                "filename": p["filename"],
            }
            for p in cat["packages"]
        ],
    }
    _write_json(os.path.join(dist_dir, "build-summary.json"), summary)
    return summary


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist = os.path.join(root, "dist")
    debs = os.path.join(root, "artifacts", "debs")
    sign_key = os.environ.get("APT_GPG_PRIVATE_KEY")
    passphrase = os.environ.get("APT_GPG_PASSPHRASE")
    allow_unsigned = "--allow-unsigned" in argv

    if len(argv) > 1 and not argv[1].startswith("-"):
        dist = argv[1]

    summary = build(root, dist, debs, sign_key, passphrase, allow_unsigned)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))