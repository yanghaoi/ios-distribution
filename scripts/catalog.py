import json
import os
import shutil


def load_site(repo_root):
    with open(os.path.join(repo_root, "config", "site.json"), "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def build_catalog(pooled, site_cfg, upstream_cfg):
    packages = []
    for item in pooled:
        packages.append(
            {
                "package": item["package"],
                "name": "Frida",
                "version": item["version"],
                "architecture": item["architecture"],
                "section": "Development",
                "description": "Observe and reprogram running programs.",
                "homepage": "https://frida.re/",
                "maintainer": "Ole André Vadla Ravnås <oleavr@nowsecure.com>",
                "size": item["size"],
                "sha256": item["sha256"],
                "filename": item["filename"],
                "upstreamVersion": upstream_cfg["upstream"]["version"],
                "upstreamUrl": upstream_cfg["upstream"]["releaseUrl"],
            }
        )
    packages.sort(key=lambda p: (p["package"], p["architecture"], p["version"]))

    return {
        "schemaVersion": 1,
        "site": {
            "name": site_cfg["siteName"],
            "subtitle": site_cfg.get("siteSubtitle", ""),
            "description": site_cfg["apt"].get("description", ""),
        },
        "apt": {
            "baseUrl": site_cfg["baseUrl"] + "apt/",
            "distribution": site_cfg["apt"]["distribution"],
            "component": site_cfg["apt"]["component"],
            "architectures": sorted({p["architecture"] for p in packages}),
            "publicKeyUrl": site_cfg["baseUrl"] + "apt/public.gpg",
        },
        "packages": packages,
        "apps": [],
    }