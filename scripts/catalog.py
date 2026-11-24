import json
import os
import shutil


def load_site(repo_root):
    with open(os.path.join(repo_root, "config", "site.json"), "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def build_catalog(pooled, site_cfg, upstream_cfg):
    versions = upstream_cfg.get("versions") or [upstream_cfg]
    release_urls = {}
    for entry in versions:
        up = entry["upstream"]
        for variant in entry["variants"]:
            v = up["version"] + variant["versionSuffix"]
            release_urls[(entry.get("id", ""), v)] = up["releaseUrl"]

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
                "upstreamVersions": sorted(
                    {
                        v.split("+")[0]
                        for _k, v in release_urls.items()
                        if v.startswith(item["version"].split("+")[0])
                    }
                )
                or [item["version"].split("+")[0]],
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