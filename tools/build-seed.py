#!/usr/bin/env python3
"""Export a limited bootstrap feed from WPVulnerability when doing offline development."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import subprocess


WORDPRESS_RULE = "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp"
COMPONENT_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")


def endpoint(component):
    kind, slug = component
    url = f"https://www.wpvulnerability.net/{kind}/{slug}/"
    return json.loads(subprocess.check_output(["curl", "--fail", "--silent", "--show-error", "--max-time", "20", url]))


def normalize(component):
    kind, slug = component
    result = endpoint(component)
    records = {}
    notice = {
        "wpvulnerability": {
            "notice": "Source: WPVulnerability API",
            "license": "CC0 1.0",
            "license_url": "https://www.wpvulnerability.com/license/",
        },
    }
    for advisory in result["data"].get("vulnerability", []):
        versions = advisory["operator"]
        low = versions["min_version"] or "*"
        high = versions["max_version"] or "*"
        sources = advisory.get("source", [])
        cve = next((source["id"] for source in sources if source["id"].startswith("CVE-")), None)
        if cve == "CVE-2026-87902":
            continue
        impact = advisory.get("impact") or {}
        rating = impact.get("cvss") or {}
        fixed = [] if versions.get("unfixed") == "1" or versions["max_operator"] != "lt" else [high]
        uid = advisory["uuid"]
        records[f"{kind}:{slug}:{uid}"] = {
            "id": uid, "title": f"Known vulnerability in {slug}", "cve": cve,
            "cvss": {"score": rating.get("score")},
            "references": [source["link"] for source in sources if source.get("link")],
            "copyrights": notice,
            "software": [{
                "type": kind, "slug": slug, "patched_versions": fixed,
                "affected_versions": {"range": {
                    "from_version": low, "from_inclusive": versions["min_operator"] != "gt",
                    "to_version": high, "to_inclusive": versions["max_operator"] != "lt",
                }},
            }],
        }
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plugin", action="append", default=[])
    parser.add_argument("--theme", action="append", default=[])
    args = parser.parse_args()
    components = [("plugin", slug) for slug in args.plugin]
    components += [("theme", slug) for slug in args.theme]
    if any(not COMPONENT_SLUG.fullmatch(slug) for _, slug in components):
        raise ValueError("Invalid WordPress component slug.")
    core = {
        "id": "GHSA-7hp8-65ch-5whp",
        "title": "WordPress page-template path traversal",
        "cve": "CVE-2026-87902",
        "cvss": {"score": 9.2},
        "references": [WORDPRESS_RULE],
        "software": [{
            "type": "core", "slug": "wordpress", "patched_versions": [fixed],
            "affected_versions": {"range": {
                "from_version": f"{branch}.0", "from_inclusive": True,
                "to_version": fixed, "to_inclusive": False,
            }},
        } for branch, fixed in {
            "7.1": "7.1.2", "7.0": "7.0.6", "6.9": "6.9.9", "6.8": "6.8.10",
        }.items()],
    }
    records = {core["id"]: core}
    with ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(normalize, components):
            records.update(result)
    args.output.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    print(f"{len(records):,} bootstrap advisories for {len(components)} selected components and WordPress core.")


if __name__ == "__main__":
    main()

