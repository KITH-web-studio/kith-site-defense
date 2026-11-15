#!/usr/bin/env python3
"""Build and sign static vulnerability database files for an HTTPS origin."""

import argparse
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_FEED = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
MAX_FEED_BYTES = 256 * 1024 * 1024
MAX_DATABASE_BYTES = 70 * 1024 * 1024
GITHUB_REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/([A-Za-z0-9_-]+)/?")

SIGN = """
if (!extension_loaded('sodium')) { fwrite(STDERR, "PHP Sodium is required"); exit(1); }
$key = base64_decode(trim(file_get_contents($argv[1])), true);
if (strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) { exit(2); }
$data = file_get_contents($argv[2]);
file_put_contents($argv[3], sodium_crypto_sign_detached($data, $key) . $data);
echo base64_encode(sodium_crypto_sign_publickey_from_secretkey($key));
"""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download():
    token = os.environ.get("WORDFENCE_INTELLIGENCE_TOKEN")
    if not token:
        raise ValueError("Set WORDFENCE_INTELLIGENCE_TOKEN in the build environment.")
    request = Request(DEFAULT_FEED, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "User-Agent": "Site Defense database publisher",
    })
    with build_opener(NoRedirects()).open(request, timeout=75) as response:
        payload = response.read(MAX_FEED_BYTES + 1)
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("Source feed exceeds size limit.")
    return json.loads(payload)


def normalize(feed):
    if not isinstance(feed, dict) or not feed:
        raise ValueError("Source feed is empty or invalid.")
    records = {}
    licenses = {}
    for item in feed.values():
        links = item.get("references", [])
        origin = next((url for url in links if url.startswith((
            "https://www.wordfence.com/threat-intel/", "http://www.wordfence.com/threat-intel/"
        ))), "")
        origin = origin or next((url for url in links if url.startswith("https://")), "")
        notices = []
        for notice in (item.get("copyrights") or {}).values():
            if not isinstance(notice, dict):
                continue
            entry = [notice.get("notice", ""), notice.get("license", ""), notice.get("license_url", "")]
            key = json.dumps(entry, ensure_ascii=False)
            index = licenses.setdefault(key, len(licenses))
            notices.append(index)
        for software in item["software"]:
            kind = software["type"]
            if kind not in {"core", "plugin", "theme"}:
                continue
            slug = "wordpress" if kind == "core" else software["slug"]
            # Some upstream records identify a GitHub-distributed component by its repository URL.
            repository = GITHUB_REPOSITORY.fullmatch(slug)
            if repository:
                slug = repository[1]
            if not slug:
                continue
            ranges = [
                [entry["from_version"], entry["from_inclusive"], entry["to_version"], entry["to_inclusive"]]
                for entry in software["affected_versions"].values()
            ]
            if not ranges:
                continue
            key = f"{kind}:{slug}"
            records.setdefault(key, []).append([
                item["id"], item["title"], item.get("cve"), (item.get("cvss") or {}).get("score"),
                ranges, software["patched_versions"], origin, notices, bool(item.get("informational")),
            ])
    if not records:
        raise ValueError("Source feed contains no usable records.")
    return records, [json.loads(key) for key in licenses]


def write_atomic(destination, data):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    try:
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def load_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--seed-dir", type=Path)
    parser.add_argument("--url", default="")
    parser.add_argument("--input", type=Path, help="Previously downloaded Wordfence Production Feed JSON")
    return parser.parse_args()


def main():
    args = load_args()
    if args.url:
        url = urlparse(args.url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Update URL must be a public HTTPS URL without credentials, a query or a fragment.")
    feed = json.loads(args.input.read_bytes()) if args.input else download()
    records, licenses = normalize(feed)
    version = int(time.time())
    header = {"schema": 2, "version": version, "licenses": licenses}
    lines = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in [header, *records.items()])
    database = ("\n".join(lines) + "\n").encode("utf-8")
    if len(database) > MAX_DATABASE_BYTES:
        raise ValueError("Normalized database exceeds size limit.")
    compressed = gzip.compress(database, mtime=0)
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "database.json.gz"
        package = Path(temporary) / "database.pack"
        source.write_bytes(compressed)
        public_key = subprocess.check_output(
            ["php", "-r", SIGN, str(args.signing_key.resolve()), str(source), str(package)],
            text=True,
        ).strip()
        write_atomic(args.output / f"database-{version}.pack", package.read_bytes())
    write_atomic(args.output / "latest.json", json.dumps({"version": version}).encode("utf-8"))
    if args.seed_dir:
        config_file = args.seed_dir / "update.json"
        config = json.loads(config_file.read_bytes()) if config_file.exists() else {}
        config.update({"url": args.url.rstrip("/"), "public_key": public_key, "seed_version": version})
        write_atomic(args.seed_dir / "vulnerabilities.json.gz", compressed)
        write_atomic(config_file, (json.dumps(config, indent=2) + "\n").encode("utf-8"))
    print(f"{sum(map(len, records.values())):,} component advisories in database {version}.")


if __name__ == "__main__":
    main()

