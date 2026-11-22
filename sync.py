import os
import shutil
import lzma
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List

import requests

# GitHub repository details
owner = "fkie-cad"
repo = "nvd-json-data-feeds"
api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"

# Local paths
local_dir = "nvd_files"
xz_dir = "releases"

# List of software to process, with every CPE prefix used for it in the NVD (older entries often use a former
# vendor or product name)
software_list = {
    "angularjs": ["cpe:2.3:a:angularjs:angular.js:", "cpe:2.3:a:angularjs:angularjs:"],
    "apache": ["cpe:2.3:a:apache:http_server:"],
    "cherokee": [
        "cpe:2.3:a:cherokee-project:cherokee:",
        "cpe:2.3:a:cherokee-project:cherokee_web_server:",
        "cpe:2.3:a:cherokee:cherokee:",
        "cpe:2.3:a:cherokee:cherokee_httpd:",
    ],
    "drupal": ["cpe:2.3:a:drupal:drupal:"],
    "iis": [
        "cpe:2.3:a:microsoft:internet_information_services:",
        "cpe:2.3:a:microsoft:internet_information_server:",
    ],
    "jetty": [
        "cpe:2.3:a:eclipse:jetty:",
        "cpe:2.3:a:mortbay:jetty:",
        "cpe:2.3:a:mortbay_jetty:jetty:",
        "cpe:2.3:a:jetty:jetty:",
        "cpe:2.3:a:jetty:jetty_http_server:",
    ],
    "joomla": ["cpe:2.3:a:joomla:joomla:", "cpe:2.3:a:joomla:joomla\\!:", "cpe:2.3:a:mamboserver:joomla:"],
    "jquery": ["cpe:2.3:a:jquery:jquery:"],
    "nextjs": ["cpe:2.3:a:vercel:next.js:", "cpe:2.3:a:zeit:next.js:"],
    # nginx_plus is left out: its versions (R31...) are not those of the open source releases detected by Wapiti
    "nginx": ["cpe:2.3:a:f5:nginx:", "cpe:2.3:a:f5:nginx_open_source:", "cpe:2.3:a:nginx:nginx:"],
    "nodejs": ["cpe:2.3:a:nodejs:node.js:", "cpe:2.3:a:nodejs:nodejs:", "cpe:2.3:a:joyent:node.js:"],
    "openssl": ["cpe:2.3:a:openssl:openssl:"],
    "php": ["cpe:2.3:a:php:php:", "cpe:2.3:a:php_group:php:"],
    "prestashop": ["cpe:2.3:a:prestashop:prestashop:"],
    "spip": ["cpe:2.3:a:spip:spip:"],
    "tomcat": ["cpe:2.3:a:apache:tomcat:"],
    "underscorejs": ["cpe:2.3:a:underscorejs:underscore:"],
    "weblogic": [
        "cpe:2.3:a:oracle:weblogic_server:",
        "cpe:2.3:a:bea:weblogic_server:",
        "cpe:2.3:a:bea_systems:weblogic_server:",
    ],
    "wordpress": ["cpe:2.3:a:wordpress:wordpress:"],
}

# A software without any new CVE for that long probably got a new CPE name in the NVD (vendor bought, product
# renamed...): its CVEs would then silently stop reaching Wapiti.
STALE_AFTER = timedelta(days=365)
# Software that rarely gets CVEs anymore (end of life, small codebase), not checked
NOT_CHECKED_FOR_STALENESS = {"angularjs", "cherokee", "iis", "jquery"}
# Written in xz_dir when some software look stale, so that the workflow can report it
STALE_REPORT = "stale_software.txt"

cve_archive_pattern = re.compile(r"CVE-\d{4}\.json\.xz$")


def download_file(url, local_path):
    print(f"Downloading {url}")
    response = requests.get(url, timeout=300)
    response.raise_for_status()
    with open(local_path, "wb") as file:
        file.write(response.content)


def process_releases():
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)
    os.makedirs(local_dir, exist_ok=True)

    response = requests.get(api_url, timeout=60)
    response.raise_for_status()
    releases = response.json()

    for release in releases:
        for asset in release["assets"]:
            if cve_archive_pattern.match(asset["name"]):
                local_path = os.path.join(local_dir, asset["name"])
                download_file(asset["browser_download_url"], local_path)


def iter_vulnerable_cpe_matches(cve_item: Dict[str, Any], cpe_ids: List[str]):
    """Yields (cpe_match, cpe_id) for the CPE matches of the software flagged as vulnerable.

    Configurations also list the platform a vulnerable product runs on (a WordPress plugin running on WordPress,
    mod_ssl running with OpenSSL...) with vulnerable set to false: such matches do not make the software vulnerable.
    """
    for configuration in cve_item.get("configurations", []):
        for node in configuration.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                for cpe_id in cpe_ids:
                    if cpe_match["criteria"].startswith(cpe_id):
                        yield cpe_match, cpe_id
                        break


def get_english_description(cve: Dict[str, Any]) -> str:
    for description in cve.get("descriptions", []):
        if description["lang"] == "en":
            return description["value"]
    return ""


def get_cvss_scores(cve: Dict[str, Any]) -> Dict[str, float]:
    scores = {}
    for mykey, nvdkey in [
        ("cvss2", "cvssMetricV2"),
        ("cvss3", "cvssMetricV3"),
        ("cvss3.1", "cvssMetricV31"),
        ("cvss4", "cvssMetricV40"),
    ]:
        try:
            primary_scores = [
                metric for metric in cve.get("metrics", {}).get(nvdkey, []) if metric.get("type") == "Primary"
            ]
            if primary_scores:
                scores[mykey] = primary_scores[0].get("cvssData", {}).get("baseScore")
        except (KeyError, IndexError):
            pass
    return scores


def get_version_range(cpe_match: Dict[str, Any]) -> List[Any]:
    start = end = None

    if "versionStartIncluding" in cpe_match:
        start = ">=" + cpe_match["versionStartIncluding"]
    elif "versionStartExcluding" in cpe_match:
        start = ">" + cpe_match["versionStartExcluding"]

    if "versionEndIncluding" in cpe_match:
        end = "<=" + cpe_match["versionEndIncluding"]
    elif "versionEndExcluding" in cpe_match:
        end = "<" + cpe_match["versionEndExcluding"]

    return [start, end]


def get_vulnerable_versions(cpe_match: Dict[str, Any], cpe_id: str):
    version = cpe_match["criteria"].removeprefix(cpe_id).split(":")[0]  # we do not handle second information like "rc1"
    if version in ("*", "-"):
        version_range = get_version_range(cpe_match)
        if version_range == [None, None]:
            return
        return version_range
    else:
        return version


def get_all_vulnerable_versions(cve: Dict[str, Any], cpe_ids: List[str]) -> List:
    result = []
    for cpe_match, cpe_id in iter_vulnerable_cpe_matches(cve, cpe_ids):
        versions = get_vulnerable_versions(cpe_match, cpe_id)
        if versions is not None and versions not in result:
            result.append(versions)
    return result


def shrink_cve(cve: Dict[str, Any], versions: List) -> Dict[str, Any]:
    new_cve = {
        "id": cve["id"],
        "description": get_english_description(cve),
    }
    new_cve.update(get_cvss_scores(cve))
    new_cve["versions"] = versions
    return new_cve


def find_stale_software(last_published: Dict[str, str], now: datetime) -> List[str]:
    """Returns a description of the checked software whose most recent CVE is older than STALE_AFTER."""
    stale = []
    for software in software_list:
        if software in NOT_CHECKED_FOR_STALENESS:
            continue
        published = last_published.get(software)
        if published is None:
            stale.append(f"{software}: no CVE found")
        elif now - datetime.fromisoformat(published).replace(tzinfo=timezone.utc) > STALE_AFTER:
            stale.append(f"{software}: last CVE published on {published[:10]}")
    return stale


def create_software_json_files():
    if os.path.exists(xz_dir):
        shutil.rmtree(xz_dir)

    os.makedirs(xz_dir, exist_ok=True)

    software_cves = {software: [] for software in software_list}
    last_published = {}
    # Each archive is decompressed and parsed once for all the software
    for file in sorted(os.listdir(local_dir)):
        if not cve_archive_pattern.match(file):
            continue

        print(f"Processing {file}")
        with lzma.open(os.path.join(local_dir, file), "rt") as f:
            cve_items = json.load(f).get("cve_items", [])

        for cve in cve_items:
            for software, cpe_ids in software_list.items():
                if any(True for _ in iter_vulnerable_cpe_matches(cve, cpe_ids)):
                    software_cves[software].append(shrink_cve(cve, get_all_vulnerable_versions(cve, cpe_ids)))
                    published = cve.get("published", "")
                    if published > last_published.get(software, ""):
                        last_published[software] = published

    for software, cves in software_cves.items():
        print(f"Creating JSON file for {software} ({len(cves)} CVEs, last published {last_published.get(software)})")
        if cves:
            software_file = os.path.join(xz_dir, f"{software}.json.xz")
            with lzma.open(software_file, "wt") as sf:
                json.dump(cves, sf)

    stale = find_stale_software(last_published, datetime.now(timezone.utc))
    if stale:
        with open(os.path.join(xz_dir, STALE_REPORT), "w", encoding="utf-8") as report:
            report.write("\n".join(stale) + "\n")
        for line in stale:
            print(f"Possibly stale: {line}")


if __name__ == "__main__":
    process_releases()
    create_software_json_files()
