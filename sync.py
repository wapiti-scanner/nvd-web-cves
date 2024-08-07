import os
import shutil
import lzma
import json
import re
from typing import Dict, Any, List

import requests

# GitHub repository details
owner = "fkie-cad"
repo = "nvd-json-data-feeds"
api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"

# Local paths
local_dir = "nvd_files"
xz_dir = "releases"

# List of software to process
software_list = {
    "angularjs": "cpe:2.3:a:angularjs:angular.js:",
    "apache": "cpe:2.3:a:apache:http_server:",
    "drupal": "cpe:2.3:a:drupal:drupal:",
    "iis": "cpe:2.3:a:microsoft:internet_information_services:",
    "jetty": "cpe:2.3:a:eclipse:jetty:",
    "joomla": "cpe:2.3:a:joomla:joomla:",
    "jquery": "cpe:2.3:a:jquery:jquery:",
    "nextjs": "cpe:2.3:a:vercel:next.js:",
    "nginx": "cpe:2.3:a:f5:nginx:",
    "nodejs": "cpe:2.3:a:nodejs:node.js:",
    "openssl": "cpe:2.3:a:openssl:openssl:",
    "php": "cpe:2.3:a:php:php:",
    "prestashop": "cpe:2.3:a:prestashop:prestashop:",
    "spip": "cpe:2.3:a:spip:spip:",
    "tomcat": "cpe:2.3:a:apache:tomcat:",
    "underscorejs": "cpe:2.3:a:underscorejs:underscore:",
    "weblogic": "cpe:2.3:a:oracle:weblogic_server:",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:",
}

cve_archive_pattern = re.compile(r"CVE-\d{4}.json.xz")


def download_file(url, local_path):
    print(f"Downloading {url}")
    response = requests.get(url)
    response.raise_for_status()
    with open(local_path, "wb") as file:
        file.write(response.content)


def process_releases():
    if os.path.exists(local_dir):
        shutil.rmtree(local_dir)
    os.makedirs(local_dir, exist_ok=True)

    response = requests.get(api_url)
    response.raise_for_status()
    releases = response.json()

    for release in releases:
        for asset in release["assets"]:
            if cve_archive_pattern.match(asset["name"]):
                local_path = os.path.join(local_dir, asset["name"])
                download_file(asset["browser_download_url"], local_path)


def cve_matches_cpe_id(cve_item: Dict[str, Any], cpe_id: str) -> bool:
    for configuration in cve_item.get("configurations", []):
        for node in configuration.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match["criteria"].startswith(cpe_id):
                    return True
    return False


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
    if not cpe_match["criteria"].startswith(cpe_id):
        return

    version = cpe_match["criteria"].removeprefix(cpe_id).split(":")[0]  # we do not handle second information like "rc1"
    if version in ("*", "-"):
        version_range = get_version_range(cpe_match)
        if version_range == [None, None]:
            return
        return version_range
    else:
        return version


def get_all_vulnerable_versions(configurations: List[Dict[str, Any]], cpe_id: str) -> List:
    result = []
    for configuration in configurations:
        for node in configuration["nodes"]:
            for cpeMatch in node["cpeMatch"]:
                versions = get_vulnerable_versions(cpeMatch, cpe_id)
                if versions is not None and versions not in result:
                    result.append(versions)
    return result


def shrink_cve(cve: Dict[str, Any], cpe_id: str) -> Dict[str, Any]:
    new_cve = {
        "id": cve["id"],
        "description": get_english_description(cve),
    }
    new_cve.update(get_cvss_scores(cve))
    new_cve["versions"] = get_all_vulnerable_versions(cve["configurations"], cpe_id)
    return new_cve


def create_software_json_files():
    if os.path.exists(xz_dir):
        shutil.rmtree(xz_dir)

    os.makedirs(xz_dir, exist_ok=True)

    for software, cpeid in software_list.items():
        print(f"Creating JSON file for {software}")
        software_cves = []
        for root, _, files in os.walk(local_dir):
            for file in files:
                if file.endswith(".json.xz"):
                    file_path = os.path.join(root, file)
                    with lzma.open(file_path, "rt") as f:
                        data = json.load(f)
                        cve_items = data.get("cve_items", [])

                        for cve in cve_items:
                            if cve_matches_cpe_id(cve, cpeid):
                                software_cves.append(shrink_cve(cve, cpeid))

        if software_cves:
            software_file = os.path.join(xz_dir, f"{software}.json.xz")
            with lzma.open(software_file, "wt") as sf:
                json.dump(software_cves, sf)


if __name__ == "__main__":
    process_releases()
    create_software_json_files()
