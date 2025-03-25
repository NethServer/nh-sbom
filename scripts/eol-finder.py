#!/usr/bin/python3

#
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""
This script performs the following tasks:
1. Evaluates all repositories listed in a given JSON file.
2. For each repository, it fetches the latest release and extracts SBOMs (Software Bill of Materials).
3. Analyzes each SBOM to identify components that have reached End-of-Life (EOL) using data from endoflife.date.
4. If EOL components are found, it creates a draft security advisory in the nh-sbom repository, if it does not already exist.

The script is intended to be run as a GitHub Action, triggered by a scheduled event.

To run the script from the command line, use the following command:
  GITHUB_TOKEN=$(gh auth token) eol-finder.py repositories.json
"""


import os
import sys
import requests
import json
from datetime import datetime
import hashlib

eol_info = {}

def parse_repository_file(repository_file):
    if not os.path.exists(repository_file):
        print(f"File {repository_file} does not exist.", file=sys.stderr)
        sys.exit(1)

    with open(repository_file, 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON file {repository_file}: {e}", file=sys.stderr)
            sys.exit(1)

    repositories = []
    for priority, urls in data.items():
        for url in urls:
            parts = url.split("/")
            if len(parts) >= 5:
                repo_owner = parts[-2]
                repo_name = parts[-1]
                repositories.append({"owner": repo_owner, "name": repo_name, "priority": priority})
            else:
                print(f"Invalid repository URL: {url}", file=sys.stderr)

    return repositories

def get_latest_release(repo_owner, repo_name, github_token):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"
    headers = {"Authorization": f"token {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"WARNING: Failed to fetch latest release for {repo_owner}/{repo_name}: {response.status_code}", file=sys.stderr)
        return None

    return response.json()

def extract_files_from_release(release):
    assets = release.get("assets", [])
    extracted_files = {}

    for asset in assets:
        if asset["name"].endswith(".cdx.json"):
            download_url = asset["browser_download_url"]
            response = requests.get(download_url)

            if response.status_code == 200:
                extracted_files[asset["name"]] = response.content
            else:
                print(f"Failed to download {asset['name']}: {response.status_code}", file=sys.stderr)

    return extracted_files

def parse_sbom(sbom_content, eol_components):
    try:
        sbom = json.loads(sbom_content)
    except json.JSONDecodeError as e:
        print(f"Error parsing SBOM content: {e}")
        return []
    ret = set()
    components = sbom.get("components", [])
    for component in components:
        if "name" in component and "version" in component:
            if component['name'] not in eol_components:
                # print(f"WARNING: {component['name']} is not in the EOL database.", file=sys.stderr)
                continue
            else:
                version_parts = component["version"].split(".")
                cycle = ".".join(version_parts[:2]) if len(version_parts) >= 2 else component["version"]
                # print(f"INFO: {component['name']} {component['version']} {cycle}", file=sys.stderr)
                ret.add((component["name"], component["version"], cycle))
    return ret

def get_component_list():
    metadata_url = f"https://endoflife.date/api/all.json"
    response = requests.get(metadata_url)
    if response.status_code == 200:
        metadata = response.json()
        return metadata
    else:
        raise Exception(f"Failed to fetch metadata for all components: {response.status_code}")

def get_eol_info(component):
    if component in eol_info:
        return eol_info[component]

    metadata_url = f"https://endoflife.date/api/{component}.json"
    response = requests.get(metadata_url)

    if response.status_code == 200:
        metadata = response.json()
        eol_info[component] = metadata
        return metadata
    else:
        print(f"Failed to fetch metadata for {component}: {response.status_code}", file=sys.stderr)
        return None

def is_eol(cycle_metadata, cycle):
    for cycle_info in cycle_metadata:
        if cycle_info['cycle'] == cycle:
            # format of eol field: 2026-11-01'
            if type(cycle_info['eol']) == str:
                eol_date = datetime.strptime(cycle_info['eol'], '%Y-%m-%d')
                if datetime.today() > eol_date:
                    return True
    return False

def get_advisories(github_token):
    existing_advisories_url = "https://api.github.com/repos/NethServer/nh-sbom/security-advisories"
    response = requests.get(existing_advisories_url, headers={"Authorization": f"token {github_token}"})
    if response.status_code == 200:
        existing_advisories = response.json()
        return existing_advisories
    else:
        print("Failed to retrieve existing advisories:", response.json(), file=sys.stderr)
        return None

def create_draft_advisory(repository, sbom, component_name, component_version, github_token):
    # Calculate a unique MD5 ID for the advisory
    unique_string = f"{repository}:{sbom}:{component_name}:{component_version}"
    advisory_id = hashlib.md5(unique_string.encode()).hexdigest()

    # Check if an advisory with the same ID already exists
    existing_advisories = get_advisories(github_token)
    if existing_advisories:
        for advisory in existing_advisories:
            if advisory["summary"].startswith(advisory_id):
                print(f"INFO: Advisory with ID {advisory_id} already exists. Skipping creation.", file=sys.stderr)
                return True
 
    advisory_description = f"Advisory ID: **{advisory_id}**\nThe component **{component_name}-{component_version}** is EOL.\nSBOM: **{sbom}** inside **{repository}**."

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }

    advisory_data = {
        "summary": f"{advisory_id}: EOL for {repository}, {component_name}-{component_version}",
        "description": advisory_description,
        "severity": "low",
        "vulnerabilities": [{"package": {"name": component_name, "ecosystem": "other"}, "vulnerable_version_range": component_version}]
    }

    response = requests.post("https://api.github.com/repos/NethServer/nh-sbom/security-advisories", headers=headers, json=advisory_data)
    if response.status_code == 201:
        print(f"INFO: Draft security advisory created successfully for {repository}", file=sys.stderr)
        return True
    else:
        print("ERROR: Failed to create draft security advisory for {repository}:", response.json(), file=sys.stderr)
        return False


def main():
    # Read GITHUB_TOKEN from environment variables
    gh_token = os.getenv('GITHUB_TOKEN')
    if not gh_token:
        print("GITHUB_TOKEN environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    # Read repository.json file from command line parameters
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <repository_json_file>")
        sys.exit(1)

    repository_file = sys.argv[1]

    error = False
    eol_components = get_component_list()
    repositories = parse_repository_file(repository_file)

    for repo in repositories:
        if not repo.get("owner") or not repo.get("name"):
            continue
        print(f"INFO: Checking repository '{repo.get('owner')}/{repo.get('name')}'")
        release = get_latest_release(repo.get("owner"), repo.get("name"), gh_token)
        if not release:
            continue

        extracted_files = extract_files_from_release(release)
        if not extracted_files:
            print(f"WARNING: No SBOM files found in the latest release of {repo.get('owner')}/{repo.get('name')}", file=sys.stderr)
            continue
        for file_name, content in extracted_files.items():
            components = parse_sbom(content, eol_components)
            for component in components:
                # component is a tuple of (name, version, cycle)
                cycle_metadata = get_eol_info(component[0])
                if is_eol(cycle_metadata, component[2]):
                    print(f"INFO: Repository '{repo.get("owner")}/{repo.get("name")}', File '{file_name}', Component '{component[0]}', Version '{component[1]}' is EOL.", file=sys.stderr)
                    error = error and create_draft_advisory(f'{repo.get("owner")}/{repo.get("name")}', file_name, component[0], component[1], gh_token)

    if error:
        sys.exit(1)

if __name__ == "__main__":
    main()
