#!/usr/bin/python3

import os
import sys
import requests
import json

def parse_report(report_file):
    try:
        with open(report_file, 'r') as file:
            report = json.load(file)
        image = report["ArtifactName"]
        os_metadata = report['Metadata']['OS']
        distro_name = os_metadata['Family']
        distro_version = os_metadata['Name']
        eosl = os_metadata.get('EOSL')
    except:
        print("Invalid SBOM format: {report_file}", file=sys.stderr)
        sys.exit(1)
    return image, distro_name, distro_version, eosl

def create_issue(image, distro_name, distro_version, token, owner, repo):
    # extract the image name and tag
    image_parts = image.split('/')
    image_name = image_parts[-1]
    image_parts = image_name.split(':')

    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    issue_data = {
        "title": f"{image_parts[0]}: {distro_name} {distro_version} is EOL",
        "body": f"The image **{image}** uses the base Linux distribution **{distro_name}** version **{distro_version}** which is end-of-life.",
    }
    response = requests.post(url, headers=headers, json=issue_data)

    if response.status_code == 201:
        print(f"Issue created successfully: {response.json().get('html_url')}")
        sys.exit(0)
    else:
        print(f"Failed to create issue: {response.status_code} - {response.text}")
        sys.exit(1)


def main():
    # Read GITHUB_TOKEN from environment variables
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    if not GITHUB_TOKEN:
        print("GITHUB_TOKEN environment variable is not set.")
        sys.exit(1)

    # Read repository owner and name from command line parameters
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} <sbom_json_file> <repo_owner> <repo_name>")
        sys.exit(1)

    report_file = sys.argv[1]
    repo_owner = sys.argv[2]
    repo_name = sys.argv[3]

    if not os.path.exists(report_file):
        print(f"File {report_file} does not exist.")
        sys.exit(1)

    # Parse the Trivy report
    image, distro_name, distro_version, eosl = parse_report(report_file)

    # Check if the base Linux distribution is EOL
    if eosl:
        print(f"The base Linux distribution {distro_name} {distro_version} is EOL.")
        create_issue(image, distro_name, distro_version, GITHUB_TOKEN, repo_owner, repo_name)

if __name__ == "__main__":
    main()
