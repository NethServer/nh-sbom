#!/usr/bin/python3

#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# This script performs the following tasks:
# 1. Evaluates all repositories listed in a given JSON file.
# 2. For each repository, it fetches the latest release and extracts SBOMs (Software Bill of Materials).
# 3. Uploads each SBOM to Dependency Track.
#
# The DEPENDENCY_TRACK_TOKEN and GITHUB_TOKEN environment variables must be set.
# The DEPENDENCY_TRACK_TOKEN must have the following permissions:
# - BOM_UPLOAD
# - PORTFOLIO_MANAGEMENT
# - PROJECT_CREATION_UPLOAD
# - VIEW_PORTFOLIO

import os
import sys
import json
import requests
import argparse
import re
import logging

DEPENDECY_TRACK_TOKEN = os.environ.get("DEPENDECY_TRACK_TOKEN")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
DT_API_URL = ""
logger = None

def extract_version(asset_name):
  # Remove extension
  base = asset_name.replace(".cdx.json", "").replace(".bom", "")
  # Try to find version-like patterns: digits and dashes, possibly with 'v' or 'pg'
  m = re.search(r'[-_](v?\d[\w\-\.]*)$', base)
  if m:
    return m.group(1).lstrip('-_')
  # Fallback: return 'latest'
  return "latest"

def extract_name(asset_name):
  name = asset_name
  # Remove known extensions
  for ext in [".cdx.json", ".bom"]:
    if name.endswith(ext):
      name = name[: -len(ext)]
  # Special cases
  if name in ("imageroot", "ui", "php"):
    return name
  # Remove version suffix (e.g., -v1-8-0, -2-16-1-pg16, etc.)
  name = re.sub(r'[-_](v?\d[\w\-\.]*)(-x86-64-generic)?$', '', name)
  return name.replace("-", ".", count=3)

def read_repo_file(repos_file):
  with open(repos_file) as f:
    return json.load(f)

def get_latest_release(owner, repo):
  url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
  headers = {"Authorization": f"token {GITHUB_TOKEN}"}
  resp = requests.get(url, headers=headers)
  if resp.status_code != 200:
    return None
  return resp.json()

def download_asset(asset_url, filename):
  headers = {"Accept": "application/octet-stream"}
  resp = requests.get(asset_url, headers=headers, stream=True)
  if resp.status_code == 200:
    with open(filename, "wb") as f:
      for chunk in resp.iter_content(chunk_size=8192):
        f.write(chunk)
    return True
  return False

def upload_sbom(sbom, project_id):
  url = f"{DT_API_URL}/bom"
  headers = {"X-Api-Key": DEPENDECY_TRACK_TOKEN}
  files = {
    "bom": (os.path.basename(sbom), open(sbom, "rb"), "application/json")
  }
  data = {
    "project": project_id
  }
  resp = requests.post(url, headers=headers, files=files, data=data)
  if resp.status_code != 200:
    logger.warning(f"Failed to upload SBOM {sbom} to {project_id}: {resp.text}")
  try:
    return resp.json()
  except Exception:
    return {"error": resp.text}

def get_project(project_name):
  url = f"{DT_API_URL}/project?pageNumber=1&pageSize=10000"
  headers = {"X-Api-Key": DEPENDECY_TRACK_TOKEN, "Accept": "application/json"}
  resp = requests.get(url, headers=headers)
  if resp.status_code != 200:
    return None, None
  projects = resp.json()
  for proj in projects:
    if proj.get("name") == project_name:
      return proj.get("uuid"), proj.get("version")
  return None, None

def create_project(project_name, parent_id=None, version=None, has_children=True):
  url = f"{DT_API_URL}/project"
  headers = {
    "X-Api-Key": DEPENDECY_TRACK_TOKEN,
    "Content-Type": "application/json"
  }
  payload = {
    "name": project_name,
    "accessTeams": [],
    "collectionLogic": "AGGREGATE_DIRECT_CHILDREN" if has_children else None,
    "collectionTag": None,
    "tags": [project_name],
    "active": True,
    "isLatest": False,
    "version": version,
  }
  if parent_id:
    payload["parent"] = {"uuid": parent_id}
  logger.debug(f"create_project {project_name} with parent {parent_id}, payload: {payload}")
  resp = requests.put(url, headers=headers, json=payload)
  respo_data = resp.json()
  logger.debug(f"create_project: response code {resp.status_code} response data {respo_data}")
  logger.debug(f"create_project {project_name} created with ID {respo_data.get('uuid')}")
  return respo_data.get("uuid")

def update_project_version(project_id, version):
  url = f"{DT_API_URL}/project/{project_id}"
  headers = {
    "X-Api-Key": DEPENDECY_TRACK_TOKEN,
    "Content-Type": "application/json"
  }
  payload = {
    "uuid": project_id,
    "version": version
  }
  logger.debug(f"update_project_version {project_id} to {version}")
  resp = requests.patch(url, headers=headers, json=payload)
  if resp.status_code != 200 and resp.status_code != 304:
    logger.warning(f"Failed to update project version: {resp.status_code}")


def process_asset(asset, repo_name, parent_id):
  asset_name = asset["name"]
  asset_url = asset["browser_download_url"]
  sbom = f"./{asset_name}"
  if not download_asset(asset_url, sbom):
    logger.warning(f"Failed to download {asset_name}")
    return
    
  if asset_name == "imageroot.cdx.json":
    project_name = f"{repo_name}-imageroot"
  elif asset_name == "ui.cdx.json":
    project_name = f"{repo_name}-ui"
  elif asset_name == "php.cdx.json":
    project_name = f"{repo_name}-php"
  elif asset_name == "sbom.cdx.json":
    project_name = f"{repo_name}-sbom"
  else:
    project_name = extract_name(asset_name)
    
  version = extract_version(asset_name)
  project_id, _ = get_project(project_name)
  logger.debug(f"Asset {asset_name} version {version} parent {parent_id}")
  if not project_id:
    project_id = create_project(project_name, parent_id, version, has_children=False)

  logger.debug(f"Uploading SBOM {sbom}. Project: {project_name} ({project_id}), Version: {version}")
  response = upload_sbom(sbom, project_id)
  if "token" not in response:
    logger.error(f"Failed to upload SBOM: {response}")
  else:
    logger.debug(f"Uploaded SBOM: {response}")
  os.remove(sbom)

def process_repo(parent_project, repo_url):
  if "github.com/" not in repo_url:
    return
  try:
    owner, repo_name = repo_url.split("github.com/")[1].split("/", 1)
    repo_name = repo_name.split("/")[0]
  except Exception:
    return
  logger.info(f"Processing repository {owner}/{repo_name}")
  release_info = get_latest_release(owner, repo_name)
  if not release_info or release_info.get("tag_name") is None:
    logger.warning(f"No releases found for repository {owner}/{repo_name}")
    return
  version = release_info["tag_name"]
  logger.info(f"Processing repository {owner}/{repo_name}, version {version}")
  project_id, project_version = get_project(repo_name)
  if not project_id:
    project_id = create_project(repo_name, get_project(parent_project)[0], version)
  else:
    if project_version != version:
      logger.info(f"Updating project {repo_name} version from {project_version} to {version}")
      update_project_version(project_id, version)
    else:
      logger.info(f"Project {repo_name} version is already up to date ({version})")
      return
  assets = [a for a in release_info.get("assets", []) if a["name"].endswith(".cdx.json")]
  for asset in assets:
    logger.info(f"Processing asset {asset['name']}")
    process_asset(asset, repo_name, project_id)

def main():
  global DT_API_URL
  global logger

  if not DEPENDECY_TRACK_TOKEN:
    print("DEPENDECY_TRACK_TOKEN not found", file=sys.stderr)
    sys.exit(1)

  if not GITHUB_TOKEN:
    print("GITHUB_TOKEN not found", file=sys.stderr)
    sys.exit(1)

  parser = argparse.ArgumentParser(description="SBOM Uploader")
  parser.add_argument("--dependency-track-api-url", help="Dependency Track API URL. Example: http://dt.gs.nethserver.net:8081/api/v1")
  parser.add_argument("--repos-file", required=True, help="Repositories JSON file")
  parser.add_argument("--log-level", default="WARNING", help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
  args = parser.parse_args()

  DT_API_URL = args.dependency_track_api_url

  logging.basicConfig(
    level=getattr(logging, args.log_level.upper(), logging.WARNING),
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()]
  )
  logger = logging.getLogger("sbom_uploader")
  logger.setLevel(getattr(logging, args.log_level.upper(), logging.WARNING))

  repos = read_repo_file(args.repos_file)
  for project in repos:
    # Create top-level project if it doesn't exist
    if not get_project(project)[0]:
      create_project(project)
    for repo_url in repos[project]:
      process_repo(project, repo_url)

if __name__ == "__main__":
  main()
