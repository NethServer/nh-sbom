# Utilities

This directory contains a collection of utilities that are used in the project.

## eol-finder.py

This script parses a SBOM in JSON format and generated by Trivy.
Then it searches the SBOM for distributions in End of Life (EOL). If any is found, it generates an issue in the repository.

### Usage

You can run the following command to generate a SBOM:

```bash
podman run --rm docker.io/aquasec/trivy image ghcr.io/nethserver/nethsecurity-vpn:latest -f json > sbom.json
```

To parse the SBOM:
```bash
GITHUB_TOKEN=$(gh auth token) ./eol-finder.py sbom.json nethserver nh-sbom
```


## sbom-uploader.py

The scripts uploads the SBOM to the [Dependency Track](https://dependencytrack.org/) server.
The script will:

- create top-level projects like "ns8", "nethsecurity" and so on
- for each repository, create a project with the same name
- searches the latest release of the repository
- upload all SBOMs in the release

Please note that the script will preserve only the latest release of the repository and SBOMs.

### Usage

Usage example:
```bash
DEPENDECY_TRACK_TOKEN=xxx GITHUB_TOKEN=$(gh auth token) python3 sbom-uploader.py --dependency-track-api-url "http://dt.gs.nethserver.net:8081/api/v1" --log-level=INFO --repos-file sbom-repositories.json 
```