# Utilities

This directory contains a collection of utilities that are used in the project.

## eol-finder.py

This script parses a SBOM in JSON format and generated by Trivy.
Then it searches the SBOM for distributions in End of Life (EOL). If any is found, it generates an issue in the repository.

### Usage

You can run the following command to generate an SBOM:

```bash
podman run --rm docker.io/aquasec/trivy image ghcr.io/nethserver/nethsecurity-vpn:latest -f json > sbom.json
```

To parse the SBOM:
```bash
GITHUB_TOKEN=$(gh auth token) ./eol-finder.py sbom.json nethserver nh-sbom
```


Then use the generated SBOM with the script like this: