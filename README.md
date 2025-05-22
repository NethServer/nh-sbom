# SBOM and dependency management

This repository contains the documentation and tools for the SBOM and dependency management process.

## Tools and file formats

During the release phase of a version, when a repository is tagged with a stable version (see conventional commit), it is necessary to:

- generate an SBOM (Software Bill of Materials)
- publish the SBOM in  as an attachment to the release

Chosen tool: [Trivy](https://trivy.dev/latest/)

The SBOM must be generated in three formats:

- **Standard CVE SARIF**: Integrated into GitHub code scanning.
- **GitHub Dependency Graph format**: Serves as a snapshot under *Insights*, does not maintain a history.
- **CycloneDX**: Must be included in the release with a name ending in `.cdx.json`

## Work plan

### Objective 1: Inventory of EOL distributions (DONE)

1. A GitHub Action has been implemented for NS8 to generate and upload the SBOM. Engine: [Trivy](https://trivy.dev).
   The action uploads the SBOM:  
     - As an attachment in CyCloneDX and SARIF format in the repository release.  
     - To the repository dependency graph.  

2. A scraper has been implemented as a GitHub Action to read EOL information from an SBOM.  
   For each EOL distribution, a new security advisory is created in this repository.

### Objective 2: Rationalization of dependencies

Use Renovate for dependency management, while Dependabot only for alerts (without automatic pull requests).
To do:

1. [Configure Dependabot](https://handbook.nethserver.org/security/#repository-configuration) for all repositories
2. Create a configuration file for Renovate that can be inherited by all NS8 repositories
   Default behavior:
   - if there are no tests, automatically merge patch versions, no automatic merge for minor and major versions
   - if there are tests, automatically merge all versions (to be implemented as an override on individual projects)
3. Create a common configuration file for Renovate for all non-NS8 projects, such as UIs

To be done by: May 2025

### Objective 3: Integration with the development cycle

Define internal governance for EOL and dependencies, balancing political and technical aspects.
The governance must be able to:
1. Coordinate work, allocating time for managing vulnerabilities and EOL
2. Provide guidelines on choices to be made in case of EOL or vulnerabilities
3. Decide on timing and methods of communication about vulnerabilities and updates
4. Define guidelines for choosing distributions when creating a container

### Objective 4: Security tools and portal for consulting information

[Dependency Track](https://dependencytrack.org/) will be the tool for managing SBOMs and vulnerabilities.

Install a Dependency Track server and configure it to:

- automatically import SBOMs from GitHub releases (see [sbom-uploader](scripts/sbom-uploader.py))
- give access to the Nethesis team for consulting SBOMs and vulnerabilities

## Target repositories

See [sbom-repositories.json](scripts/sbom-repositories.json) for the list of repositories
that are part of the SBOM process.

The following projectes does not have a valid SBOM because no go.mod file is present:
- [Windmill](https://github.com/nethesis/windmill) 
- [Legacy Backupd](https://github.com/nethesis/legacy_backupd)

## External resources

- [NethServer development process handbook](https://handbook.nethserver.org/)
- [ns8-release-module - GitHub CLI Extension](https://github.com/NethServer/gh-ns8-release-module)
