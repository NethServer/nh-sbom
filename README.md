# SBOM and dependency management

This repository contains the documentation and tools for the SBOM and dependency management process.

Contents:

- [Work plan](#work-plan)
- [Affected repositories](#affected-repositories)

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

1. Configure Dependabot in a [homogeneous way](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts) for all repositories
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

### Objective 4: Security tools

Create a tool that analyzes CVEs of the base distribution of NS8 and NethSecurity.
This tool should also be available to the community.

In the case of NS8, the tool must analyze the installed images.
In the case of NethSecurity, the tool must analyze the installed packages.

This work can begin after completing objectives 1 and 2.

### Objective 5: Portal for consulting information

Create a portal, or use an existing portal, for consulting security and EOL information.
With the portal, it should be possible to respond to support requests such as:

- Is product x in EOL?
- Is product x vulnerable to CVE y?

Possible candidates:
- [Sbomify](https://sbomify.com/)
- [dependency track](https://dependencytrack.org/)

## Affected repositories

### NS8

Main repositories:

- [Core](https://github.com/NethServer/ns8-core)
- [Samba](https://github.com/NethServer/ns8-samba)
- [Traefik](https://github.com/NethServer/ns8-traefik)
- [Mail](https://github.com/NethServer/ns8-mail)
- [WebTop](https://github.com/NethServer/ns8-webtop)
- [eJabberd](https://github.com/NethServer/ns8-ejabberd)
- [IMAPSync](https://github.com/NethServer/ns8-imapsync)
- [CrowdSec](https://github.com/NethServer/ns8-crowdsec)
- [NethSecurity Controller](https://github.com/NethServer/ns8-nethsecurity-controller)
- [LDAP Proxy](https://github.com/NethServer/ns8-ldapproxy)
- [User Manager](https://github.com/NethServer/ns8-user-manager)
- [Loki](https://github.com/NethServer/ns8-loki)
- [Nextcloud](https://github.com/NethServer/ns8-nextcloud)
- [Mattermost](https://github.com/NethServer/ns8-mattermost)
- [Netdata](https://github.com/NethServer/ns8-netdata)
- [Dnsmasq](https://github.com/NethServer/ns8-dnsmasq)
- [Piler](https://github.com/NethServer/ns8-piler)
- [OpenLDAP](https://github.com/NethServer/ns8-openldap)
- [Metrics](https://github.com/NethServer/ns8-metrics)

Main repositories, not container-based:

- [UI Library](https://github.com/NethServer/ns8-ui-lib)
- [Images](https://github.com/NethServer/ns8-images)

Low priority applications:

- [Prometheus](https://github.com/NethServer/ns8-prometheus)
- [Webserver](https://github.com/NethServer/ns8-webserver)
- [PostgreSQL](https://github.com/NethServer/ns8-postgresql)
- [MariaDB](https://github.com/NethServer/ns8-mariadb)
- [Roundcube Mail](https://github.com/NethServer/ns8-roundcubemail)
- [Grafana](https://github.com/NethServer/ns8-grafana)

Applications with very low priority:

- [SOGo](https://github.com/NethServer/ns8-sogo)
- [WordPress](https://github.com/NethServer/ns8-wordpress)
- [DokuWiki](https://github.com/NethServer/ns8-dokuwiki)
- [Collabora](https://github.com/NethServer/ns8-collabora)
- [Passbolt](https://github.com/NethServer/ns8-passbolt)
- [MinIO](https://github.com/NethServer/ns8-minio)
- [Kickstart](https://github.com/NethServer/ns8-kickstart)
- [Porthos](https://github.com/NethServer/ns8-porthos)

### NethVoice

Container-based:

- [NethVoice proxy](https://github.com/nethesis/ns8-nethvoice-proxy)
- [NethVoice](https://github.com/nethesis/ns8-nethvoice)

Not container-based:

- [NethCTI Server](https://github.com/nethesis/nethcti-server)
- [NethVoice CTI](https://github.com/nethesis/nethvoice-cti)
- [NethVoice Report](https://github.com/nethesis/nethvoice-report)
- [Phone Island](https://github.com/nethesis/phone-island)
- [Tancredi](https://github.com/nethesis/tancredi)
- [Contatta](https://github.com/nethesis/contatta/tree/ns8)
- [AstProxy](https://github.com/nethesis/astproxy)
- [Falconieri](https://github.com/nethesis/falconieri)

### NethSecurity

Not container-based:

- [Core](https://github.com/nethserver/nethsecurity)
- [Controller](https://github.com/nethserver/nethsecurity-controller)
- [UI](https://github.com/nethserver/nethsecurity-ui)
- [Library](https://github.com/NethServer/python3-nethsec)

Extra services, not container-based:

- [Parceler](https://github.com/nethesis/parceler)
- [Icaro](https://github.com/nethesis/icaro)

### Other projects

- [Windmill](https://github.com/nethesis/windmill)
- [Legacy Backupd](https://github.com/nethesis/legacy_backupd) (private)
- [Yomi Proxy](https://github.com/nethesis/yomi-proxy) (private)

## External resources

- [NethServer development process handbook](https://handbook.nethserver.org/)
- [ns8-release-module - GitHub CLI Extension](https://github.com/NethServer/gh-ns8-release-module)
