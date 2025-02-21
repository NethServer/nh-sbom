# SBOM and dependency management

This repository contains the documentation and tools for the SBOM and dependency management process.

Contents:

- [Work plan](#work-plan)
- [Affected repositories](#affected-repositories)

## Work plan

### Objective 1: Inventory of EOL distributions

1. Implement a GitHub Action for NS8, based on a common action to generate and upload the SBOM.
   Chosen engine to generate the SBOM: Syft
   The action must upload the SBOM:
   - in the repository release as an attachment in JSON and SARIF format
   - in the repository dependency graph

   Use syft to generate the SBOM.
   Allow targeting both directories (for NethSecurity and UIs) or a container image.

   Create 2 separate actions: one for generating the SBOM, and one for uploading and analyzing.

2. Implement a scraper as a GitHub Action that reads EOL information from an SBOM.
   For each EOL distribution, create an issue with the information.
   For each non-EOL distribution, create an issue reporting the end-of-support date using the [Endoflife](https://endoflife.date/docs/api) API.
   Evaluate integrating the issues within a project.

### Objective 2: Rationalization of dependencies

Use Renovate for dependency management, while Dependabot only for alerts (without automatic pull requests).
To do:

1. Configure Dependabot in a [homogeneous way](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts) for all repositories
2. Create a configuration file for Renovate that can be inherited by all NS8 repositories
   Default behavior:
   - if there are no tests, automatically merge patch versions, no automatic merge for minor and major versions
   - if there are tests, automatically merge all versions (to be implemented as an override on individual projects)
3. Create a common configuration file for Renovate for all non-NS8 projects, such as UIs

To be done by: March 14

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

Main repositories, not container-based:

- [UI Library](https://github.com/NethServer/ns8-ui-lib)
- [Images](https://github.com/NethServer/ns8-images)

Low priority applications:

- [Prometheus](https://github.com/NethServer/ns8-prometheus)
- [Webserver](https://github.com/NethServer/ns8-webserver)
- [PostgreSQL](https://github.com/NethServer/ns8-postgresql)
- [MariaDB](https://github.com/NethServer/ns8-mariadb)
- [Roundcube Mail](https://github.com/NethServer/ns8-roundcubemail)
- [Node Exporter](https://github.com/NethServer/ns8-node_exporter)
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
