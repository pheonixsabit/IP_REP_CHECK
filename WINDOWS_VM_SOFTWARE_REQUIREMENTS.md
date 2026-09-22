# Windows VM Software Requirements

This checklist covers deployment of both applications on a new Windows VM:

- `IP REP CHECK`
- `iso_compliance_portal`

## Required Base Software

- Windows Server 2019 or newer, fully patched
- PowerShell 5.1 or newer
- Current Chrome, Edge, or Firefox for administration
- Trusted TLS certificate and private key for the VM hostname
- Windows Firewall rules restricted to approved client networks

## IP Reputation Checker

- Node.js 20 LTS or newer
- WinSW for installing the Node.js server as a Windows service
- AbuseIPDB API key
- VirusTotal API key for optional VirusTotal enrichment and URL threat names
- Outbound DNS and HTTPS access to:
  - `api.abuseipdb.com`
  - `www.virustotal.com`
- Corporate proxy settings and corporate CA PEM file, when required

Default port: `3443`.

## ISO Compliance Portal

- Python 3.13.x with the Python launcher and `venv`
- PostgreSQL 14 or newer for production
- Python dependencies from `requirements.txt`, installed into `.venv`
- Waitress, installed by `requirements.txt`, for Windows application serving
- IIS or another approved reverse proxy for production HTTPS termination
- Protected storage and backups for uploaded evidence and media files

Default port: `14443` when using `scripts\start_windows.ps1`.

## Optional Software

- `mkcert` 1.4.4 or newer for local development certificates
- IIS URL Rewrite and Application Request Routing when IIS is used as the reverse proxy

## Installation References

- IP Reputation Checker: `IP REP CHECK\DEPLOYMENT.md`
- ISO Portal software list: `iso_compliance_portal\docs\software_requirements.md`
- ISO Portal deployment guide: `iso_compliance_portal\docs\deployment_guide.md`
- ISO Portal Windows setup: `iso_compliance_portal\scripts\setup_windows_production.ps1`
