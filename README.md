# IP Reputation Checker

A lightweight local web app for checking pasted or imported IPv4/IPv6 addresses with AbuseIPDB and preparing an incident-notification email.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the complete Linux, Windows Server, TLS, monitoring, and upgrade guide.

The combined Windows VM software checklist is in [WINDOWS_VM_SOFTWARE_REQUIREMENTS.md](../WINDOWS_VM_SOFTWARE_REQUIREMENTS.md).

## New Windows VM software checklist

Install or prepare the following software before deploying both applications on the same Windows VM:

### Required base software

- Windows Server 2019 or newer, fully patched.
- PowerShell 5.1 or newer. Run installation and service commands from an elevated PowerShell window.
- Git, if the applications will be cloned or updated from a repository.
- A current Chrome, Edge, or Firefox browser for administration and verification.
- An approved TLS certificate for the VM hostname, including its private key. Self-signed certificates are suitable only for testing.
- Windows Firewall rules allowing only approved client networks to reach the application ports.

### IP Reputation Checker

- Node.js 20 LTS or newer. No npm packages are required.
- WinSW for installing `server.js` as a Windows service.
- AbuseIPDB API key, required for IP checks.
- VirusTotal API key, optional but required for VirusTotal enrichment and URL threat-name results.
- Outbound DNS and HTTPS access to `api.abuseipdb.com` and, when enabled, `www.virustotal.com`.
- Corporate proxy details and the organization CA PEM bundle when outbound traffic must use a TLS-inspecting proxy.

Default service port: `3443`.

### ISO 27001 Compliance Evidence Portal

- Python 3.13.x, with the Python launcher and `venv` support available.
- PostgreSQL 14 or newer for production. PostgreSQL 17 is the default package used by the Windows setup script.
- The Python packages pinned in `iso_compliance_portal\requirements.txt`, installed into the project `.venv`; this includes Django, psycopg, Waitress, Pillow, ReportLab, and the portal dependencies.
- Waitress, installed from `requirements.txt`, to serve Django on Windows.
- IIS or another approved reverse proxy for production TLS termination. This is not needed for a local HTTP-only test.
- A separate protected location and backup plan for uploaded evidence and media files.

Default application port: `14443` when using `scripts\start_windows.ps1`.

### Optional software

- `mkcert` 1.4.4 or newer, only for locally trusted development certificates for the portal.
- IIS URL Rewrite and Application Request Routing, if IIS will proxy HTTPS traffic to Waitress or Node.js.

After installation, configure each application's `.env` file, install dependencies, run migrations and static-file collection for the portal, install the IP checker with WinSW, and create restricted Windows Firewall rules for ports `3443` and `14443`.

## Deploy securely

Requirements: Node.js 20 or later, a TLS certificate/private key, and an AbuseIPDB API key. The service has no npm dependencies.

Never add API keys or private certificates to source control. Copy `.env.example` to `.env`, set `ABUSEIPDB_API_KEY`, and place the TLS files at `certs/server.crt` and `certs/server.key`. Set `VIRUSTOTAL_API_KEY` only when VirusTotal enrichment is required.

The historical keys that were present in `server.js` should be revoked and replaced in their providers' dashboards before deployment.

### Linux (systemd)

1. Create a restricted service user: `sudo useradd --system --home /opt/ip-reputation-checker --shell /usr/sbin/nologin ipchecker`.
2. Copy this application to `/opt/ip-reputation-checker` and ensure `ipchecker` can read it. Store TLS files and the environment file outside the code directory, for example in `/etc/ip-reputation-checker/` (permissions `600`).
3. In `/etc/ip-reputation-checker/ip-reputation-checker.env`, set the values from `.env.example`, including `TLS_KEY_FILE` and `TLS_CERT_FILE` pointing to the protected certificate files.
4. Copy `deploy/ip-reputation-checker.service` to `/etc/systemd/system/`, then run `sudo systemctl daemon-reload && sudo systemctl enable --now ip-reputation-checker`.
5. Check with `systemctl status ip-reputation-checker` and browse to `https://SERVER_NAME:3443`.

For a public-facing service, terminate TLS at a managed load balancer or reverse proxy and restrict inbound traffic to the chosen HTTPS port.

### Windows Server (WinSW)

1. Install Node.js 20 LTS and copy the project to `C:\IP-Reputation-Checker`.
2. Copy `.env.example` to `.env`, populate the required values, and restrict the file and `certs` folder to the service account. The application loads this file at startup; environment variables supplied by the service account take precedence.
3. Download [WinSW](https://github.com/winsw/winsw/releases) into `C:\IP-Reputation-Checker` and rename it `ip-reputation-checker.exe`.
4. Keep the supplied `deploy/ip-reputation-checker.xml` beside the executable as `ip-reputation-checker.xml`; update paths if Node or the application is installed elsewhere.
5. From an elevated PowerShell in that folder, run `.\ip-reputation-checker.exe install` then `.\ip-reputation-checker.exe start`.

Allow the chosen TCP port in Windows Firewall only for approved source networks. Use the Windows Services console or `.\ip-reputation-checker.exe status` to monitor it.

## Local run

1. Install Node.js 20 or later.
2. Copy `.env.example` to `.env` and set the required key.
3. Add TLS files as `certs/server.crt` and `certs/server.key`.
4. Run `npm start`, then browse to `https://localhost:3443`.

Restart the Node process after changing `server.js`; Node does not reload server routes automatically. For the installed Windows service, restart it from an elevated PowerShell with `Restart-Service ip-reputation-checker` or restart it through the Services console.

`GET /healthz` returns a simple health response for monitoring systems.

Application logs are written to `LOG/app.log`. WinSW service output is also configured to roll inside the `LOG` directory. Keep this directory private and do not commit its contents.

The setup page can use a direct connection or a proxy. If the corporate proxy inspects HTTPS traffic, set `CORPORATE_CA_FILE` to a readable PEM bundle containing the organization’s root CA; certificate verification remains enabled. As a temporary diagnostic workaround only, set `CORPORATE_PROXY_INSECURE_TLS=true` to disable certificate validation for outbound connections through the configured proxy. Remove it as soon as the corporate CA is available. Proxy passwords are encrypted in the browser with a per-process RSA public key before being sent; HTTPS encrypts the complete request in transit. The private key is held only in server memory.

## CSV input

Download the template from the app. It uses one `ip_address` column. `.txt` imports accept one target per line; pasted input supports IPv4, IPv6, CIDR ranges up to 256 addresses, and HTTP(S) URLs separated by lines, spaces, commas, or semicolons. URLs are resolved to their DNS addresses before reputation checks.

## Malicious reports

Malicious results include a `View report` action. IP reports include total AbuseIPDB reports, distinct reporting users, VirusTotal communicating files, and threat tags. CIDR reports list the number of reported IPs and their addresses. URL reports include VirusTotal threat names. Reports also show AbuseIPDB categories, VirusTotal vendors, and links to the corresponding provider pages. The feature is informational and does not automatically submit a provider report or block an address.
