# IP Reputation Checker — Deployment Guide

This guide is for installing the IP Reputation Checker as a long-running HTTPS service on Linux or Windows Server. The application is a dependency-free Node.js service: it serves the web UI, calls AbuseIPDB (and optionally VirusTotal), and keeps proxy credentials in process memory.

## 1. Deployment checklist

Before installation, prepare:

- Node.js 20 LTS or newer.
- A DNS name or server address and an HTTPS certificate for that name.
- An AbuseIPDB API key. A VirusTotal API key is optional, but recommended for additional reputation context.
- Firewall access to TCP `3443`, or the port selected with `PORT`.
- Outbound HTTPS access to `api.abuseipdb.com` and, if enabled, `www.virustotal.com`.

Do not commit `.env`, API keys, certificate files, or private keys. Any keys previously embedded in the source must be revoked and replaced before production use.

## 2. Application configuration

Copy `.env.example` to `.env` and set the required values:

| Variable | Required | Description |
| --- | --- | --- |
| `ABUSEIPDB_API_KEY` | Yes | AbuseIPDB API key used for IP checks. |
| `VIRUSTOTAL_API_KEY` | No | Enables VirusTotal enrichment when present; AbuseIPDB remains the required provider. |
| `HOST` | No | Listener address; use `0.0.0.0` for a server. |
| `PORT` | No | HTTPS listener port; defaults to `3443`. |
| `TLS_KEY_FILE` | No | Private key path; defaults to `certs/server.key`. |
| `TLS_CERT_FILE` | No | Certificate path; defaults to `certs/server.crt`. |
| `CERT_DIR` | No | Directory used for the default certificate paths. |
| `CORPORATE_CA_FILE` | No | PEM CA bundle used to validate HTTPS connections through a TLS-inspecting corporate proxy. |
| `CORPORATE_PROXY_INSECURE_TLS` | No | Set to `true` only as a temporary workaround; disables certificate validation for outbound proxy connections. |

The application reads `.env` at startup when a variable has not already been supplied by the operating system. OS/service-manager variables take precedence. Restart the service after changing configuration.

## 3. TLS certificates

Use a certificate issued by the organization’s CA or a public CA in production. The certificate must include the hostname users will enter in the browser. Keep the private key readable only by the service account.

For a temporary Linux test certificate:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost"
chmod 600 certs/server.key
```

For a temporary Windows certificate, run PowerShell as an administrator:

```powershell
$cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation Cert:\LocalMachine\My
```

Browsers will warn for self-signed certificates. Use a trusted certificate for users and monitoring systems.

## 4. Linux with systemd

1. Create a service account and application directory:

   ```bash
   sudo useradd --system --home /opt/ip-reputation-checker --shell /usr/sbin/nologin ipchecker
   sudo mkdir -p /opt/ip-reputation-checker /etc/ip-reputation-checker
   sudo chown -R ipchecker:ipchecker /opt/ip-reputation-checker
   ```

2. Copy the project files into `/opt/ip-reputation-checker`. Install Node.js 20 LTS from the approved distribution source.

3. Store the environment file at `/etc/ip-reputation-checker/ip-reputation-checker.env`:

   ```ini
   ABUSEIPDB_API_KEY=replace-me
   VIRUSTOTAL_API_KEY=
   HOST=0.0.0.0
   PORT=3443
   TLS_KEY_FILE=/etc/ip-reputation-checker/server.key
   TLS_CERT_FILE=/etc/ip-reputation-checker/server.crt
   CORPORATE_CA_FILE=/etc/ip-reputation-checker/corporate-proxy-ca.pem
   ```

4. Copy the certificate and key to that directory. Set ownership and permissions:

   ```bash
   sudo chown root:ipchecker /etc/ip-reputation-checker/server.key /etc/ip-reputation-checker/server.crt
   sudo chmod 640 /etc/ip-reputation-checker/server.key /etc/ip-reputation-checker/server.crt
   sudo chmod 600 /etc/ip-reputation-checker/ip-reputation-checker.env
   ```

5. Install the supplied unit and start the service:

   ```bash
   sudo cp deploy/ip-reputation-checker.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now ip-reputation-checker
   sudo systemctl status ip-reputation-checker
   ```

6. Permit only approved client networks through the firewall. For `ufw`, for example:

   ```bash
   sudo ufw allow from 10.0.0.0/8 to any port 3443 proto tcp
   ```

7. Open the HTTPS address in an approved browser. After proxy settings are submitted, the application displays an animated check and tests internet access, AbuseIPDB, and VirusTotal. Select `Continue` when all checks pass. If a check fails, select `Configure proxy`, correct the route or credentials, and run the checks again.

Useful operations:

```bash
sudo journalctl -u ip-reputation-checker -f
sudo systemctl restart ip-reputation-checker
sudo systemctl disable --now ip-reputation-checker
```

## 5. Windows Server with WinSW

1. Install Node.js 20 LTS and copy the project to `C:\IP-Reputation-Checker`.
2. Copy `.env.example` to `.env`, set the API key and TLS paths, and grant read access only to the service account and administrators.
3. Download [WinSW](https://github.com/winsw/winsw/releases), rename the executable to `ip-reputation-checker.exe`, and place it beside `deploy/ip-reputation-checker.xml` (renamed to `ip-reputation-checker.xml`).
4. Update the XML working directory or Node executable path if your installation differs from the supplied defaults.
5. In an elevated PowerShell prompt:

   ```powershell
   cd C:\IP-Reputation-Checker
   .\ip-reputation-checker.exe install
   .\ip-reputation-checker.exe start
   .\ip-reputation-checker.exe status
   ```

6. Add a restricted Windows Firewall rule, replacing the source subnet with the approved network:

   ```powershell
   New-NetFirewallRule -DisplayName "IP Reputation Checker HTTPS" -Direction Inbound -Protocol TCP -LocalPort 3443 -RemoteAddress 10.0.0.0/8 -Action Allow
   ```

7. Browse to `https://SERVER_NAME:3443` from an approved client. After proxy settings are submitted, the application automatically tests internet access, AbuseIPDB, and VirusTotal. Select `Continue` when all checks pass. If a check fails, select `Configure proxy`, update the settings, and test again.

View service logs in the `LOG` directory created by WinSW. The application also writes `LOG/app.log`. Stop, update the application files, and start again for upgrades:

```powershell
.\ip-reputation-checker.exe stop
# copy the new release files
.\ip-reputation-checker.exe start
```

## 6. Monitoring and verification

The health endpoint does not call external APIs and can be used for liveness checks:

```text
GET https://server.example.com:3443/healthz
200 {"status":"ok"}
```

An HTTPS client that does not trust a self-signed certificate will need the organization CA installed; do not disable certificate validation in production monitoring.

After deployment, verify:

1. The service is running and listening on the expected interface and port.
2. `/healthz` returns HTTP 200.
3. A test IP lookup succeeds through the configured outbound network/proxy.
4. The setup flow displays `Continue` only after all connectivity checks pass; failures display `Configure proxy`.
5. Invalid API credentials produce a controlled error rather than exposing a key.
6. Logs do not contain API keys, proxy passwords, or private key contents.

## 7. Upgrades and rollback

Keep releases in a versioned directory or source-control tag. Before upgrading, back up only the environment file and certificates, not secrets in tickets or logs. Stop the service, replace application files, run `node --check server.js`, and start it again. If the health check fails, restore the previous application directory and restart the service. Rotate API keys and TLS certificates independently of application releases.

## 8. Troubleshooting

| Symptom | Checks |
| --- | --- |
| Service exits immediately | Confirm both TLS files exist and are readable by the service account; inspect systemd or WinSW logs. |
| `EADDRINUSE` | Another process owns `PORT`; change `PORT` or stop the conflicting process. |
| `/healthz` works but lookups fail | Check outbound DNS/HTTPS, API key validity, rate limits, and proxy settings. |
| Browser certificate warning | Install a certificate containing the requested hostname and trusted by the client. |
