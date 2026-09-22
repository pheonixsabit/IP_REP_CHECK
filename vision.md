# IP Reputation Checker --- Vision

**Purpose:** Provide a local internal workflow for checking IPv4 and IPv6 addresses against reputation services and preparing a human-reviewed incident-notification email.

**Users:** IDLC Finance security, network, fraud-monitoring, and incident-response staff who need to review suspicious network activity.

**Data it touches:** Publicly available IPv4/IPv6 addresses and reputation metadata from AbuseIPDB and optional VirusTotal, classified as public/non-confidential project data. The tool must not be used for customer, employee, financial, CIB, or other restricted personal data.

**Success criteria:** Staff can submit one or more valid addresses, compare reputation results from the configured providers, identify connectivity or provider failures, export results, and prepare an email for human review without exposing API keys or proxy passwords.

**Status:** UAT

**Steward:** To be confirmed
**Backup:** To be confirmed
