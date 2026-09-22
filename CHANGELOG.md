- Expanded threat reports with AbuseIPDB report totals and distinct reporters, VirusTotal communicating files and threat tags for IPs, reported IP counts and addresses for CIDR ranges, and VirusTotal threat names for URLs.

# Changelog

All notable changes to the IP Reputation Checker are recorded here.

## 2026-09-13

### Added

- Added user-controlled sorting to the reputation results table, including accessible direction indicators for sortable columns.

## 2026-09-07

### Added

- Added a proxy setup connectivity flow with staged PC, Internet, AbuseIPDB, and VirusTotal checks, branded logos, success/failure actions, and a combined all-clear state.
- Added Source and Activity suggestions with support for custom text in the email composer.
- Added persistent Night mode with accessible Day mode switching and reduced-motion support.

### Changed

- URL handling now accepts full web addresses, queries the normalized origin, and displays the base host instead of the full page path.
- The email composer excludes trusted-provider results from suspicious or malicious emails, while `Email all IPs` includes every valid result.
- Refined the desktop layout for 1920x1080 and 1366x768 displays with animated panels, responsive spacing, uppercase titles, and red gradient actions.

## 2026-09-06

### Added

- Added CIDR range expansion (limited to 256 addresses) and HTTP(S) URL DNS resolution for reputation checks, preserving the original target in results and exports.
- Added bare hostname resolution for targets such as `www.google.com`.
- Added malicious-result reports showing AbuseIPDB categories and VirusTotal detecting vendors, with links to both provider reports.
- Added an animated checking screen and redirected completed checks to a dedicated results view.

### Changed

- Results now display successful checks first and move validation or provider errors to the bottom.
- Results now include a `New check` action to return to the target input screen.

## 2026-09-02

### Added

- Added the project vision and documented publicly available IP reputation data as public/non-confidential project data.
- Added application logging to `LOG/app.log`.
- Moved existing WinSW service logs into the `LOG` directory and configured future service output to use that directory.
- Added a persisted daily AbuseIPDB request counter with a 500-request limit and a visible browser indicator.

### Documentation

- Documented the tool purpose, intended users, success criteria, prototype status, and data-use boundary.
