# PHP Vulnerability Exposure Scanner

An interactive Bash utility for mapping web domains to PHP versions, checking those versions against the affected/fixed ranges for recent PHP CVEs, and reporting the `session.upload_progress` setting where it can be detected.

The scanner obtains domain/version data from the WHM API when available. Otherwise, it reads Nginx and Apache virtual-host configuration from common configuration directories. Its report includes detected domains, PHP version and status, PHP path or endpoint, data source, runtime upload-progress status, and a server summary.

## CVE background

The project checks for **CVE-2026-109618** and **CVE-2026-109619**, two PHP runtime vulnerabilities that can lead to remote code execution (RCE):

- **CVE-2026-109618 — RCE via out-of-memory (OOM) corruption.** In certain request-processing paths, an allocation failure can leave request memory in an invalid or uninitialized state. Request cleanup may subsequently access that state, potentially enabling RCE. The PHP advisory describes Apache mod_php as confirmed susceptible; susceptibility in other SAPIs depends on their request handling and configuration.
- **CVE-2026-109619 — RCE via stale global state.** Some worker-level global state can retain pointers into memory belonging to a prior request. If that state is accessed before it is correctly reset for a later request, it can refer to freed memory and potentially enable RCE.

The PHP security advisories list these affected ranges and fixed releases:

| PHP branch | Affected versions | Fixed release |
|---|---|---|
| 8.2 | Earlier than 8.2.35 | 8.2.35 |
| 8.3 | Earlier than 8.3.36 | 8.3.36 |
| 8.4 | Earlier than 8.4.27 | 8.4.27 |
| 8.5 | Earlier than 8.5.12 | 8.5.12 |

As of **October 22, 2026**, php.net lists **PHP 8.5.12**, released on October 21, 2026, as the latest PHP release; its announcement identifies it as a security release. Update to a fixed release in the applicable branch, or a later supported release, and verify the installed vendor package version. Distribution packages may include backported fixes without matching the upstream version number.

> **Important:** This scanner is an inventory and version-checking aid, not an exploitability test. Disabling `session.upload_progress` is a separate, temporary configuration action offered by the tool; it does **not** fix CVE-2026-109618 or CVE-2026-109619. The scan makes no requests to the domains and runs no exploit. Always consult the PHP advisories and your operating-system or hosting vendor's guidance.

## Requirements

- A Linux server with Bash and standard system utilities.
- Read access to web-server configuration files. Root access may be needed to inspect some server configurations.
- For WHM discovery: `whmapi1` and either `jq` or Perl with the `JSON::PP` module. If WHM is unavailable or fails, the script falls back to local configuration scanning.
- PHP CLI and/or PHP-FPM can improve version and runtime-setting detection. Without an identifiable runtime, some results may be `UNKNOWN`.
- Root access for the optional mitigation and package-update actions. Package updates support `apt`, `dnf`, and `yum`.

## Usage

Run the script from the project directory:

```bash
cd php2shell-scan
sudo bash check-php.sh
```

The interactive menu provides:

1. **Scan domains and PHP versions** — scan and display a report.
2. **Apply temporary fix** — after confirmation, create PHP configuration drop-ins that set `session.upload_progress.enabled = 0`. Existing files with different contents are not overwritten. The script offers to restart active PHP-FPM/Apache services.
3. **Update installed PHP 8.2+ packages** — after confirmation, update installed PHP packages using a supported package manager. Review the package list and expected impact before proceeding.
4. **View/save report** — display the latest scan report and optionally save it as `php-cve-report-<timestamp>.txt` in the current directory.
5. **Exit** — close the script.

To scan an additional configuration directory:

```bash
sudo bash check-php.sh --config-dir /srv/example/nginx
```

`--config-dir` can be supplied more than once. Each additional directory is scanned alongside the default locations. Show command-line help with:

```bash
bash check-php.sh --help
```

## Understanding the report

- `AFFECTED` / `FIXED`: version classification against the thresholds encoded in the script.
- `NOT AFFECTED`: the version is below the project's affected-version boundary; this is not a substitute for checking the vendor advisory.
- `UNKNOWN`, `VERSION CONFLICT`, or `REQUIRES ADVISORY VERIFICATION`: the scanner cannot confidently classify the runtime, or the detected version requires manual verification.
- `session.upload_progress`: reports whether the setting was detected as active, disabled, or unknown for the mapped runtime.

Configuration labels may reveal only a PHP minor version. For Apache mod_php, the default CLI PHP may be used as a fallback, so a reported version may not exactly match every domain or worker. Confirm the actual web runtime and package build before taking action.

## Safety notes

Scanning configuration is read-only. The mitigation option creates PHP configuration files, while the update option invokes the system package manager and may restart services. Review the proposed changes, maintain backups and a recovery plan, and test changes according to your server's operational procedures.

## Sources

- [PHP downloads and current releases](https://www.php.net/downloads.php)
- [PHP 8.5.12 release announcement](https://www.php.net/releases/8_5_12.php)
- [CVE-2026-109618 PHP security advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 PHP security advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
