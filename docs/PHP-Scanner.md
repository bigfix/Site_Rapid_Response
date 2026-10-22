# PHP scanner for Windows and Linux

Checks for PHP versions affected by **CVE-2026-109618** and **CVE-2026-109619**,
shows where they are installed, and reports when the last scan finished. This scanner uses the existing BigFix PHP
YARA rules and does not run or change the PHP applications it finds.

## Get started

1. Import the [Windows Task](../Fixlets/Windows/22%20PHP_Bounded_YARA-X_Discovery_-_Windows.bes)
   or [Linux Task](../Fixlets/Linux/23%20PHP_Bounded_YARA-X_Discovery_-_Linux.bes),
   plus the [Results Analysis](../Fixlets/Universal/24%20PHP_Bounded_YARA-X_Scan_Results.bes).
2. Activate the Results Analysis.
3. Open the Task's **Description** tab. Leave the default settings unless you need
   different coverage.
4. Select **Configure and Take Action**, choose computers, and run the scan.
5. Review the four Analysis properties below.

This is an optional alternative to the original scanners in this repository.
Use its companion Results Analysis; the original Analysis reads a different
result format. The existing macOS scanner is separate.

The standard-name default can miss renamed PHP files that the original scanner
finds. Enable **Renamed or nonstandard PHP binaries** when broader coverage is
needed; this increases scan time.

## Default settings

The default looks for commonly named PHP programs and libraries. It avoids
unnecessary file reads and keeps legitimate per-user application folders included.

| Setting | Default | What it controls |
| --- | --- | --- |
| File search time | 20 minutes | How long to look for files to check. |
| Content scan time | 15 minutes | How long YARA may inspect the selected files. |
| Maximum files checked | 5,000,000 | Limits discovery work. |
| Maximum candidate input | 30 GiB | Limits the combined size of files sent to YARA. |
| Maximum individual file size | **512 MiB** | Skips files this size or larger. |
| YARA CPU setting | 10% | Engine CPU target; not a limit on total computer CPU use. |

Each setting has an explanation beside it in the Description tab. Raising limits
can increase scan time and disk activity.

### Optional wider searches

These options are **off by default**:

- **Renamed or nonstandard PHP binaries:** check other program names. This can
  find renamed or embedded PHP, but takes longer.
- **PHP source/build text:** include build files and headers as supporting
  evidence. These alone do not mark a computer as having vulnerable PHP.
- **Broader locations:** include normally skipped OS, recovery, cache and data
  folders. Network storage and other safety exclusions still apply.
- **Extra-gentle disk access:** lower disk priority on Windows; scans may take longer.

Default names include php, php-cgi, php-fpm, phpdbg, libphp, mod_php, lsphp and
frankenphp, with common version suffixes. PHP DLLs on Windows and shared libraries
on Linux are included because they can contain the PHP runtime. Ordinary .php
website scripts do not identify the installed runtime version.

## Exclude folders

Enter paths separated by commas in **Additional directory exclusions**.
Leave it blank if you do not need custom exclusions.

| Linux example | Windows example | What is excluded |
| --- | --- | --- |
| `/data/*` | `C:\folder\*` | The folder and all its subfolders. |
| `/data/` | `C:\folder\` | Only files directly in that folder; subfolders are still searched. |
| `*/data/*` | `*\folder\*` | Every matching folder and all its subfolders. |

Only * is a wildcard. Spaces are allowed; commas inside folder names are not.
Windows matching ignores case; Linux matching is case-sensitive.
You can enter up to 32 exclusions, totaling 4096 UTF-8 bytes.

PHP inside an excluded folder will not be reported. Your chosen exclusions
remain active with wider searches and do not cause a partial-scan warning.

## Understand the results

| Property | Meaning |
| --- | --- |
| **YARA PHP Vulnerable Detected** | TRUE when an upstream-affected runtime is found; FALSE when none is found in a completed scan; UNKNOWN when results are unavailable, coverage is incomplete, or PHP evidence needs verification. |
| **YARA Vulnerable PHP Path and Version** | One path and version per result, up to 100. Unverified paths are clearly labeled, including Vendor patch status unverified. None detected is shown only for a usable negative result. |
| **YARA PHP Last Scan** | Last completion time in UTC, or NO SCAN. Also shows a short warning when coverage is incomplete or the latest attempt failed. |
| **YARA Last Scan Length** | How long the scan took, in hours, minutes and seconds. Queueing, downloads and reporting delays are separate. |

**Check the last-scan result before relying on FALSE.** No scan or an oversized,
unreadable or invalid summary produces UNKNOWN. Old result files also show
UNKNOWN until the updated scanner runs. After importing the updated Analysis,
run its companion Task to refresh the results.

- **Completed:** the scan finished within its selected scope. Finding no PHP is
  a successful result.
- **Partial:** a limit or a meaningful access problem prevented full coverage.
  Findings are kept, and the BigFix action succeeds. The result is UNKNOWN unless
  an affected runtime was found, in which case it remains TRUE.
- **Failed:** the attempt produced no new usable result. Previous findings are
  retained with a warning.

A scan in progress keeps the previous completed results. Very short scans may
mean no eligible PHP files were found, so YARA had nothing to inspect. Displayed
times are rounded or measured in whole seconds.

## Coverage and requirements

- **Windows:** x64 Windows 11 and later, or Windows Server 2016 and later;
  PowerShell 5.1/.NET required.
- **Linux:** x86_64 RHEL 7–10, Rocky/AlmaLinux 8–10 and Ubuntu. Requires Bash 4+,
  GNU find/coreutils, awk, tar/gzip and flock. **No Python, installed PHP or compiler
  is required for scanning.**
- **BigFix:** Client 9.5.7 or later, using a client release that supports its OS.
  Test on a small group before wider deployment. Not every listed OS/client
  combination has been tested end to end.

The default skips OS/recovery folders, known caches, backups and personal media.
Network mounts, links, cloud placeholders, container/image stores and
scanner-owned files are excluded. Archives and disk images are not opened.
Storage presented as a local disk may still be scanned even if physically remote.
Renamed or custom embedded PHP may be missed unless the wider search is enabled.

For CVE-2026-109618 and CVE-2026-109619, the upstream fixed releases are
**8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Earlier affected versions, including older
PHP branches, are flagged for review.

**Some operating-system vendors apply fixes without changing the upstream PHP
version.** Affected-version Linux files owned by a package, and builds with a
vendor suffix, are labeled **Vendor patch status unverified**. These produce
UNKNOWN unless a separate affected runtime is found. Package lookups are read-only,
cached per affected path, with two-second timeouts and a 30-second total lookup
budget (plus process-termination grace);
lookup errors also leave patch status unverified. No package is installed or
changed. Check the vendor's advisory to establish whether its package is patched.
Results do not establish web exposure or exploitability.

Unsupported local filesystems are listed in the log and cause a partial-coverage
warning when other filesystems can still be scanned. Intended network,
system and excluded-container mounts do not cause that warning.

Windows 10, ARM64, Debian, SUSE, Oracle Linux and Amazon Linux coverage is planned.
These remain on the testing to-do list rather than being claimed as supported
by the current Tasks.

## Find the detailed log

The detailed log is scan.log in the **YARA_PHP** folder under the BigFix client
state root. Typical locations:

- Windows: `C:\Program Files (x86)\BigFix Enterprise\BES Client\YARA_PHP`
- Linux: `/var/opt/BESClient/YARA_PHP`

The log records findings, exclusions and any coverage limits. The small
summary.txt file supplies the Analysis properties. Each action attempt uses its
own workspace, removed after the action finishes. An interrupted action can leave
its workspace behind; retries use a separate workspace and respect the scan lock.
Valid UTF-8 paths display normally; control characters and invalid bytes are escaped.

The original community YARA rules are unchanged. See the repository
[LICENSE](../LICENSE) and [TERMS](../TERMS).
