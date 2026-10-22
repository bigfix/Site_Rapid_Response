# Maintainer notes

These notes cover integrations and source maintenance. For running scans and
reading results, start with the [operator guide](README.md).

## API actions

The Console form passes settings to the Task's existing action. It does not carry
a second copy of the scanner. API actions can pass the same parameters directly;
omitted parameters use the defaults.

The Description displays whole minutes. API time parameters use **seconds**.

| Parameter | Default | Purpose |
| --- | --- | --- |
| PHPEnumerationSeconds | 1200 | File-search limit. |
| PHPScanSeconds | 900 | YARA content-scan limit. |
| PHPMaxFiles | 5000000 | Discovery file-count limit. |
| PHPCandidateGB | 30 | Total candidate input, in GiB. |
| PHPMaxFileMB | 512 | Skip files at or above this size, in MiB. |
| PHPCpuLimit | 10 | YARA engine CPU target, not a whole-host limit. |
| PHPIncludeNonstandardNames | 0 | Set to 1 to include other native binary names. |
| PHPIncludeBuildText | 0 | Set to 1 to include source/build evidence. |
| PHPIncludeBroaderLocations | 0 | Set to 1 to restore soft location exclusions. |
| PHPGentleDisk | 0 | Set to 1 for lower Windows disk scheduling priority. |
| PHPExcludeDirectoriesHex | x | Encoded custom exclusions; x means empty. |

For API exclusions, use lowercase x followed by hexadecimal UTF-8 bytes of the
comma-separated paths. For example, /data/* becomes x2f646174612f2a.
The Console encodes ordinary paths automatically.

## Edit and validate the content

The readable scanner sources are in this folder; the Tasks contain escaped copies
for BigFix delivery. After editing sources, run:

```text
python -B tools/php-yara/sync_content.py --write
python -B tools/php-yara/validate_content.py
```

Python 3.9+ and Node.js are needed for these **maintainer tools only**, not for
endpoint scanning. To additionally validate against a BES schema, install
xmlschema in your development environment and run:

```text
python -B tools/php-yara/validate_content.py --schema /path/to/BES.xsd
```

The validator checks embedded sources, form behavior, defaults and the four
properties. It checks Bash syntax when Bash is available. Also parse-check the
PowerShell files with Windows PowerShell 5.1, run the repository's configured
pre-commit hooks, and test behavior changes on representative endpoints.

Settings definitions and action wrappers are maintained in the BES files.
Keep their validation rules consistent with the form and scanner sources.

## Validation coverage

- Real affected and fixed PHP versions were detected and classified on Windows
  Server 2019, RHEL 8 and RHEL 9.
- Windows Console settings and default/custom Windows/Linux API action settings
  were checked against endpoint results.
- Offline checks cover source matching, schemas, script syntax, form inputs and
  property behavior.
- Client 9.5.7 evaluator and command checks do not establish an installed-9.5.7
  action runtime test. Older Console releases and Linux Console launch still need
  end-to-end validation. Not every scoped OS release has been tested.

Keep this distinction when documenting support. Measure performance on
representative workloads; short name-filtered scans do not imply all file
contents were scanned.

## Result and download contracts

The properties read a small summary every five minutes. Preserve atomic summary
updates, bounded path output, existing findings after a failed attempt, and
partial-coverage warnings. Finding no PHP is successful. Only an attempt without
a new usable result should fail.

The YARA-X archive and extracted engine are hash-checked. Keep matching package
URLs, sizes and hashes in the native actions and assets.json. The original
community rules are unchanged; their hash is recorded in manifest.json.

The output folder is obtained from parent folder of data folder of client.
Keep custom persistent output in YARA_PHP, outside the BigFix-managed data/cache
folders. Preserve the detailed scan log and remove temporary work files.

Manual BES import and ordinary release downloads are separate from the newer
repository-based site-gathering feature. Server/relay download policy and
connectivity still apply.
