Written for: BigFix operators running this content on endpoints.

---

# YARA-X Scan — Operator Guide

## 0. Content

| # | Title | Role |
| --- | --- | --- |
| 1002 | Deploy YARA-X Signatures - Universal | Writes `.yar` files + engine layout |
| 2001 / 3001 / 4001 | Scan with YARA-X Signatures - Windows / Linux / macOS | Runs the scan |
| 1001 | YARA-X Scan Results - Universal | Analysis — reports findings |
| 1003 | Remove YARA-X Scan Data - Universal | Deletes everything |

Everything lives under the client data folder:

```
__BESData/__Global/__MitigationToolkit/yara/
  bin/  signatures/  results/  work/
```

## 1. Deploy the signatures

Take **1002 Deploy YARA-X Signatures - Universal** against the target scope.

Run this **first**. The scan tasks are deliberately not relevant until a signature file exists, so deploy-before-scan is enforced by the content rather than by you.

Verify: `signatures/signatures.version` should read `2026-11-17.5`.

Re-take 1002 whenever signatures change — it overwrites in place, no removal needed.

## 2. Activate the Analysis

Activate **1001 YARA-X Scan Results - Universal** on the same scope, before scanning, so first results are collected as they arrive.

## 3. Run the scan

Take the task matching each platform:

- **2001** — Windows
- **3001** — Linux
- **4001** — macOS

**Set the cadence on the action, not in the content.** These tasks carry no result-age relevance — they do not go non-relevant after a scan. Decide your own interval:

| Need | Action setting |
| --- | --- |
| One-off sweep | Single run |
| Ongoing monitoring | Reapply, *whenever it becomes relevant again*, with a reapply interval (e.g. 7 days) |
| Fixed window | Scheduled action, start/end time constrained |

Scans are CPU- and I/O-heavy. Stagger with a randomized start offset on large scopes. A `scan.running` marker in `work/` prevents concurrent runs on the same endpoint.

## 4. Review results

Analysis **1001** exposes five properties:

| Property | What it tells you |
| --- | --- |
| YARA Scan Matches Found | `True` / `False` — anything at all |
| YARA per-signature Matches Found | Which signature files matched |
| YARA Signature Results Count | `( java_detect, 1 )` — per-signature counts, including zeros |
| YARA Scan Time | Result file timestamp — **use this to judge staleness** |
| YARA Result Details | `( signature, path, product, version )` — one row per finding |

Typical triage:

1. Filter on **YARA Scan Time** first. An old timestamp means stale data, not a clean endpoint.
2. Group **YARA Result Details** by product to get your inventory.
3. Read the version from the fourth tuple value and compare against the triage table below.

Zero rows with a recent scan time is a real negative. No rows *and* no scan time means the scan never ran.

Raw files, if you need them on the endpoint:

```
.../yara/results/yara_results_runtimes.text     signature⇥path⇥product⇥version
.../yara/results/yara_results_signatures.text   signature⇥match count
```

## 5. Clear scan data

Take **1003 Remove YARA-X Scan Data - Universal** when you are done, or before a clean re-baseline.

This deletes the **entire** `yara` folder — engine binary, signatures *and* results. After it runs the scan tasks go non-relevant and the Analysis reports nothing. Re-run step 1 to start over.

Use it when: decommissioning the campaign, reclaiming disk, or forcing a clean slate after a signature change you don't want blended with old results.

---

# Java exposure — Oracle CSPU, November 2026

Published 17 November 2026. [Appendix JAVA](https://www.oracle.com/security-alerts/cspunov2026.html#AppendixJAVA). **11 Java SE CVEs, all remotely exploitable without authentication.**

## Reachability — read this before the CVE table

Oracle's notes split these into three classes:

| Note | Meaning | Reaches |
| --- | --- | --- |
| **1** | Exploited only by supplying data to APIs, *without* Web Start or applets — e.g. through a web service | **Server** |
| **2** | Applies to sandboxed Web Start / applets loading untrusted code. **Explicitly does not apply to servers running only trusted code** | **Client only** |
| **3** | Exploitable via APIs *and* via the client sandbox | **Both** |

If your estate is servers and managed workstations with no sandboxed applets or Java Web Start, **the Note 2 rows drop out of scope entirely.**

## Full CVE list

| CVE | Component | CVSS | Reaches | Java SE versions affected |
| --- | --- | --- | --- | --- |
| CVE-2026-114938 | Compiler | **8.1** | Server | 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-86144 | JavaFX (libxml2) | 7.5 | *Client only* | 8u511b33 · *JavaFX 21.0.13, 25.0.5, 27.0.1* |
| CVE-2026-114939 | JGSS | 7.4 | *Client only* | 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114940 | JSSE (TLS) | 7.4 | **Both** | same as above |
| CVE-2026-114941 | Compiler | 7.0 | Server | 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114942 | Libraries | 7.0 | Server | 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114943 | Hotspot | 6.5 | **Both** | 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114944 | Core Java Libraries | 5.9 | **Both** | 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114945 | Libraries | 5.3 | **Both** | 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114946 | Compiler | 4.8 | **Both** | 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 |
| CVE-2026-114947 | JSSE (TLS) | 3.7 | *Client only* | 25.0.5.0.3, 27.0.1.0.3 |

CVE-2026-86144 is the only row requiring user interaction. CVE-2026-114945 is the only one with **low** attack complexity — every other row is High.

**GraalVM** is affected in parallel: GraalVM for JDK 17.0.21.0.3 / 21.0.13.0.3 on nine rows, GraalVM Enterprise Edition 21.3.20.0.3 on six.

## Triage by what the scan reports

Match the version in the fourth tuple value of **YARA Result Details**:

| Scan reports | Server-reachable | Worst server score | Client-only (extra) | Priority |
| --- | --- | --- | --- | --- |
| `1.8.0_511` | 3 — 114940, 114944, 114946<br>**+2 on a `-perf` build** — 114938, 114943 | 7.4 · **8.1 on `-perf`** | 86144, 114939 | **High** — applets/Web Start are live on 8 |
| `11.0.33` | 4 — 114940, 114943, 114944, 114946 | 7.4 | 114939 | Medium — **escapes 114938** |
| `17.0.21` | 5 — 114938, 114940, 114943, 114944, 114946 | **8.1** | 114939 | **High** |
| `21.0.13` | 8 — 114938, 114940, 114941, 114942, 114943, 114944, 114945, 114946 | **8.1** | 86144, 114939 | **High** |
| `25.0.5` / `27.0.1` | 8 — same as 21 | **8.1** | 86144, 114939, 114947 | **Highest** |
| `1.8.0` (no update level) | Indeterminate | — | — | Manual inspection |
| Other versions | Not in this bulletin | — | — | Check prior CPUs |

**The driver on every modern line is CVE-2026-114938** — Compiler, 8.1, server-reachable, no user interaction, full confidentiality/integrity/availability impact. It hits 17, 21, 25 and 27, plus Java 8 `-perf` builds only. Java 11 is the one line that escapes it.

**Java 8 deserves separate attention** despite its lower raw scores: it is the only version where the Note 2 client-side rows (86144 at 7.5, 114939 at 7.4) are realistically reachable, because Java Web Start was removed from Oracle JDK in 11 and the Applet API was removed in 21. On 17+ a Note 2 row needs a third-party Web Start (OpenWebStart / IcedTea-Web) to be exploitable at all — worth confirming against your inventory rather than assuming.

## Three limits you must account for

**1. The scan sees `11.0.33`, not `11.0.33.0.3`.** Our `java_detect` signature reads `JAVA_VERSION` from the JDK `release` file, which carries no Oracle patch-set suffix and no `b33` / `-perf` qualifier. A scan hit **narrows the candidate set — it does not confirm vulnerability**. Treat a matching row as "inspect this install", then confirm the exact build with `java -version` or the package manager.

This bites hardest on Java 8, where `-perf` alone decides whether the 8.1 Compiler flaw applies and the scan cannot tell you.

**2. The scan cannot tell you reachability.** It finds runtimes, not deployment models. Whether a host runs sandboxed applets, Web Start, or a web service exposing the affected APIs is not on disk — pair the scan inventory with your application owners before down-scoping any Note 2 row.

**3. Non-Oracle builds are out of this advisory's scope.** Oracle's matrix governs Oracle Java SE, GraalVM and JavaFX only:

- **Temurin / Ubuntu OpenJDK / Corretto etc.** — most of these CVEs originate in shared OpenJDK code and usually flow through, but the vendor's own advisory and fixed build govern. Use the scan for inventory, then check that vendor.
- **IBM Semeru / OpenJ9** — a different VM; Oracle's advisory does not apply. Use IBM's bulletin. These also report level-only (`1.8.0`) and produce two rows per install.
- **GraalVM installs** appear as ordinary `java` rows with the JDK version — distinguish them by install path, not version string.
