# Rapid Response

beta site for rapid response BigFix content.

## YARA-X Discovery Scanner

The [YARA-X Scanner](docs/YARA-X.md) adds configurable runtime discovery and a compact companion Analysis for multiple embeddable libraries and runtime engines that may be bundled in multiple coexisting versions across different applications and paths.  Zero-day vulnerabilities have driven a need to detect these embedded components and compare them against a frequently-changing list of vulnerabilities and to gauge risk based on their exposure and usage.

At this time a common set of Definitions, Scan Actions, and Analysis Results are helpful in describing the versions and installation paths for PHP, Apache, Node, and Java.  More products are likely to be added over time.  The Analysis does not provide CVE data for specific versions or distinguish which are most recent, these scans are only a first step in gauging risk.

The consolidated scans and results deprecate the PHP scanner described below, but the original Fixlets, Tasks, and Analysis remain available for use for now.

## Enhanced PHP vulnerability scanner (deprecated)

The [Windows/Linux PHP scanner](docs/PHP-Scanner.md) adds
configurable runtime discovery and a compact companion Analysis. The original
Tasks and macOS content remain available. Review the bundle's scope, defaults,
version/backport caveats and validation coverage before deployment.

# Use at your own risk

This site is not subject to the full series of testing and regression that one might expect from Published content from the BigFix Team.  In particular, coverage by Operating System or specific application configurations may not have been tested, nor may workload testing have been considered.

Content in this repo is subject to rapid change as issues are identified and new detection techniques are identified.

# No warranty

Content in this repository is provided "as is," without warranty of any kind — see the repository TERMS for the full disclaimer that applies to anyone using or downloading this content. Maintainers may decline, edit, or remove any contribution at their discretion, and are under no obligation to merge, support, or maintain any particular contribution.
