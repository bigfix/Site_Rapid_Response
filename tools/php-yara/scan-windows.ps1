#Requires -Version 5.1
<# Bounded PHP signature discovery. Never executes discovered PHP binaries.
   PhpCandidateFilter.cs and the pinned rules ship beside this script. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Engine,
    [Parameter(Mandatory=$true)][string]$EngineSha256,
    [Parameter(Mandatory=$true)][string]$Rules,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$Archive,
    [string]$ArchiveSha256,
    [string[]]$Roots,
    [ValidateRange(1,5000000)][long]$MaxFiles = 5000000,
    [ValidateRange(1,2048)][long]$MaxFileMB = 512,
    [ValidateRange(1,100)][long]$CandidateGB = 30,
    [ValidateRange(1,3600)][int]$EnumerationSeconds = 1200,
    [ValidateRange(1,3600)][int]$ScanSeconds = 900,
    [ValidateRange(1,99)][int]$CpuLimit = 10,
    [ValidateRange(0,1)][int]$GentleDisk = 0,
    [ValidateRange(0,1)][int]$IncludeBuildText = 0,
    [ValidateRange(0,1)][int]$IncludeBroaderLocations = 0,
    [ValidateRange(0,1)][int]$IncludeNonstandardNames = 0,
    [string]$ExcludeDirectoriesHex = 'x'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$ruleSha256 = '0f68f1276f3d50db3dcba06fd1d8089e157fbc8e60bcca49ac1e7b2dde664615'
$utf8 = New-Object Text.UTF8Encoding($false)

function Assert-NoReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse path rejected' }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Write-AtomicText([string]$Path, [string]$Text) {
    Assert-NoReparsePath $Path
    Assert-NoReparsePath ($Path + '.new')
    [IO.File]::WriteAllText($Path + '.new', $Text, $utf8)
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($Path + '.new', $Path, [NullString]::Value) }
    else { [IO.File]::Move($Path + '.new', $Path) }
}

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
Assert-NoReparsePath $OutputDirectory
$null = [IO.Directory]::CreateDirectory($OutputDirectory)
$lock = $null
Assert-NoReparsePath (Join-Path $OutputDirectory 'scan.lock')
try { $lock = [IO.File]::Open((Join-Path $OutputDirectory 'scan.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
catch [IO.IOException] { exit 75 }
$started = [DateTime]::UtcNow.ToString('o')
$summaryPath = Join-Path $OutputDirectory 'summary.txt'
$logPath = Join-Path $OutputDirectory 'scan.log'
$clock = [Diagnostics.Stopwatch]::StartNew()
try {
    Write-AtomicText $logPath ("Scan running; started $started. Properties retain the last finished scan until this scan ends.`n")
    $ruleBytes = $utf8.GetBytes([IO.File]::ReadAllText($Rules, $utf8).Replace("`r`n","`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actualRuleHash = [BitConverter]::ToString($sha.ComputeHash($ruleBytes)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actualRuleHash -ne $ruleSha256) { throw 'Rule/prefilter hash mismatch' }
    if (-not [IO.File]::Exists($Engine)) {
        if (-not $Archive -or -not $ArchiveSha256) { throw 'Engine missing; verified archive required' }
        # Same process: avoid a second PowerShell startup. The bootstrap verifies
        # both archive and executable hashes before returning.
        & (Join-Path $PSScriptRoot 'extract-engine.ps1') -Archive $Archive -ArchiveHash $ArchiveSha256 -Destination $Engine -EngineHash $EngineSha256
    }
    elseif ((Get-FileHash -LiteralPath $Engine -Algorithm SHA256).Hash.ToLowerInvariant() -ne $EngineSha256) { throw 'Engine hash mismatch' }
    if (-not ('PhpCandidateFilter' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'PhpCandidateFilter.cs') }
    $customExclusions = New-Object PhpDirectoryExclusions($ExcludeDirectoriesHex)
    try { [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
    if (-not $Roots) { $Roots = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [IO.DriveType]::Fixed -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName }) }
    $candidateList = Join-Path $PSScriptRoot 'candidates.txt'
    $stats = [PhpCandidateFilter]::WriteCandidates($Roots, $OutputDirectory, $candidateList, $MaxFiles, ($MaxFileMB * 1MB), ($CandidateGB * 1GB), $EnumerationSeconds, ($GentleDisk -eq 1), ($IncludeBuildText -eq 1), ($IncludeBroaderLocations -eq 1), ($IncludeNonstandardNames -eq 1), $customExclusions)
    $reasons = New-Object 'Collections.Generic.List[string]'
    if ($stats.BudgetReason) { $reasons.Add($stats.BudgetReason) }
    if ($stats.Errors -gt 0) { $reasons.Add('enumeration_or_read_errors') }
    if ($stats.SizeSkipped -gt 0) { $reasons.Add('individual_file_size_limit') }
    $rawPath = Join-Path $PSScriptRoot 'results.ndjson'
    $errorPath = Join-Path $PSScriptRoot 'engine.stderr.txt'
    Assert-NoReparsePath $rawPath
    Assert-NoReparsePath $errorPath
    $scanClock = [Diagnostics.Stopwatch]::StartNew()
    if ($stats.Candidates -gt 0) {
        $arguments = @('scan','--scan-list','--print-strings','--print-meta','--output-format','ndjson',
                       '--threads','2','--cpu-limit',[string]$CpuLimit,'--timeout',[string]$ScanSeconds,
                       '--max-matches-per-pattern','64',$Rules,$candidateList)
        # These controlled paths are ordinary Windows file paths (no embedded
        # quotes, and no directory-ending backslash); no command shell is used.
        foreach ($argument in $arguments) { if ($argument.Contains('"')) { throw 'Unsupported quoted argument' } }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = [IO.Path]::GetFullPath($Engine)
        $info.Arguments = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $stdoutFile = [IO.File]::Open($rawPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $stderrFile = [IO.File]::Open($errorPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $child = $null
        try {
            $child = [Diagnostics.Process]::Start($info)
            $outputCopy = $child.StandardOutput.BaseStream.CopyToAsync($stdoutFile)
            $errorCopy = $child.StandardError.BaseStream.CopyToAsync($stderrFile)
            while (-not $child.WaitForExit(200)) {
                if ($scanClock.Elapsed.TotalSeconds -gt ($ScanSeconds + 15) -or $stdoutFile.Length -gt 64MB -or $stderrFile.Length -gt 8MB) {
                    $child.Kill()
                    $reasons.Add('engine_deadline_or_output_budget')
                }
            }
            $null = $outputCopy.GetAwaiter().GetResult()
            $null = $errorCopy.GetAwaiter().GetResult()
            if ($child.ExitCode -ne 0) { $reasons.Add('engine_exit_' + $child.ExitCode) }
        }
        finally {
            if ($child) { if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }; $child.Dispose() }
            $stdoutFile.Dispose()
            $stderrFile.Dispose()
        }
        if ((Get-Item -LiteralPath $errorPath).Length -gt 0) { $reasons.Add('engine_warnings_or_file_errors') }
    }
    else { [IO.File]::WriteAllText($rawPath,'',$utf8); [IO.File]::WriteAllText($errorPath,'',$utf8) }
    $findings = New-Object 'Collections.Generic.List[object]'
    $findingCount = 0
    foreach ($line in [IO.File]::ReadLines($rawPath, $utf8)) {
        try { $record = $line | ConvertFrom-Json }
        catch { $reasons.Add('invalid_or_truncated_engine_json'); continue }
        $findingCount++
        if ($findings.Count -ge 5000) { continue }
        $versions = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        $ruleNames = @($record.rules | ForEach-Object { $_.identifier })
        foreach ($rule in $record.rules) {
            foreach ($match in $rule.strings) {
                if ($match.identifier -in @('$ver','$pv','$cfg_ver','$hdr_ver')) {
                    $text = $match.match.Replace('\x00','').Replace([string][char]0,'')
                    foreach ($version in [regex]::Matches($text,'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}[0-9A-Za-z.+~_-]*')) { [void]$versions.Add($version.Value) }
                }
            }
        }
        $kind = if ($ruleNames -contains 'PHP_Runtime_Version') { 'PHP_RUNTIME_SIGNATURE' }
                elseif (@($ruleNames | Where-Object { $_ -ne 'PHP_Build_Artifact' }).Count -gt 0) { 'PHP_BINARY_OR_MODULE' }
                else { 'BUILD_ARTIFACT_ONLY' }
        $findings.Add([ordered]@{path=$record.path; kind=$kind; versions=@($versions | Sort-Object); rules=$ruleNames})
    }

    # Only core/runtime signatures or standard Windows SAPI/core version resources
    # can set the vulnerable flag. Extension/build evidence remains in scan.log.
    $vulnerable = New-Object 'Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $unknown = 0
    $fixes = @{'8.2'=35; '8.3'=36; '8.4'=27; '8.5'=12}
    foreach ($finding in $findings) {
        if ($finding.kind -eq 'BUILD_ARTIFACT_ONLY') { continue }
        $leaf = [IO.Path]::GetFileName([string]$finding.path)
        $core = $finding.kind -eq 'PHP_RUNTIME_SIGNATURE' -or ($finding.rules -contains 'PHP_Windows_VersionInfo' -and $leaf -match '^php(?:[0-9]+(?:ts|nts|apache[0-9_]*)?|(?:-cgi|-win)|dbg)?\.(exe|dll)$')
        if (-not $core) {
            # Ordinary PHP extensions do not contain the affected PHP core.
            if ($leaf -notmatch '^php_[^.]+\.dll$') { $unknown++ }
            continue
        }
        if (-not $finding.versions.Count) { $unknown++; continue }
        foreach ($version in $finding.versions) {
            if ($version -notmatch '^(\d+)\.(\d+)\.(\d+)(.*)$') { $unknown++; continue }
            $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]; $suffix = $Matches[4]
            $branch = "$major.$minor"
            # A prerelease of the fixed release is conservatively still affected.
            $affected = ($major -eq 5 -and $minor -ge 4) -or ($major -eq 7) -or ($major -eq 8 -and $minor -lt 2)
            if ($fixes.ContainsKey($branch)) { $affected = $patch -lt $fixes[$branch] -or ($patch -eq $fixes[$branch] -and $suffix -match '^(alpha|beta|RC|dev)') }
            elseif (-not $affected) { $unknown++; continue }
            if ($affected) {
                $displayPath = ([string]$finding.path) -replace '^\\\\\?\\', ''
                $displayPath = $displayPath.Replace("`r",'\r').Replace("`n",'\n').Replace("`t",'\t')
                [void]$vulnerable.Add($displayPath + ' | PHP ' + $version)
            }
        }
    }
    if ($findingCount -gt 5000) { $reasons.Add('finding_limit') }
    if ($unknown -gt 0) { $reasons.Add('PHP_version_or_runtime_unconfirmed') }
    $elapsed = [long][Math]::Round($clock.Elapsed.TotalSeconds)
    $duration = '{0} hours, {1} minutes, {2} seconds' -f [Math]::Floor($elapsed / 3600), [Math]::Floor(($elapsed % 3600) / 60), ($elapsed % 60)
    $completed = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $messages = @{enumeration_budget='search limit'; directory_budget='folder limit'; candidate_byte_budget='total size limit'; individual_file_size_limit='file size limit'; engine_deadline_or_output_budget='scan time/output limit'; enumeration_or_read_errors='unreadable locations'; engine_warnings_or_file_errors='YARA warnings'; finding_limit='result limit'; PHP_version_or_runtime_unconfirmed='unconfirmed PHP evidence'}
    $why = @($reasons | Select-Object -Unique | ForEach-Object { if ($messages.ContainsKey($_)) { $messages[$_] } else { 'YARA error' } })
    $lastScan = $completed + $(if ($why.Count) { ' (Partial: ' + ($why -join ', ') + '; see scan.log)' } else { '' })
    $pathRows = New-Object 'Collections.Generic.List[string]'
    $pathBytes = 0
    foreach ($path in $vulnerable) {
        $row = 'VULNERABLE=' + $(if ($path.Length -gt 900) { $path.Substring(0,870) + '...[full path in scan.log]' } else { $path })
        $rowBytes = $utf8.GetByteCount($row) + 1
        if ($pathRows.Count -ge 100 -or $pathBytes + $rowBytes -gt 120000) { break }
        $pathRows.Add($row); $pathBytes += $rowBytes
    }
    if ($vulnerable.Count -gt $pathRows.Count) { $lastScan += ' (first ' + $pathRows.Count + ' paths shown; all paths in scan.log)' }
    $report = [ordered]@{completed=$completed; duration=$duration; state=$(if ($reasons.Count) {'Partial'} else {'Completed'});
        started=$started; stats=$stats; scan_seconds=$scanClock.Elapsed.TotalSeconds; seconds=$clock.Elapsed.TotalSeconds;
        reasons=$reasons.ToArray(); roots=$Roots; custom_directory_exclusions=$customExclusions.Patterns.ToArray(); vulnerable_paths=@($vulnerable); findings_count=$findingCount; findings=$findings.ToArray();
        engine_messages=[IO.File]::ReadAllText($errorPath); rule_sha256=$ruleSha256;
        limits=@{max_files=$MaxFiles; max_file_mb=$MaxFileMB; candidate_gb=$CandidateGB; enumeration_seconds=$EnumerationSeconds; scan_seconds=$ScanSeconds; cpu_limit=$CpuLimit; gentle_disk=$GentleDisk; include_build_text=$IncludeBuildText; include_broader_locations=$IncludeBroaderLocations; include_nonstandard_names=$IncludeNonstandardNames};
        meaning='TRUE means an upstream-affected PHP runtime version was detected. FALSE means none detected in this scan scope, not proof of absence or web exploitability. Custom vendor backports require verification.'}
    Write-AtomicText $logPath (($report | ConvertTo-Json -Depth 14) + "`n")
    $summary = @(('DETECTED=' + $(if ($vulnerable.Count) { 'TRUE' } else { 'FALSE' })), ('LAST_SCAN=' + $lastScan), ('DURATION=' + $duration))
    $summary += $pathRows.ToArray()
    # A single replacement publishes all four properties together; in-progress
    # scans never clear a previous positive result or publish a start time as completion.
    Write-AtomicText $summaryPath (($summary -join "`n") + "`n")
    if ($reasons.Count) { exit 10 }
}
catch {
    Write-AtomicText $logPath ("Scan failed at $([DateTime]::UtcNow.ToString('o')): $($_.Exception.Message)`n")
    $previous = if ([IO.File]::Exists($summaryPath)) { [IO.File]::ReadAllLines($summaryPath) } else { @('DETECTED=FALSE','LAST_SCAN=NO SCAN','DURATION=NO SCAN') }
    $previous = @($previous | ForEach-Object { if ($_.StartsWith('LAST_SCAN=')) { ($_ -split ' \(Last attempt failed')[0] + ' (Last attempt failed; see scan.log)' } else { $_ } })
    Write-AtomicText $summaryPath (($previous -join "`n") + "`n")
    throw
}
finally { if ($lock) { $lock.Dispose() } }
