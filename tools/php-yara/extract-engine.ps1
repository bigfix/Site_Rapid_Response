#Requires -Version 5.1
param([string]$Archive,[string]$ArchiveHash,[string]$Destination,[string]$EngineHash)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
if (Test-Path -LiteralPath $Destination) { throw 'Engine destination exists' }
if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ArchiveHash) { throw 'Archive hash mismatch' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $entry = $zip.GetEntry('yr.exe')
    if (-not $entry -or $entry.Length -gt 64MB) { throw 'Unexpected archive entry' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$Destination,$false)
}
finally { $zip.Dispose() }
if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $EngineHash) { throw 'Engine hash mismatch' }
