#Requires -Version 5.1
<#
.SYNOPSIS
Removes only a verified owned current-user WslProxy installation.
.DESCRIPTION
No elevation, forced process termination, shared networking changes, user configuration,
credential or controller recovery-journal deletion. Unknown/modified installations refuse.
Close the installed GUI explicitly first; only its authenticated idle broker can be
shut down. A verified private helper holds the per-user controller lock through removal.
Default: %LOCALAPPDATA%\Programs\WslProxy. Select isolated lab installations explicitly.
For interrupted uninstall, run this entrypoint from an intact extracted release outside
InstallDir with -Recover. Only recorded owned files are removed; unknown files/reparse
points are preserved and cause refusal. Never bypass system execution policy.
.EXAMPLE
.\uninstall.ps1 -InstallDir 'D:\ProxyLab\install-qa\app'
.EXAMPLE
.\uninstall.ps1 -InstallDir 'D:\ProxyLab\install-qa\app' -Recover
#>
[CmdletBinding()]
param([string] $InstallDir, [switch] $Recover)
try {
    . (Join-Path $PSScriptRoot 'common.ps1')
    Invoke-Installer -SourceRoot $PSScriptRoot -InstallDir $InstallDir -Uninstall -Recover:$Recover
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
