#Requires -Version 5.1
<#
.SYNOPSIS
Installs/upgrades the verified unsigned Windows x64 ZIP for the current user.
.DESCRIPTION
Run from an intact extracted release outside InstallDir, under the existing permitted
PowerShell execution policy. No elevation, network changes, session stop, or policy bypass.
Close the installed GUI explicitly first. Only an authenticated idle sibling broker may
be gracefully shut down. Active, orphan, recovery-required and unknown controllers refuse.
Default: %LOCALAPPDATA%\Programs\WslProxy. A custom parent must already exist, be
current-user-owned, deny other untrusted writers, and contain no reparse-point ancestors.
-Clock-free numeric major.minor.patch policy: downgrades require -AllowDowngrade;
same-version is a no-op only when the entire release manifest digest matches exactly.
Use -Recover only to resolve the recorded interrupted transaction. Recovery keeps a
complete new pair if installed, otherwise restores a complete old backup; cleanup is
allowlisted and restartable. Never manually remove controller recovery journals.
.EXAMPLE
.\install.ps1 -InstallDir 'D:\ProxyLab\install-qa\app'
.EXAMPLE
.\install.ps1 -InstallDir 'D:\ProxyLab\install-qa\app' -Recover
#>
[CmdletBinding()]
param([string] $InstallDir, [switch] $AllowDowngrade, [switch] $Recover)
try {
    . (Join-Path $PSScriptRoot 'common.ps1')
    Invoke-Installer -SourceRoot $PSScriptRoot -InstallDir $InstallDir -AllowDowngrade:$AllowDowngrade -Recover:$Recover
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
