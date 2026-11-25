#Requires -Version 5.1
<#
.SYNOPSIS
Install smoke test for one release ZIP, on a machine without WSL (CI).
.DESCRIPTION
In a fresh private directory under -WorkDir: extract the ZIP, install it,
check the installed backend's version, reinstall the same package (no file may
change), try a package with one modified file (must be refused, install
unchanged) and uninstall (no program file may remain). Never touches the
default install location: every call passes -InstallDir. Writes the outcome
as JSON to -Output (passed, installed_version, installed_files,
reinstall_unchanged, tampered_refused, uninstall_clean, error) and exits 1 on
any failure.
No takeover is started; that needs WSL and is accepted on a real machine.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Zip,
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $WorkDir,
    [Parameter(Mandatory)] [string] $Output
)
$ErrorActionPreference = 'Stop'
$report = [ordered]@{ passed = $false; installed_version = $null; installed_files = 0; reinstall_unchanged = $false; tampered_refused = $false; uninstall_clean = $false; error = $null }

function New-PrivateParent([string] $Path) {
    # Like the installer's own directories: owned by this user, no inherited
    # rules, only this user, SYSTEM and Administrators may write.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    foreach ($id in @($sid, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'), (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
}

function Invoke-Script([string] $Script, [string] $InstallDir) {
    # Windows PowerShell 5.1 turns a native command's stderr line into a
    # terminating error under 'Stop'; the installer reports refusals there.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & powershell.exe -NoProfile -File $Script -InstallDir $InstallDir 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    $text = ($lines -join "`n").Trim()
    # Error text is wrapped at the console width, even inside words.
    return [pscustomobject]@{ Code = $code; Text = $text; Flat = ($text -replace '\s', '') }
}

function Get-Snapshot([string] $Path) {
    $items = Get-ChildItem -LiteralPath $Path -Recurse -File -Force | Sort-Object FullName
    return ($items | ForEach-Object { '{0}|{1}|{2}' -f $_.FullName.Substring($Path.Length), (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash, $_.LastWriteTimeUtc.Ticks }) -join "`n"
}

try {
    if (Test-Path -LiteralPath $WorkDir) { throw "WorkDir must not exist yet: $WorkDir" }
    New-PrivateParent $WorkDir
    $package = Join-Path $WorkDir 'package'
    $app = Join-Path $WorkDir 'app'
    Expand-Archive -LiteralPath $Zip -DestinationPath $package

    $result = Invoke-Script (Join-Path $package 'install.ps1') $app
    if ($result.Code -ne 0) { throw "Fresh install failed ($($result.Code)): $($result.Text)" }
    $reported = (& (Join-Path $app 'wsl-proxyctl.exe') --version | Out-String).Trim()
    if ($reported -cne "wsl-proxyctl $Version") { throw "Installed backend reports '$reported', expected 'wsl-proxyctl $Version'" }
    $report.installed_version = $reported
    $report.installed_files = @(Get-ChildItem -LiteralPath $app -Recurse -File -Force).Count

    $before = Get-Snapshot $app
    $result = Invoke-Script (Join-Path $package 'install.ps1') $app
    if ($result.Code -ne 0 -or $result.Flat -notmatch 'Alreadyinstalled') { throw "Reinstall of the same package was not a no-op ($($result.Code)): $($result.Text)" }
    if ((Get-Snapshot $app) -cne $before) { throw 'Reinstalling the same package changed files.' }
    $report.reinstall_unchanged = $true

    $tampered = Join-Path $WorkDir 'package-tampered'
    Copy-Item -Recurse -LiteralPath $package -Destination $tampered
    Add-Content -LiteralPath (Join-Path $tampered 'USAGE.txt') -Value 'modified'
    $result = Invoke-Script (Join-Path $tampered 'install.ps1') $app
    if ($result.Code -eq 0 -or $result.Flat -notmatch 'missingormodified') { throw "A modified package was not refused ($($result.Code)): $($result.Text)" }
    if ((Get-Snapshot $app) -cne $before) { throw 'A refused package changed the installation.' }
    $report.tampered_refused = $true

    $result = Invoke-Script (Join-Path $package 'uninstall.ps1') $app
    if ($result.Code -ne 0) { throw "Uninstall failed ($($result.Code)): $($result.Text)" }
    $left = @(if (Test-Path -LiteralPath $app) { Get-ChildItem -LiteralPath $app -Recurse -Force })
    if ($left.Count -ne 0) { throw "Uninstall left files behind: $($left.Name -join ', ')" }
    $reserved = @(Get-ChildItem -LiteralPath $WorkDir -Force -Filter '.wsl-proxy-*')
    if ($reserved.Count -ne 0) { throw "Uninstall left transaction, stage or backup entries: $($reserved.Name -join ', ')" }
    $report.uninstall_clean = $true
    $report.passed = $true
    $report | ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
    $report | ConvertTo-Json
    exit 0
} catch {
    $report.error = "$_"
    $report | ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
    Write-Error $_ -ErrorAction Continue
    exit 1
}
