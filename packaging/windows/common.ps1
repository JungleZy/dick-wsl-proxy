# Shared implementation for the unsigned, current-user ZIP installer (Windows PowerShell 5.1+).
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Product = 'wsl-proxy'
$script:MarkerName = '.wsl-proxy-install.json'
$script:Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:RootNames = @('wsl-proxyctl.exe', 'wsl-proxy-desktop.exe', 'install.ps1', 'uninstall.ps1', 'common.ps1', 'USAGE.txt', 'BUILD-RECORD.json', 'Cargo.lock', 'THIRD-PARTY-NOTICES.json')
# Runtime files the application writes beside its EXEs (desktop store, environment progress,
# diagnostics exports, scratch). They belong to the user, not to a release: walks skip them,
# upgrades carry them into the new directory, and uninstall leaves them in the install directory.
$script:DataPattern = '^(?:desktop\.sqlite(?:\.migrating)?(?:-wal|-shm|-journal)?|environment-progress-.{1,255}\.(?:json|tmp)|diagnostics-[0-9]{1,24}\.json|io-[0-9]{1,10}-[0-9]{1,20}\.tmp)$'
if (-not ('WslProxyInstallerPath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WslProxyInstallerPath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string path);
    public static long Attributes(string path) {
        uint value = GetFileAttributesW(path);
        if (value != UInt32.MaxValue) return value;
        int error = Marshal.GetLastWin32Error();
        if (error == 2 || error == 3) return -1;
        throw new Win32Exception(error);
    }
}
'@
}

function Get-FullPath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1f"*?<>|]' -or $Path.StartsWith('\\')) { throw 'Only a local absolute filesystem path is permitted.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or $full.Length -le 3) { throw 'Select a local directory below a drive root (no UNC/device/stream paths).' }
    return $full
}

function Assert-NoReparse([string] $Path) {
    $full = Get-FullPath $Path
    $cursor = [IO.Path]::GetPathRoot($full)
    foreach ($part in $full.Substring($cursor.Length).Split('\')) {
        if ($part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw "Unsafe Windows path component: $part" }
        $cursor = Join-Path $cursor $part
        # Native attributes inspect the entry itself, including a dangling reparse point.
        $attributes = [WslProxyInstallerPath]::Attributes($cursor)
        if ($attributes -ge 0 -and ($attributes -band 0x400) -ne 0) { throw "Reparse points are not permitted: $cursor" }
    }
}

# Owners and writers trusted besides the current user: SYSTEM and Administrators.
# An elevated process (an elevated backend needs an elevated installer, decision 21)
# creates files owned by Administrators by default, and both may already modify
# everything here; any other account is refused.
$script:TrustedOwners = @($script:Sid, 'S-1-5-18', 'S-1-5-32-544')

function Assert-Owned([string] $Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:TrustedOwners) { throw "Path must be owned by the current Windows user, SYSTEM or Administrators: $Path" }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (($rule.FileSystemRights.value__ -band 0xD0156) -ne 0 -and $rule.IdentityReference.Value -notin $script:TrustedOwners) { throw "Path permits another identity to modify it: $Path" }
    }
}

# What the installer writes stays owned by the current user, as New-PrivateDirectory
# does for its own directories, even when it runs elevated.
function Set-UserOwner([string] $Path) {
    Assert-NoReparse $Path
    $sid = New-Object Security.Principal.SecurityIdentifier($script:Sid)
    if ((Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $script:Sid) { return }
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetOwner($sid)
        [IO.Directory]::SetAccessControl($Path, $security)
    } else {
        $security = New-Object Security.AccessControl.FileSecurity
        $security.SetOwner($sid)
        [IO.File]::SetAccessControl($Path, $security)
    }
}

function New-PrivateDirectory([string] $Path) {
    Assert-NoReparse $Path
    if (Test-Path -LiteralPath $Path) { throw "Refusing to reuse a staging directory: $Path" }
    $parent = Split-Path -Parent $Path
    Assert-Owned $parent
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:Sid)))
    foreach ($sid in @($script:Sid, 'S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    Assert-Owned $Path
}

function Get-Digest([string] $Path) {
    Assert-NoReparse $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
}

function Read-Json([string] $Path) {
    Assert-NoReparse $Path
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -gt 4MB) { throw "Invalid or oversized JSON file: $Path" }
    return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json)
}

function Write-NewJson([string] $Path, $Value) {
    Assert-NoReparse $Path
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Set-UserOwner $Path
}

function Assert-Fields($Object, [string[]] $Fields) {
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    if (($actual -join '|') -cne (($Fields | Sort-Object) -join '|')) { throw 'Unexpected metadata fields; refusing to guess ownership or format.' }
}

function Get-Version([string] $Version) {
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw "Only numeric major.minor.patch release versions are supported: $Version" }
    return [version] $Version
}

function Assert-RelativeFile([string] $Name) {
    if ($script:RootNames -ccontains $Name) { return }
    if ($Name -cmatch '^licenses/[A-Za-z0-9][A-Za-z0-9_.+-]*-[0-9][A-Za-z0-9_.+-]*/[A-Za-z0-9_.-]+$' -and -not $Name.Contains('..')) { return }
    throw "Unexpected package filename: $Name"
}

function Test-DataName([string] $Relative, $Item) {
    return (-not $Relative -and -not $Item.PSIsContainer -and $Item.Name -cmatch $script:DataPattern)
}

# A directory left by uninstall: no marker, no release files, only runtime data (or nothing).
function Test-DataOnly([string] $Path) {
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) { if (-not (Test-DataName '' $item)) { return $false } }
    return $true
}

function Move-Data([string] $From, [string] $To, $Gate) {
    $items = @(Get-ChildItem -LiteralPath $From -Force | Where-Object { Test-DataName '' $_ })
    if ($items.Count -eq 0) { return }
    if (-not (Test-Path -LiteralPath $To)) { New-PrivateDirectory $To }
    Assert-Owned $To
    foreach ($item in $items) {
        Assert-Owned $item.FullName
        $destination = Join-Path $To $item.Name
        Assert-NoReparse $destination
        if (Test-Path -LiteralPath $destination) { throw "Runtime data file exists in both $From and $To; preserve both: $($item.Name)" }
        Assert-Maintenance $Gate
        [IO.File]::Move($item.FullName, $destination)
    }
}

function Remove-DataBackup([string] $Path, [string] $Target, $Gate) {
    Assert-Owned $Path
    if (-not (Test-DataOnly $Path)) { throw "Backup holds more than runtime data; preserve it: $Path" }
    Move-Data $Path $Target $Gate
    Assert-Maintenance $Gate
    [IO.Directory]::Delete($Path, $false)
}

function Get-Package([string] $Root, [switch] $Installed) {
    Assert-NoReparse $Root
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "Package directory is missing: $Root" }
    $manifestPath = Join-Path $Root 'release.json'
    $manifest = Read-Json $manifestPath
    Assert-Fields $manifest @('schema_version', 'product', 'version', 'target', 'architecture', 'kind', 'files', 'payload', 'verification', 'licenses')
    # New packages are MSVC builds. Installed copies of earlier GNU-built releases stay readable so they can be upgraded or uninstalled.
    $supportedTarget = $manifest.target -ceq 'x86_64-pc-windows-msvc' -or ($Installed -and $manifest.target -ceq 'x86_64-pc-windows-gnu')
    if ($manifest.schema_version -ne 1 -or $manifest.product -cne $script:Product -or -not $supportedTarget -or $manifest.architecture -cne 'x64') { throw 'Unsupported release manifest identity/platform.' }
    $null = Get-Version $manifest.version
    if ($manifest.kind -ceq 'qa-vintage-not-published') {
        if ($manifest.version -cne '0.1.0') { throw 'QA vintage packages are supported only for the genuine 0.1.0 fixture, never as a published release.' }
    } elseif ($manifest.kind -ceq 'release-candidate') {
        if ((Get-Version $manifest.version) -le [version]'0.1.0') { throw 'Release-candidate packages require maintenance-capable version 0.1.1 or newer; 0.1.0 is QA vintage only.' }
    } else { throw 'Unsupported package kind; expected release-candidate or the explicitly marked 0.1.0 QA vintage fixture.' }
    Assert-Fields $manifest.payload @('backend', 'desktop')
    if ($manifest.payload.backend -cne 'wsl-proxyctl.exe' -or $manifest.payload.desktop -cne 'wsl-proxy-desktop.exe') { throw 'Manifest must name the fixed same-directory EXE pair.' }
    $files = @{}
    $directories = @{}
    foreach ($entry in $manifest.files) {
        Assert-Fields $entry @('path', 'sha256', 'size')
        Assert-RelativeFile $entry.path
        if ($files.ContainsKey($entry.path) -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $entry.size -isnot [ValueType] -or $entry.size -lt 0 -or [decimal]$entry.size % 1 -ne 0) { throw 'Invalid/duplicate manifest file record.' }
        $files[$entry.path] = $entry
        $filePath = Join-Path $Root $entry.path
        Assert-NoReparse $filePath
        $file = Get-Item -LiteralPath $filePath -Force
        if ($file.PSIsContainer -or $file.Length -ne $entry.size -or (Get-Digest $filePath) -cne $entry.sha256) { throw "Package file is missing or modified: $($entry.path)" }
        $dir = [IO.Path]::GetDirectoryName($entry.path.Replace('/', '\'))
        while ($dir) { $directories[$dir] = $true; $dir = [IO.Path]::GetDirectoryName($dir) }
    }
    foreach ($name in $script:RootNames) { if (-not $files.ContainsKey($name)) { throw "Required package file absent: $name" } }
    # Walk one directory at a time so no reparse point is traversed even while rejecting extras.
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue('')
    while ($pending.Count) {
        $relative = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath (Join-Path $Root $relative) -Force) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse package entry: $($item.FullName)" }
            # Runtime data may be held open by a running app (WAL, delete-on-close scratch), so it
            # is not opened here; Move-Data checks ownership when maintenance relocates it.
            if (Test-DataName $relative $item) { continue }
            if ($Installed) { Assert-Owned $item.FullName }
            $name = if ($relative) { "$relative\$($item.Name)" } else { $item.Name }
            if ($item.PSIsContainer) {
                if (-not $directories.ContainsKey($name)) { throw "Unowned directory in package/install: $name" }
                $pending.Enqueue($name)
            } elseif ($name -ceq 'release.json' -or ($Installed -and $name -ceq $script:MarkerName)) { continue
            } elseif (-not $files.ContainsKey($name.Replace('\', '/'))) { throw "Unowned file in package/install: $name" }
        }
    }
    return [pscustomobject]@{ Root = $Root; Manifest = $manifest; Digest = Get-Digest $manifestPath; Files = $files; Directories = $directories }
}

function Get-Install([string] $Path, [string] $LogicalPath = $Path) {
    Assert-Owned $Path
    $markerPath = Join-Path $Path $script:MarkerName
    Assert-NoReparse $markerPath
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw "Nonempty directory is not an owned WslProxy installation (trusted marker missing): $Path" }
    $marker = Read-Json $markerPath
    Assert-Fields $marker @('schema_version', 'product', 'install_dir', 'owner_sid', 'installation_id', 'manifest_sha256')
    $guid = [guid]::Empty
    if ($marker.schema_version -ne 1 -or $marker.product -cne $script:Product -or $marker.owner_sid -cne $script:Sid -or $marker.install_dir -ine $LogicalPath -or -not [guid]::TryParseExact($marker.installation_id, 'N', [ref]$guid)) { throw "Install ownership marker does not match this user/path: $Path" }
    Assert-Owned $markerPath
    $package = Get-Package $Path -Installed
    if ($marker.manifest_sha256 -cne $package.Digest) { throw 'Installed manifest was modified; preserve it and recover from a verified intact package.' }
    return [pscustomobject]@{ Package = $package; Marker = $marker }
}

function Copy-Package($Package, [string] $Destination, [string] $LogicalPath, [string] $InstallationId) {
    New-PrivateDirectory $Destination
    foreach ($dir in @($Package.Directories.Keys | Sort-Object { $_.Length })) {
        $path = Join-Path $Destination $dir
        [IO.Directory]::CreateDirectory($path) | Out-Null
        Set-UserOwner $path
    }
    foreach ($name in @($Package.Files.Keys) + @('release.json')) {
        $path = Join-Path $Destination $name
        [IO.File]::Copy((Join-Path $Package.Root $name), $path, $false)
        Set-UserOwner $path
    }
    Write-NewJson (Join-Path $Destination $script:MarkerName) @{ schema_version = 1; product = $script:Product; install_dir = $LogicalPath; owner_sid = $script:Sid; installation_id = $InstallationId; manifest_sha256 = $Package.Digest }
    $copy = Get-Install $Destination $LogicalPath
    if ($copy.Package.Digest -cne $Package.Digest) { throw 'Staged release differs from verified source.' }
}

function Remove-RecordedInstall([string] $Path, $Tx, [string] $Digest, $Records, $Gate) {
    Assert-Owned $Path
    $files = @{}
    $directories = @{}
    foreach ($entry in $Records) {
        Assert-Fields $entry @('path', 'sha256', 'size')
        Assert-RelativeFile $entry.path
        if ($files.ContainsKey($entry.path) -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $entry.size -lt 0) { throw 'Invalid recorded cleanup allowlist.' }
        $files[$entry.path] = $entry
        $dir = [IO.Path]::GetDirectoryName($entry.path.Replace('/', '\'))
        while ($dir) { $directories[$dir] = $true; $dir = [IO.Path]::GetDirectoryName($dir) }
    }
    foreach ($required in $script:RootNames) { if (-not $files.ContainsKey($required)) { throw 'Incomplete recorded cleanup allowlist.' } }
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue('')
    while ($pending.Count) {
        $relative = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath (Join-Path $Path $relative) -Force) {
            if (Test-DataName $relative $item) { continue }
            Assert-Owned $item.FullName
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in transaction cleanup; nothing is followed.' }
            $name = if ($relative) { "$relative\$($item.Name)" } else { $item.Name }
            if ($item.PSIsContainer) {
                if (-not $directories.ContainsKey($name)) { throw "Unowned transaction directory: $name" }
                $pending.Enqueue($name)
            } elseif ($name -ceq 'release.json') {
                if ((Get-Digest $item.FullName) -cne $Digest) { throw 'Recorded release manifest was modified.' }
            } elseif ($name -ceq $script:MarkerName) {
                $marker = Read-Json $item.FullName
                Assert-Fields $marker @('schema_version', 'product', 'install_dir', 'owner_sid', 'installation_id', 'manifest_sha256')
                if ($marker.schema_version -ne 1 -or $marker.product -cne $script:Product -or $marker.owner_sid -cne $script:Sid -or $marker.install_dir -ine $Tx.install_dir -or $marker.installation_id -cne $Tx.id -or $marker.manifest_sha256 -cne $Digest) { throw 'Recorded cleanup marker differs.' }
            } else {
                $key = $name.Replace('\', '/')
                if (-not $files.ContainsKey($key) -or $item.Length -ne $files[$key].size -or (Get-Digest $item.FullName) -cne $files[$key].sha256) { throw "Unowned/modified transaction file: $name" }
            }
        }
    }
    # Runtime data stays with the installation path: the new release after an upgrade, or the
    # otherwise empty install directory after uninstall.
    Move-Data $Path $Tx.install_dir $Gate
    # Missing recorded files are allowed only here, enabling restart after partial cleanup.
    foreach ($name in @($files.Keys)) {
        Assert-Maintenance $Gate
        $filePath = Join-Path $Path $name
        Assert-NoReparse $filePath
        if (Test-Path -LiteralPath $filePath) { [IO.File]::Delete($filePath) }
    }
    foreach ($dir in @($directories.Keys | Sort-Object { $_.Length } -Descending)) {
        $dirPath = Join-Path $Path $dir
        Assert-NoReparse $dirPath
        if (Test-Path -LiteralPath $dirPath) { Assert-Maintenance $Gate; [IO.Directory]::Delete($dirPath, $false) }
    }
    foreach ($name in @('release.json', $script:MarkerName)) { Assert-Maintenance $Gate; [IO.File]::Delete((Join-Path $Path $name)) }
    Assert-Maintenance $Gate
    [IO.Directory]::Delete($Path, $false)
}

function Invoke-Control([string] $Backend, [string] $Digest, [string] $Argument, [string] $InputText = '') {
    Assert-NoReparse $Backend
    $pin = [IO.File]::Open($Backend, 'Open', 'Read', 'Read')
    try {
        if ((Get-Digest $Backend) -cne $Digest) { throw 'Controller changed before execution; no unverified binary was run.' }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $Backend; $info.Arguments = $Argument; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        try {
            if ($InputText) { $process.StandardInput.WriteLine($InputText) }
            $process.StandardInput.Close()
            $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(15000)) { throw 'Controller did not answer; it has NOT been killed. Close it explicitly and retry.' }
            return [pscustomobject]@{ Code = $process.ExitCode; Text = $stdout.Result; Error = $stderr.Result }
        } finally { $process.Dispose() }
    } finally { $pin.Dispose() }
}

function Assert-Idle($Value, [switch] $Legacy) {
    if ($Value.phase -cne 'idle' -or $null -ne $Value.active_target -or $Value.config_generation -ne 0 -or $Value.PSObject.Properties.Name -contains 'code') { throw 'Controller is active, recovery-required, or unknown. Use the controller to inspect/recover explicitly; installer never stops a session.' }
    if (-not $Legacy -and ($Value.PSObject.Properties.Name -notcontains 'operation_generation' -or $Value.operation_generation -isnot [ValueType] -or $Value.operation_generation -lt 0)) { throw 'Controller has no verified operation generation.' }
}

function Close-IdleBroker($Installed, $Source) {
    $candidate = if ($null -ne $Installed) { $Installed.Package } else { $Source }
    $backend = Join-Path $candidate.Root 'wsl-proxyctl.exe'
    $digest = $candidate.Files['wsl-proxyctl.exe'].sha256
    $result = Invoke-Control $backend $digest 'status'
    if ($result.Code -eq 0) {
        Assert-Idle ($result.Text | ConvertFrom-Json) -Legacy:($candidate.Manifest.version -ceq '0.1.0')
        return
    }
    $failure = $result.Text | ConvertFrom-Json
    if ($failure.code -cne 'controller_busy') { throw "Controller status failed; no mutation performed: $($result.Text) $($result.Error)" }
    $result = Invoke-Control $backend $digest 'rpc' '{"command":"status"}'
    if ($result.Code -ne 0) { throw "Another controller/session or foreign portable broker holds the lock. Close it explicitly after verifying idle; no process was killed. $($result.Text)" }
    Assert-Idle ($result.Text | ConvertFrom-Json) -Legacy:($candidate.Manifest.version -ceq '0.1.0')
    $result = Invoke-Control $backend $digest 'rpc' '{"command":"shutdown_daemon"}'
    if ($result.Code -ne 0 -or ($result.Text | ConvertFrom-Json).shutdown -ne $true) { throw 'Authenticated idle broker did not acknowledge shutdown; refusing installation.' }
}

function Start-Maintenance($Package, [string] $Parent) {
    $helper = Join-Path $Parent ('.wsl-proxy-helper-' + [guid]::NewGuid().ToString('N'))
    New-PrivateDirectory $helper
    $exe = Join-Path $helper 'wsl-proxyctl.exe'
    $process = $null
    $helperExited = $true
    $helperPid = 0
    try {
        [IO.File]::Copy((Join-Path $Package.Root 'wsl-proxyctl.exe'), $exe, $false)
        $pin = [IO.File]::Open($exe, 'Open', 'Read', 'Read')
        try {
            if ((Get-Digest $exe) -cne $Package.Files['wsl-proxyctl.exe'].sha256) { throw 'Maintenance helper integrity check failed.' }
            $legacy = $Package.Manifest.version -ceq '0.1.0'
            $info = New-Object Diagnostics.ProcessStartInfo
            $info.FileName = $exe; $info.Arguments = if ($legacy) { 'session' } else { 'maintenance' }
            $info.UseShellExecute = $false; $info.CreateNoWindow = $true
            $info.WorkingDirectory = $helper
            $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
            $process = [Diagnostics.Process]::Start($info)
            $helperPid = $process.Id
            $line = $process.StandardOutput.ReadLineAsync()
            if (-not $line.Wait(15000)) { throw "Maintenance handshake timed out. No files changed. Close idle helper PID $($process.Id) explicitly if it remains." }
            if ([string]::IsNullOrWhiteSpace($line.Result)) { throw 'Maintenance helper refused or exited without a JSON handshake; no install files were changed.' }
            $value = $line.Result | ConvertFrom-Json
            if ($value.PSObject.Properties.Name -contains 'code') { throw "Maintenance refused: $($line.Result). No status-only fallback or session cleanup was attempted." }
            if ($legacy) { Assert-Idle $value -Legacy
            } else {
                Assert-Fields $value @('maintenance', 'protocol', 'phase', 'operation_generation', 'version', 'pid')
                if ($value.maintenance -cne $true -or $value.protocol -ne 1 -or $value.phase -cne 'idle' -or $value.version -cne $Package.Manifest.version -or $value.pid -ne $process.Id -or $value.operation_generation -isnot [ValueType] -or $value.operation_generation -lt 0) { throw 'Maintenance lock handshake was not exact; no status-only fallback is permitted.' }
            }
            if ($process.HasExited) { throw 'Maintenance helper exited without holding the lock.' }
            return [pscustomobject]@{ Process = $process; Pin = $pin; Directory = $helper; Exe = $exe; Digest = $Package.Files['wsl-proxyctl.exe'].sha256; Legacy = $legacy }
        } catch {
            if ($null -ne $process) { $process.StandardInput.Close(); $helperExited = $process.WaitForExit(5000); $process.Dispose() }
            $pin.Dispose()
            throw
        }
    } catch {
        if (-not $helperExited) { throw "Maintenance helper PID $helperPid did not exit. No forced kill was performed. Close it explicitly; preserve $helper for inspection. $($_.Exception.Message)" }
        if (Test-Path -LiteralPath $exe) { Assert-NoReparse $exe; if ((Get-Digest $exe) -ceq $Package.Files['wsl-proxyctl.exe'].sha256) { [IO.File]::Delete($exe) } }
        if (@(Get-ChildItem -LiteralPath $helper -Force).Count -eq 0) { [IO.Directory]::Delete($helper, $false) }
        throw
    }
}

function Assert-Maintenance($Gate) {
    if ($Gate.Process.HasExited) { throw 'Maintenance lock was lost. Preserve transaction files and rerun with -Recover; do not start the application.' }
}

function Stop-Maintenance($Gate) {
    try {
        if (-not $Gate.Process.HasExited) {
            if (-not $Gate.Legacy) { $Gate.Process.StandardInput.WriteLine('release'); $Gate.Process.StandardInput.Flush() }
            $Gate.Process.StandardInput.Close()
            if (-not $Gate.Process.WaitForExit(5000)) { throw "Idle helper PID $($Gate.Process.Id) did not exit; no forced kill was performed. Close it explicitly and preserve $($Gate.Directory)." }
        }
        if ($Gate.Process.ExitCode -ne 0) { throw 'Maintenance helper exited with an error; inspect controller status explicitly.' }
    } finally {
        $exited = $Gate.Process.HasExited
        $Gate.Pin.Dispose(); $Gate.Process.Dispose()
        if ($exited) {
            Assert-Owned $Gate.Directory
            if ((Get-Digest $Gate.Exe) -cne $Gate.Digest) { throw 'Helper changed; refusing cleanup.' }
            [IO.File]::Delete($Gate.Exe)
            [IO.Directory]::Delete($Gate.Directory, $false)
        }
    }
}

function Resolve-Target([string] $InstallDir) {
    $defaultParent = Join-Path $env:LOCALAPPDATA 'Programs'
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        Assert-Owned $env:LOCALAPPDATA
        if (-not (Test-Path -LiteralPath $defaultParent)) { New-PrivateDirectory $defaultParent }
        $InstallDir = Join-Path $defaultParent 'WslProxy'
    }
    $target = Get-FullPath $InstallDir
    Assert-NoReparse $target
    $parent = Split-Path -Parent $target
    Assert-Owned $parent
    if ((Split-Path -Leaf $target) -match '^\.wsl-proxy-' -or $target.Length -gt 180) { throw 'Choose a non-reserved installation directory with a path shorter than 181 characters.' }
    return $target
}

function Assert-Separate([string] $Source, [string] $Target) {
    if ($Source -ieq $Target -or $Source.StartsWith($Target + '\', [StringComparison]::OrdinalIgnoreCase) -or $Target.StartsWith($Source + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Run from an intact extracted package outside the installation directory; source and target may not overlap.' }
}

function Get-TransactionPath([string] $Target) { return ($Target + '.wsl-proxy-transaction.json') }

function Get-Transaction([string] $Target) {
    $path = Get-TransactionPath $Target
    Assert-Owned $path
    $tx = Read-Json $path
    Assert-Fields $tx @('schema_version', 'product', 'owner_sid', 'id', 'install_dir', 'stage_dir', 'backup_dir', 'operation', 'old_digest', 'new_digest', 'old_files', 'new_files')
    $id = [guid]::Empty
    if ($tx.schema_version -ne 1 -or $tx.product -cne $script:Product -or $tx.owner_sid -cne $script:Sid -or $tx.install_dir -ine $Target -or -not [guid]::TryParseExact($tx.id, 'N', [ref]$id) -or $tx.operation -notin @('install', 'uninstall')) { throw 'Invalid transaction ownership record; preserve it for manual inspection.' }
    $parent = Split-Path -Parent $Target
    if ($tx.stage_dir -ine (Join-Path $parent ('.wsl-proxy-stage-' + $tx.id)) -or $tx.backup_dir -ine (Join-Path $parent ('.wsl-proxy-backup-' + $tx.id))) { throw 'Transaction paths do not match the owned sibling layout.' }
    foreach ($digest in @($tx.old_digest, $tx.new_digest)) { if ($null -ne $digest -and $digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid transaction manifest digest.' } }
    return $tx
}

function Assert-TransactionInstall([string] $Path, $Tx, [string] $Digest) {
    $install = Get-Install $Path $Tx.install_dir
    if ($install.Package.Digest -cne $Digest -or $install.Marker.installation_id -cne $Tx.id) { throw "Transaction directory identity mismatch: $Path" }
}

function Recover-Transaction([string] $Target, $Gate) {
    $tx = Get-Transaction $Target
    Assert-Maintenance $Gate
    if ($tx.operation -ceq 'uninstall') {
        if (Test-Path -LiteralPath $tx.stage_dir) { throw 'Unexpected uninstall staging directory; preserve it.' }
        # Cleanup may already have moved runtime data back into a fresh install directory.
        if ((Test-Path -LiteralPath $Target) -and -not (Test-DataOnly $Target)) {
            Assert-TransactionInstall $Target $tx $tx.old_digest
            if (Test-Path -LiteralPath $tx.backup_dir) { throw 'Both uninstall target and backup exist; preserve them for inspection.' }
            Assert-Maintenance $Gate
            [IO.Directory]::Move($Target, $tx.backup_dir)
        }
        if (Test-Path -LiteralPath $tx.backup_dir) { Remove-RecordedInstall $tx.backup_dir $tx $tx.old_digest $tx.old_files $Gate }
    } else {
        # A first install over a directory holding only runtime data parks that data as the backup.
        $restoredData = $null -eq $tx.old_digest -and (Test-Path -LiteralPath $Target) -and (Test-DataOnly $Target)
        if ((Test-Path -LiteralPath $Target) -and @(Get-ChildItem -LiteralPath $Target -Force).Count -gt 0 -and -not $restoredData) {
            $present = Get-Install $Target
            if ($present.Marker.installation_id -cne $tx.id -or $present.Package.Digest -notin @($tx.old_digest, $tx.new_digest)) { throw 'Interrupted target differs from recorded owned releases.' }
            if (Test-Path -LiteralPath $tx.backup_dir) {
                if ($present.Package.Digest -cne $tx.new_digest) { throw 'Old target and backup both exist; preserve them.' }
                if ($null -eq $tx.old_digest) { Remove-DataBackup $tx.backup_dir $Target $Gate
                } else { Remove-RecordedInstall $tx.backup_dir $tx $tx.old_digest $tx.old_files $Gate }
            }
        } elseif ($restoredData) {
            if (Test-Path -LiteralPath $tx.backup_dir) { throw 'Runtime data exists in both the target and the backup; preserve them.' }
        } elseif (Test-Path -LiteralPath $tx.backup_dir) {
            if ($null -eq $tx.old_digest) {
                Assert-Owned $tx.backup_dir
                if (-not (Test-DataOnly $tx.backup_dir)) { throw 'Backup holds more than runtime data; preserve it.' }
            } else { Assert-TransactionInstall $tx.backup_dir $tx $tx.old_digest }
            Assert-Maintenance $Gate
            [IO.Directory]::Move($tx.backup_dir, $Target)
        } elseif ($null -ne $tx.old_digest) { throw 'Previous installation is missing; preserve transaction/staging files for inspection.' }
        if (Test-Path -LiteralPath $tx.stage_dir) { Remove-RecordedInstall $tx.stage_dir $tx $tx.new_digest $tx.new_files $Gate }
    }
    Assert-Maintenance $Gate
    [IO.File]::Delete((Get-TransactionPath $Target))
}

function Assert-GuiClosed([string] $Target) {
    foreach ($process in @(Get-Process -Name 'wsl-proxy-desktop' -ErrorAction SilentlyContinue)) {
        try {
            $image = $process.Path
            if ([string]::IsNullOrEmpty($image)) { throw 'GUI process identity is unavailable.' }
            if ((Split-Path -Parent $image) -ieq $Target) { throw "Close the installed desktop window explicitly before maintenance (PID $($process.Id)). No process was killed." }
        } finally { $process.Dispose() }
    }
}

function Invoke-Installer([string] $SourceRoot, [string] $InstallDir, [switch] $Uninstall, [switch] $AllowDowngrade, [switch] $Recover) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) { throw 'This package supports Windows x64 only.' }
    $target = Resolve-Target $InstallDir
    $sourcePath = Get-FullPath $SourceRoot
    if (-not $Uninstall -or $Recover) { Assert-Separate $sourcePath $target }
    $source = Get-Package $sourcePath -Installed:($sourcePath -ieq $target)
    $transactionPath = Get-TransactionPath $target
    $hasTransaction = Test-Path -LiteralPath $transactionPath
    if ($hasTransaction -and -not $Recover) { throw "Interrupted installation transaction exists: $transactionPath. Do not start the application or delete journals. From an intact extracted package rerun this command with -Recover." }
    if ($Recover -and -not $hasTransaction) { throw 'No owned interrupted transaction exists at the selected installation path.' }
    $installed = $null
    $emptyTarget = $false
    $dataOnly = $false
    if (Test-Path -LiteralPath $target) {
        Assert-Owned $target
        if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw 'Installation path is not a directory.' }
        if (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 0) { $emptyTarget = $true
        } elseif (Test-DataOnly $target) { $dataOnly = $true
        } else { $installed = Get-Install $target }
    }
    if ($Recover) {
        $tx = Get-Transaction $target
        if (($Uninstall -and $tx.operation -cne 'uninstall') -or (-not $Uninstall -and $tx.operation -cne 'install')) { throw 'Use the same install/uninstall entrypoint that created this interrupted transaction.' }
    } elseif ($Uninstall -and $null -eq $installed) {
        if ($emptyTarget) { throw 'Selected empty directory is not an owned installation; it was not deleted.' }
        if ($dataOnly) { Write-Output "Not installed at $target; only runtime data files remain there. Nothing changed."
        } else { Write-Output "Not installed at $target; nothing changed." }
        return
    }
    if (-not $Uninstall -and -not $Recover -and $null -ne $installed) {
        $comparison = (Get-Version $source.Manifest.version).CompareTo((Get-Version $installed.Package.Manifest.version))
        if ($comparison -lt 0 -and -not $AllowDowngrade) { throw 'Version downgrade refused by default. Only an explicit -AllowDowngrade permits a verified older package.' }
        if ($comparison -eq 0 -and $source.Digest -cne $installed.Package.Digest) { throw 'Same version has a different manifest/build. Use a new release version, not an ambiguous replacement.' }
    }
    Assert-GuiClosed $target
    Close-IdleBroker $installed $source
    $gate = Start-Maintenance $source (Split-Path -Parent $target)
    try {
        Assert-Maintenance $gate
        Assert-NoReparse $target
        if ($Recover) {
            Recover-Transaction $target $gate
            Write-Output "Recovered owned transaction at $target. Verify the installed version before launching; rerun install to apply the desired release."
            return
        }
        # Recheck ownership/integrity after taking the shared controller lock.
        if ($null -ne $installed) {
            $current = Get-Install $target
            if ($current.Package.Digest -cne $installed.Package.Digest -or $current.Marker.installation_id -cne $installed.Marker.installation_id) { throw 'Installation changed while acquiring maintenance; no mutation performed.' }
        } elseif (Test-Path -LiteralPath $target) {
            Assert-Owned $target
            if ($dataOnly) { if (-not (Test-DataOnly $target)) { throw 'Target gained non-data files while acquiring maintenance.' }
            } elseif (@(Get-ChildItem -LiteralPath $target -Force).Count -ne 0) { throw 'Target became nonempty while acquiring maintenance.' }
        }
        if (-not $Uninstall -and $null -ne $installed -and $source.Digest -ceq $installed.Package.Digest) {
            Write-Output "Already installed, verified release $($source.Manifest.version) at $target; no files changed."
            return
        }
        $id = if ($null -ne $installed) { $installed.Marker.installation_id } else { [guid]::NewGuid().ToString('N') }
        $parent = Split-Path -Parent $target
        $tx = [pscustomobject]@{
            schema_version = 1; product = $script:Product; owner_sid = $script:Sid; id = $id; install_dir = $target
            stage_dir = Join-Path $parent ('.wsl-proxy-stage-' + $id)
            backup_dir = Join-Path $parent ('.wsl-proxy-backup-' + $id)
            operation = $(if ($Uninstall) { 'uninstall' } else { 'install' })
            old_digest = $(if ($null -ne $installed) { $installed.Package.Digest } else { $null })
            new_digest = $(if ($Uninstall) { $null } else { $source.Digest })
            old_files = $(if ($null -ne $installed) { @($installed.Package.Manifest.files) } else { @() })
            new_files = $(if ($Uninstall) { @() } else { @($source.Manifest.files) })
        }
        foreach ($path in @($tx.stage_dir, $tx.backup_dir)) { Assert-NoReparse $path; if (Test-Path -LiteralPath $path) { throw "Reserved transaction directory already exists; preserve it: $path" } }
        Write-NewJson $transactionPath $tx
        try {
            if ($Uninstall) {
                Assert-Maintenance $gate
                [IO.Directory]::Move($target, $tx.backup_dir)
            } else {
                Copy-Package $source $tx.stage_dir $target $id
                Assert-Maintenance $gate
                if ($null -ne $installed -or $dataOnly) { [IO.Directory]::Move($target, $tx.backup_dir)
                } elseif (Test-Path -LiteralPath $target) { [IO.Directory]::Delete($target, $false) }
                try {
                    Assert-Maintenance $gate
                    [IO.Directory]::Move($tx.stage_dir, $target)
                } catch {
                    if (($null -ne $installed -or $dataOnly) -and -not (Test-Path -LiteralPath $target) -and -not $gate.Process.HasExited) {
                        if ($null -ne $installed) { Assert-TransactionInstall $tx.backup_dir $tx $tx.old_digest
                        } elseif (-not (Test-DataOnly $tx.backup_dir)) { throw 'Backup holds more than runtime data; preserve it.' }
                        [IO.Directory]::Move($tx.backup_dir, $target)
                    }
                    throw
                }
                $null = Get-Install $target
            }
            Recover-Transaction $target $gate
        } catch {
            throw "Maintenance transaction did not finish: $($_.Exception.Message) Preserve $transactionPath and its named stage/backup. Do not launch the app. From an intact extracted package rerun the same entrypoint -InstallDir `"$target`" -Recover. Do not delete controller journals or unknown files."
        }
        if ($Uninstall) {
            Write-Output "Uninstalled owned application files from $target. User configuration, credentials and recovery journals were preserved."
            if (Test-Path -LiteralPath $target) { Write-Output "Runtime data files (desktop.sqlite and others) remain in $target; a later install there keeps using them. Delete that folder to remove them." }
        } else { Write-Output "Installed verified release $($source.Manifest.version) at $target. Unsigned SHA256 checks prove consistency, not publisher authenticity." }
    } finally { Stop-Maintenance $gate }
}
