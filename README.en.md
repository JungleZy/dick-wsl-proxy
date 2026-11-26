<div align="center">

# dick-wsl-proxy

**Takes over the outbound traffic of one WSL2 distribution: allowlisted TCP goes direct, everything else goes through a two-hop chain (host proxy → residential SOCKS5), and a failed hop never silently falls back to a direct connection.**

Windows desktop app `wsl-proxy-desktop` · controller and CLI `wsl-proxyctl`

![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)
![WSL](https://img.shields.io/badge/WSL2-NAT%20mode-4E9A06)
![Source version](https://img.shields.io/badge/source%20version-0.1.15-informational)
[![Latest release](https://img.shields.io/github/v/release/JungleZy/dick-wsl-proxy?include_prereleases&label=latest%20release)](https://github.com/JungleZy/dick-wsl-proxy/releases)
![Rust](https://img.shields.io/badge/Rust-2024%20edition-B7410E)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[简体中文](README.md) · English

</div>

> [!WARNING]
> **Every takeover restarts the target distribution.** Before installing any rule, the controller sets the target's timezone to the residential exit's timezone and then restarts only that distribution, ending every program running in it. The CLI `start` and `switch` commands ask for no confirmation. Read [Read this first](#read-this-first) before you start.

| Overview | Getting started | Reference | Development |
| --- | --- | --- | --- |
| [What it does](#what-it-does) | [Requirements](#requirements) | [Policy reference](#policy-reference) | [Building from source](#building-from-source) |
| [Features](#features) | [Installation](#installation) | [Stopping and recovery](#stopping-and-recovery) | [Repository layout](#repository-layout) |
| [How it works](#how-it-works) | [Desktop quick start](#desktop-quick-start) | [FAQ](#faq) | [Documentation](#documentation) |
| [Read this first](#read-this-first) | [Command line](#command-line) | [Security notes](#security-notes) | [Contributing](#contributing) |
| | | | [License](#license) |

## What it does

All WSL2 distributions share the Windows network exit. To send **one** distribution's traffic through a residential proxy, the usual options are configuring a proxy in every program (something always leaks) or running a global or TUN proxy on Windows (which also catches other distributions and Windows itself).

dick-wsl-proxy takes over only the distribution you choose, from the Windows side:

- Programs in the target need no proxy settings. New connections from the shell, from background services and from Docker containers are all taken over.
- Other distributions and native Windows programs keep their original routes.
- It changes neither the Windows system proxy nor WSL's shared `resolv.conf` or `.wslconfig`, and installs no proxy software or listener inside WSL.
- When something breaks, traffic is blocked rather than allowed to bypass the proxy. The original network path comes back only when you explicitly stop the takeover.

It is not a general-purpose VPN: it handles one WSL2 distribution, and the backend has been validated only in WSL2 NAT networking mode. Each Windows account can take over only one distribution at a time; a switch first confirms the old target is restored, then takes over the new one, and established TCP connections do not move across.

## Features

- **Per-distribution takeover**: installs iptables rules tagged with this instance into the target, matched by cgroup so that only this distribution's processes are redirected to the Windows ingress.
- **Direct allowlist**: IPs, CIDRs, exact domains and domain suffixes. Matching TCP is connected directly by Windows. A new configuration store comes pre-filled with suffixes of common services in mainland China.
- **Two-hop chain**: other traffic first goes through the SOCKS5 proxy already running on the host (first hop), then through a residential SOCKS5 proxy with username/password authentication (second hop).
- **Fail closed**: if either hop fails, the connection fails; faults keep traffic blocked rather than degrading to direct.
- **System DNS takeover**: the target's system DNS is answered by Windows and never falls back to a local or ISP resolver. Names outside the allowlist use fake-ip and are resolved by the residential proxy by default; allowlisted names go to a domestic DoH resolver.
- **UDP and QUIC**: forwarded through the proxies' UDP ASSOCIATE. If the proxies do not support UDP, such UDP is refused for the rest of that takeover and never sent direct.
- **IPv6**: taken over when the target has global IPv6; otherwise the target's external IPv6 is blocked.
- **Docker containers**: traffic from Docker bridge networks in the target is proxied too.
- **Timezone follows the exit**: the target's timezone is set to the residential exit's timezone so that the timezone and IP agree.
- **Desktop app**: a home page that monitors protection and traffic; distribution management (create, edit, back up, delete, change timezone); rules, connection records, run log and settings; a tray icon.
- **Crash recovery**: takeover state is written to recovery records. If the controller crashes, a separate holder process keeps the port and the rules keep blocking; `status` and `stop` restore explicitly.

## How it works

![How it works: new connections from the target are redirected by iptables to a Windows ingress; allowlisted TCP goes direct, other TCP and all UDP go through the host SOCKS5 and the residential SOCKS5 and are refused on failure; Windows takes over system DNS](docs/images/architecture.en.svg)

1. On start, the controller installs rules in the target as root, redirecting new connections from the target to an ingress that Windows listens on at the WSL virtual adapter (port 43531 by default).
2. For each connection, the ingress asks the target kernel's connection tracking table for the original destination through a read-only query process. That process is started by `wsl.exe`, talks only over stdin/stdout and opens no port. If no entry is found, or the entry does not belong to this takeover, the connection is refused; the destination is never guessed.
3. Only then does the ingress decide between a direct connection and the two-hop chain.

### Where traffic goes

| Traffic | Route |
| --- | --- |
| Allowlisted TCP | Direct from Windows |
| Other TCP (including IPv6 when managed IPv6 is on) | Host SOCKS5 → residential SOCKS5; if either hop fails, the connection fails |
| UDP, including QUIC, **allowlisted or not** | UDP ASSOCIATE through both proxies. If the startup probe fails, all such UDP is refused for that takeover and the desktop shows "UDP blocked" |
| System DNS (the resolver in the target's `resolv.conf`, UDP/TCP 53) | Answered by Windows; see the next section |
| Queries sent straight to another DNS server on port 53 (e.g. `dig @1.1.1.1`) | Refused, neither proxied nor direct |
| ICMP and other non-TCP/UDP protocols | Dropped |
| IPv6 | Taken over as above when the target has a global IPv6 address and default route; otherwise everything except loopback is blocked |

UDP never goes direct on purpose: a web page could use an allowlisted STUN server through WebRTC to learn the real Windows exit IP.

**Docker containers**: only the target's Docker bridge networks are covered, and a network created during a takeover is covered within about 30 seconds. The target can still reach its own containers, and published ports stay reachable from Windows through `localhost`; a new network works only once it is covered, e.g. in the first seconds after `docker compose up`. Containers of other runtimes such as Podman are not proxied, and other distributions' containers are left alone. If the target's Docker is running but its networks cannot be read when a takeover starts (for example its API never answers), the start fails and the takeover needs recovery: the target's own traffic is blocked, but **the target's containers are not stopped and may connect directly** until you stop the takeover.

### How names are resolved

- **Names outside the allowlist use fake-ip by default.** An A query is answered at once with a `198.19.x.x` stand-in (TTL 1 second); AAAA and HTTPS/SVCB queries get an empty answer. When a program connects to that address, the ingress hands the name to the residential proxy to resolve. If the residential proxy cannot connect by name, the takeover runs without fake-ip.
- **With fake-ip off**, those queries go through both hops to the policy's DoH upstream `dns_upstream`. A new configuration store is pre-filled with Google DoH (`8.8.8.8:443`, `dns.google`).
- **Allowlisted names** are sent by Windows straight to a domestic DoH upstream, AliDNS by default (`223.5.5.5:443`, `dns.alidns.com`), so directly connected sites get nearby addresses. If that upstream is unreachable or answers unusably, the query goes through both hops instead. The target receives a `198.18.x.x` alias address, and only TCP to that alias goes direct.
- **Caching**: an answer that expired less than an hour ago is returned first (with a 30-second TTL) while it is refreshed in the background. Stale answers also come from the configured upstream; they are not local resolution.

## Read this first

**1. A takeover changes the target's timezone and restarts the target.**
On every start of, or switch to, a target, after the preflight passes and you confirm, and before any rule is installed:

- Windows queries `my.ippure.com` through both hops for the residential exit's timezone;
- the target's timezone is set to it;
- `[time] useWindowsTimezone=false` is written into the target's `/etc/wsl.conf`, otherwise WSL would put the Windows timezone back the next time the target starts;
- only that distribution is restarted, and every program running in it is ended. This happens even when the timezone was already right.

If the timezone cannot be looked up, or the target lacks its data under `/usr/share/zoneinfo`, the takeover does not start. Stopping does not restore the old timezone.

**2. Connections opened before the rules are in place stop working during the takeover.**
A program that connects after the restart but before the rules are installed (a VPN or Tailscale started at boot, for example) is neither proxied nor left direct:

- its TCP connections are reset on their next packet, and the program reconnects through the proxy;
- its UDP packets are dropped. A fixed-port UDP program such as WireGuard stays down for the whole takeover, and restarting it does not help (same port, same old connection-tracking entry). Turn off its start at boot and start it once the takeover is running, so its traffic goes through the residential proxy like other UDP (not tested).

**3. A target with global IPv6 cannot use domain allowlists.**
In that case any domain or domain-suffix entry in the policy makes the start fail (`ipv6_domain_allowlist_unsupported`). A new configuration store already contains suffixes, so clear both domain columns on the Rules page first. The refusal happens after the timezone change and restart.

**4. Two side effects of fake-ip.**
`198.19.x.x` addresses inside the target are expected. A name that does not exist shows up as a failed connection rather than NXDOMAIN.

**5. The residential password is stored in plain text.**
The residential server, username and password are kept in `desktop.sqlite` next to the EXE, with no extra encryption beyond the Windows account's file permissions. Uninstalling does not delete it. Never commit an `.env` file or a password.

**6. Process exit does not mean the network is restored.**
Closing the window, killing a process or a controller crash does not restore direct routing; the rules keep blocking. You must stop explicitly; see [Stopping and recovery](#stopping-and-recovery).

The exception is a restart of the target or of WSL: after the target restarts on its own, shuts down when idle, or after `wsl --shutdown`, this takeover's rules no longer apply and the target's new connections go direct. The check that runs about every 30 seconds then puts drop-only rules in the target (every new connection its own processes start, except to loopback, is dropped), and the overview says the target is blocked. The block also drops what the target's Docker networks seen during the takeover forward; a network never seen during the takeover is not covered. Until that check, up to about 30 seconds, connections go direct. Without a running backend, the process holding the ingress ports does the same; once you reconnect, the backend does it.

**7. Isolation has been measured on one kernel only.**
"Other distributions are unaffected" was measured only on WSL kernel 6.18.58.1. A target whose kernel is older or cannot be read is refused by the preflight until WSL is updated. Whether an update gets past this floor has not been tested.

**8. Release packages are unsigned.**
The SHA-256 checksum shows the file is intact; it does not identify the publisher. Packages released after v0.1.11 also carry a GitHub build provenance attestation, which shows the release pipeline of this repository built them; that is not a code signature either, and Windows still warns about an unknown publisher.

## Requirements

**Windows**

- Windows x64. Running it needs no administrator rights.
- An existing SOCKS5 proxy on this machine as the first hop. Its address must be a loopback IPv4 address with no authentication, for example the SOCKS5 port of a local proxy app. A new configuration store is pre-filled with `127.0.0.1:7892`.
- A residential SOCKS5 proxy with username/password authentication.
- For UDP (including QUIC) to work, **both** the host proxy and the residential proxy must support UDP ASSOCIATE. If either lacks it, the takeover still starts but UDP is refused.

**Target distribution**

- WSL2 in NAT networking mode. WSL1, mirrored, bridged and other modes are not supported.
- WSL kernel 6.18.58.1 or newer.
- systemd as PID 1.
- `iptables-nft` and `ip6tables-nft`: the rules go into the nft tables through them (decision 37). The preflight still checks for `iptables-legacy` and `ip6tables-legacy`; the Ubuntu `iptables` package ships both.
- Kernel capabilities: `xt_cgroup`, `nf_conntrack`, `nf_nat`, `iptable_nat`, `ip6table_nat`, and IPv4/IPv6 REJECT; the nft writes also need `nft_compat` (a module in the WSL kernel), which the preflight does not check yet. After a cold start, missing modules can be loaded from the distribution; see below.
- `/usr/bin/python3`. Note that the preflight does not check this yet; a target without it fails only after the timezone change and restart.
- Timezone data under `/usr/share/zoneinfo`, and basic tools such as `awk`, `od`, `sha256sum` and `ip`.

## Installation

> [!NOTE]
> Prebuilt packages are published on GitHub Releases from [v0.1.11](https://github.com/JungleZy/dick-wsl-proxy/releases/tag/v0.1.11) on: v0.1.11 is a pre-release, and from v0.1.12 on they are regular releases. The packages are unsigned and nobody has yet confirmed the third-party redistribution obligations. The older `v0.1.4`–`v0.1.7` tags have no packages.

### Download a release package

The release pipeline runs when a `v*` tag is pushed. It builds natively on a GitHub Windows runner, runs the format check, clippy, every test, an import-table check and an install smoke test, then packages and publishes a release on [GitHub Releases](https://github.com/JungleZy/dick-wsl-proxy/releases). Each version has two files:

- `wsl-proxy-<version>-windows-x64.zip`: both EXEs, the install and uninstall scripts, the build record and the third-party license inventory;
- `wsl-proxy-<version>-windows-x64.zip.sha256`: the checksum.

In PowerShell:

```powershell
# 1. Check the checksum against the one on the release page
Get-FileHash -Algorithm SHA256 .\wsl-proxy-<version>-windows-x64.zip

# Optional: check the build provenance (releases after v0.1.11, needs the GitHub CLI)
gh attestation verify .\wsl-proxy-<version>-windows-x64.zip -R JungleZy/dick-wsl-proxy

# 2. Extract to a new directory (not into the install directory)
Expand-Archive .\wsl-proxy-<version>-windows-x64.zip -DestinationPath .\wsl-proxy-<version>
cd .\wsl-proxy-<version>

# 3. Install for the current user, by default to %LOCALAPPDATA%\Programs\WslProxy
.\install.ps1
```

- Run it in a normal PowerShell that is allowed to run the script; no administrator rights are needed. Do not change the execution policy to get around local restrictions.
- `-InstallDir` picks another location. The directory has limits: a local drive, at most 180 characters, and a parent owned by the current user, SYSTEM or Administrators. See the [M5 release notes](docs/plans/m5/README.md) for the full conditions.
- The installer only copies files: no shortcuts, no PATH change, no registry entries. Afterwards, open `wsl-proxy-desktop.exe` in the install directory.

### Upgrade and uninstall

1. **Stop the takeover, then close the window.** The installer refuses while a takeover is active or needs recovery, or while the desktop window from the install directory is open, and it never kills a process.
2. **Upgrade**: versions after 0.1.11 can upgrade themselves from the desktop app; see [Update check and one-click upgrade](#update-check-and-one-click-upgrade). To upgrade by hand, run `.\install.ps1` from the new package's extracted directory against the same `-InstallDir`. Downgrades are refused unless you add `-AllowDowngrade`.
3. **Uninstall**: run `.\uninstall.ps1` from the extracted directory. It removes only the program files; three things stay behind:
   - `desktop.sqlite` in the install directory, with the residential password in plain text;
   - `%LOCALAPPDATA%\WSLProxyLab`, holding the controller lock, recovery records and the DNS alias ledger;
   - the start-at-login registry entry. Turn off start at login under **Settings › Desktop** before uninstalling.

   To remove everything, delete the first two directories by hand.
4. If the backend runs as administrator, a normal PowerShell cannot reach it; the installer reports that the controller lock is held and changes nothing. Run the script from an administrator PowerShell in that case.
5. If the file swap is interrupted, rerun the same command with `-Recover` from an intact extracted package.

### Build from source

See [Building from source](#building-from-source).

## Desktop quick start

Keep `wsl-proxy-desktop.exe` and the matching version of `wsl-proxyctl.exe` in the same directory (the installer already does), and open the former. On first launch it starts `wsl-proxyctl.exe` in the background as the current user, as a resident backend.

1. **Settings**:
   - enter the residential proxy's server IPv4, port, username and password (the password is shown in plain text);
   - under **Network and DNS**, check the host SOCKS5 address and adjust DNS if needed;
   - click **Save settings**.
   - To check the residential proxy first, use **Test** in the residential proxy section. It asks for confirmation, because the direct path sends the username and password in plain text without the first hop.
2. **Rules**: fill the direct rules one per line in three columns (IP / CIDR, exact domain, domain suffix), then click **Save rules**. A new configuration store comes pre-filled with suffixes of common services in mainland China.
3. **Environments**: click **Set as target** on the distribution to take over; it is saved once you confirm. Setting a target alone does not take over the network.
4. **Home**: click **Start takeover**.
   - The preflight runs automatically.
   - If kernel modules are missing, the app asks whether to load the ones already in the distribution.
   - A confirmation dialog then states that the timezone will change and the target will restart. The takeover starts once you confirm.
5. **Stop**: click **Stop takeover** on Home, or **Stop and restore direct** in the tray menu.

The desktop UI is in Chinese; the labels above are translations.

### The six pages

| Page | Purpose |
| --- | --- |
| Home | Protection status, protection chain, traffic chart, event timeline. The main button changes with the state: choose a target / save changes / start takeover / stop takeover / abandon this record / reconnect |
| Environments | Distribution list and details; set as target; create, edit components, change timezone, back up, delete a distribution (these five need no takeover in progress) |
| Rules | Direct rules in three columns: IP / CIDR, exact domain, domain suffix |
| Connections | Connection records (the newest 50,000 finished connections are kept), re-check public exit, export redacted diagnostics, reset DNS aliases |
| Logs | Run log with search and All / Errors / Warnings filters |
| Settings | Residential proxy, network and DNS, forwarding limits, desktop (start at login), WSL platform, about (update check and upgrade) |

### Tray and closing the window

- **Closing the window only hides it to the tray; the proxy keeps running.** If the tray icon could not be shown (for example, Explorer was not ready at login), closing quits the window and leaves the backend running.
- **The tray icon shows whether a takeover is running.** A green shield with a light sweeping along its pulse line means a takeover is running; a still grey shield means idle; red means recovery is needed; amber with a flat line means the backend state is unconfirmed (a takeover may still be in effect). Hover to see the state and the target distribution.
- Click the tray icon to open the main window. The right-click menu shows the current state at the top, and its main action follows the state like the main button on Home (**Start takeover**, **Stop and restore direct**, **Reconnect backend** and so on). It also offers **Check public exit**, **View connection records**, **View run log** and **Start at login**.
- **Exit** in the tray menu: when idle, it shuts the backend down and quits; during a takeover it asks first, then stops the takeover, restores direct routing, shuts the backend down and quits. It does not quit if any step fails.
- If the desktop process is killed or crashes, the backend keeps running; reopen the app to reconnect.
- Only one desktop window runs at a time. Opening it again brings the existing window to the front.

### Kernel modules after a cold start

After WSL starts cold or restarts, the shared kernel may not have the required modules loaded. If the preflight before a start finds them missing, the desktop asks whether to load them. Once you confirm, it does three things:

- loads only modules already present under the target's `/lib/modules` and registers empty filter/nat tables;
- writes the module list to `/etc/modules-load.d/wsl-proxy.conf`;
- writes and enables a `wsl-proxy-tables.service`, so later WSL starts are ready without asking.

It installs no packages and does not touch `.wslconfig`. From 0.1.11 the REJECT modules (used to reset old connections) are needed too, so a kernel prepared by an earlier version is asked once more. If the target kernel is older than 6.18.58.1 the app does not offer this, because loading modules cannot fix it; update WSL first. See [M6](docs/plans/m6/README.md).

### WSL platform and updates

**Settings › WSL platform** shows the `wsl.exe` version, the WSL2 kernel, the default version and the registered distributions. While no takeover is running, it can also run `wsl --update` explicitly. Note:

- it stops every distribution;
- it waits at most 30 minutes; past that the update process is ended, and WSL may be left half updated;
- while waiting, do not close the app, quit the backend or start another environment task, or the result may be lost or reported as a failure;
- after a failure, a timeout or no result, check with `wsl --version` in PowerShell and run `wsl --update` yourself if needed.

See [M7](docs/plans/m7/README.md).

### Update check and one-click upgrade

The "Updates" group under Settings › About:

- **Check**: 15 seconds after the app opens it asks GitHub for a newer release, then once a day; "Check for updates" asks right away. It goes through the host SOCKS5 when one is saved, direct if that fails, never through the residential proxy. Every check shows GitHub your exit IP; turn off "Check for updates automatically" if the app should not go online by itself.
- **Notice**: a newer release is announced once, and the status bar shows it next to the version.
- **Upgrade**: after you click "Upgrade to vX" and confirm, the app downloads the package (about 41 MB), checks it against the SHA-256 published with the release, closes its window, runs the new package's `install.ps1`, reopens itself and shows the result. The window usually takes a minute or two to come back, with no progress shown meanwhile; do not open the app yourself, or the installer refuses the upgrade (the open window then shows why).

One-click upgrade needs all of these. When either of the first two is missing, the Upgrade button is greyed out with the reason beside it; the execution policy is checked only after you click Upgrade, and if it does not allow scripts the app says so and downloads nothing:

- no takeover is running or waiting for recovery (stop it on the home page first);
- this copy was installed with `install.ps1` (not unpacked and run in place, not self-built);
- the effective PowerShell execution policy runs local scripts (RemoteSigned, Unrestricted or Bypass). The app never changes or bypasses the policy; under Restricted, upgrade by hand from the releases page.

The package is unsigned: the SHA-256 check catches a broken download but does not prove who published it, the same trust as downloading by hand. Only program files are replaced; the settings database, start-at-login entry and recovery records stay. If the upgrade does not finish, the reopened window explains why and gives the command to run by hand; if replacing files was interrupted, the app does not reopen and a message box gives the `-Recover` command. See [M8](docs/plans/m8/README.md).

### Environment management

The Environments page can create a distribution (Ubuntu-24.04 by default, optionally with zsh, Chrome, and a Chinese input method), edit its components, change its timezone, back it up to a file, or delete it.

- A new distribution with `apt-get` (such as Ubuntu or Debian) gets the system language `LANG=en_US.UTF-8` and `LANGUAGE=en_US:en` with no `LC_ALL`; Chrome in it reports en-US for both its language (`navigator.language`) and the Intl locale (not yet tested by creating a distribution from the desktop app). The Chinese input method only adds fcitx5 Pinyin and the zh_CN locale without making it the default language, and Pinyin stays the default input method;
- saving an edit with Chrome or the Chinese input method selected switches the system language to that en_US setting;
- editing components or changing the timezone restarts the distribution;
- deleting unregisters the distribution and removes all its files;
- reading a distribution's details starts it if it is not running.

## Command line

Everything can also be done from PowerShell with `wsl-proxyctl.exe`.

> [!NOTE]
> Every subcommand except `rpc` first takes the controller lock, of which each Windows account has exactly one. While the desktop backend is running, they report `controller_busy` (exit code 3). Send the request to the backend with `rpc` instead, or quit the desktop app from the tray first.

### Preflight

```powershell
$ctl = '.\wsl-proxyctl.exe'
& $ctl list                        # list registered distributions; starts none
& $ctl preflight Ubuntu-24.04      # read-only preflight; use a name from list
```

`preflight` may wake the target but installs no rules. Check `passed` and `blockers` in the JSON output: `passed: true` only means the checks passed, not that the proxy is active. Exit code 0 means passed, 2 means blocked.

If the blockers include `capability.kernel.*` or `baseline.ip*tables*`, the shared kernel is cold. Load the modules and run the preflight again:

```powershell
& $ctl prepare-kernel Ubuntu-24.04 --confirm
& $ctl preflight Ubuntu-24.04
```

`prepare-kernel` requires that no takeover is running and does the same as the desktop prompt. To undo the boot-time loading, run `systemctl disable wsl-proxy-tables.service` in the target, then delete `/etc/modules-load.d/wsl-proxy.conf` and `/etc/systemd/system/wsl-proxy-tables.service`.

### Import the residential proxy settings

Prepare an `.env` file. Only these four keys are allowed, and `ip` must be IPv4:

```ini
ip=203.0.113.10
port=1080
username=user01
password=change-me
```

```powershell
& $ctl import-credential --name my-residence --env-file D:\path\to\residential.env
```

The settings are written to `desktop.sqlite` next to the EXE, with the password in plain text. `--name` is only a label recorded in the policy. When you no longer need them, `forget-credential --name my-residence` clears these fields.

### Start, inspect, stop

Prepare a policy JSON file (fields under [Policy reference](#policy-reference)), then enter session mode and submit JSON commands one per line:

```powershell
& $ctl session
```

```jsonl
{"command":"start","target":"Ubuntu-24.04","profile":"D:\\path\\to\\policy.json"}
{"command":"status"}
{"command":"stop"}
```

- `start` runs: preflight → timezone sync and target restart (**no confirmation**) → preflight again → install rules → readiness probes. It returns `forwarding_managed` only when the DNS and HTTPS readiness probes pass. Any failure leaves the state as "recovery required", which needs an explicit `stop`.
- `profile` may also point to `desktop.sqlite` next to the EXE. The desktop app must then have saved its settings at least once; a CLI import alone does not count, and the start fails with `desktop_store_not_saved`.
- Closing the session's standard input (EOF) also stops the takeover.

### Subcommands

| Subcommand | Purpose |
| --- | --- |
| `list` | List distributions; read-only, wakes none |
| `preflight <target> [--port 43531]` | Read-only preflight; may wake the target |
| `prepare-kernel <target> --confirm` | Load existing modules, register empty tables, write boot configuration; requires idle |
| `wsl-platform` | Read-only report on the WSL platform |
| `wsl-platform-update --confirm` | Run `wsl --update`; requires idle and stops every distribution |
| `start <target> --profile <policy> [--port 43531]` | Start a takeover (changes the timezone and restarts the target), then stay in the foreground and stop when stdin closes |
| `switch <target> --expected-generation <N>` | Switch targets (changes the new target's timezone and restarts it); only inside the `session` that holds the takeover, or through `rpc` to the desktop backend |
| `status` | Print the current state as JSON |
| `stop [--expected-generation <N>]` | Stop a takeover or run recovery; repeating it when idle still succeeds |
| `abandon --confirm` | Drop the record when the target was unregistered and `stop` cannot finish |
| `import-credential --name <label> --env-file <path>` | Import residential proxy settings |
| `forget-credential --name <label>` | Clear residential proxy settings |
| `reset-dns-aliases --confirm` | Clear the alias ledger when allowlisted-name aliases run out; requires idle |
| `session` | Session mode: read JSON commands line by line, stop the takeover when stdin closes |
| `rpc` | Read one JSON request from stdin and hand it to the running desktop backend |

The `phase` field of `status` takes four values: `idle`, `forwarding_managed` (takeover running), `forwarding_scoped` (diagnostic mode) and `recovery_required`. See [M2](docs/plans/m2/README.md) and [M3](docs/plans/m3/README.md) for details.

## Policy reference

The policy is a JSON file of at most 1 MiB; unknown fields are rejected. Minimal example:

```json
{
  "first_hop": "127.0.0.1:7892",
  "credential": "my-residence",
  "dns_upstream": "8.8.8.8:443",
  "dns_tls_name": "dns.google",
  "direct_ips": [],
  "direct_domains": [],
  "direct_suffixes": []
}
```

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `first_hop` | yes | | First-hop SOCKS5; must be a loopback IPv4:port |
| `credential` | yes | | Label for the residential settings; not used for lookup |
| `dns_upstream` | yes | | DoH upstream reached through both hops, as IPv4:port |
| `dns_tls_name` | yes | | TLS host name of that upstream, used for certificate checks |
| `direct_ips` | yes | | Direct IPs or CIDRs, IPv4 or IPv6; a CIDR must name its network address |
| `direct_domains` | yes | | Exact domains to connect directly |
| `direct_suffixes` | yes | | Domain suffixes to connect directly; match the suffix itself and every subdomain |
| `health_domain` | no | `ippure.com` | HTTPS host used by the readiness probe; must not be allowlisted |
| `fake_ip` | no | `true` | Give names outside the allowlist a stand-in address and let the residential proxy resolve them |
| `direct_dns_upstream` | no | `"223.5.5.5:443"` | Domestic DoH for allowlisted names; must be a public IPv4:port; `null` turns it off |
| `direct_dns_tls_name` | no | `dns.alidns.com` | TLS host name of the domestic DoH |
| `max_tcp_connections` | no | `256` | Concurrent TCP limit (including DNS over TCP), 16–1024; new connections beyond it are refused, not queued |
| `tcp_idle_timeout_seconds` | no | `1800` | Close after this long with no data in either direction, 30–86400 |
| `tcp_half_close_timeout_seconds` | no | `60` | Close after one side finishes and the other sends nothing for this long, 5–3600 |

- The ingress port is not part of the policy. Set it with `--port`; the default is 43531 and it must be at least 1024.
- The allowlist must not match `my.ippure.com` (the timezone lookup has to go through the proxy) or `health_domain`.
- The desktop Settings and Rules pages are a graphical editor for this policy, saved in `desktop.sqlite`.

## Stopping and recovery

**Normal stop**

- Desktop: **Stop takeover** on Home, or **Stop and restore direct** in the tray.
- CLI: send `{"command":"stop"}` in the original session.

**Window closed, backend still running**

Stop through the backend from the install directory:

```powershell
$ctl = Join-Path $env:LOCALAPPDATA 'Programs\WslProxy\wsl-proxyctl.exe'
$state = '{"command":"status"}' | & $ctl rpc | ConvertFrom-Json
@{command='stop'; expected_generation=$state.operation_generation} | ConvertTo-Json -Compress | & $ctl rpc
'{"command":"status"}' | & $ctl rpc
```

Once it is back to `idle`, `{"command":"shutdown_daemon"}` makes the backend exit.

**After a controller crash**

In a new PowerShell, run:

```powershell
& $ctl status    # should show recovery_required; may wake the target
& $ctl stop      # removes rules and mappings, frees the port, deletes the recovery records
```

The expected result is `phase` `idle` and `active_target` `null`. `controller_busy` means another program holds the lock; it does not mean the network was restored.

**Target unregistered during a takeover**

`stop` reports `journal_distribution_no_longer_matches_registration`. Run `& $ctl abandon --confirm` (on the desktop, **Abandon this record** on Home), then run `wsl --shutdown` once to clear any rules left inside WSL.

> [!IMPORTANT]
> Do not delete `m1-active.json` or `m3-operation.json` under `%LOCALAPPDATA%\WSLProxyLab`, and do not flush shared firewall rules or the connection-tracking table. Deleting recovery records does not restore the network; it only removes what recovery needs.

## FAQ

**Names in the target resolve to `198.19.x.x`. Is that normal?**
Yes, those are fake-ip stand-ins. When a program connects to one, the ingress hands the real name to the residential proxy to resolve. Allowlisted names resolve to `198.18.x.x` alias addresses instead.

**Why does a name that doesn't exist give a connection failure instead of NXDOMAIN?**
With fake-ip on, every name outside the allowlist first gets a stand-in address; only the residential proxy finds out the name does not exist. For the old behavior, turn off **Network and DNS › Remote resolution** in Settings, or set `"fake_ip": false` in the policy.

**The desktop shows "UDP blocked".**
The UDP probe at startup failed: the host proxy or the residential proxy (or both) does not support UDP ASSOCIATE. All UDP, including QUIC, is refused for this takeover and never sent direct; TCP and system DNS are unaffected. The next start or switch probes again.

**Why does UDP to allowlisted sites go through the proxy?**
To keep WebRTC from leaking the real exit IP. A web page sends UDP to a STUN server to learn its own public address; if an allowlisted STUN server could be reached directly, the page would see the Windows exit IP.

**Why was the target restarted, and why did its timezone change?**
That is part of every takeover; see item 1 of [Read this first](#read-this-first).

**The start fails with `ipv6_domain_allowlist_unsupported`.**
The target has global IPv6 and the policy has domain or domain-suffix entries. Clear both domain columns on the Rules page and start again.

**The CLI reports `controller_busy`.**
The desktop backend or another session holds the controller lock. Use `'{"command":"status"}' | .\wsl-proxyctl.exe rpc`, or quit the desktop app from the tray first.

**Does `dig @8.8.8.8 example.com` fail?**
Yes. Only queries to the system resolver are taken over; queries sent straight to another DNS server on port 53 are refused, neither proxied nor direct. DoH or DoT built into a program is ordinary TCP and goes through the proxy.

**The preflight blocks because the kernel is older than 6.18.58.1.**
Update WSL first: **Settings › WSL platform** in the desktop app, or `wsl --update` in PowerShell.

**Is the proxy still running after I close the window?**
Yes. Closing only hides the window to the tray, and the backend keeps the takeover. To stop, use **Stop takeover** on Home or the tray menu.

**How do I remove everything after uninstalling?**
Turn off start at login in Settings before uninstalling, then delete the install directory (with `desktop.sqlite`) and `%LOCALAPPDATA%\WSLProxyLab` by hand. Inside the distribution, remove the timezone setting in `/etc/wsl.conf`, `/etc/modules-load.d/wsl-proxy.conf` and `wsl-proxy-tables.service` yourself.

## Building from source

Final builds, tests and packaging must happen on Windows with the Windows Rust toolchain. The controller and the desktop app are Windows programs, and much of their code is not compiled on Linux, so a successful build in WSL says nothing about whether the Windows build works.

**Prerequisites**

- Rust stable with the `x86_64-pc-windows-msvc` host. The project uses the Rust 2024 edition; the repository pins no minimum version, and the maintainer uses 1.100.0.
- Visual Studio C++ build tools.
- The Windows SDK: building the desktop app uses its `fxc.exe` to compile shaders. You can point `GPUI_FXC_PATH` at it instead.
- Leave `RUSTFLAGS` unset. The repository's `.cargo/config.toml` turns on the static C runtime (`+crt-static`) for MSVC targets; setting `RUSTFLAGS` overrides it, and the EXEs would then depend on the VC++ runtime.
- Packaging needs Python 3.11 or newer.

**Build and test** (PowerShell, at the repository root)

```powershell
cargo build --locked --release                                       # controller wsl-proxyctl only
cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop  # controller and desktop app
cargo test --locked --workspace
```

Output goes to `target\release\`. The default Cargo member is the controller alone, so building the CLI does not compile GPUI.

**Packaging**

The release packaging steps are defined by [`.github/workflows/release.yml`](.github/workflows/release.yml): check the import tables, export `cargo metadata` for the Windows platform only (`--filter-platform x86_64-pc-windows-msvc`), write the build record, package with `scripts/package-windows.py`, then run the install smoke test; a separate job checks third-party licenses with `cargo-deny` against `deny.toml` at the repository root. The package's `THIRD-PARTY-NOTICES.json` and `licenses/` cover only the Windows dependency graph (erring on the side of too many); where a dependency ships no license file, the standard text of the license it declares is included (`packaging/licenses/`). Script arguments and the local acceptance records are in [M5](docs/plans/m5/README.md). The scripts refuse to overwrite existing output files; `work/` and `dist/` are not in `.gitignore`, so write the output outside the repository.

`scripts/build-desktop-windows.sh` can cross-compile Windows EXEs from WSL, but that is only a development check; its output must not go into a release package.

## Repository layout

```text
src/                  controller wsl-proxyctl
  command.rs, main.rs   CLI and session commands
  controller*, transition*  takeover start/stop, switching and recovery records
  ingress*              Windows ingress: TCP, UDP and IPv6 forwarding
  managed_dns*          managed DNS: cache, fake-ip, allowlist alias ledger
  policy*               policy parsing, two-hop dialer, domestic suffix list
  query_bridge*         asks the target kernel for original destinations via wsl.exe
  ipc*                  named pipe between the desktop app and the backend
  environment*          distribution management and timezone sync
  guest/                scripts run inside the target: rules, preflight, kernel preparation, probes
desktop/              GPUI desktop app wsl-proxy-desktop
packaging/windows/    install.ps1, uninstall.ps1, common.ps1
scripts/              packaging, build record, import check, release notes, install smoke test
.github/workflows/    release.yml release pipeline
CHANGELOG.md          per-version change list in Chinese; the release notes take their Changes section from it
docs/                 architecture, decisions, roadmap, discussions, reviews
design/               desktop UI specification and early prototypes
```

## Documentation

The project documentation is written in Chinese.

| Document | Contents |
| --- | --- |
| [Architecture](docs/arch/README.md) | Current design and isolation boundaries |
| [Decisions](docs/decisions.md) | Numbered decision log; superseded entries are kept |
| [Discussions](docs/discussions/) | Design rationale; accepted conclusions are folded into the architecture and recorded as decisions |
| [Reviews](docs/review/) | Project, code and UI review records |
| [Roadmap](docs/plans/README.md) | Milestones, acceptance criteria and implementation records |
| [M0: target identification and preflight](docs/plans/m0/README.md) | Distribution enumeration, identity, read-only preflight |
| [M1: reversible ingress](docs/plans/m1/README.md) | Rule installation, connection ownership checks, crash recovery |
| [M2: two hops, allowlist and DNS](docs/plans/m2/README.md) | Policy JSON, credential import, session commands, routing and failure semantics |
| [M3: switching and recovery](docs/plans/m3/README.md) | Switch sequence, operation generations, recovery |
| [M4: desktop app](docs/plans/m4/README.md) | Desktop operation, backend and failure boundaries, residential proxy test |
| [M5: release and compatibility](docs/plans/m5/README.md) | Install, upgrade, uninstall, supported scope, performance measurements, release pipeline |
| [M6: kernel preparation](docs/plans/m6/README.md) | Loading existing modules and registering empty tables after a cold start |
| [M7: WSL platform check and update](docs/plans/m7/README.md) | Read-only check and explicit `wsl --update` |
| [M8: update check and one-click upgrade](docs/plans/m8/README.md) | Find a newer GitHub release, download and check it, hand it to the installer |
| [UI specification](design/ui-design-spec.md) | Current desktop UI; the code wins where they differ |

## Contributing

Issues and pull requests are welcome. Contributions of code and documentation are licensed under the project's [MIT License](LICENSE). Read [AGENTS.md](AGENTS.md) first; the main points:

- **Verify on Windows.** Final builds, tests and runs use the Windows Rust toolchain on the same working tree. `cargo build`, `cargo test` and cross-compiles in WSL are only intermediate checks and cannot be reported as passing.
- **Before submitting, run the checks the pipeline runs:**

  ```powershell
  cargo fmt --all --check
  cargo clippy --locked --workspace --all-targets -- -D warnings
  cargo test --locked --workspace
  python src/guest/test_kernel.py
  python src/guest/test_https_probe.py
  python src/guest/test_kernel_env.py
  python scripts/test_package_windows.py
  cargo deny --workspace check licenses   # install once: cargo install cargo-deny --locked
  ```

- **Documentation rules:**
  - `docs/arch/` describes only the current design;
  - discussions go in `docs/discussions/` and review records in `docs/review/`;
  - accepted decisions are recorded in `docs/decisions.md`;
  - file names follow `date-category-topic.md`, with no commit hashes;
  - examples never use real people's names.
- **Never commit** an `.env` file, a password or any residential proxy credential.

## Security notes

- Residential proxy credentials are stored in plain text in `desktop.sqlite` next to the EXE, protected only by the Windows account's file permissions.
- The named pipe between the desktop app and the backend accepts only processes of the same Windows account whose integrity level is not lower than the backend's ([decision 21](docs/decisions.md)). When the backend runs as administrator, normal-privilege processes cannot reach it.
- The direct path of the residential proxy test sends the SOCKS5 username and password in plain text without the first hop, and the residential provider sees your real IP. The app therefore asks for confirmation before testing.
- "Export redacted diagnostics" keeps only states and numeric counters, with no destination addresses, domains or credentials; still treat the file as internal.
- Release packages are unsigned and nobody has yet confirmed the third-party redistribution obligations; from v0.1.12 on they are still published as regular releases, and each release note lists both under its known limitations. Packages released after v0.1.11 carry a GitHub build provenance attestation; see [Installation](#installation).
- This project does not defend against a local administrator or against root inside the target distribution.

## License

This project is released under the [MIT License](LICENSE), copyright JungleZy.

Release packages also carry the licenses of third-party dependencies: `THIRD-PARTY-NOTICES.json` lists every package in the Windows dependency graph with its license, and `licenses/` holds the license texts. Where a package ships no license file, the standard text of the license it declares is included. The release pipeline checks dependency licenses with `cargo-deny` against [`deny.toml`](deny.toml).
