# dick-wsl-proxy · `wsl-proxyctl`

[简体中文](#简体中文) · [English](#english)

## 简体中文

`wsl-proxyctl` 是一个 Windows 命令行工具：它只代理一个 WSL2 发行版中本地进程新建的出站连接，包括已在运行的后台服务。应用不用单独配置代理；其他发行版和 Windows 原生进程保留原有网络路径。工具不修改 Windows 系统代理或 WSL 共享的 `resolv.conf`。

**流量怎么走？** 命中 IP、CIDR、域名或域名后缀白名单的 TCP 连接由 Windows 直连；UDP 不论是否命中白名单都不直连（否则网页能经白名单里的 STUN 服务器，借 WebRTC 拿到 Windows 的真实出口 IP）。其余 IPv4 TCP 连接先经过宿主机已有的 SOCKS5 代理，再经过住宅 SOCKS5 出口；任一跳失败都不会改走直连。目标发行版的系统 DNS（UDP/TCP 53）由 Windows 接管，不回退到本地或运营商解析：
- **白名单以外的域名默认用 fake-ip。** A 查询当场回一个 `198.19.x.x` 占位地址（AAAA 回空），连接时把域名交给住宅代理去解析。所以在目标里看到这类地址是正常的；不存在的域名表现为连接失败，而不是「域名不存在」。住宅代理不支持按域名连接时，本次接管自动不启用。可用策略 `"fake_ip": false` 或设置页「远端解析」关闭，关闭后这些查询经双跳访问指定的 DNS-over-HTTPS 上游。
- **命中域名白名单的查询**改由 Windows 直接问国内 DoH 上游（默认阿里 DNS，可在策略或设置页更换，留空即关闭），使直连站点拿到国内地址；国内上游连不上或应答不可用时仍经双跳。

**适用范围。** Windows x64 原生桌面控制台与 CLI，后端按 WSL2 NAT 验证，不是通用 VPN。目标的 WSL 内核低于 6.18.58.1（只在这个版本上实测过其他发行版不受影响）或读不出版本时，预检阻断，需先升级 WSL；升级成功能否过这道门槛没有实测过。目标具备全局 IPv6 地址和默认路由时启用受管 IPv6，否则阻断目标外部 IPv6。普通 UDP（含 QUIC，白名单的也一样）经住宅代理的 UDP Associate 转发；启动时这项探测不通过（例如住宅代理不支持 UDP），接管仍会启动，但本次接管期间这类 UDP 一律拒绝、不会直连，界面显示“UDP 已阻断”，下次启动或切换时重新探测。同一 Windows 账户一次只接管一个发行版；切换前先确认旧目标已恢复，不迁移既有 TCP 连接。目标里 Docker 的容器流量也经代理（只认 bridge 网络，接管中新建的网络最多约 30 秒后纳入），目标访问自己的容器、Windows 经 `localhost` 访问端口映射照常可用（新建的网络同样要等纳入后才行，例如 `docker compose up` 后的头几十秒）；Podman 等其他运行时的容器不经代理，别的发行版的容器不受影响。

**接管会改目标的时区并重启目标。** 每次启动或切换到某个目标，预检通过、确认之后、装规则之前，Windows 经双跳查住宅出口所在时区，把目标的时区改成它，并在目标的 `/etc/wsl.conf` 写 `[time] useWindowsTimezone=false`（不然 WSL 下次启动目标时会改回 Windows 的时区），然后只重启这个发行版：其中正在运行的程序都会被结束，时区本来就对也会重启。查不到时区或目标里缺这个时区的数据（`/usr/share/zoneinfo`）时不接管。停止接管不会改回时区。CLI 的 `start`、`switch` 没有确认步骤，同样会重启目标。

**图形界面。** 将 `wsl-proxy-desktop.exe` 与配套 `wsl-proxyctl.exe` 放在同目录，打开前者。选目标、保存策略并明确启动；关闭窗口只收进托盘，不停止代理。托盘菜单「退出」会在确认后停止接管、恢复直连并关闭后台，再退出程序。桌面被强制结束时后台照旧保留，重新打开可连接已有后台。见 [M4 使用说明和验收边界](docs/plans/m4/README.md)。冷启动或 WSL 重启后，目标内核可能没有加载所需模块；启动接管前的预检发现缺少这些能力时，会先询问是否加载发行版里已有的模块并创建空表（不安装软件、需先停止接管），确认后自动重新预检，并把模块列表和空表初始化写进发行版的开机配置；以后 WSL 启动会自动准备好，不再询问。见 [M6 内核环境准备](docs/plans/m6/README.md)。设置页的「WSL 平台」卡片只读显示 `wsl.exe` 版本、WSL2 内核、默认版本与已注册发行版；没有接管时可以用它显式运行 `wsl --update` 升级 WSL 平台：会终止所有发行版，最多等 30 分钟，超时会结束升级进程，WSL 可能停在升级到一半；等待期间不要关闭程序或做别的环境操作，否则结果可能看不到或被误报为失败。失败、超时或没看到结果时，在 PowerShell 里用 `wsl --version` 核对，必要时自己再运行 `wsl --update`。见 [M7 WSL 平台检查与升级](docs/plans/m7/README.md)。

**安装与升级。** Windows x64 候选包采用按用户安装的未签名 ZIP。校验、显式恢复、升级/卸载步骤与已测/未测环境见 [M5 发布说明](docs/plans/m5/README.md)；不要将 ZIP 哈希当作签名。
`0.1.3` 在保留逐包归属校验的前提下合并 UDP 回包查询：本地 16 并发已连接 UDP 回显 p95 从 348.66 ms 降至 88.55 ms，直连为 6.71 ms。全表均忙时仍拒绝新流。见 [M5 延迟与边界](docs/plans/m5/README.md#013udp-回包并发延迟)。

**从哪里开始？** 先按下方的[只读预检](#preflight)检查目标发行版。预检通过后，按 [M2 配置与启动指南](docs/plans/m2/README.md)准备 Windows 侧策略、导入住宅代理设置（写入 EXE 同级的 `desktop.sqlite`，含明文密码），并在 `session` 中启动接管。策略文件里的 `credential` 只是标签，不要把 `.env` 或密码提交到仓库。正常停止时在同一会话发送 `{"command":"stop"}`；如果控制器崩溃，在新的 Windows 进程中依次运行 `wsl-proxyctl.exe status` 和 `wsl-proxyctl.exe stop`，不要把进程退出当作网络已经恢复。

## English

`wsl-proxyctl` is a Windows CLI that proxies new outbound connections from local processes in **one WSL2 distribution**, including services that were already running. Applications need no proxy settings. Other distributions and native Windows processes keep their original routes; the controller changes neither the Windows system proxy nor WSL’s shared `resolv.conf`.

**Where does traffic go?** Windows connects directly for TCP connections matching an allowlisted IP, CIDR, domain, or domain suffix. UDP never goes direct, allowlisted or not; otherwise a web page could use WebRTC with an allowlisted STUN server to learn the real Windows exit IP. Other IPv4 TCP connections use the host’s existing SOCKS5 proxy and then a residential SOCKS5 proxy. If either hop fails, the connection fails rather than going direct. Windows takes over the target’s system DNS (UDP/TCP port 53) and never falls back to a local or ISP resolver:
- **Names outside the allowlist use fake-ip by default.** An A query is answered at once with a `198.19.x.x` stand-in (AAAA gets an empty answer), and the connection hands the name to the residential proxy to resolve. Such addresses inside the target are expected; a name that does not exist shows up as a failed connection rather than NXDOMAIN. If the residential proxy cannot connect by name, the takeover runs without fake-ip. Turn it off with `"fake_ip": false` in the policy or **Remote resolution** in Settings; those queries then use the two hops to reach the configured DNS-over-HTTPS upstream.
- **Queries for allowlisted domains** go directly from Windows to a domestic DoH upstream (AliDNS by default; change it in the policy or Settings, or leave it empty to turn it off), so direct sites get nearby addresses. If that upstream cannot be reached or answers unusably, the query still goes through the two hops.

**Supported scope.** The Windows x64 native desktop and CLI share the controller tested on WSL2 NAT. It is not a general-purpose VPN. A target whose WSL kernel is older than 6.18.58.1 (the only kernel on which other distributions were seen to stay untouched) or cannot be read is refused by the preflight until WSL is updated; whether an update gets past this floor has not been tested. A target with a global IPv6 address and default route uses managed IPv6 interception, while external IPv6 is blocked when those prerequisites are absent. Application UDP, including QUIC and allowlisted destinations, uses the residential UDP Associate. If that startup probe fails (for example, the residential proxy lacks UDP support), takeover still starts, but such UDP is refused, never sent direct, for the rest of that session; the desktop shows UDP as blocked, and the next start or switch probes again. Only one distribution per account can be active. Switching restores the old target before enabling the new one; existing TCP connections do not migrate. Traffic from the target's Docker containers is proxied too (bridge networks only; a network created during a takeover is covered within about 30 seconds), while the target can still reach its own containers and published ports stay reachable from Windows through `localhost` (for a new network only once it is covered, e.g. in the first seconds after `docker compose up`); containers of other runtimes such as Podman are not proxied, and other distributions' containers are left alone.

**A takeover sets the target's timezone and restarts the target.** On every start of, or switch to, a target (after the preflight passes and you confirm, before any rule is installed), Windows looks up the residential exit's timezone through the two hops, sets the target to it, writes `[time] useWindowsTimezone=false` into the target's `/etc/wsl.conf` (otherwise WSL puts the Windows timezone back the next time the target starts), and then restarts only that distribution. Every program running in it is ended, even when the timezone was already right. If the timezone cannot be looked up, or the target lacks its data under `/usr/share/zoneinfo`, the takeover does not start. Stopping does not restore the old timezone. The CLI `start` and `switch` commands ask for no confirmation and restart the target as well.

**Desktop.** Keep `wsl-proxy-desktop.exe` and the matching `wsl-proxyctl.exe` together and launch the desktop executable. Choose a target, save the policy, and explicitly start it. Closing the window only hides it to the tray; the proxy keeps running. **Exit** in the tray menu stops the takeover after confirmation, restores direct routing, shuts the background controller down, and then quits. If the desktop process is killed, the controller keeps running; reopen to reconnect. See the [M4 operator guide](docs/plans/m4/README.md). A cold WSL kernel may have none of the required modules loaded. If the preflight before a start finds them missing, the desktop asks whether to load modules already shipped with the distribution and create empty tables; it installs nothing, then reruns the preflight. The same confirmation also installs a boot-time module list and a oneshot that registers the empty tables, so later WSL starts need no prompt. See [M6](docs/plans/m6/README.md). The **WSL platform** card in Settings reports the `wsl.exe` version, WSL2 kernel, default version and registered distributions; while idle it can also run `wsl --update` explicitly. That stops every distribution and waits at most 30 minutes; past that the update process is ended and WSL may be left half updated. Keep the app and its backend open and start no other environment task meanwhile, or the result may be lost or reported as a failure. After a failure, a timeout or no result, check with `wsl --version` in PowerShell and run `wsl --update` yourself if needed. See [M7](docs/plans/m7/README.md).

**Install and upgrade.** The Windows x64 candidate is an unsigned per-user ZIP. See [M5 release and recovery notes](docs/plans/m5/README.md) for verification, safe maintenance and the support matrix. The ZIP checksum does not authenticate its publisher.
Version `0.1.3` batches UDP reply checks without caching destinations. Local connected UDP echo p95 at concurrency 16 fell from 348.66 ms to 88.55 ms (direct: 6.71 ms). A genuinely busy mapping table still rejects new flows.

**Getting started.** Run the [read-only preflight](#preflight) below for the target distribution. Once it passes, follow the [M2 setup guide](docs/plans/m2/README.md) for the Windows policy file, credential import, and `session` commands. Reference the residential credential by name in the policy; never commit the `.env` file or a password. To stop normally, send `{"command":"stop"}` in the active session. If the controller crashes, run `wsl-proxyctl.exe status` and then `wsl-proxyctl.exe stop` from a new Windows process. Process exit alone does not mean the original network path has been restored.

<a id="preflight"></a>

## 构建与只读预检 · Build and run a read-only preflight

在装有 Rust 工具链（支持 Rust 2024 edition）的 Windows 上，从仓库根目录打开 PowerShell。用 `list` 输出中的目标注册名替换示例。

From the repository root, open PowerShell on Windows with a Rust toolchain that supports the 2024 edition. Replace the example target name with a registered name from `list`.

```powershell
cargo build --locked --release
$ctl = '.\target\release\wsl-proxyctl.exe'
& $ctl list
& $ctl preflight WSLProxyLab-Target
```

`list` 不会启动发行版。`preflight` 可能唤醒所选目标发行版，但不安装引流规则。查看 JSON 中的 `passed` 和 `blockers`；`passed: true` 仅表示预检通过，不表示代理已启用。

`list` does not start distributions. `preflight` may wake the selected target, but installs no traffic rules. Check `passed` and `blockers` in the JSON output. `passed: true` means the checks passed, not that the proxy is active.

如果阻断项含 `capability.kernel.*` 或 `baseline.ip*tables*`，说明共享 WSL 内核处于冷启动状态。在桌面点「启动接管」时，预检报告这些阻断后会询问是否加载；也可以运行下面的命令。它加载目标发行版里已有的模块、注册空表，并写入发行版的 `/etc/modules-load.d/wsl-proxy.conf` 与 `wsl-proxy-tables.service`，让以后 WSL 启动时自动准备好；不安装软件，删除这两个文件即可取消开机加载。

If the blockers contain `capability.kernel.*` or `baseline.ip*tables*`, the shared WSL kernel is cold. When the desktop preflight reports them before a start, it asks whether to load them; the commands below do the same. It loads modules already shipped with the target, registers empty tables, and installs a boot-time module list plus a oneshot in the distribution, so later WSL starts are ready without asking; it installs no packages, and deleting those two files restores the prompt.

```powershell
& $ctl prepare-kernel WSLProxyLab-Target --confirm
& $ctl preflight WSLProxyLab-Target
```

## 文档怎么维护 · Documentation guide

| 文档 / Document | 内容 / Purpose |
| --- | --- |
| [架构 / Architecture](docs/arch/README.md) | 现行设计与隔离边界 / Current design and isolation boundaries |
| [讨论 / Discussions](docs/discussions/) · [决策 / Decisions](docs/decisions.md) | 讨论保留论证过程；定论并入架构并登记决策 / Keep rationale in discussions; record decisions and fold accepted designs into the architecture |
| [开发计划 / Roadmap](docs/plans/README.md) | 里程碑、验收条件与执行记录 / Milestones, acceptance criteria, and implementation records |
| [M2：策略与 DNS / Policy and DNS](docs/plans/m2/README.md) | 策略 JSON、凭据导入、会话示例 / Policy JSON, credential import, and session examples |
| [M3：切换与恢复 / Switching and recovery](docs/plans/m3/README.md) | 切换顺序、异常恢复与实测边界 / Switch sequence, crash recovery, and limits of the validation evidence |
| [M4：桌面操作 / Desktop operation](docs/plans/m4/README.md) | 原生双件启动、关闭窗口与后台的区别、诊断与恢复 / Native binary pair, reconnect, diagnostics and recovery |
| [M5：发布与兼容性 / Release and compatibility](docs/plans/m5/README.md) | 安装、升级、卸载、兼容矩阵与性能证据 / Per-user installation, recovery, measured scope and limits |
| [M6：内核环境准备 / Kernel preparation](docs/plans/m6/README.md) | 冷启动后显式加载目标已有模块、注册空表 / Explicit module loading and empty tables after a cold kernel |
