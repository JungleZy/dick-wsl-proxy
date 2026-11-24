# dick-wsl-proxy · `wsl-proxyctl`

[简体中文](#简体中文) · [English](#english)

## 简体中文

`wsl-proxyctl` 是一个 Windows 命令行工具：它只代理一个 WSL2 发行版中本地进程新建的出站连接，包括已在运行的后台服务。应用不用单独配置代理；其他发行版和 Windows 原生进程保留原有网络路径。工具不修改 Windows 系统代理或 WSL 共享的 `resolv.conf`。

**流量怎么走？** 命中 IP、CIDR、域名或域名后缀白名单的业务连接由 Windows 直连。其余 IPv4 TCP 连接先经过宿主机已有的 SOCKS5 代理，再经过住宅 SOCKS5 出口；任一跳失败都不会改走直连。目标发行版的系统 DNS（UDP/TCP 53）始终经双跳访问指定的 DNS-over-HTTPS 上游，白名单不豁免 DNS 查询。

**适用范围。** Windows x64 原生桌面控制台与 CLI，后端按 WSL2 NAT 验证，不是通用 VPN。目标具备全局 IPv6 地址和默认路由时启用受管 IPv6，否则阻断目标外部 IPv6。非白名单普通 UDP（含 QUIC）经住宅代理的 UDP Associate 转发；启动时这项探测不通过（例如住宅代理不支持 UDP），接管仍会启动，但本次接管期间这类 UDP 一律拒绝、不会直连，界面显示“UDP 已阻断”，下次启动或切换时重新探测。同一 Windows 账户一次只接管一个发行版；切换前先确认旧目标已恢复，不迁移既有 TCP 连接。

**图形界面。** 将 `wsl-proxy-desktop.exe` 与配套 `wsl-proxyctl.exe` 放在同目录，打开前者。选目标、保存策略并明确启动；关闭窗口只收进托盘，不停止代理。托盘菜单「退出」会在确认后停止接管、恢复直连并关闭后台，再退出程序。桌面被强制结束时后台照旧保留，重新打开可连接已有后台。见 [M4 使用说明和验收边界](docs/plans/m4/README.md)。冷启动或 WSL 重启后，目标内核可能没有加载所需模块；启动接管前的预检发现缺少这些能力时，会先询问是否加载发行版里已有的模块并创建空表（不安装软件、需先停止接管），确认后自动重新预检，并把模块列表和空表初始化写进发行版的开机配置；以后 WSL 启动会自动准备好，不再询问。见 [M6 内核环境准备](docs/plans/m6/README.md)。设置页的「WSL 平台」卡片只读显示 `wsl.exe` 版本、WSL2 内核、默认版本与已注册发行版；没有接管时可以用它显式运行 `wsl --update` 升级 WSL 平台。见 [M7 WSL 平台检查与升级](docs/plans/m7/README.md)。

**安装与升级。** Windows x64 候选包采用按用户安装的未签名 ZIP。校验、显式恢复、升级/卸载步骤与已测/未测环境见 [M5 发布说明](docs/plans/m5/README.md)；不要将 ZIP 哈希当作签名。
`0.1.3` 在保留逐包归属校验的前提下合并 UDP 回包查询：本地 16 并发已连接 UDP 回显 p95 从 348.66 ms 降至 88.55 ms，直连为 6.71 ms。全表均忙时仍拒绝新流。见 [M5 延迟与边界](docs/plans/m5/README.md#013udp-回包并发延迟)。

**从哪里开始？** 先按下方的[只读预检](#preflight)检查目标发行版。预检通过后，按 [M2 配置与启动指南](docs/plans/m2/README.md)准备 Windows 侧策略、导入住宅代理设置（写入 EXE 同级的 `desktop.sqlite`，含明文密码），并在 `session` 中启动接管。策略文件里的 `credential` 只是标签，不要把 `.env` 或密码提交到仓库。正常停止时在同一会话发送 `{"command":"stop"}`；如果控制器崩溃，在新的 Windows 进程中依次运行 `wsl-proxyctl.exe status` 和 `wsl-proxyctl.exe stop`，不要把进程退出当作网络已经恢复。

## English

`wsl-proxyctl` is a Windows CLI that proxies new outbound connections from local processes in **one WSL2 distribution**, including services that were already running. Applications need no proxy settings. Other distributions and native Windows processes keep their original routes; the controller changes neither the Windows system proxy nor WSL’s shared `resolv.conf`.

**Where does traffic go?** Windows connects directly for application traffic matching an allowlisted IP, CIDR, domain, or domain suffix. Other IPv4 TCP connections use the host’s existing SOCKS5 proxy and then a residential SOCKS5 proxy. If either hop fails, the connection fails rather than going direct. The target’s system DNS (UDP/TCP port 53) uses the same two hops to reach the configured DNS-over-HTTPS upstream, even for allowlisted domains.

**Supported scope.** The Windows x64 native desktop and CLI share the controller tested on WSL2 NAT. It is not a general-purpose VPN. A target with a global IPv6 address and default route uses managed IPv6 interception, while external IPv6 is blocked when those prerequisites are absent. Non-allowlisted application UDP, including QUIC, uses the residential UDP Associate. If that startup probe fails (for example, the residential proxy lacks UDP support), takeover still starts, but such UDP is refused, never sent direct, for the rest of that session; the desktop shows UDP as blocked, and the next start or switch probes again. Only one distribution per account can be active. Switching restores the old target before enabling the new one; existing TCP connections do not migrate.

**Desktop.** Keep `wsl-proxy-desktop.exe` and the matching `wsl-proxyctl.exe` together and launch the desktop executable. Choose a target, save the policy, and explicitly start it. Closing the window only hides it to the tray; the proxy keeps running. **Exit** in the tray menu stops the takeover after confirmation, restores direct routing, shuts the background controller down, and then quits. If the desktop process is killed, the controller keeps running; reopen to reconnect. See the [M4 operator guide](docs/plans/m4/README.md). A cold WSL kernel may have none of the required modules loaded. If the preflight before a start finds them missing, the desktop asks whether to load modules already shipped with the distribution and create empty tables; it installs nothing, then reruns the preflight. The same confirmation also installs a boot-time module list and a oneshot that registers the empty tables, so later WSL starts need no prompt. See [M6](docs/plans/m6/README.md). The **WSL platform** card in Settings reports the `wsl.exe` version, WSL2 kernel, default version and registered distributions; while idle it can also run `wsl --update` explicitly. See [M7](docs/plans/m7/README.md).

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
