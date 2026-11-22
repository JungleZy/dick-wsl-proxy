# dick-wsl-proxy · `wsl-proxyctl`

[简体中文](#简体中文) · [English](#english)

## 简体中文

`wsl-proxyctl` 是一个 Windows 命令行工具：它只代理一个 WSL2 发行版中本地进程新建的出站连接，包括已在运行的后台服务。应用不用单独配置代理；其他发行版和 Windows 原生进程保留原有网络路径。工具不修改 Windows 系统代理或 WSL 共享的 `resolv.conf`。

**流量怎么走？** 命中 IP、CIDR、域名或域名后缀白名单的业务连接由 Windows 直连。其余 IPv4 TCP 连接先经过宿主机已有的 SOCKS5 代理，再经过住宅 SOCKS5 出口；任一跳失败都不会改走直连。目标发行版的系统 DNS（UDP/TCP 53）始终经双跳访问指定的 DNS-over-HTTPS 上游，白名单不豁免 DNS 查询。

**适用范围。** Windows x64 原生桌面控制台与 CLI，后端按 WSL2 NAT 验证，不是通用 VPN。目标具备全局 IPv6 地址和默认路由时启用受管 IPv6，否则阻断目标外部 IPv6。非白名单普通 UDP（含 QUIC）要求住宅代理支持 UDP Associate，否则启动失败并保持阻断。同一 Windows 账户一次只接管一个发行版；切换前先确认旧目标已恢复，不迁移既有 TCP 连接。

**图形界面。** 将 `wsl-proxy-desktop.exe` 与配套 `wsl-proxyctl.exe` 放在同目录，打开前者。选目标及对照、保存策略并明确启动；关闭窗口不等于停止代理。重新打开可连接已有后台，恢复原网须选择“停止并恢复直连”。见 [M4 使用说明和验收边界](docs/plans/m4/README.md)。

**安装与升级。** Windows x64 候选包采用按用户安装的未签名 ZIP。校验、显式恢复、升级/卸载步骤与已测/未测环境见 [M5 发布说明](docs/plans/m5/README.md)；不要将 ZIP 哈希当作签名。
`0.1.3` 在保留逐包归属校验的前提下合并 UDP 回包查询：本地 16 并发已连接 UDP 回显 p95 从 348.66 ms 降至 88.55 ms，直连为 6.71 ms。全表均忙时仍拒绝新流。见 [M5 延迟与边界](docs/plans/m5/README.md#013udp-回包并发延迟)。

**从哪里开始？** 先按下方的[只读预检](#preflight)检查两套实验发行版。预检通过后，按 [M2 配置与启动指南](docs/plans/m2/README.md)准备 Windows 侧策略、导入住宅代理凭据，并在 `session` 中启动接管。策略文件只引用凭据名称，不要把 `.env` 或密码提交到仓库。正常停止时在同一会话发送 `{"command":"stop"}`；如果控制器崩溃，在新的 Windows 进程中依次运行 `wsl-proxyctl.exe status` 和 `wsl-proxyctl.exe stop`，不要把进程退出当作网络已经恢复。

## English

`wsl-proxyctl` is a Windows CLI that proxies new outbound connections from local processes in **one WSL2 distribution**, including services that were already running. Applications need no proxy settings. Other distributions and native Windows processes keep their original routes; the controller changes neither the Windows system proxy nor WSL’s shared `resolv.conf`.

**Where does traffic go?** Windows connects directly for application traffic matching an allowlisted IP, CIDR, domain, or domain suffix. Other IPv4 TCP connections use the host’s existing SOCKS5 proxy and then a residential SOCKS5 proxy. If either hop fails, the connection fails rather than going direct. The target’s system DNS (UDP/TCP port 53) uses the same two hops to reach the configured DNS-over-HTTPS upstream, even for allowlisted domains.

**Supported scope.** The Windows x64 native desktop and CLI share the controller tested on WSL2 NAT. It is not a general-purpose VPN. A target with a global IPv6 address and default route uses managed IPv6 interception, while external IPv6 is blocked when those prerequisites are absent. Non-allowlisted application UDP, including QUIC, requires residential UDP Associate support, otherwise startup fails closed. Only one distribution per account can be active. Switching restores the old target before enabling the new one; existing TCP connections do not migrate.

**Desktop.** Keep `wsl-proxy-desktop.exe` and the matching `wsl-proxyctl.exe` together and launch the desktop executable. Closing the window disconnects the UI, not the proxy; reopen to reconnect, or explicitly stop to restore routing. See the [M4 operator guide](docs/plans/m4/README.md).

**Install and upgrade.** The Windows x64 candidate is an unsigned per-user ZIP. See [M5 release and recovery notes](docs/plans/m5/README.md) for verification, safe maintenance and the support matrix. The ZIP checksum does not authenticate its publisher.
Version `0.1.3` batches UDP reply checks without caching destinations. Local connected UDP echo p95 at concurrency 16 fell from 348.66 ms to 88.55 ms (direct: 6.71 ms). A genuinely busy mapping table still rejects new flows.

**Getting started.** Run the [read-only preflight](#preflight) below with two test distributions. Once it passes, follow the [M2 setup guide](docs/plans/m2/README.md) for the Windows policy file, credential import, and `session` commands. Reference the residential credential by name in the policy; never commit the `.env` file or a password. To stop normally, send `{"command":"stop"}` in the active session. If the controller crashes, run `wsl-proxyctl.exe status` and then `wsl-proxyctl.exe stop` from a new Windows process. Process exit alone does not mean the original network path has been restored.

<a id="preflight"></a>

## 构建与只读预检 · Build and run a read-only preflight

在装有 Rust 工具链（支持 Rust 2024 edition）的 Windows 上，从仓库根目录打开 PowerShell。用 `list` 输出中的两个不同注册名替换示例：第一个是目标，`--witness` 是用于核对隔离的对照发行版。

From the repository root, open PowerShell on Windows with a Rust toolchain that supports the 2024 edition. Replace the example names with two distinct registered names from `list`: the first is the target; `--witness` identifies the distribution used to check isolation.

```powershell
cargo build --locked --release
$ctl = '.\target\release\wsl-proxyctl.exe'
& $ctl list
& $ctl preflight WSLProxyLab-Target --witness WSLProxyLab-Control
```

`list` 不会启动发行版。`preflight` 可能唤醒所选两套发行版，但不安装引流规则。查看 JSON 中的 `passed` 和 `blockers`；`passed: true` 仅表示预检通过，不表示代理已启用。

`list` does not start distributions. `preflight` may wake the selected pair, but installs no traffic rules. Check `passed` and `blockers` in the JSON output. `passed: true` means the checks passed, not that the proxy is active.

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
