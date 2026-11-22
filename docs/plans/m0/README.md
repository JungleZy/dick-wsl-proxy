# M0 执行记录：Windows 控制器与只读预检

本阶段的实现选择和证据记录在此；不改变[现行架构](../../arch/README.md)。**已交付 Windows x64 原生 CLI `wsl-proxyctl`。没有 `start`、代理转发、规则写入或 GPUI；预检通过也不接管网络。**

## 运行

在有 Rust 工具链的 Windows 上，于仓库根目录执行 `cargo build --locked --release`。本次实测使用从 WSL 交叉构建的 Windows GNU x64 release 可执行文件，已经放在实验机 `D:\WSL\ProxyLab\m0-1pRyLo\wsl-proxyctl.exe`。例如在 PowerShell 中：

```powershell
$ctl = 'D:\WSL\ProxyLab\m0-1pRyLo\wsl-proxyctl.exe'
& $ctl list
& $ctl status
& $ctl preflight WSLProxyLab-Target --witness WSLProxyLab-Control --port 43769
$LASTEXITCODE
```

`list` 读当前 Windows 用户的发行版注册表，不启动发行版。`preflight` 接受注册名称或注册 GUID；通过 `wsl.exe --distribution-id` 在明确指定的目标、对照中以 Linux root 执行内置探测，可能唤醒这两个发行版。不会探测未选择的其他注册项，不读取住宅凭据，也不自动安装工具。`--port` 是待检查的 **Windows** 入口端口（默认 43531）；分别独占绑定 TCP 和 UDP 后释放，不监听、不转发。这是即时可用性检查，不是为下一阶段预留端口。

预检在目标和对照身份、cgroup 边界及工具能力均通过后，会临时安装一条带唯一标记的 `xt_cgroup --path /` 计数规则。目标和对照分别发起本地回环连接，要求只有目标命中，随后精确删除规则。匹配结果或清理结果无法确认时，预检阻断并保留恢复所需的错误信息。

`session` 持有当前用户唯一控制锁，逐行接收 JSON 命令，例如 `{"command":"status"}`；EOF 正常退出。独立子命令也先取得同一把锁。锁文件位于当前用户 LocalAppData 下的 `WSLProxyLab\controller.lock`，锁由打开的文件句柄维持，进程退出自动释放；不通过删除文件强行解锁。

## 如何读输出

- 预检报告为 JSON。`controller.phase=idle`、`active_target=null`、`config_generation=0` 是 M0 的实际状态；`target` 是**候选目标**，不是活动目标。`passed` 和 `blockers` 给出本次判定；`witness.snapshot.blockers` 中仅对目标执行规则才需要的工具缺失，不会否定对照身份。
- 身份使用注册 GUID、注册名与 guest 名、PID 1 及普通进程 cgroup 归属、cgroup v2 命名空间和工作负载共同子树的设备号/索引节点。判断不依赖共享 IP、进程 UID 或写死的 inode。位于该子树以外的 WSL `/init` 基础设施，通过实际可执行文件的 inode 识别并单列；其他不明越界进程不放行。内核能力区分内建和已加载模块，不为通过预检去加载模块。
- `evidence` 给出探测状态和值；`baseline_fingerprints` 给出成功采集项的指纹，覆盖解析器、路由、规则及防火墙状态。完整报告可能含本地网络拓扑、DNS 内容、规则与路径，供本机诊断，不宜直接公开。连接跟踪可读性检查不输出连接条目。
- 对独立 `preflight` 命令，退出码 `0` 表示只读预检通过，`2` 表示已生成报告但被条件阻断，`3` 表示控制器已被占用；未注册的目标或调用失败返回 `1`。参数语法错误由 CLI 解析器单独报错。M0 的隔离证据目前要求显式指定不同的对照发行版；没有对照会报告 `isolation_witness_missing`，不会暗中启动其他发行版。

## 两个 D 盘实验环境的验收结果

用 Windows PowerShell 启动真实 release EXE。A=`WSLProxyLab-Target`，B=`WSLProxyLab-Control`，注册位置分别为 `D:\WSL\ProxyLab\Target` 和 `D:\WSL\ProxyLab\Control`；均是 WSL2、NAT，运行探针的 UID 同为 0，默认网关同为 `172.28.80.1`。

| 场景 | 实际结果 |
|---|---|
| A 为目标，B 作对照 | 退出 `0`，无阻断项。A/B 的 cgroup 命名空间分别为 `4026534269`、`4026534294`，该轮子树标识分别为 `25:386884`、`25:389597`；入口 `172.28.80.1:43769` 的 TCP、UDP 均可绑定。两边身份有效，活动目标仍为空。 |
| B 为目标，A 作对照 | 退出 `2`。B 的 IPv4/IPv6 legacy iptables 工具及对应规则基线不可用；身份识别成功，但拒绝把工具缺失当成空规则或可接管。未向 B 安装软件。 |
| 省略对照 / 使用同一注册项 / 不存在的目标 | 分别返回 `isolation_witness_missing`、`same_distribution`、`not_registered`。 |
| Windows 临时独占占用待检 TCP 端口 | A 退出 `2`，命中 `host_port_unavailable`。端口在测试后释放。UDP 被占用的情况另有独立测试。 |
| 持锁与进程崩溃 | 一个 `session` 持锁时第二个原生进程发起预检，退出 `3`、`controller_busy`；终止锁持有进程后，新控制器可获得锁并返回空闲。 |
| 网络是否改变 | 比对独立于控制器采集的 `before-*` / `after-*` 文件，两发行版各自字节一致：包含 DNS 文件摘要和链接目标、双栈路由/策略规则摘要；A 还包含剔除计数器后的 legacy 防火墙摘要。B 没有该工具，明确记录为不可用。 |

编译与质量验证：`cargo test --locked` 通过 8 项测试；`sh -n src/probe.sh`、Windows 目标的 `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings`、Windows release 构建均通过。原生 EXE SHA-256：`dc1bcaa4d02f2b7ef41abc444854bfef8417d17a3621545990c20c0ca4bcbf84`。

原始证据与 EXE 同目录：`list-lab-only.json`、`preflight-A.json`、`preflight-B.json`、`preflight-without-witness.json`、`preflight-occupied.json`、`input-rejections.json`、`lock-while-held.json`、`status-after-owner-exit.json` 及前后基线。没有把本机整份诊断输出纳入仓库。

## 进入 M1 的边界

M0 覆盖的是当前 NAT + systemd + 可区分 cgroup 子树的布局，不是对任意 WSL 版本、网络模式或重启首包的保证。每次采样只代表当时状态；M1 在落规则前必须重新核对身份、端口和状态。A 可作为 M1 的首个目标，B 仍可做不受影响的对照；在 B 缺少所需工具的情况下不得宣称可反向接管。后续仍需验收真正的业务入口、可逆启停、受管 DNS 与单目标切换。
