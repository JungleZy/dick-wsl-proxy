# 项目审查：HEAD `b03c97a` + 0.1.8 未提交改动

> 审查快照：2026-11-23 14:45–14:54（HEAD `b03c97a`，工作区未提交改动 +4125/−700，版本 0.1.8）。
> **审查期间工作区被其他会话并发修改**：14:54 有人在 `src/desktop_store.rs` 加入 WAL（本审查已纳入）；15:01–15:02 有人在改「单二进制重构」（`src/lib.rs`、`src/main.rs`、`desktop/src/main.rs`、`src/ipc/windows.rs`），**这部分不在本审查范围**。当前工作区处于该重构中间态：`cargo test -p wsl-proxy-desktop` 因 `src/host.rs:337` 的 `wsl_proxyctl::paths` 解析失败而无法编译。本审查的代码行号以 14:54 快照为准；被重构移动过的 `src/main.rs`（原 176 行）部分行号已不存在。

**结论：故障不降级、归属从严这条主线仍然成立，前两轮的高危/中危问题大多修好。真正需要处理的是三类：**

1. **一项核心隔离验证被悄悄撤掉。** `d2e606f` 当天加的「目标/对照跨发行版 cgroup 匹配自检 + `--witness`」在之后的 `b03c97a`（提交说明是「finalize desktop UI」）里被整体删除，`docs/plans/m0`、M5 支持矩阵、架构与决策却仍按旧设计叙述。旧 H1（旧内核可能把对照发行版的流量也接管）因此重新打开，而且这次没有任何代码门槛。
2. **0.1.8 新增的桌面存储、环境管理、IPv6 数据面有一批中危问题**：IPv6 入路的失败会整条 worker 退出、IPv6 计划推导与 guest 校验来源不一致、切换中断后的恢复仍可能永久卡死、环境操作在 4 分钟 IPC 上限下必然「界面报失败但后台继续」、新建环境回滚有可能注销别人的发行版、桌面把住宅密码明文显示并回写、连接记录把备份文件当「诊断导出」。
3. **发布链路与验收记录没跟上 0.1.8。** 静态 CRT 依赖一个未跟踪的 `.cargo/config.toml`；`src/paths.rs` 也是未跟踪文件；Windows 打包脚本用 locale 编码读 JSON；clippy `-D warnings` 仍失败；没有 0.1.8 的候选包或实机记录。

**需要负责人拍板的事：**

| 决策 | 为什么要你定 |
|---|---|
| H1：恢复「对照发行版 + 实际匹配自检」，还是登记「不再验证跨发行版隔离」并修改 `docs/arch`/`docs/decisions`/M5 支持矩阵 | 这是产品隔离承诺的核心；两种选择的后续工作量与发布口径完全不同 |
| IPv6 数据面是否算 0.1.8 的支持范围 | M5 矩阵现在写「没有 IPv6 代理」，代码却默认启用受管 IPv6 透明代理，且无就绪验证/实机证据 |
| 环境管理（新建/编辑/备份/删除发行版）是否属于本产品范围 | 它把攻击面从「代理配置」扩到「以 root 改发行版」；若保留，需要错误码、超时、回滚单独的验收 |
| 0.1.8 是否升版并补候选包/实机验收，还是先只做开发里程碑 | 决定 README/M5 是否要同步版本与证据 |
| 文档缺口由谁并入 `docs/arch`、`docs/decisions.md`、M4/M5、`docs/contracts` | 按 `AGENTS.md`，这些改动不在实现任务里顺手做 |

## 审查范围和证据等级

- **后端五块**（guest 内核辅助/预检/策略、数据面入口、DNS 与查询通道、控制面与 IPC、桌面存储与 RPC）各由一个独立子审查完整过一遍；桌面 UI、发布与文档由一个子审查负责。中等及以上发现我再逐条对照代码复核。
- **我本人复核的**：`b03c97a` 相对 `d2e606f` 的删除（`git show b03c97a`）、`src/command.rs`/`src/probe.rs`/`docs/plans/m0`、`src/controller.rs`/`src/controller/lifecycle.rs`、`src/desktop_store.rs`、`src/desktop_control.rs`、`src/environment.rs`、`src/plan.rs`、`src/guest/kernel.py`、`src/guest/probe.sh`、`src/ingress/*` 的关键路径、桌面 `bootstrap.rs`/`views.rs`/`overview.rs` 的状态与渲染、`desktop/src/app/instance.rs`、`scripts/package-windows.py`、`packaging/windows/common.ps1` 的本次 diff，以及全部文档。
- 证据等级：**本人复核**（我读代码确认）/ **子审未复核**（只有子审查读过）/ **需实机**（取决于 Windows 或 Linux 内核行为）。

审查期间没有改代码、没有启用接管、没有在任何 WSL 里执行规则操作。

### 本次实际跑过的检查（Windows 原生）

| 检查 | 结果 |
|---|---|
| `cargo test --locked -p wsl-proxyctl` | **141 passed, 0 failed**（rustc 1.100.0，MSVC） |
| `cargo test --locked -p wsl-proxy-desktop` | **8 passed**（快照前；现因并发重构不可编译，见开头说明） |
| `cargo fmt --all -- --check` | 通过 |
| `cargo check --locked -p wsl-proxy-desktop` | 通过 |
| `cargo clippy --locked -p wsl-proxyctl --all-targets -- -D warnings` | **失败 2 条**：`src/desktop_store.rs:219` too_many_arguments、`src/environment.rs:667` collapsible_if |
| `cargo clippy --locked -p wsl-proxy-desktop --all-targets -- -D warnings` | **失败 8 条**：`backend.rs:189/215`、`chrome.rs:173`、`diagnostics.rs:806`、`tray.rs:112/151/275/281`（4 类 lint） |
| `python src/guest/test_kernel.py` | 63 passed |
| `python scripts/test_package_windows.py` | 2 passed |
| `cargo build --locked --release -p wsl-proxyctl`（`CARGO_TARGET_DIR` 指到临时目录） | 通过（56.7s）；产物导入表无 `VCRUNTIME140`/`api-ms-win-crt`/`MSVCP140` |
| release 全套（含桌面） | **未重新验证**：`target\\release` 里的 `wsl-proxy-desktop.exe`/`wsl-proxyctl.exe` 正在运行（PID 612/12144，今天 14:29–14:36 构建），重新链接会被文件占用拒绝；已检查现有两个 EXE 的导入表，同样没有 `VCRUNTIME140` |

说明：本会话的 PowerShell 环境里 `CC` 被设成无关命令，导致 bundled SQLite 首次编译失败；验证时清空 `CC`/`CXX` 后完成。这是评审环境的干扰，不是项目问题。

## 发现总表

| 编号 | 严重度 | 问题 | 位置 | 证据 |
|---|---|---|---|---|
| H1 | 高 | 跨发行版隔离自检与 `--witness` 在 `b03c97a` 被整体删除，未登记；M0/M5/架构仍按旧设计叙述 | `src/command.rs:166-202`、`src/probe.rs:36-39`、`docs/plans/m0/README.md:13,19,25,28,38`、`docs/plans/m5/README.md:27` | 本人复核 |
| M1 | 中 | IPv6 UDP 单次查址失败用 `?` 冒泡，整条 IPv6 worker 退出 → 会话误报 `recovery_required`、首次 stop 失败；且每包同步查址、无批处理、被拒不计数 | `src/ingress/ipv6.rs:224,335-340,389-413`、`src/ingress.rs:224-229` | 本人复核；频率需实机 |
| M2 | 中 | `MAX_DNS_UDP` 8→64 但元数据作业队列仍 80：v4 最坏 129 个在途 job 会被直接拒绝（改前 73），高并发查址失败 | `src/ingress.rs:49,1099-1103`、`src/ingress/metadata_lane.rs:40-41,69-78` | 本人复核 |
| M3 | 中 | IPv6 计划从「任意接口/任意路由表」推导，guest `guard()` 只认 eth0 唯一 global 地址 + 主表唯一默认路由 → 预检通过后启动失败 | `src/plan.rs:159-211`、`src/guest/kernel.py:205-221` | 本人复核 |
| M4 | 中 | 预检 `passed:true` 不保证能启动：`network.gateway_route` 缺失不阻断、不校验网关 dev、IPv6 入口端口未做占用检查 | `src/guest/probe.sh:116-119`、`src/plan.rs:102-118`、`src/probe.rs:135-159`、`src/ports.rs:86-95`、`src/ingress.rs:92-96` | 子审未复核；触发需实机 |
| M5 | 中 | IPv6 三类 stale-context 错误不在 `remove`/`inspect` 白名单：接管期间 IPv6 地址/路由一变，规则删不掉、恢复卡死 | `src/guest/kernel.py:1182-1188`、`:213,220,225` | 本人复核 |
| M6 | 中 | M5 支持矩阵仍写「没有 IPv6 代理」，与 README 和已实现的受管 IPv6 透明代理矛盾；IPv6 数据面无就绪门槛和实机验收 | `docs/plans/m5/README.md:30`、`README.md:11`、`src/plan.rs:131-143`、`src/ingress/ipv6.rs` | 本人复核 |
| M7 | 中 | 切换中断时旧目标「仍注册但 WSL 起不来」或 `releasing_old` 阶段被注销，`stop` 永远失败（无出路恢复） | `src/controller.rs:183-188`、`src/controller/lifecycle.rs:41-57,211-228` | 本人复核；WSL 不可达需实机 |
| M8 | 中 | `open()` 把 WAL 变成硬要求，非 WAL 文件系统上整个 store 不可用，`start` 也起不来（0.1.8 可用性回归） | `src/desktop_store.rs:140-147` | 本人复核；触发环境需实机 |
| M9 | 中 | 环境操作（最长约 70 分钟）走 240 秒 IPC 上限：界面报失败、后台继续、期间其它请求不可用 | `src/environment.rs:13-16`、`src/ipc/windows.rs:52`、`src/main.rs` daemon 分支 | 本人复核常量 |
| M10 | 中 | `create` 失败回滚按名字 `--unregister`，未核对是否本次创建：并发注册的同名发行版可能被删除 | `src/environment.rs:470-486,597-601` | 子审未复核；触发需并发 |
| M11 | 中 | 编辑环境超时直接 kill `wsl.exe`，可能留下半配置的 apt/dpkg；错误文案对 edit 不成立并吞具体退出码 | `src/environment.rs:266,681-689`、`src/host.rs:190-194`、`desktop/src/app/backend.rs:151` | 复核代码路径；dpkg 后果需实机 |
| M12 | 中 | 「新建环境总是安装 systemd 和 iptables」只对 apt 系成立，但发行版列表含 openSUSE/SUSE/RHEL/Fedora/Arch/Oracle，创建成功也无法接管 | `src/environment.rs:271-296`、`desktop/src/app/distributions.rs:3-37`、`docs/plans/m5/README.md` 新增节 | 本人复核列表与脚本；默认包需实机 |
| M13 | 中 | `reset-dns-aliases` 在桌面形态不可达（daemon 常驻持锁、无 rpc 分支/UI），`.pending` 时仍永久拒绝分配；M4 遗留的「无恢复命令」实际未解决 | `src/command.rs:72-76,257-273`、`src/desktop_control.rs`、`src/managed_dns/ledger.rs:196-204,254-264` | 本人复核 dispatch |
| M14 | 中 | 启动连不上后台或 daemon 退出后没有重连入口；单实例再次启动静默退出，只能托盘退出重开 | `desktop/src/app/bootstrap.rs:230`、`views.rs:378-380`、`instance.rs:22-35` | 本人复核 |
| M15 | 中 | 预检阻断项只显示英文机器码；Start/Switch/Stop 路径的阻断项无页面可见；失败预检在时间线上仍显示绿色「预检结果已更新」 | `desktop/src/app/bootstrap.rs:557-597,690-693`、`overview.rs:453-457` | 本人复核 |
| M16 | 中 | 住宅密码明文：`profile_get` 回传明文 password、设置页用普通 `Input` 显示、保存会把旧密码写回凭据库 | `src/desktop_store.rs:99-118,866-875`、`desktop/src/app/bootstrap.rs:936-948`、`views.rs:1987` | 本人复核；凭据库行为需实机 |
| M17 | 中 | 环境备份路径复用 `export_path`，连接页显示「诊断已导出：<env.tar>」并可打开其位置 | `desktop/src/app/bootstrap.rs:658-660`、`diagnostics.rs:495-496,546-556` | 本人复核 |
| M18 | 中 | 发布链路：`.cargo/config.toml` 与 `src/paths.rs` 均未跟踪（前者丢失静态 CRT，后者 clean clone 编译失败）；打包脚本不校验 CRT | `.cargo/config.toml`（`??`）、`src/paths.rs`（`??`）、`scripts/package-windows.py:32-39,101-117`、`docs/plans/m5/README.md:124-128` | 本人复核 |
| M19 | 中 | `package-windows.py` 用 locale 默认编码读 build record / `cargo metadata`（Windows 中文系统 cp936），UTF-8/BOM 输入解码失败，原生 Windows 打包流程走不通 | `scripts/package-windows.py:88,89,95` | 本人复核代码；实跑需实机 |
| M20 | 中 | `clippy -D warnings` 门槛仍失败（控制器 2 条、桌面 8 条）；仓库无 CI、无固定工具链 | 见「本次跑过的检查」 | 本人跑 |

低严重度发现见下一节（L1–L24）。

## 高严重度

### H1 跨发行版隔离验证在 `b03c97a` 被删除且无登记

**历史。** 第一轮审查的 H1 指出：引流规则用 `-m cgroup --path /` 区分发行版，依赖内核按调用者 cgroup 命名空间解析路径；在 5.10 系或未回移相关补丁的内核上，`/` 会解析到全局根，对照发行版的流量也会被打标、DNAT 并送进住宅出口。`d2e606f`（11-22 17:26，提交说明「verify cgroup isolation during preflight」）实现了缓解：预检在目标里装一条临时计数规则，分别从目标和对照发起本地连接，要求只有目标命中、随后精确删除；`start`/`preflight` 一度要求 `--witness`。

**现状。** HEAD `b03c97a`（11-22 22:23，提交说明「finalize desktop UI and theme persistence」）把整套东西删掉了：

- `Command::Preflight`/`Start`/`StartScoped` 的 `witness` 参数删除，`Preflight` 结构体不再有 `witness` 字段（`src/command.rs:166-202`）；
- `probe::verify_cgroup_isolation` 及其 5 个脚本构造函数全部删除（现在 `src/probe.rs` 只剩 `inspect`/`snapshot`）；
- 阻断项 `isolation_witness_missing`、`isolation_identity_unverified`、`shared_cgroup_boundary` 消失；
- 桌面端同步删除了「对照 WSL」选择和预检对照展示；
- `src/guest/probe.sh:155` 仍采集 `kernel.release`，全仓库无人使用。

**后果。** `preflight` 现在只证明目标自己的身份/capability/端口，不再证明「规则只匹配目标」。旧 H1 的失败模式（旧内核误捕对照发行版）重新变成无检测、无门槛、无文档说明的风险；而这正是 `docs/arch/README.md` 与 `docs/decisions.md` 01 的核心承诺。

**文档状态。** `docs/plans/m0/README.md` 第 13/19/25/28/38 行仍写 `preflight ... --witness WSLProxyLab-Control`、临时计数规则、`isolation_witness_missing`/`same_distribution` 退出行为——按文档敲命令现在会被 clap 直接拒绝。M5 支持矩阵（`docs/plans/m5/README.md:27`）仍写「每个目标都必须核实实际布局和隔离」。`docs/arch/`、`docs/decisions.md` 自上次审查以来**一次都没改过**（`git log 8ce39d8..HEAD -- docs/arch docs/decisions.md` 为空）。

**建议。** 二选一并写进决策记录：恢复对照自检（这是 M0 已验证过的机制），或明确接受「不验证跨发行版匹配」并把内核版本/发行版范围写成支持矩阵的硬条件，同时更新 m0/M5/架构。不能保留现在的状态：代码没有验证，文档仍在承诺。

## 中严重度

（以下每条按「现象/触发/后果/建议」压缩成 2–4 句；UDP 阻断主线和「不降级」在数据面审查中确认成立，不是问题。）

### M1 IPv6 UDP 入路的失败处理与性能

`collect_udp` 对回包查址失败用 `?` 直接冒泡（`src/ingress/ipv6.rs:335-340`），一次映射过期/歧义/4 秒超时就让整个 IPv6 worker 退出；`Ingress::health` 随后报 issue，整场会话显示 `recovery_required`（IPv4 仍在转发），首次显式 stop 还会因 join 失败而报错。v4 同位置是逐流 `failed()`+退役。另：IPv6 每个数据报都同步查址、没有 v4 的 16 个一批和回包轮转（`ipv6.rs:217-230`），目标有全局 IPv6 时 UDP 吞吐会被压到约 100pps 并挡住同线程的 IPv6 TCP accept；被拒/失败也不计入 `rejected_udp`/连接记录。建议按 v4 的逐流退役 + record_error 改写，`is_stopping` 时返回 Ok；批处理落地前不要把 IPv6 写进支持矩阵。

### M2 DNS UDP 并发提高后元数据队列容量不匹配

`MAX_DNS_UDP` 从 8 提到 64（`src/ingress.rs:49`），但 `MetadataLane` 作业通道仍是 `sync_channel(80)`、注释还写着「eight DNS workers」（`src/ingress/metadata_lane.rs:40-41`）。v4 最坏 64 TCP + 64 DNS UDP + 1 个 UDP 组 = 129 个在途 job，超过 80 时 `try_send` 直接失败（`query_transport_queue_full`），表现为连接建不起来/DNS 回包被丢。改前最坏 73，属本次改动引入的容量回归。建议队列容量由 `MAX_TCP + MAX_DNS_UDP + 常数` 推导并加常量关系测试。

### M3/M4 IPv6 计划推导、guest 校验与预检口径不一致

`ipv6_scope` 从 `ip -6 -oneline address show`（任意接口）取第一个 global 地址、从 `ip -6 route show table all`（任意表）取第一个 default via（`src/plan.rs:159-211`）；guest `guard()` 却要求 eth0 上恰好一个 global 地址、主表恰好一条 dev=eth0 的默认路由（`src/guest/kernel.py:205-221`）。目标有 docker0/tailscale0 等带 global IPv6 的接口时，预检通过、启动才失败。另外 `probe.sh` 只在 `/usr/sbin/ip` 存在时采 `network.gateway_route`（`probe.sh:116`），而 `plan` 强制需要它；预检也不校验网关是否在 eth0、不检查 IPv6 入口端口的占用（`ports.rs` 只绑 IPv4）。建议预检里直接构造一次 `Plan` 并把失败转成 blocker，端口检查覆盖 IPv6。

### M5 IPv6 变化会让 `stop` 删不掉规则

`execute()` 只对 5 类 stale-context 错误放行 `remove`/`inspect`（`src/guest/kernel.py:1182-1188`），IPv6 新加的 `guest_ipv6_address_changed`、`ipv6_gateway_changed_or_ambiguous`、`ipv6_ingress_scope_missing` 都不在集合里。接管期间 IPv6 前缀/默认路由一变，`stop` 直接失败、规则和映射残留、停在 `recovery_required`。建议把三类 IPv6 错误并入 stale 集合并补 stale-remove 测试。

### M6 IPv6 支持口径自相矛盾

`docs/plans/m5/README.md:30` 的支持矩阵写「IPv6｜没有 IPv6 代理。managed 生成针对目标 cgroup 的外部出站阻断规则」；`README.md:11` 与代码（`plan.rs:131-143`、`ingress/ipv6.rs`）却是「有全局 IPv6 和默认路由时启用受管透明代理」。`managed::Runtime::verify()` 只验证 IPv4 DNS 与 HTTPS，IPv6 没有任何就绪门槛，M5 的实机证据也只覆盖「阻断」。用户会按矩阵理解成 IPv6 被阻断，实际被引流。建议统一口径，并在写进矩阵前补 IPv6 的就绪验证与验收。

### M7 切换中断后的恢复仍有死路

`retire` 在做任何清理前要求目标仍注册且 `inspect` 可达（`src/controller.rs:183-188`）；`verify_restored` 只在「未注册」时跳过（`lifecycle.rs:41-57`）。A→B 切换中断在 `starting_new`/`old_restored`，而 A 仍注册但 WSL 启动失败（M3 记录里的真实 `ERROR_TIMEOUT`），`stop` 会永远失败；`releasing_old` 阶段用户注销目标发行版同样卡死。后果是 `pending`/`m1-active.json`/ingress/lease 都放不掉，`shutdown_daemon` 因非 idle 被拒，文档又禁止手删恢复日志。建议：`old_restored` 用持久证明收尾、`starting_new` 先 retire(new)，对「注册但不可达」提供明确人工确认路径。

### M8 WAL 变成硬要求

`open()` 设置 `journal_mode=WAL`，返回值不是 `wal` 就返回错误（`src/desktop_store.rs:140-147`），所有 store API 都从这里进入。`%LOCALAPPDATA%` 被重定向到 SMB/不支持 WAL 的卷时（企业环境常见），不只是记录丢失：`profile_get`/`profile_save` 失败、`start` 的 `load_runtime` 也失败，受管接管根本无法启动——0.1.7 默认 rollback journal 时这些环境可用，属可用性回归。建议 WAL 失败时回退 `delete` 并写降级日志，错误文本给可操作提示。

### M9 环境操作与 IPC 响应上限

环境操作自身期限是 10/20/30/30 分钟（`src/environment.rs:13-16`，create 最长约 70 分钟），但桌面等 daemon 回复的硬上限是 240 秒（`src/ipc/windows.rs:52`），daemon 又只有一个管道实例、handler 串行。新建环境（下载 + apt + Chrome）或备份大发行版通常超过 4 分钟：界面先报失败，后台继续跑 10–30 分钟，期间其它请求 5 秒超时——用户很可能据此关窗或重复提交，界面认知与磁盘状态不一致。建议改成异步 job + 轮询，或按命令单独放宽客户端等待上限并允许多实例查询。

### M10 新建环境回滚可能注销别人的发行版

`rollback_create` 用 `registered_distribution(name)` 按名字匹配，匹配到就 `wsl --unregister`（`src/environment.rs:470-486`），注释假设该名字一定来自本次请求。名称占用检查和最终注册之间隔着最长 30 分钟的下载/安装窗口；用户或其它工具在此期间用同名 `wsl --import`，回滚就会注销那个发行版（删除其 vhdx，不可恢复）。建议安装前记录发行版 id 集合，回滚只注销本次新增且 `base_path` 等于目标目录的条目，核对不上就保留现场并报错。

### M11 编辑超时会留下半配置的 apt/dpkg

`edit` 在用户已有发行版里跑 `apt-get update/install`，20 分钟 `CONFIGURE_DEADLINE` 到点后 `GuestChild::drop` 直接 kill `wsl.exe`（`src/host.rs:190-194`），不撤销任何改动；错误统一包成 `environment_setup_failed`，桌面显示「环境初始化失败，已尝试撤销本次导入」——对 edit 是假话，且把 `environment_setup_requires_apt`、`environment_timezone_not_found` 等具体退出码全部吞掉。慢镜像下国内网络很现实。建议 create/edit 分开错误码与文案，超时只报超时并提示可能需要 `dpkg --configure -a`。

### M12 非 apt 发行版与「总是安装 systemd/iptables」不符

`run_apt` 只在 `apt-get` 存在时为真（`src/environment.rs:271-296`），systemd/iptables 也只在这个分支装；但新建 UI 的发行版列表包含 openSUSE/SUSE/RHEL/Alma/Fedora/Arch/Oracle（`desktop/src/app/distributions.rs:3-37`），M5 新增节写「新建环境总是安装 systemd 和 iptables」。这些发行版创建会成功并提示组件完成，之后预检报工具缺失，环境详情页也不报告这两项能力，用户看不出缺什么。建议限制列表到 apt 系，或补各系安装步骤并让 inspect 报告能力。

### M13 DNS 别名重置在桌面形态不可达

别名号段耗尽/`.pending` 造成的「自动 reset 被禁止」现在的出路是 CLI `reset-dns-aliases --confirm`（`src/command.rs:72-76,257-273`），但它要被控制器锁保护，桌面 daemon 启动后整段 `serve` 一直持锁；桌面没有该命令的 dispatch 分支或 UI（`src/desktop_control.rs` 只在日志名里出现 `reset_dns_aliases`），README/M2 也没写这条命令。结论：桌面用户遇到别名耗尽时仍无路可走，M4「没有重置命令」只解决了一半。建议桌面加确认入口并在 daemon 内部执行，命令写进文档，错误串直接给出可执行指引；`.pending` 由 reset 明确清理。

### M14 后台失联后没有重连入口

`Kind::Bootstrap`（唯一会调 `ensure_daemon()` 的任务）只在 `Desktop::new` 发一次（`bootstrap.rs:230`）；状态栏「后台在线」和托盘「刷新后台状态」都只发 `Kind::Status`，而 `ipc::request` 不会拉起 daemon。CLI session 占锁导致 Bootstrap 失败、升级后 daemon 退出、`stale_profile_revision` 提示「请刷新后重试」时，界面永远 unknown、所有操作禁用；单实例 mutex 让再次双击 EXE 静默退出（`instance.rs:22-35`），只能托盘退出重开，且失败原因在 `windows_subsystem="windows"` 下没有控制台可见。建议状态栏加「重新连接」并允许重试 Bootstrap，单实例冲突时唤起已有窗口。

### M15 预检结果不可见且失败被标绿

显式预检失败时提示直接拼接机器码（`bootstrap.rs:595`，如 `capability.kernel.conntrack_readable.unverified`）；Start/Switch/Stop 的阻断项只提示「请查看阻断项」，但 `preflight` 全仓唯一消费点是 `is_some()`（`overview.rs:453`），阻断项没有任何页面渲染。同时事件时间线对**失败**的预检也显示 TEAL「预检结果已更新」——正是「把失败显示成绿色成功」。建议做中文映射并在概览/确认框渲染阻断项列表，按 `passed` 决定颜色。

### M16 住宅密码明文显示、回传与回写

`profile_get` → `desktop_store::ensure` 的 `prepare_residential` 从 Windows Credential Manager 补全 `password`，`view()` 原样返回（`desktop_store.rs:99-118,866-875`）；桌面 `accept_profile` 把它写进 `residential_password` 字段（`bootstrap.rs:936-948`），设置页用普通 `Input` 渲染（`views.rs:1987`）——同项目的环境密码用的是 `compact_secret_field`/`NewPassword`。截屏/录屏即可泄漏；且任何一次保存都会把输入框里的旧密码写回凭据库，若期间用 CLI 更新过同名凭据会被静默回滚。建议 `view` 不返回密码（或只返回「已保存」标记）、界面改用密码框、区分「未修改」不写回，并加「profile_get 响应不含 password」的测试。

### M17 环境备份被当成脱敏诊断显示

`Kind::EnvironmentBackup` 成功时把 tar 备份路径写进 `export_path`（`bootstrap.rs:658-660`），连接页把 `export_path` 一律渲染成「诊断已导出：{path}」，「打开报告位置」也 reveal 该路径（`diagnostics.rs:495-496,546-556`）。环境备份包含整个发行版文件，用户按「脱敏诊断」的认知分享出去就是隐私泄漏。建议备份用独立字段（已有 `backup_result_path`），连接页只认 `Kind::Export` 设置的值。

### M18 发布配置与新增源文件未入库，打包不校验 CRT

`.cargo/config.toml`（`crt-static`）和 `src/paths.rs` 在 `git status` 里都是 `??`：前者丢失会让 MSVC 默认动态 CRT 静默回归（正是本轮要修的 `VCRUNTIME140.dll` 依赖），后者丢失会让 clean clone 直接编译失败；`package-windows.py` 只验 PE 机型和哈希，不检查导入表，也不记录 CRT 模式。M5 文档已把这个未跟踪文件当作「仓库的」配置。建议把两者纳入版本控制，打包脚本解析两个 EXE 的导入表，拒绝 `VCRUNTIME140*.dll`/`api-ms-win-crt-*.dll`/`ucrtbase.dll` 并写进 build record。

### M19 打包脚本在 Windows 上按 locale 编码读 JSON

`scripts/package-windows.py:88,89,95` 用 `Path.read_text()` 无 encoding。本机（中文 Windows、Python 3.12）`locale.getencoding()` 是 cp936：对 UTF-8 中文内容会 `UnicodeDecodeError`；用 PowerShell 5.1 重定向生成的 UTF-16LE 或带 BOM 的 UTF-8 也解不动。`cargo metadata` 输出含依赖的非 ASCII 文本，Windows 原生发布流程会卡在这一步。建议显式 `encoding="utf-8"`（记录文件可用 `utf-8-sig`），并在 M5 给出 Windows 生成 build record / metadata 的确切命令与编码。

### M20 质量门槛与 HEAD 验收状态

`cargo clippy -- -D warnings` 在控制器（2 条，均为本轮新增代码）和桌面（8 条，含 4 类 lint）都失败；仓库没有 CI、没有 `rust-toolchain.toml`，门槛全靠人工，已经出现漂移。版本号已到 0.1.8，但 M5 记录仍是 0.1.1–0.1.3 的候选包，README 仍引用 0.1.3 的性能数据，没有 0.1.8 的安装/升级/实机记录；M4/M5 旧记录还把 WSL 交叉编译产物当交付依据，与 `AGENTS.md` 新规冲突。建议先修 clippy、补 0.1.8 的候选包与验收记录，再更新 README/M5 版本口径。

## 低严重度

| 编号 | 问题 | 位置 | 证据 |
|---|---|---|---|
| L1 | 域名白名单连接的记录目的地址是合成地址 `198.18.x.x`，不是真实直连 IP；M5 说记录「目的 IP 和端口」 | `src/ingress/tcp.rs:18-20`、`src/ingress.rs:966`、`src/desktop_store.rs:511-516` | 本人复核 |
| L2 | 失败命令的运行日志只有通用 code，无 phase/target/代次，也不记录 `controller_error` 的 message | `src/desktop_control.rs:180-191,238-244` | 本人复核 |
| L3 | 无内联状态的命令成功后再调一次 `controller.status()`；recovery_required 下等于再做一次最长 30 秒的 guest inspect | `src/desktop_control.rs:238-247,297-312` | 子审未复核 |
| L4 | 状态快照与转换日志不在同一事务：日志写失败后缓存不更新但下次同状态不再补写，可能永久缺一条转换日志 | `src/desktop_store.rs:337-392` | 本人复核 |
| L5 | daemon 退出前 `flush` 返回值被忽略、5 秒超时/阻塞 send 不计数，超时后已排队记录静默丢失 | `src/main.rs` daemon 分支、`src/ingress/flow_stats.rs:88-92` | 本人复核 |
| L6 | Known Folder 失败仍写成 `lock_known_folder_failed`，经 acquire 包装成 `lock_failed: lock_known_folder_failed: HRESULT ...`，误导排查 | `src/paths.rs:32-36` | 本人复核 |
| L7 | 连接记录写失败只加计数、错误被丢弃；无 `user_version`，`CREATE TABLE IF NOT EXISTS` 不修正不兼容旧表，届时每批 upsert 失败、记录永久静默丢失 | `src/desktop_store.rs:148-205,489-509,540-586` | 子审未复核 |
| L8 | UDP 阻断状态下每包仍 `chain_udp` +1、`rejected_udp` 不增，桌面把被拒 UDP 显示成「住宅链路」 | `src/ingress.rs:814-825,1024-1036`、`overview.rs:320-324` | 子审未复核 |
| L9 | 阻断态不是初始态：guest 规则装好后才探测，窗口内建成的链式 UDP 在探测失败后继续转发；探测最长 15 秒期间逐包 `chain_udp` 仍阻塞入口循环 | `src/controller.rs:117,140`、`src/managed.rs:153-157` | 子审未复核 |
| L10 | `flow_stats::ACTIVE_LIMIT=256` 已低于 v4 上限（64 TCP + 128 UDP + 64 DNS）+ IPv6 可达行数；超限静默 `pop_front` 活跃行，「活跃连接」少显示 | `src/ingress/flow_stats.rs:10,194-199` | 子审未复核 |
| L11 | 新增测试未覆盖入口层 UDP 阻断行为（不直连、DNS 不受影响、白名单 UDP 仍直连、IPv6 路径） | `src/ingress/tests.rs:539-585` | 子审未复核 |
| L12 | 桌面所有字段统一 `trim()`：住宅/环境密码首尾空格被静默删除（后端按原样接受空格） | `desktop/src/app/model.rs:303-308` | 子审未复核 |
| L13 | 概览健康卡只要 `status_valid` 就显示「入口已监听/工作线程已观测」，idle、recovery 也一样 | `overview.rs:85-100` | 子审未复核 |
| L14 | 设置页保存徽标用全局 `self.error`（策略页已改用 `save_error`），无关错误会让「保存失败」长期残留 | `views.rs:1922-1936` | 子审未复核 |
| L15 | 刷新列表后若已无选中目标，右侧仍显示已删除环境的详情和编辑/删除按钮 | `bootstrap.rs:745-749`、`actions.rs:474-490` | 子审未复核 |
| L16 | 环境页用 `selected`（候选）显示「当前目标」，与概览的 `active_target` 矛盾 | `views.rs:1190-1194,1403-1428`、`overview.rs:65-68` | 子审未复核 |
| L17 | 删除环境确认未提示会终止发行版里正在运行的程序（编辑/时区表单有提示） | `actions.rs:665-667` | 子审未复核 |
| L18 | 事件时间线第二/三条用硬编码「2 分钟」「5 分钟」，伪造事件时间 | `overview.rs:488-494` | 本人复核 |
| L19 | 环境/路径类错误码未映射（`environment_install_dir_*`、`environment_backup_*`、`environment_not_found` 等），落到泛化「操作失败，请重试。」 | `desktop/src/app/backend.rs:98-178` | 子审未复核 |
| L20 | `forwarding_scoped`（规则仍在生效）下 UDP 事实显红色「未确认」，与状态栏「诊断转发中」不一致 | `diagnostics.rs:485-493` | 子审未复核 |
| L21 | 旧审查 L3–L8 未变：`mark_mentions` 不识别 CONNMARK/nft；conntrack 8 秒期限早于 iptables 操作；安装许可用墙上时钟；本机 eth0 地址仍被引流；`probe.sh` 失败分支 `$workloads` 未赋值；`host.rs` 任一非法注册表子键仍使枚举失败 | `src/guest/kernel.py:548-568,839-845,303-331,413-416`、`src/guest/probe.sh:92-95`、`src/host.rs:127-129` | 子审未复核 |
| L22 | session 的 stdin 读错误（如非 UTF-8 行）仍 `?` 直接返回，跳过 EOF 停止 | `src/main.rs` 快照版（原 160-176 行） | 本人复核 |
| L23 | 管道服务端令牌完整性级别仍未检查；journal `persist` 不限长、`load` 只接受 16 KiB | `src/ipc/windows.rs`、`src/controller/journal.rs:33,43,52-63` | 子审未复核 |
| L24 | `CREATE_BREAKAWAY_FROM_JOB` 无回退：在禁止 breakaway 的作业对象里（SSH/计划任务/CI）daemon 和 lease worker 起不来 | `src/ipc/windows.rs:350-366`、`src/lease.rs:95-103` | 子审未复核 |

另有几条文档/发布类低严重度：

| 编号 | 问题 | 位置 |
|---|---|---|
| L25 | 对当前活动目标跑 `preflight` 会误报 `host_port_unavailable`（保留端口判断只覆盖「候选≠活动目标」） | `src/command.rs:216-237` |
| L26 | 「IPv6 自动探测成功 + 域名白名单」静态不兼容，但只在 `activate` 才拒绝；预检已 `passed` 后才失败 | `src/controller.rs:98-104` |
| L27 | `/etc/wsl.conf` 写入非原子（`cat > conf`）、BOM/UTF-16 认不出 `[boot]` 会追加重复节、改目标键会丢该行注释 | `src/environment.rs:174-214` |
| L28 | 查询冷启动给 30 秒预算、单查询 12 秒，但调用方 4 秒就超时；WSL 冷启动时第一批连接/查询必先失败一轮 | `src/query_bridge.rs:274-277`、`src/ingress.rs:56` |
| L29 | `environment.rs` 覆盖 wsl.conf 的保序/`sh -n` 测试都标 `#[cfg(unix)]`，在 `AGENTS.md` 规定的 Windows 最终验证里不会运行 | `src/environment.rs:838-917` |
| L30 | 打包测试用 `pack.TARGET` 自证、未断言 msvc；安装器 GNU/MSVC 矩阵仍无自动化测试；`build-desktop-windows.sh` 仍自称 native Windows release（与 AGENTS 冲突） | `scripts/test_package_windows.py:54,63-64`、`packaging/windows/common.ps1:119`、`scripts/build-desktop-windows.sh:2,157` |
| L31 | 文档不一致：M4:8「用户名/密码不显示在编辑器中」与设置页明文密码不符；M4:19 仍写连接记录「有界内存 256/128、5 分钟」（0.1.8 已改 SQLite 50,000）；M5:29 仍写非白名单 UDP「其余拒绝」（与 0.1.8 的 Associate 转发冲突）；`docs/discussions/desktop-gpui-optimization.md` 仍描述已删除的「对照 WSL」选择；`AGENTS.md:9` 提到的 `docs/contracts/` 不存在；M4「密码不显示在编辑器中」与现状不符 | `docs/plans/m4/README.md:19`、`docs/plans/m5/README.md:29`、`docs/discussions/desktop-gpui-optimization.md:39,46`、`AGENTS.md:9` |

## 旧发现状态

| 旧编号 | 现状 |
|---|---|
| **H1** | **回归，见 H1**：`d2e606f` 的修复被 `b03c97a` 删除 |
| H2（accept 遇 ConnectionReset 退出） | **已修**（`23f3b1c`）：`transient()` 已含 `ConnectionReset`（`src/ingress/tcp.rs:59-66`），accept 分支 `continue`（`src/ingress.rs:861-863`） |
| M1（切换中断 stop 依赖旧目标） | **部分修复**：改名/移动、注销后的两个阶段已放宽；「注册但 WSL 起不来」仍为死路，见 M7 |
| M2（remove 复用完整身份检查） | **部分修复**：已对 remove/inspect 放行 5 类 stale 错误；IPv6 三类未放行，见 M5 |
| M3（元数据查询阻塞入口） | **主体修复**：查询移到 metadata_lane 线程、传输错误冷却 30s→3s、入口等待 13s→4s；残留见 L3/M2/L28 |
| M4（合成地址只烧不回收） | **部分修复**：同名同 IP 跨会话复用、会话内回收、新增 CLI reset；但 reset 在桌面不可达（M13），`.pending` 时仍永久失败 |
| M5（AAAA/ipv6hint 借用别名） | **已修**（`96dfd8b`）：A/AAAA 映射、SVCB ipv6hint、响应含合成地址均拒绝 |
| M6（HTTPS 探测不证明双跳） | **已修**（`396ef7a`）：要求 `chain_tcp` 计数增长 |
| M7（TCP DNS 非阻塞） | **已修**：`serve_dns_tcp` 先 `set_nonblocking(false)` |
| M8（半关闭 15 秒绝对期限） | **已修**（`b4b2be1`）：改为「无进展 15 秒」静默期 |
| M9（lease/daemon 未脱离父作业） | **已修**：两处 spawn 均加 `CREATE_BREAKAWAY_FROM_JOB`（副作用见 L24） |
| L1（session stdin 读错误跳过 stop） | **未变**，见 L22 |
| L2（/proc 扫描漏 ProcessLookupError） | **已修**：同时捕获并复核 `os.path.exists` |
| L3–L8、L11–L12 | **未变或部分**：见 L21（L3/L4/L5/L6/L8）、L10（L11 相关）、L12 的 5ms 轮询仍在 |
| L9（异常应答不给 SERVFAIL） | **未变**：TTL 0、私网 IP、CNAME 形状异常仍整次失败 |
| L10（策略文件 BOM） | **已修**：`policy/profile.rs:53` 先剥 BOM |
| L13/N1（daemon 秒退空等 15s） | **已修**：子进程退出后读退出码，2 秒宽限后报 `ipc_daemon_exited_before_pipe: exit_code=3` |
| L14（管道完整性级别） | **未变**，见 L23 |
| L15（journal 长度不一致） | **未变**，见 L23 |
| L16/N4（`forwarding_scoped` 显示未接管） | **已修**：状态栏显示「诊断转发中」；残留连接页 UDP 显示，见 L20 |
| N2（认证失败强杀合法 daemon） | **已修**：先取管道服务端 PID，相同或取不到时只报错不杀 |
| N3（强杀后再等 15s） | **已修**：清理等待上限改为 3 秒 |
| N5（见证/对照术语混用） | **已消除**：界面两词均无；但文档仍描述旧选择（L31） |
| N6（路径条「未选择目标」） | **已修**：路径条移除，概览用 `active_target`，空值文案「无运行目标」 |
| 刷新列表回归 | **已修且保留** |
| 桌面 0 测试 | **已变**：新增 8 个测试，本次实际跑过全部通过 |

## 做得好的地方

- **归属判定和故障方向没有退步。** 数据面审查确认：住宅 UDP 探测失败后 v4/IPv6 链式 UDP 都是直接拒绝、没有直连兜底；白名单 UDP 仍直连；系统 DNS 不受 UDP 门闸影响；FlowSink 只做旁路记录；新增的验证测试覆盖了「探测失败后不联系两跳」。
- **前两轮的高危/中危大多真正修好了**，而且都有测试：accept 错误、TCP DNS 阻塞、半关闭期限、AAAA/ipv6hint、HTTPS 双跳证据、作业对象脱离、daemon 启动/清理竞态、DNS 别名跨会话复用。
- **测试与代码质量在提升。** 控制器 141 项测试、桌面 8 项测试、Python 63 项全部通过；`cargo fmt` 干净；MSVC release CLI 构建通过且静态 CRT 生效；transition 状态机（351 行）、DNS ledger、IPC 身份核验都有针对性测试。
- **存储与隐私设计克制。** 连接记录字段只有静态枚举、数字、`IP:port`、发行版名；诊断导出走白名单、完全不读 SQLite；队列 `try_send` 不阻塞转发；SQL 全部参数化。
- **安装器防御没有削弱。** 本次 GNU/MSVC 兼容分支只 +4 行，ACL/重解析点/事务 allowlist/`-Recover` 检查未动。

## 本次没有覆盖的

- **没有任何 Windows/WSL 实机测试**：旧内核 cgroup 匹配、IPv6 计划/guard 的触发场景、UDP 阻断的实际失败模式、accept/socket 错误码、SQLite WAL 在重定向卷上的行为、dpkg 半配置、环境操作实际耗时都只是代码级结论。
- **桌面交互未实机点按**：无真实桌面会话，未截图、未验证托盘/二次启动/弹窗叠放/窄窗口布局；并发重构后桌面测试当前无法编译。
- **发布链未实跑**：ZIP 生成、安装/升级/卸载/降级/`-Recover`、0.1.8 候选包、两 EXE 的完整导入表均未在 Windows 实机验证（release 目标目录被运行中的实例占用）。
- **没有做依赖漏洞扫描、许可证审查、性能测量**；没有审 `design/` 与 `docs/images` 一类视觉文件。

## 建议处理顺序

1. **H1 拍板**：恢复隔离自检，或登记「不验证跨发行版匹配」并同步改 m0/M5/架构/决策（不然后续所有验收都缺一个前提）。
2. **发布阻塞项**：把 `.cargo/config.toml`、`src/paths.rs` 纳入版本控制；修 `package-windows.py` 的编码；修 clippy 2+8 条；然后在 Windows 上重新跑 release 构建和 0.1.8 候选包。
3. **恢复死路**：M7（切换中断）、M8（WAL 硬要求）、M13（DNS 别名重置不可达）、M14（无重连入口）——这几项会直接把用户困住。
4. **可用性/隐私**：M9/M10/M11/M12（环境管理）、M15/M16/M17（桌面预检/密码/备份）、M1/M2（IPv6 UDP 与元数据容量）。
5. **文档并入**：按 L31 和开头「需要负责人拍板」的清单，由负责人把 0.1.8 的行为、IPv6 口径、连接记录、环境管理并进 `docs/arch`、`docs/decisions.md`、M4/M5 与 README；补 `docs/contracts/` 或删掉 AGENTS 里的引用。

## 附：审查期间工作区的并发修改

- 14:54:08 `src/desktop_store.rs` 加入 WAL（已纳入本审查，见 M8）。
- 15:01:56–15:02:35 出现「单二进制重构」：`src/lib.rs` 从 3 行扩成控制器的完整实现（含 `run_main`），`src/main.rs` 变成 5 行入口，`desktop/src/main.rs` 改为按参数分发到 `wsl_proxyctl::run_main()`，`src/ipc/windows.rs` 同步调整，`Cargo.toml` 的 `default-members` 改成 `desktop`。这部分**不在本审查范围**，且当前处于中间态：`cargo test -p wsl-proxy-desktop` 在 `src/host.rs:337`（`wsl_proxyctl::paths::state_dir()`）编译失败。若该重构继续，请以重构后的状态另行验证。
- 审查期间 `target\\release` 里的桌面与 daemon 进程（PID 612/12144）仍在运行，说明维护者可能同时在做手工验证；本次没有停止或干扰它们。
