# M6 · 冷启动内核环境准备

**结论：桌面端增加一次显式的「准备内核环境」操作。** 它只加载目标发行版自带的模块、注册空的 filter/nat 表，并把同样的准备写成开机配置（模块列表与空表 oneshot），不安装软件、不写规则；预检仍然只读。设计边界已并入[接管架构](../../arch/README.md)与[决策 14、15](../../decisions.md)。

## 背景

[M3 记录](../m3/README.md)写过：冷启动后的共享内核没有注册所需的 cgroup 匹配和 NAT 表，第一次预检按设计拒绝；当时由维护者手动加载磁盘上已有的模块。界面只显示 `capability.*`、`baseline.*` 阻断码，用户无法在应用内恢复，每次 WSL 重启后都会再次遇到。M6 把这个人工步骤做成显式、可审计的应用操作。

## 操作边界

| 会做 | 不会做 |
|---|---|
| 按固定顺序加载 12 个模块：`ip_tables`、`iptable_filter`、`iptable_nat`、`ip6_tables`、`ip6table_filter`、`ip6table_nat`、`xt_cgroup`、`xt_connmark`、`xt_conntrack`、`xt_comment`、`xt_mark`、`xt_nat`。 | 不安装软件包，不下载或编译模块，不改 `.wslconfig`；除下面两个开机文件及其 enable 链接外，不改发行版持久配置。 |
| 只看 `/lib/modules/<release>`：已加载或 `modules.builtin` 中内建的跳过；其余先用 `modprobe -n` 证明可加载，再 `modprobe`。 | 不使用 `--force`，不卸载任何模块，不重试失败项。 |
| 对缺失的 IPv4/IPv6 `filter`、`nat` 各执行一次对应的 `iptables-legacy` / `ip6tables-legacy -t <table> -S`（只读转储），让内核注册空表。 | 不 flush、不增删规则、不碰已有表；转储内容不落日志。 |
| 写入并启用开机配置：`/etc/modules-load.d/wsl-proxy.conf`（只列本次证明可用的模块，直接覆盖同名旧文件、不留备份；早期版本会留 `.bak-*` 备份，不会自动清理）和 `/etc/systemd/system/wsl-proxy-tables.service`（oneshot，开机执行同样四条 `-S` 查询、标准输出/错误丢弃）。 | 不写常驻服务、代理、凭据或计划任务；unit 失败不会让目标发行版进入 degraded，预检会重新报缺少能力。 |
| 只在控制器 `idle`、且没有安装 journal 或待完成切换时执行；桌面端先确认。 | 不在接管中执行，不在预检里隐式执行，不启动接管。 |

影响的是同一 WSL 内核上的所有发行版；模块常驻、空表保留默认 ACCEPT 策略。开机配置保存在目标发行版里，WSL 重启后由 `systemd-modules-load` 和这个 oneshot 重新加载/注册，不需要再次确认。

## 契约

```powershell
wsl-proxyctl.exe prepare-kernel Target --confirm
```

桌面端通过同一后台的 RPC 发送 `{"command":"prepare_kernel","target":"<名称或 GUID>","confirm":true}`。

响应：

| 字段 | 内容 |
|---|---|
| `preparation.ok` | 操作本身是否执行；模块不可用不算执行失败，记在 `modules_failed`。 |
| `preparation.kernel_release` / `boot_id` / `netns` / `modules_dir` | 本次影响的共享内核证据。 |
| `preparation.modules_required` / `modules_before` / `modules_added` / `modules_failed` | 固定模块集与前后状态；失败项带截断原因。 |
| `preparation.tables` | `before`、`after`、`added`（按 v4/v6），并校验 `added = after − before`。 |
| `preparation.table_failures` | 表注册失败的 family/table/原因。 |
| `preparation.autoload` | `/etc/modules-load.d/wsl-proxy.conf` 的路径、模块列表、是否写入与错误；`backup` 字段保留，恒为空。 |
| `preparation.boot_unit` | `/etc/systemd/system/wsl-proxy-tables.service` 的路径、是否写入、是否已 `systemctl enable` 与错误。 |
| `record_path` / `record_error` | 准备记录写入 `%LOCALAPPDATA%\WSLProxyLab\kernel-env.json` 的结果。 |
| `blockers` / `inspection_error` | 准备后重新运行只读预检的阻断项（不含入口端口检查）。 |

拒绝码：`confirmation_required`、`kernel_prepare_requires_idle`、`target_already_owned`、`kernel_prepare_failed`。guest 脚本固定、不接收请求数据；Windows 侧严格校验字段、模块名、表名与前后关系，缺少证据字段的响应不会被当成「无需准备」。

## 界面

- 用户点「启动接管」后预检失败，且阻断项属于内核能力时，弹出确认框询问是否加载目标已有的模块；确认框说明会加载什么、会写入哪两个开机文件（并说明可手工删除）、影响共享内核，以及不做什么。取消则提示缺少这些能力无法启动，不保留按钮。
- 同一次启动尝试只询问一次；确认后自动重跑预检，通过就接着弹启动确认，不再要求用户重新点启动。非内核能力的阻断照旧直接列出。「切换目标」时旧目标还在接管、不能加载模块，只列出阻断项并提示先停止当前接管。
- 执行期间沿用写操作的忙碌状态；完成后刷新状态、清空旧预检结果，并在通知和运行日志中给出新增模块、失败模块与剩余阻断项数量。

## 验证（2026-11-24，Windows 本机）

- `cargo test --locked`：183 项控制器单测、9 项 IPC 通过；guest 纯逻辑 `src/guest/test_kernel_env.py`：12 项通过（Windows Python，不启动 WSL）；CLI 的 clippy `-D warnings` 通过。
- 桌面 crate 的测试与 release 构建在本轮未能复跑：工作区同时存在另一项未完成的改动（新增的 `Kind::WslPlatform`/`WslUpdate` 等还没有 match 分支），桌面 crate 暂时无法编译。该并行改动与本功能无关，因此「开机自动加载」的通知文案没有桌面测试结果。
- 实机 Target（`6.18.58.1-microsoft-standard-WSL2`，netns `net:[4026531833]`）：
  1. 用 `rmmod` 卸载 `xt_cgroup`、`xt_connmark`、`ip6table_filter`、`ip6table_nat`、`ip6_tables`，模拟冷内核；WSL `/init` 预载的 IPv4 `iptable_filter`/`iptable_nat` 保留。
  2. `preflight Target` 拒绝，7 个阻断项：`capability.kernel.module.xt_cgroup.unverified`、`capability.kernel.module.ip6table_nat.unverified`、`capability.kernel.matches_v4.cgroup.unverified`、`capability.kernel.matches_v6.cgroup.unverified`、`capability.kernel.targets_v6.DNAT.unverified`、`capability.kernel.tables_v6.nat.unverified`、`baseline.ip6tables_legacy.unavailable`。
  3. `prepare-kernel Target --confirm` 退出 0：新增 `ip6_tables`、`ip6table_filter`、`ip6table_nat`、`xt_cgroup`、`xt_connmark`，注册 IPv6 `filter`/`nat`，`blockers: []`；记录文件包含目标、`boot_id`、`netns` 与准备前后的模块/表。
  4. 随后 `preflight Target` 通过；再次执行准备新增为 0；不带 `--confirm` 被拒绝。
  5. 通过运行中的后台走 RPC 同名请求，结果一致；运行日志记录「新增 0 个模块…剩余 0 个阻断项」；`shutdown_daemon` 正常退出。新桌面二进制也做过启动冒烟：它拉起后台，`status` 返回 `idle`；随后停止后台并结束窗口进程，没有残留进程。
- 开机自动加载实测（CLI）：`prepare-kernel Target --confirm` 写入并启用两个开机文件后，`rmmod` 五个模块、`wsl --terminate Target`；从另一个发行版确认模块与 IPv6 表已消失；`preflight Target` 通过（0 阻断），`systemctl show wsl-proxy-tables.service -p Result` 为 `success`，v4/v6 的 `filter`、`nat` 均为已注册空表。准备结果里的 `autoload.written`、`boot_unit.written`、`boot_unit.enabled` 均为真。
- 入口从常驻按钮改为「预检失败时询问」后：桌面单测覆盖只对空闲启动询问、同一次尝试只问一次、切换不询问，以及真实冷内核产生的 7 个阻断项；确认框、自动重跑和启动确认的串联没有人工点击验证。
- 首轮 E2E 发现 Windows 校验把固定模块顺序误判为「未排序」，准备已执行但命令报错；修正为只要求去重后重跑，以上是修正后的结果。

**未覆盖：** 真实 Windows 重启或 `wsl --shutdown` 后的首次启动（本轮只重启了目标发行版，没有重启共享 WSL 虚拟机）；没有 `/usr/bin/python3`、没有 `/lib/modules`、模块签名被拒或禁用 systemd 的发行版；已有外部规则的表；桌面窗口的人工点击与截图。这些环境下的行为只能按代码与错误码推断，不能当作已实机验证。

## 后续

- 发行版没有模块文件时，本操作只能报告不可用；要补齐需要安装或构建内核模块，属于另一项决定。
- 不需要开机自动加载时，删除 `/etc/modules-load.d/wsl-proxy.conf` 与 `/etc/systemd/system/wsl-proxy-tables.service`，再执行 `systemctl disable wsl-proxy-tables.service`；下次启动起恢复为「预检失败时询问」。
- 开机 unit 只做只读查询并忽略失败；如果以后内核不再提供某个模块，预检仍会报缺少能力并回到询问流程。
