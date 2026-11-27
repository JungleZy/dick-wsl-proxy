# M9 · 按环境配置住宅代理（决策 40 第一期）

**结论：每个环境有自己的住宅代理和 Windows 入口端口，启动和停止挪到环境页；一次仍只能接管一个环境。** 代码在 Windows 上编译、单元测试通过；界面和真实接管 2026-11-27 在 Windows 上按 U1–U8 逐步点过（见「界面与真实接管验证」）。设计见[决策 40](../../decisions.md)和[讨论记录](../../discussions/2026-11-27-设计方案-多环境并行接管与按环境配置住宅代理.md)。

## 第一期做了什么

| 部分 | 现在的样子 |
|---|---|
| 配置库 | 新表 `environment_residential`，按发行版注册表 GUID（小写）一行：协议、服务器、端口、用户名、密码、入口端口、修订号。入口端口在表里唯一。旧库打开时建表，不改旧表。 |
| 共用配置 | `profile_save` 只存共用策略（代理链、DNS、规则、转发限制），不再带住宅代理、目标和端口；旧桌面端带着这些字段发来时整条请求被拒。 |
| 后台命令 | 新增 `environment_residential_save`、`environment_residential_assign`、`environment_residential_discard`；`residential_probe` 要带 `distro_id`，只检测那个环境，结果带环境的修订号和共用配置的修订号；删除环境时连带删掉它那一行。 |
| 启动 | `start` 不带端口时用这个环境保存的入口端口；住宅代理总是用目标自己的那一份。桌面端启动时除了共用配置的修订号，还要带 `residential_revision`，和库里这个环境的不一致就拒绝（`saved_environment_revision_required`）。 |
| 切换 | `switch` 从命令行、桌面通道和控制器里删掉。恢复记录里的 `Kind::Switch` 仍能读，旧版本留下的、被中断的切换照样能恢复。 |
| 桌面端 | 环境详情加「接管」卡片：住宅代理、入口端口、检测、启动 / 停止 / 恢复直连 / 放弃记录；列表每行显示接管状态，去掉「设为目标」。首页改成概览，主按钮在空闲时是「去环境页」。托盘主操作：空闲「打开环境页」，接管中「停止全部接管」，需要恢复「去恢复接管」（打开那个环境的页面），目标已注销「放弃本次记录」。设置页去掉住宅代理和入口端口。应用窗口的「直连上网」提示改为和后台实际接管的目标比较。 |

## 实现时定下来的事

以下几条和事先给负责人看的计划不完全一样，或者是计划里没写到的细节，待负责人确认后并进 `decisions.md` 和 `docs/arch/`：

1. **旧的那一份住宅代理怎么迁。** 后台列出发行版之后（桌面端读配置、命令行 `start` 用配置库时），按旧 `desktop_json.target` 找环境：名称完全相同或 GUID 不分大小写相同，且恰好一个。找到并且那个环境还没有自己的住宅代理，就连同旧入口端口（没被别的环境占用时）一起迁过去，清空旧字段和旧目标。找不到就原样留着，界面在环境详情里提示「还没分给任何环境」，让用户分给正在看的环境或丢弃。
2. **入口端口在第一次保存时分配，不是第一次启动时。** 规则：从 43531 起，取第一个库里没有别的环境占用的端口。只看配置库，不探测 Windows 上的端口；真被别的程序占着，由启动前的预检报出来。用户可以自己填，填了别的环境的端口会被拒绝（`ingress_port_in_use`）。
3. **`import-credential` 必须带 `--target`；`forget-credential` 的 `--target` 可选。** 带 `--target` 时清空那个环境的住宅代理（它正在接管或有恢复记录时拒绝）；不带时只丢弃未分配的那一份。计划里写的是两个都必须带。
4. **`chain-probe`（隐藏的实验诊断）也要带 `--target`**，用那个环境的住宅代理。
5. **命令行带 `--port`，或者 `--profile` 是策略文件时，不做第 1 条的迁移。** 策略文件不写端口时仍用 43531。
6. **环境页换到另一个环境时，上一个环境没保存的住宅代理修改会丢掉**，弹一条提醒说明。没有做「先保存再切换」的拦截。
7. **首页只显示正在接管（或需要恢复）的那一个环境**，不列出所有环境；空闲时只说有几个环境配好了住宅代理。
8. **在程序外注销的发行版，它那一行不会自动清掉。** 只有在桌面端删除环境时才连带删除。留下的行占着一个入口端口号，不影响别的功能。
9. **新装的程序要先在设置页保存一次**（共用配置修订号不能是 0），才能启动接管。这条沿用旧规则，只是以前保存设置时顺带保存了住宅代理，现在住宅代理在环境页单独保存。
10. **启动按钮的限制**：另一个环境正在接管或需要恢复时，环境页的「启动接管」置灰，下面写明要先停止哪一个。空闲闸门（环境操作要求当前没有接管）的范围第一期没动。

## 文件

| 位置 | 内容 |
|---|---|
| `src/desktop_store/environments.rs` | 新表、按环境读写、端口分配、旧数据迁移与分配 |
| `src/desktop_store.rs` | `save` 只存共用策略；`view` 带各环境的行和未分配的那一份 |
| `src/desktop_control.rs` | 新的三条后台命令、按环境检测、启动时的修订号核对、删除环境时连带删行 |
| `src/command.rs`、`src/managed.rs`、`src/policy.rs` | `start` 按环境取住宅代理和端口；删掉 `switch`；凭据命令加 `--target` |
| `src/controller/lifecycle.rs` | 删掉 `switch()`；恢复逻辑不变 |
| `desktop/src/app/drafts.rs`、`actions.rs`、`bootstrap.rs` | 环境页的草稿、保存、检测、启动；选中环境的同步 |
| `desktop/src/app/views.rs`、`overview.rs`、`tray/model.rs`、`island/model.rs` | 环境详情的「接管」卡片、列表状态、首页概览、托盘和状态岛的主操作 |

## 验证（2026-11-27，Windows 本机，同一份工作区代码）

- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings` 无告警。
- `cargo test --workspace`：控制器 303 项、库 29 项、桌面 109 项通过。新增的测试覆盖：按环境的行、修订号和端口唯一；旧数据按名称迁移和未分配时的分配、丢弃；启动只读自己的环境；桌面端发的三种新请求能被后台解析，旧桌面端带目标和端口的保存被拒，`switch` 已从桌面通道去掉；桌面端的保存请求、端口输入和按 ID 找行。
- `python src/guest/test_kernel.py`（107 项）、`test_https_probe.py`（4 项）、`test_kernel_env.py`（13 项）、`scripts/test_package_windows.py`（7 项）通过。
- `cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop` 通过。

## 后台冒烟（2026-11-27，`target\release` 里新编的 EXE，负责人自己的 0.1.17 配置库，先备份）

经 `wsl-proxyctl.exe rpc` 发桌面端会发的请求，不经界面：

- `profile_get`：旧的那一份住宅代理（HTTP）迁到了旧目标 WSLProxyLab-Target 的 GUID 下，入口端口沿用 43531；库里旧字段清空、旧目标变成 `null`；`unassigned_residential` 为空；回复里不再有 `desktop` 和 `residential`。
- 给 WSLProxyLab-Control 存一份虚构的住宅代理：第一次保存不带端口，分到 43532；同样请求再发一次报 `stale_environment_revision`；填 43531 报 `ingress_port_in_use`；填 80 报 `invalid_ingress_port`；服务器写成非 IPv4 报 `credential ip must be literal IPv4`。
- 旧桌面端带 `desktop` 的 `profile_save` 报 `invalid_desktop_profile_fields`；没有未分配住宅代理时 `environment_residential_assign` 报 `unassigned_residential_missing`。
- `start`：`residential_revision` 错或缺都报 `saved_environment_revision_required`，`profile_revision` 错报 `saved_profile_revision_required`；三次都在动手之前拒绝，操作代次停在 295，仍是空闲。`switch` 报 `command_not_available_on_desktop_channel`；`residential_probe` 不带 `distro_id` 报 `distro_id_required`。
- 测完用 `shutdown_daemon` 关掉后台，从库里删掉给 Control 存的那一行虚构数据。

## 界面与真实接管验证（2026-11-27，同一台 Windows，用这一版 `target\release` 的 EXE）

在负责人自己的配置库上按交接文档 U1–U8 实际操作桌面界面（合成点击），每一步截图核对，并对照数据库记录：

- U1：环境页打开 WSLProxyLab-Target，接管卡片显示迁移前的那份 HTTP 住宅代理（服务器、端口与备份一致）、入口端口 43531，右上角标签「住宅代理已配置」；库里那一行没变（修订号 1）。
- U2：切到 WSLProxyLab-Control，输入框和入口端口为空、启动接管置灰并提示「这个环境还没有保存住宅代理」；切回 Target 恢复原来那份；库里没有新行、没有新的保存日志。
- U3：入口端口改成 43600 保存，右上角弹出「住宅代理已保存；下次启动这个环境的接管时生效。」，「有未保存修改」消失；再改回 43531 保存。日志两条「环境的住宅代理已保存到 SQLite」（id 327、328），Target 那行修订号 3、入口端口 43531。
- U4：设置页「网络与 DNS」「转发限制」「桌面运行」都没有住宅代理和入口端口；首页主按钮「去环境页」；托盘头部「未接管」、主操作「打开环境页」。
- U5（经负责人同意）：检测住宅代理，结论「可直连，也可经宿主 SOCKS5」，两条路都「能连上，登录和转发都成功」；日志 id 329「住宅代理检测：直连和经宿主 SOCKS5 都能用」。
- U6（经负责人同意）：启动接管成功，日志 id 330–332（预检通过、已进入接管状态、已开始接管）；`runtime_state` 为 `forwarding_managed`、目标 `WSLProxyLab-Target`、操作代次 296；首页显示入口 172.28.80.1:43531 监听中、住宅出口 UDP 已阻断、系统 DNS 已接管。
- U7：接管中点 Control，「启动接管」置灰并写明「WSLProxyLab-Target 正在接管或需要恢复；一次只能接管一个环境，请先停止它」；首页主按钮「停止接管」；托盘头部「接管中 · WSLProxyLab-Target」、主操作「停止全部接管」；库里没有 Control 的启动日志。
- U8：停止接管成功，日志 id 333–334（当前处于空闲状态、已停止接管并恢复直连）；`runtime_state` 回到 `idle`、操作代次 297；接管期间的连接记录 id 673–682 全部指向 WSLProxyLab-Target（系统 DNS 3 条、fake-IP TCP 1 条、NTP UDP 6 条）。
- 验证后从托盘退出，应用窗口、状态岛和后台都关闭，`wsl-proxyctl.exe`、`wsl-proxy-desktop.exe` 没有残留进程。

## 验证之后还没覆盖的

- 「分给这个环境」「丢弃」只在单元测试里走过：真实库里的旧数据已自动迁走，没有剩下未分配的那一份。
- 迁移是单向的：新版本第一次读配置库后，旧字段被清空，再装回 0.1.17 会看到空的住宅代理。
- 一次只能接管一个环境（第一期范围）：多环境并行接管要等后续的设计。
- HTTP 上游时 UDP 的连接记录写成「双跳」的理由加失败，实际在 `policy.rs` 的 `associate()` 里直接拒绝、不发出任何字节（界面上的「UDP 已阻断」是对的）；记录的措辞要不要改成「拒绝」，留给负责人决定。
