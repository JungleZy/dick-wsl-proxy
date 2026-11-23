# M4：Windows GPUI 控制台

## 运行方式

将 `wsl-proxy-desktop.exe` 与同版本的 `wsl-proxyctl.exe` 放在同一个目录，运行桌面 EXE。窗口是 GPUI 原生渲染，不是浏览器页面。首次连接会以当前用户身份启动配套控制器的 `daemon` 模式；整个 UI 不需要以 Windows 管理员身份运行。

1. 在**总览**选择候选发行版和 Windows 业务入口端口。只选中目标不会接管网络。可先运行只读预检；失败时处理显示的能力缺项，程序不自行安装 WSL 软件。
2. 在**策略**填写宿主机已有 SOCKS5 入口、住宅凭据名称、DoH 上游的字面 IPv4:端口与 TLS 名称、健康检测域名及直连白名单。导入 `.env` 是一次明确操作：文件路径交给当前用户的本地后台，用户名/密码不显示在编辑器中。保存草稿不会改变正在运行的链路。
3. **显式保存策略**，回到总览确认启动。确认切换才开始释放当前目标。若另一个窗口修改了策略或接管代次已经变化，陈旧操作会被拒绝，而不是重新发送。根据后台返回的实际状态决定是否继续。
4. **连接与诊断**显示实际转发的活跃/最近连接、原目标、命中策略、累计字节与采样速率。普通 UDP 不支持双跳时显示拒绝，不算直连。出口地址不是 SOCKS 节点参数或 HTTPS 的对端地址；只有显式点击“检测出口”才从实际受管发行版访问 IPPure，并记录观测时间。DNS 就绪是有时间戳的探测结果，不表示所有域名在此后都一定可用。
5. **关窗不是停止。** 窗口可以关闭和重新打开，后台继续持有当前目标与规则。需要恢复原网时，明确确认“停止并恢复直连”。后台在状态未知或需要恢复时不会因为 UI 退出而放行。无法从 GUI 停止时，用下述命令查询或恢复。

## 后台与故障边界

- `wsl-proxyctl.exe session` 仍是 CLI 自己持锁的前台模式，EOF 保留原有的正常停止语义。桌面使用独立的命名管道后台，两者不能同时拥有同一个用户的网络控制权。已有 CLI 会话时不要强杀它来启动桌面；先在原会话中正常停止并退出。
- 窗口与后台通过仅当前用户、本机可连接的命名管道交换有界 JSON。客户端在发送请求前核对服务端进程的用户和配套 EXE 身份。读写有时限，未确认的变更不会因窗口断连被自动重放。拿不到状态时应显示未知，并重新读取后台，而不是使用过期绿色状态。
- 关闭窗口后也能在同目录 PowerShell 调用：`'{"command":"status"}' | .\wsl-proxyctl.exe rpc`。要主动停止，将状态中的实际 `operation_generation` 带入 `{"command":"stop","expected_generation":…}`。正常恢复至 `idle` 后，发送 `{"command":"shutdown_daemon"}` 可退出后台，便于替换 EXE。不能带着活动规则退出后台；如果后台已崩溃，沿用 [M3 的独立恢复流程](../m3/README.md)，不手删恢复日志；目标已被注销时，用概览页「放弃本次记录」，之后执行一次 `wsl --shutdown`。
- EXE 所在目录带有 Windows「低完整性」强制标签时（例如被开发工具沙箱标记的工作目录），系统以 Low 级别启动其中的程序，双击时还会弹「无法验证发布者」的安全警告。Low 级别的后台打不开 LocalAppData 中的锁文件，托盘图标也无法注册，所以桌面 EXE 启动时一旦检测到自身低于普通用户级别，就弹框说明原因和所在目录，然后直接退出，不占用单实例锁。处理方法：将两件 EXE 一起复制到不带该标签的目录运行，或移除目录标签；不需要以管理员身份运行。
- 桌面草稿在 EXE 同级目录的 `desktop.sqlite`，含策略、选择和版本，不含住宅密码。保存操作使用版本比较避免覆盖另一窗口的修改。脱敏诊断同样导出到 EXE 同级目录（`diagnostics-<时间>.json`），只保留状态与数值计数，不导出原始请求正文、目的地址、域名、凭据引用或任意错误全文。住宅凭据写入 Windows Credential Manager。
- 程序运行产生的其他文件也放在 EXE 同级目录：环境新建/编辑的进度文件 `environment-progress-<名称>.json`，以及和 `wsl.exe` 交换输入输出的临时文件 `io-*.tmp`（关闭即删）。EXE 所在目录必须可写，否则配置库和 WSL 调用都会失败，错误信息里带出该目录。
- 早先版本把 `desktop.sqlite` 放在当前用户 LocalAppData 的 `WSLProxyLab` 下。新版后台第一次打开配置库时，若 EXE 旁边还没有配置库，就把旧库（含未合并的 WAL 内容）整理复制过来，落盘后再删除旧文件；迁移失败直接报错并给出旧文件路径，不会换成空配置库继续。EXE 旁边已有配置库时不再迁移，也不覆盖。
- 以下文件仍按 Windows 账户放在 LocalAppData 的 `WSLProxyLab`，不跟程序文件夹走：控制锁 `controller.lock`、恢复记录 `m1-active.json` 与 `m3-operation.json`、DNS 别名账本 `dns-alias.*`。它们保证每个账户只有一个控制器，并且崩溃恢复和别名分配不会因为换了文件夹运行而丢失或被悄悄重置。主题偏好和开机自启在注册表 `HKCU`，住宅密码在 Credential Manager，都不是文件。
- 连接记录是有界的内存数据，不是抓包：最多 256 条活跃、128 条近期记录；近期保留 5 分钟。`tx`/`rx` 是入口实际处理的传输字节；速率是两次采样的增量，不是线路测速。无内核映射时不虚构目标或域名。

## 构建

- 原生 Windows：准备 Rust 和 GPUI 所需的 Windows 构建工具，执行 `cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop`。两件产物位于同一 `target\release`。仓库默认 Cargo 成员仍是控制器，构建 CLI 无需编译 GPUI。
- WSL 交叉构建：使用 [隔离构建脚本](../../../scripts/build-desktop-windows.sh)，环境要求见 `--help`。脚本只修正临时 GPUI 源副本对宿主平台的编译开关，使用 Windows 自带的 Direct3D HLSL 编译器生成真实 shader 字节码，不修改 Cargo 注册表、仓库锁文件或 Windows 全局工具链。产物是 Windows x64 EXE；这不是安装包或已签名的发布渠道。

## 本机原生验收

交付目录：`D:\WSL\ProxyLab\m4-lab\final\`。两件需放在同一目录，启动 `wsl-proxy-desktop.exe`。本机使用 WSL 交叉构建的 Windows x64 release；桌面 SHA-256 `626ff6cad62c6b51a8126360e35d4739a470dd40b68d7849d4f9e162cebcd935`，后台 `466c23b76c9bd7b2d1612dbc320e0fc05852fe71c42eb17f28e0b4599dc2fbdf`。

| 实际操作 | 证据与边界 |
|---|---|
| 打开窗口、选择和保存 | 原生 HWND 显示中文总览、策略和连接诊断。通过窗口选择 Target 与 Control、编辑非秘密字段并显式保存。实测凭据导入走同目录 CLI 的 IPC，没有用原生文件选择器导入真实秘密。 |
| 启动与关窗 | GUI 启动确认后，实际目标为 `WSLProxyLab-Target`，操作代次 17，DNS 已受管。仅关闭该窗口后，独立 `status` 仍报告 `forwarding_managed`、同一目标和代次。预先运行的 Target 服务此时完成一次新的住宅出口 HTTPS 200，Control 仍是原出口。Target 的另一次请求连接被重置，保留该失败。 |
| 重新打开 | 新窗口重新取得后台目标和代次 17，并显示真实 DNS、业务连接、规则结果及字节数。UI 发起了显式出口探测与脱敏报告导出，不把导出文件当作完整流量日志。 |
| 取消 / 停止 | 在窗口打开停止确认后取消，接管继续；再次打开并确认，进入 `idle`（18）。32 项恢复比较一致。原 `.env` 未修改，临时凭据、策略、实验服务和监听均已清理。`kernel/cleanup.json` 记录 5 个新增模块完整移除且未卸载任何基线模块，两组 DNS、路由及受测表/规则与本轮基线相符。 |

`qa/01-native-bootstrap.png`、`qa/08-reopened-active.png`、`qa/09-real-diagnostics.png` 和 `qa/11-ui-stopped-idle.png` 是实际窗口截图，`qa/frontend-closed-status.json` 及 `frontend-closed-pulse-*` 是关窗期间证据。第一次冷预检拒绝、一次 WSL 启动超时均未跳过检查、未自动重放修改。完整的活跃接管轮使用 `qa/delivery` 双件；交付版额外校正了未保存/未连接提示和同端口切换预检，不能把 M3 的 CLI 双向切换记录写成 M4 的 GUI 双向实测。

交付目录 `final` 的双件另做了空闲态实机冒烟：实际窗口截图见 `qa/final-release-idle.png`；关闭窗口后，同目录 RPC 仍返回 `idle`、代次 18；随后显式关闭空闲后台，无剩余进程，未重新创建测试策略。见 `qa/final-release-after-close-status.json` 和 `qa/final-release-cleanup.json`。

完整验收汇总见 `qa/acceptance-summary.json`。关窗再打开后，后台累计收发字节从 797/5,552 增至 2,732/15,329，并显示 35 条近期连接。主动出口探测确认 `matches_residential=true`，导出的诊断中未找到导入的 IP、用户名或密码。活跃态的连续性由目标、代次及实际服务请求证明，未直接记录活跃后台的 PID 连续性。本轮对 Control 的候选预检被拒，Target 未改变；**没有执行 GUI 切换命令或切换确认**。停止确认的取消与执行均已实测。

测试：控制器主程序 82 项、可移植 IPC 5 项通过；Windows 原生 IPC 9 项通过，含拒绝不匹配的服务端映像、客户端提前断开、半包与超时。发布打包、签名、升级/卸载回归和更广泛平台兼容仍属于 M5。
