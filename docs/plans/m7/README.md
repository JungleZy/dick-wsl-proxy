# M7 · WSL 平台检查与显式升级

**结论：设置页增加「WSL 平台」卡片。** 它只读报告 `wsl.exe` 版本、WSL2 内核、默认版本、已注册发行版和当前进程权限，并提供一次显式的 `wsl --update` 升级。检查只运行 `wsl.exe` 的只读子命令并读注册表，不启动发行版、不写规则；升级只在没有接管时可用、必须确认，按版本前后的实际变化报告结果。发行版本身仍在「环境」页新建、编辑、备份和删除。

## 背景

桌面端此前只能管理发行版：创建、编辑、备份、删除（决策 12），冷启动内核准备另见 [M6](../m6/README.md)。用户看不到 `wsl.exe` 本体的版本与内核，也没有升级入口；当安装发行版遇到旧版 WSL 拒绝 `--location` 时，只能从错误提示里得到一句「请运行 wsl --update」。WSL 平台的版本还直接决定预检能否看到所需能力，因此把它作为一个只读检查加在设置页。

## 操作边界

| 会做 | 不会做 |
|---|---|
| 运行 `wsl --version`、`wsl --status`，读 `HKCU\…\Lxss` 下的发行版列表和当前进程令牌的提权标志；全部只读。 | 不启动发行版（`wsl --version`/`--status` 不启动任何发行版）、不改默认发行版或默认版本、不转换发行版的 WSL 版本。 |
| 升级运行 `wsl --update`（上限 30 分钟），只替换 WSL 包。 | 不 `--web-download`、不设置 `.wslconfig`、不安装发行版里的软件、不改 `/etc`、不卸载 WSL。 |
| 只在控制器 `idle`、没有恢复记录、没有待完成切换时执行升级，并要求显式确认。 | 不在接管中执行，不在检查里隐式升级，不自动提权。 |
| 用 `wsl --version` 前后的实际版本差判断是否升级成功，命令输出只作末尾原文回报。 | 不解析本地化的命令输出来判定结果；不猜测「有新版本可升」。 |

检查项固定为四项，代码与界面措辞分开：

| 代码 | `blocker` | `warning` |
|---|---|---|
| `wsl.executable` | 没有找到 `wsl.exe` | — |
| `wsl.version_supported` | `wsl --version` 不可用（旧版 WSL） | — |
| `wsl.default_version_2` | — | 默认版本是 WSL 1，或没有读到默认版本 |
| `wsl.no_wsl1_distribution` | — | 有发行版是 WSL 1（不能作为接管目标），`detail` 列出名称 |

## 契约

```powershell
# 只读：不启动发行版，不落规则
wsl-proxyctl.exe wsl-platform

# 升级：替换 WSL 包并可能重启 WSL，需要空闲和确认
wsl-proxyctl.exe wsl-platform-update --confirm
```

桌面端通过同一后台的 RPC 使用 `{"command":"wsl_platform"}` 和 `{"command":"wsl_platform_update","confirm":true}`。升级与发行版操作一样返回 `job`，结果从 `{"command":"environment_job"}` 取。

检查响应：

| 字段 | 内容 |
|---|---|
| `wsl.executable` / `installed` | 解析到的 `wsl.exe` 路径与是否存在 |
| `wsl.version_supported` | `wsl --version` 是否可用；`version_error` 是失败原因 |
| `wsl.version` / `kernel_version` / `windows_version` | 按固定行序和值的形状识别：第一行是 WSL 版本，第二行是内核版本，`10.0.` 开头的是 Windows 版本 |
| `defaults.version` / `defaults.distribution` / `status_error` | `wsl --status` 的值：默认发行版按已注册名称匹配，默认版本只接受 `1`/`2` |
| `distributions` / `wsl1` | 已注册发行版及其版本；WSL1 的名称列表 |
| `elevated` | 当前后台进程是否带提权标志（只用于提示升级时可能弹出管理员确认） |
| `checks` / `blockers` / `warnings` | 上面四项检查的 `code`、`level`、`detail` |
| `checked_at_unix_seconds` | 本次检查的时刻 |

升级响应：

| 字段 | 内容 |
|---|---|
| `before` / `after` | 升级前后读到的 WSL 版本与内核版本 |
| `updated` | 版本或内核是否真的变了 |
| `elevated` | 执行时的提权状态 |
| `output` | `wsl --update` 输出的末尾一段（去掉进度回车和空行，最多 2000 字符），不参与判定 |
| `checked_at_unix_seconds` | 升级完成的时刻 |

拒绝码：`confirmation_required`、`wsl_update_requires_idle`、`target_already_owned`（有恢复记录或待完成切换）、`wsl_not_installed`、`wsl_update_failed`、`wsl_platform_failed`。`wsl_update_failed` 只出现在 CLI；经 RPC 时外层是 `desktop_request_failed`，内层是 `wsl_update_command_failed:…` 或 `wsl_not_installed`。升级期间后台拒绝启动、切换、预检、内核准备、出口检测、关闭后台和其他环境操作。

## 界面

- 设置页新增「WSL 平台」卡片：状态徽标（尚未检查 / 检查中 / 需要处理 / 有提醒 / 正常 / 检查失败）、`WSL 版本`、`WSL2 内核`、`Windows 版本`、`wsl.exe`、`默认版本`、`默认发行版`、`发行版 N 个（M 个 WSL1）`、`权限`，四项检查说明，上次升级结果，以及一段说明：检查只读、升级会替换 WSL 包并可能重启 WSL。
- 进入设置页时自动做一次静默检查：不占用界面、不弹加载框、不覆盖页面提示，也不进全局错误条；卡片自己的徽标显示「检查中」，失败只写在卡片里。「检查」按钮重新检查。
- 「升级 WSL」在空闲、没有其他操作时可用；只有检查结果明确说 `wsl.exe` 未安装时才禁用，没检查过或检查失败时仍可点。确认框说明会替换 WSL 包、可能重启 WSL（所有发行版里的程序和后台服务都会停止）、最多等 30 分钟（超时会结束 `wsl --update`，WSL 可能停在升级到一半）、等待期间不要关闭程序、退出后台或做别的环境操作、失败或没看到结果时用 `wsl --version` 核对，标准用户运行时还提示可能弹出管理员权限提示；确认后走后台环境任务：加载框 → 结果对话框 → 自动重新检查，卡片显示升级后的版本。
- 升级失败同时进全局错误条和结果对话框，卡片内保留上一次检查结果；运行日志的来源统一为 `wsl`：成功记「WSL 已升级：A → B」「WSL 已是最新」「无法确认是否升级」，失败记一条错误级别记录，原因见结果对话框。

## 验证（2026-11-24，Windows 本机）

- `cargo test --locked`：184 项控制器单测（含 `wsl_platform` 的 6 项：中英文版本输出、缺失内核行不拿别的行顶替、状态值解析、输出截断）与 9 项 IPC 测试通过；`cargo test -p wsl-proxy-desktop --locked`：24 项通过（含徽标、检查说明、升级说明、升级失败说明 4 项）。
- 两个 crate 的 `cargo clippy --locked --all-targets -- -D warnings` 无告警；`cargo fmt --all -- --check` 通过；`cargo build --release --locked` 产出 CLI 与桌面两件。
- 实机（WSL `3.0.5.0`，内核 `6.18.58.1-1`，Windows `10.0.26300.9974`，标准用户）`wsl-platform` 输出：默认版本 2、默认发行版 `Ubuntu-24.04`、3 个发行版均为 WSL2、`elevated: false`、`blockers`/`warnings` 为空。通过运行中的后台发同名 RPC 请求结果一致。
- 不带 `confirm` 的 `wsl_platform_update` 被拒绝（`confirmation_required`），没有执行命令；`shutdown_daemon` 正常退出。
- 桌面启动冒烟：拉起后台、写入/更新 `desktop.sqlite`、窗口进程结束后后台照常；随后通过 RPC 关闭后台，没有残留进程。
- 桌面实机（UI Automation 驱动 + 窗口截图）：打开「设置」页后卡片自动完成一次静默检查（不弹加载框），显示「正常 / 刚刚检查」、`WSL 3.0.5.0`、内核 `6.18.58.1-1`、Windows `10.0.26300.9974`、默认 `WSL 2` / `Ubuntu-24.04`、`3 个（0 个 WSL1）`、`标准用户（升级时可能要确认管理员权限）`，四项检查均通过；「升级 WSL」在空闲时可用，确认框显示当前 WSL 版本、会替换 WSL 包并可能重启 WSL、标准用户可能出现管理员提示；点「取消」后没有执行任何命令。
- 真实升级尝试（经维护者同意，11:20–11:25）：在桌面点「升级 WSL」并确认，后台 3–5 秒后拿到 `wsl --update` 的失败：`exit code: 0xffffffff`、`Wsl/UpdatePackage/HTTP_E_STATUS_FORBIDDEN`（输出里的「正在检查更新。已禁止(403)」），WSL 版本仍是 `3.0.5.0`，运行中的发行版没有被终止。桌面按失败处理：结果对话框和全局错误条显示「升级 WSL 失败：<wsl 原文> 请检查网络、Windows 更新和权限；也可以在以管理员身份打开的终端里运行 wsl --update，或用 wsl --update --web-download 从 GitHub 下载更新。」，卡片保留上一次检查结果，运行日志记一条 `error`、来源 `wsl`。同一台机器上直接运行 `wsl --update` 得到同样的 403，说明是本机到 Store 更新端点的网络/策略限制，不是程序把命令跑错。
- 提权对照（11:31）：用 `Start-Process -Verb RunAs` 在 High Mandatory Level（`S-1-16-12288`）下再执行一次 `wsl --update`，得到同样的 `Wsl/UpdatePackage/HTTP_E_STATUS_FORBIDDEN` 与 `exit -1`，版本仍是 `3.0.5.0`。所以这个 403 与是否管理员无关；本机 `ConsentPromptBehaviorAdmin=0`（从不通知），提权时没有弹 UAC。同一时间 Store 目录接口与 Windows Update 端点分别直连、经本机代理 `127.0.0.1:7892` 访问的状态码一致（200 / 400），没有 403，说明本机代理没有拦截这些域名。

**未覆盖：** 升级成功的那条路径——下载、安装、重启 WSL、版本变化——没有验证：本机 `wsl --update` 在检查阶段就被 403 拒绝（直接运行也一样），只能确认失败处理正确；「已是最新」和升级成功后的结果对话框与卡片文案只在单测里覆盖。只用带 `--version` 的 WSL 3.0.5.0 验证；旧版 WSL（无 `--version`）、有 WSL1 发行版、`wsl.exe` 缺失、管理员与标准用户两种提示下的真实行为都未验证。接管中「升级 WSL」按钮的禁用状态按代码推断，没有在真实接管时截图。

## 后续

- 升级成功的路径仍未验证：需要在能访问 Store 更新端点的网络里再跑一次，补记下载、安装、重启和版本变化的结果。本机 403 的绕行办法是 `wsl --update --web-download`（从 GitHub 下载，不走 Store 更新通道）、从 Microsoft Store 更新，或换网络重试；提权不能解决。
- 长期保留这个入口已登记为[决策 26](../../decisions.md)。
- `wsl --update` 是否需要管理员权限取决于 WSL 的安装方式；当前不主动提权，失败时把原因和「在管理员终端运行 wsl --update」交给用户。若以后确实遇到只差提权的失败，再考虑「以管理员身份重试」：由桌面用 `runas` 启动一个只执行 `wsl --update` 的提权子进程，而不是让整个界面以管理员运行。
