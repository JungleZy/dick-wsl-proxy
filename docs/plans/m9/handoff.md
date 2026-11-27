# M9 第一期交接：按环境配置住宅代理

**结论：代码写完了，Windows 上编译、测试、后台冒烟、界面 U1–U8 和一次真实接管都通过。代码还没提交，在本地分支 `feat/per-environment-residential` 上。** 负责人的配置库已经迁成新格式，迁移前备份过。

做了什么、为什么这么做，见同目录的 [README.md](README.md)；这份只写接手的人要知道的现场状态和下一步。

## 现场状态

| 项 | 状态 |
|---|---|
| 分支 | `feat/per-environment-residential`，从 `main` 的 `50e4e76` 拉出；全部改动未提交，没推远程 |
| 改动 | `src/`（配置库、后台命令、命令行、控制器）、`desktop/src/app/`、`README.md`、`README.en.md`、`design/ui-design-spec.md`、新增 `docs/plans/m9/` |
| 没动 | `docs/arch/`、`docs/decisions.md`（实现里定下来的 10 条在 README.md「实现时定下来的事」，等负责人认可后再并进去） |
| `target\release\` | `wsl-proxyctl.exe`、`wsl-proxy-desktop.exe` 是这个分支编出来的新版本 |
| 配置库 | `target\release\desktop.sqlite` 已被新版本读过：旧住宅代理迁到 WSLProxyLab-Target（`{05312bc5-…}`），入口端口 43531；旧字段已清空 |
| 备份 | `target\release\desktop.sqlite.bak-0.1.17-20261127`，是迁移前的原样（同目录的 `-wal`、`-shm` 是只读打开它时 SQLite 生成的，可删） |
| 后台 | 已用 `shutdown_daemon` 关掉，没有 `wsl-proxyctl.exe`、`wsl-proxy-desktop.exe` 在运行 |
| 早先留下的 | 原型 worktree `D:\workspace\dick-wsl-proxy-nftlab`（分支 `lab/private-nft-tables`）、`D:\wpmlab` 实验文件、两个实验发行版里装的 `nftables` 包，都还在，等负责人决定去留。`D:\wpmlab\session.out` 里有住宅服务器地址，不要进仓库 |

## 已经验证的

- Windows：`cargo fmt --all --check`、`cargo clippy --locked --workspace --all-targets -- -D warnings`、`cargo test --locked --workspace`（控制器 303、库 29、桌面 109）、四个 Python 测试、`cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop` 全部通过。
- 后台冒烟：经 `rpc` 发桌面端的请求，迁移、按环境保存、修订号过期、端口冲突、启动前的修订号核对都按设计工作，明细见 README.md「后台冒烟」。

## 界面和真实接管（已完成）

U1–U8 已于 2026-11-27 08:11–08:19 做完，配置库记录（运行日志 id 326–334、连接记录 id 673–682、Target 那一行修订号 3）和截图（`D:\wpmlab\m9-ui\`）都与预期一致，明细见 README.md「界面与真实接管验证」。还没覆盖的见 README.md「验证之后还没覆盖的」。下一步是提交、开 PR。

## 你操作、我核对

你按下面的编号操作，做完回我一行，例如「U1 过，U2 过，U3 不过：保存后标签没消失」。我不靠你的描述下结论：每一步都会在配置库里留下记录，我自己去读，和预期对上才算过。

**基线（2026-11-27 08:06，后台已关）**：运行日志 `runtime_logs` 最大 id 是 325，连接记录 `connection_records` 最大 id 是 672；`environment_residential` 只有 Target 一行，修订号 1，入口端口 43531；后台空闲，操作代次 295。我只看比基线新的记录。

**截图**：只在你觉得界面不对时截，存到 `D:\wpmlab\m9-ui\`，文件名用编号（例如 `U3.png`）。环境卡片上的住宅代理密码是明文显示的，截图前先遮掉，或者只截出问题的那一块。

| 编号 | 你做什么 | 你回我什么 | 我去核对什么 |
|---|---|---|---|
| U1 | 打开 `target\release\wsl-proxy-desktop.exe`，到「环境」页点 WSLProxyLab-Target | 「接管」卡片里的协议、服务器、端口、入口端口是不是你原来那份；右上角状态标签写什么 | 预期：HTTP、原来的服务器和端口、入口端口 43531，标签「住宅代理已配置」。库里 Target 那一行没变（修订号仍是 1） |
| U2 | 点 WSLProxyLab-Control，再点回 Target | 换过去时输入框是不是空的、入口端口是不是空；换回来是不是又是 Target 那份 | 库里没有新行、没有新的保存日志 |
| U3 | 在 Target 卡片里把入口端口改成 43600，看到「有未保存修改」后点「保存住宅代理」；再改回 43531 保存一次 | 两次保存后有没有弹「住宅代理已保存」、标签是否消失 | 日志里两条「环境的住宅代理已保存到 SQLite」；Target 那一行修订号变成 3，入口端口回到 43531 |
| U4 | 打开设置页，再看首页，再右键托盘图标 | 设置页里还有没有住宅代理、入口端口；首页主按钮写什么；托盘主操作写什么 | 预期：设置页没有这两项；首页「去环境页」；托盘「打开环境页」。这一步库里没有记录，只靠你回的话和截图 |
| U5（要你同意） | 在 Target 卡片里点「检测住宅代理」并确认。直连那一路会把账号密码明文发出去 | 卡片上显示的结论 | 日志里一条 `residential_probe`「住宅代理检测：…」，结论要和你看到的一致 |
| U6（要你同意） | 在 Target 卡片里点「启动接管」，确认。会改 Target 的时区、重启它、结束里面所有程序 | 成功还是失败；失败的话错误条原文 | 日志里「已开始接管」，或者「启动接管失败（代码）」；我再用 `status` 看阶段是不是 `forwarding_managed`、目标是不是 Target |
| U7 | 接管中点 WSLProxyLab-Control | 它的「启动接管」是不是灰的，下面是不是写着要先停 Target；首页、托盘主操作写什么 | 预期：置灰并写明 Target；首页「停止接管」；托盘「停止全部接管」。库里不应出现 Control 的启动日志 |
| U8 | 在 Target 卡片里点「停止接管」，确认 | 成功还是失败 | 日志里「已停止接管并恢复直连」；`status` 回到 `idle`；接管期间的连接记录 id 大于 672、目标都是 Target |

U5、U6 你不想做就回「跳过」，我在记录里写明没测。任何一步不过，先别往下做，把那一步的结果发给我。

## 回退

- 只想回到 0.1.17：关掉新版本的后台和窗口，把 `desktop.sqlite.bak-0.1.17-20261127` 复制回 `desktop.sqlite`（先删掉 `desktop.sqlite-wal`、`desktop.sqlite-shm`，如果有），再用 0.1.17 的 EXE。新版本迁移后的库给 0.1.17 用，住宅代理是空的。
- 丢掉代码改动：`git switch main` 后删分支 `feat/per-environment-residential`（未提交的改动要先 `git stash` 或确认不要了）。

## 常用命令（在 WSL 里发到 Windows）

```bash
cd /mnt/d/workspace/dick-wsl-proxy
/mnt/c/Windows/System32/cmd.exe /c "cd /d D:\workspace\dick-wsl-proxy && cargo test --locked --workspace"
/mnt/c/Windows/System32/cmd.exe /c "cd /d D:\workspace\dick-wsl-proxy && cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop"
```

后台冒烟：先起后台 `target\release\wsl-proxyctl.exe daemon`，把一条 JSON 请求写进文件，再 `target\release\wsl-proxyctl.exe rpc < 请求文件`；测完发 `{"command":"shutdown_daemon"}`（只在空闲时接受）。`profile_get` 的回复里有住宅代理的用户名和密码，看输出时先遮掉。
