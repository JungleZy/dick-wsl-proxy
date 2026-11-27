# M10 交接：多环境并行接管（第二期）

**结论：第二期三段的代码都写完了，Windows 上编译、测试都通过。后台已用两个环境、两个不同的住宅代理真实同时接管过；桌面端的多环境界面还没实际点过。代码提交在本地分支 `feat/private-nft-tables`，没推送，没合进 main。**

做了什么、为什么这么做，见同目录的 [README.md](README.md)。这份只写接手的人要知道的现场状态，以及界面要怎么点、点完我怎么核对。

## 现场状态

| 项 | 状态 |
|---|---|
| 分支 | `feat/private-nft-tables`，从 main 的 `73b9f75` 拉出，三个提交：`5e7eeee`（第一段，独立 nft 表）、`9965917`（第二段，一个后台管多个接管）、`7df27ac`（第三段，桌面端多环境界面）。没推送。 |
| `target\release\` | `wsl-proxyctl.exe`、`wsl-proxy-desktop.exe` 是 `7df27ac` 编出来的。 |
| 配置库 | `target\release\desktop.sqlite`：Target 用 `.env` 第二个住宅代理（HTTP），入口端口 43531；Control 用第一个（SOCKS5），入口端口 43532。 |
| 恢复记录 | 状态目录里是按环境的新格式：Target、Control 各一份操作记录，代次都是 4，没有进行中的操作，也没有接管记录。旧的全局记录文件已经迁移、删除。 |
| 后台 | 已关闭，没有 `wsl-proxyctl.exe`、`wsl-proxy-desktop.exe` 在运行。 |
| 文档 | README 中英文、`design/ui-design-spec.md`、`docs/plans/m10/README.md` 已随代码更新。`docs/decisions.md` 里决策 40 的状态（「第一期待实现；第二期待实验」）还没改，等你认可执行记录后一起改。 |
| 早先留下的 | 原型 worktree `D:\workspace\dick-wsl-proxy-nftlab`、`D:\wpmlab` 实验文件、实验发行版里装的 `nftables` 包都还在。`D:\wpmlab\session.out` 里有住宅服务器地址，不要进仓库。 |

## 已经验证的

- Windows：
  - `cargo fmt --all --check`、`cargo clippy --locked --workspace --all-targets -- -D warnings` 无告警；
  - `cargo test --locked --workspace`：控制器 303 项、库 29 项、桌面 121 项通过；
  - 四个 Python 测试全过；
  - release 编译通过。
- 第一段：真实接管 Target 一次。
  - 规则只在独立表里；
  - 在 Control 里改写共用表，Target 的规则不受影响；
  - 定时核对两轮，规则集写入事件为 0；
  - 停止后清理干净。
- 第二段：经后台 `rpc` 让 Target、Control 同时接管。
  - 入口端口、规则表、出口都各自独立；
  - 两边的定时核对都正常；
  - 先停一个，另一个不受影响；
  - 连接记录和日志按环境分开记。

## 你操作、我核对

你按编号操作，做完回我一行，例如「M1 过，M2 不过：首页只显示一行」。每一步我都会去配置库和恢复记录里核对，对上了才算过。

**基线（2026-11-27 09:54，后台已关）：**

- 运行日志 `runtime_logs` 最大 id 是 361；
- 连接记录 `connection_records` 最大 id 是 757；
- Target、Control 的操作代次都是 4，都空闲。

我只看比这些新的记录。

**截图：** 只在界面看着不对时截，存到 `D:\wpmlab\m10-ui\`，文件名用编号（例如 `M2.png`）。环境卡片上的住宅代理密码是明文显示的，截图前请遮掉。

**注意：** 每次启动接管，都会把那个发行版的时区改成住宅出口所在的时区并重启它，里面正在运行的程序会被结束。

| 编号 | 你做什么 | 你回我什么 | 我去核对什么 |
|---|---|---|---|
| M1 | 打开 `target\release\wsl-proxy-desktop.exe`，在环境页先启动 WSLProxyLab-Target，再启动 WSLProxyLab-Control | Control 的「启动接管」是不是可以点，两个是否都成功，各自的标签写什么 | 两个环境各有一条「已开始接管」日志；两份操作记录的代次各加 1；两个发行版里各有一张自己的独立表 |
| M2 | 看首页 | 一句话状态怎么写；主按钮写什么；下方是不是两行、每行有没有按钮；保护链路的目标、入口、住宅出口节点写什么 | 预期：写着 2 个环境；主按钮「停止全部接管」；两行各有「停止接管」；节点写「2 个环境」「各环境不同」。这一步库里没有记录，只靠你回的话和截图 |
| M3 | 鼠标悬停托盘图标，再看状态岛、展开它 | 托盘悬停文字；状态岛收起时的速率、展开后有几行、每行写什么 | 预期：托盘「接管中 · 2 个环境」；展开后两行，各有出口和速率。库里没有记录，只靠你回的话和截图 |
| M4 | 连接页：看实时连接，再对两个环境各点一次「复核出口」 | 实时连接里两个环境的连接是否都有；两个按钮是否各自出结果 | 两条出口检测日志各对应一个环境；接管期间新增的连接记录两个环境都有 |
| M5 | 首页在 Control 那一行点「停止接管」，确认 | Control 是否停下、Target 是否还在接管 | Control 有一条「已停止接管并恢复直连」，日志写的是 Control；Control 的代次再加 1，Target 的代次不变 |
| M6 | 在环境页重新启动 Control，然后在托盘右键菜单点「停止全部接管」 | 确认框是否列出两个环境；是否依次停下，最后都空闲 | 两个环境各有一条停止日志，时间先后相邻；两份操作记录都没有进行中的操作 |
| M7 | 再把两个都启动，然后在托盘点「退出」并确认 | 程序是否依次停止两个环境、关闭后台后退出 | 两条停止日志；之后没有 `wsl-proxyctl.exe` 进程，两个发行版里没有独立表 |

M1 的「启动接管」如果还是灰的，或者任何一步不过，先停在那一步，把结果发给我。

## 还没验证的

- 放弃一个已注销的环境、并在别的环境里删掉它的规则表：只有单元测试。
- 「最多一个环境运行 Docker」的拒绝路径：Control 没装 Docker，没真实走过。
- 两个环境同时接管期间，后台重启或其中一个发行版单独重启：没测。
- UDP 经住宅出口：两个住宅代理在启动时的 UDP 探测都没通过，测不了。

## 回退

- **只想回到 main：**
  1. 关掉后台和窗口；
  2. 运行 `git switch main`；
  3. 用 main 重新编译。

  新格式的恢复记录在旧版本里读不到，所以回退前要确认所有环境都已停止。
- **回到 0.1.17 的配置库：** 用 `target\release\desktop.sqlite.bak-0.1.17-20261127` 覆盖，做法见 [m9 的交接文档](../m9/handoff.md)。

## 常用命令（在 WSL 里发到 Windows）

```bash
/mnt/c/Windows/System32/cmd.exe /c "cd /d D:\workspace\dick-wsl-proxy && cargo test --locked --workspace"
```

```bash
/mnt/c/Windows/System32/cmd.exe /c "cd /d D:\workspace\dick-wsl-proxy && cargo build --locked --release -p wsl-proxyctl -p wsl-proxy-desktop"
```

经后台发请求的方法：

1. 启动后台：`target\release\wsl-proxyctl.exe daemon`；
2. 把一条 JSON 请求写进文件，运行 `target\release\wsl-proxyctl.exe rpc < 请求文件`；
3. 状态请求是 `{"command":"status"}`，返回 `{"sessions":[...]}`；
4. 停止要带 `"target"`（环境的 GUID）和这个环境自己的 `"expected_generation"`；
5. 测完发 `{"command":"shutdown_daemon"}`，只有所有环境都空闲时后台才会接受。
