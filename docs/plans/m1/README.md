# M1 执行记录：可逆的 Windows TCP/UDP 入口

这一阶段验证的是**选定端点的引流与恢复**，不是公网全量代理。当前 Windows 原生控制器直接转发至用户列出的 IPv4 原目标，不读取 `.env`，不启动住宅代理，不接管 DNS。双跳、白名单与业务/DNS 同时启停属于 M2。实现中的状态名 `forwarding_scoped` 表示限定范围的转发，不能解释成产品级「已接管」。

## 手动运行

先用 M0 的 `preflight` 核对目标和对照。M1 当前只接受本次运行的 Windows WSL 网关或 guest eth0 地址上的 1–8 个明确端点，原目标和入口必须为不同的非特权端口。两个发行版可以访问同一个原目标用于对照，但只有 Target 的 cgroup 会被引流。示例里的 IP/端口来自实验机，不是跨机器常量。

在 PowerShell 执行 `wsl-proxyctl.exe session`。下例使用 M2 及更新控制器的显式诊断命令 `start_scoped`；本页归档的原始 M1 EXE 对应命令为 `start`。当前 `start` 必须提供策略文件并同时接管 DNS，不能降级成局部直连。

```jsonl
{"command":"start_scoped","target":"WSLProxyLab-Target","witness":"WSLProxyLab-Control","port":43771,"origins":["172.28.80.1:43772","172.28.83.138:43772"]}
{"command":"status"}
{"command":"stop"}
```

需要真实可达的原服务才能收到响应。`start` 不是 `preflight`：它会以 Linux root 身份在目标发行版执行运行时操作。固定 Python 3 标准库辅助逻辑通过 stdin 执行，不在 WSL 安装进程或软件包。会话持有当前用户的控制锁，其他写入实例不能接管。显式 `stop` 或正常输入 EOF 恢复本会话持有的规则；如果控制器被强制终止，用新的 `wsl-proxyctl.exe status` 查看残留，再执行 `wsl-proxyctl.exe stop` 恢复。未接管时再次停止应返回 `idle`。

## 实现决定与恢复条件

- `src/m1.rs`：在任何规则提交前，将注册 GUID、运行时身份、端点及非零实例标记写入当前用户 LocalAppData 的 `WSLProxyLab\m1-active.json`。写入暂存文件、落盘后改名。遗留日志占用唯一接管位置；不能通过删除日志假装已经恢复。
- `src/kernel.rs`、`src/kernel.py`：变更前重新核对发行版身份、boot ID、cgroup 根及地址。仅操作实例的专用链和完整规则。Windows 查找连接时需要同时匹配实际协议、对端、回包入口、原目标清单以及实例的连接标记；客户端无法在报文里指定下一跳。缺失或冲突不转发。
- `src/query_bridge.rs`：转发前通过一次受限的 stdio 握手核对身份；同一批 TCP/UDP 请求复用元数据查询通道，每次仍向内核核验映射，不缓存猜测的目的地址。查询器不监听网络、不转发流量、不安装文件，空闲或关闭时退出。握手失败不激活，查询失败不回落直连。`status.forwarding` 可查看查询与转发诊断。
- `src/ingress.rs`：在 WSL 虚拟接口独占绑定 TCP/UDP；由 Windows 自己连接核实后的原目标。限制并发、空闲时长和缓存的 UDP 会话；停止时关闭活动 TCP 并等待工作线程结束。TCP 流不能迁移，由应用重连。
- `src/lease.rs`：独立 Windows 进程持有入口 socket 的副本，不读取或转发数据。控制器单独崩溃不释放该端口给其他程序；规则仍在时绝不能用“自动撤规则、恢复直连”来重启服务。恢复程序先清理内核状态，再通知持有者释放 socket。
- 停止时先撤引流，随后对已证实属于本实例的 conntrack 映射逐条核对并按内核 ID 删除，使旧 UDP socket 的后续数据报可回原路。不清空共享规则或连接表，不改 DNS、默认路由或 Windows 系统代理。任一步不能确认就报错并保留日志，不声称已恢复。
## D 盘原生验收结果

最终 Windows release EXE：`D:\WSL\ProxyLab\m1-20261119-lab\wsl-proxyctl.exe`，SHA-256 `00b9108606d139a7f5eddf2657917dba249d7f5c658f392bcf21eeacf2c238b5`。验收目录 `D:\WSL\ProxyLab\m1-20261119-lab\run-20261119-122915\`，`summary.json` 的失败数为 **0**。A=`WSLProxyLab-Target`，B=`WSLProxyLab-Control`。两组均使用相同 UID，两个原目标共用端口 43772。

| 场景 | 实际结果 |
|---|---|
| 正常转发 | A 的普通进程和接管前已启动的 systemd 服务访问两个原目标，TCP/UDP 均收到正确响应，目标端看到 Windows 转发来源。B 及 Windows 原生对照保持原路径。UDP 发完即关的数据报按接收端记录核对；没有将已关 socket 记作收到回包。 |
| 归属不明或端口冲突 | TCP、UDP 端口预占用均拒绝启动。直接向入口发送伪造目的地的请求不能让任何原目标收到数据。 |
| 主动停止 | A 的普通命令和后台服务的新连接恢复直连。接管期间建立的 UDP socket 不换源端口即可再次直达原目标；经代理的 TCP 由应用重连后恢复。启用前建立的直连 TCP/UDP 未被追溯接管。 |
| 强制终止控制进程 | 独立进程读取到 `recovery_required`；规则仍在，测试范围内 A 的新 TCP/UDP 失败且未直达原目标，B 与 Windows 仍正常。执行独立 `stop` 后恢复，再次执行仍返回 `idle`。 |
| 最终状态 | A/B 和 Windows 所记录的 DNS、路由、防火墙规则指纹与基线一致；无本次活动日志、监听或测试服务。TCP/UDP 43771、43772 均可重新绑定。 |

`evidence.jsonl` 保存请求、断言和状态；`windows-origin.jsonl`、`guest-origin.jsonl` 保存目标端证据。较早调试轮发现了规则序列化顺序差异导致停止拒绝、逐包冷启动 WSL 导致超时等问题；未把失败轮当作通过。旧日志保留后使用修正的所有权核对恢复，没有跳过检查或清空防火墙。代码检查：25 项 Rust 测试、16 项内核辅助逻辑测试通过，Windows 目标 Clippy 无告警。


## 不在本阶段的承诺

- 启用前存在的直连 TCP 不自动迁移；停止后的连接跟踪表、计数器不是启动前的逐字节副本。恢复的判据是本实例的规则、映射、监听消失，受测连接走原路径，原有 DNS/路由和外部规则未被覆盖。
- 接管期间 WSL 被重启、注销重装或 cgroup 身份改变时，控制器采取保守策略，不以旧身份删除现有内核对象。跨重启协调、切换和完整端口威胁模型仍按 M3/M5 验收。
- M1 依赖临时的 WSL 元数据调用；没有将其作为生产性能结果。未覆盖 IPv6、任意公网目标或恶意 Linux root/Windows 管理员。
