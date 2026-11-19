# M3 执行记录：单目标切换与中断恢复

## 操作契约

同一 Windows 账户最多有一个接管所有者。`switch` 用于**当前持锁的 managed 会话**，不是启动第二个后台，也不是把旧 TCP 连接迁移到新发行版。可切换到使用同一 Windows 入口地址和端口的发行版。省略 `profile` 时复用用户选定的链路和白名单，但新建目标自己的 DNS 别名表与就绪探测状态。

通过 `wsl-proxyctl.exe session` 发出 `status`，从回复取 **`operation_generation`**（持久操作代次）。然后提交如下 JSON；示例的 `7` 必须换成刚读到的实际值：

```jsonl
{"command":"switch","target":"WSLProxyLab-Control","expected_generation":7}
```

- `switch` 的 `expected_generation` 必填；`start` / `start_scoped` / `stop` 也可指定。自动化应在读到状态后带上代次；过期命令拒绝，不撤旧规则或重复落新规则。`config_generation` 是网络规则的实例标记，**不能代替**操作代次。
- 不需要额外填写 `witness`：切换时当前发行版就是新目标的隔离对照。不能用 `switch` 静默接管已失去会话的孤儿实例；先明确恢复再启动。
- 正常停止在同一会话发送 `{"command":"stop"}`；意外退出后，用新的原生进程执行 `wsl-proxyctl.exe status`、`wsl-proxyctl.exe stop`。未带代次的 `stop` 是人工明确恢复命令。成功停止后的重复停止保持空闲，不消耗新代次。

## 切换顺序与失败处理

| 阶段 | 能改变什么 | 中断后的处理 |
|---|---|---|
| 候选预检 | 校验目标注册身份、cgroup、网络、内核能力和策略，只读检查候选规则冲突。同一入口若正由当前活动实例独占，不误报为外部端口冲突。 | B 不具备能力、配置非法或目标端口被外部进程占用时，A 保持不变，不提交切换。 |
| `releasing_old` | 先持久化唯一操作代次、旧/新目标及规则标识，才开始撤旧规则、清理可确认归属的映射、结束旧 TCP 与释放入口。 | 无法证明旧目标已恢复，保持待恢复，禁止给新目标写规则。 |
| `old_restored` | 旧目标的内核规则与映射已经核实不存在，监听保管者已释放。允许此时没有活动目标。 | 不重建 A，也不根据候选选择自动启动 B。可显式 `stop` 核实并结束该操作。 |
| `starting_new` | 重新核对 B，不继承 A 的 cgroup 身份、连接或 DNS 状态。新入口必须独占绑定，DNS 与业务均须通过真实就绪探测。 | 落保护前失败且确定无残留，可回空闲；落保护后失败则 B 保留保护，显式恢复。A 不被自动重新接管。 |

`src/lifecycle.rs` 协调运行状态，`src/transition.rs` 将意图原子写入当前用户 LocalAppData 的 `WSLProxyLab\m3-operation.json`。原有 `m1-active.json` 仍是单个网络实例的恢复凭据。重启时对比两者，并只读检查实际 cgroup、已标记的双栈规则、连接跟踪和端口持有者；不能验证则报告原因，不按旧 UI 的选择或仅凭端口删除网络对象。恢复是**取消未完成切换并回原网**，不是重放 `start`。持久操作代次在空闲时仍保留，防止旧命令在下次运行中生效。

Linux 侧对变更与核对串行化。Windows 先保存网络所有权，之后发放绑定到这一份计划的短时单次安装许可；安装时核销。显式恢复会撤销许可，从而避免进程被杀后延迟到达的旧安装覆盖恢复结果。正常释放删除已观测到的临时许可；不确定的授权可能保留有期的撤销标记，不能授权转发，后续变更会清理过期标记。没有共享防火墙清表或连接表重置。

## D 盘原生验收：正常切换

使用 `D:\WSL\ProxyLab\m3-lab\m3-observe.exe`，SHA-256 `7e83f3b1260154ccd579c5e9be2444019a88d22e73fedc8221cc741cc933457e`。`run-20261119-141054` 记录了两套发行版在同一 Windows 入口 `172.28.80.1:44011` 上的真实切换。A 为 `WSLProxyLab-Target`，B 为 `WSLProxyLab-Control`。

| 状态 | A 的已运行服务所见出口 | B 的已运行服务所见出口 |
|---|---|---|
| 接管前 | 原出口 `106.85.173.*` | 原出口 `106.85.173.*` |
| 接管 A，代次 3 | 住宅 `154.64.151.*` | 原出口 |
| 切换到 B，代次 4 | 原出口 | 住宅 |
| 切回 A，代次 5 | 住宅 | 原出口 |

B 原本缺少 legacy iptables 工具。先验证切换被拒绝，A 仍是原代次；再临时提供同版本、核对哈希的测试工具，未更改 B 的软件包登记，也没有覆盖原有文件。正常双向切换经过目标 UDP/TCP DNS 和 HTTPS 就绪探测；用旧代次发送的 `switch` 和 `stop` 被拒绝，未误停当前目标。该轮结束后已按清单移除 137 条新增链接及临时目录，核对包数据库、两套 WSL 的 DNS/路由/规则及 Windows 对照基线。

真实链路验证使用明确选择的 AliDNS DoH 上游。之前有两个启动尝试因 UDP DNS 就绪探测失败而被拒绝，随后显式停止并核对恢复；没有自动改走本地 DNS，也不将失败尝试计作成功。该轮旧 socket 回显检查受测试脚本的 PowerShell 同名别名影响，不据此宣称旧连接验证通过。

## 实测边界与待补项目

本次验收的原生构建产物为 `target/x86_64-pc-windows-gnu/release/wsl-proxyctl.exe`，与上述已测 EXE 同一 SHA-256。构建验证通过：74 项 Rust 测试、42 项内核辅助逻辑测试，Windows x64 release 与 Windows 目标 Clippy 通过。持久日志的原子写失效、同代次不同意图、陈旧命令、阶段间隙和安装许可撤销等有隔离测试；它们不是两发行版的实机崩溃验收。

在正常往返之后的一次新目标启动，DNS 就绪探测失败；控制器没有报告切换成功，显式停止后对照了两组和 Windows 的基线。继续补测时，原生 Windows `wsl.exe` 对实验 Target 启动最小只读命令也返回 `Wsl/Service/CreateInstance/ERROR_TIMEOUT`（`run-20261119-142506/guest-native-minimal.stdout`）；该轮未启动接管，也没有再次暂存工具或导入凭据。没有执行会影响其他发行版的 `wsl --shutdown` 或重启 WSL 服务。

最后从原生 Windows 读取所有权文件：`m1-active.json` 不存在；`m3-operation.json` 的 `generation=8`、`pending=null`。这是空闲的代次高水位，不是残留接管。最近一次能读取两发行版内部网络基线并完整比对的轮次是 `run-20261119-141054`；后续受阻轮未对发行版执行接管或暂存操作。

可复核 `D:\WSL\ProxyLab\m3-lab\lab-summary.json`、`final-windows-cleanup.json`、`deps\cleanup-B.json` 和正常往返轮的 `evidence.jsonl`。往返轮有 59 个通过的断言，含 16/16 个访客 DNS 探测、8/8 个访客 HTTPS 出口请求；24 次变更采样中未见两代自有 hook 并存，采样不等于连续时间证明。Windows 最终没有本次控制器、监听或临时凭据。

**未完成实机验收：**旧 UDP 原 socket / 已代理 TCP 重连在**跨发行版切换**时的对照；故意使旧目标清理无法确认后禁止 B 落规则；在 `old_restored` 后制造新目标落规则前的端口竞态；切换中强杀拥有者并由新进程逐阶段核实及取消。M1/M2 的崩溃验证和 M3 单元测试不能替代这些实测。WSL 恢复可启动后，只补这些场景，不必重跑已通过的住宅出口 A→B→A。

上轮应维护者要求暂不重启实验发行版。本轮续测开始前，D 盘证据目录已可读，两个注册名分别由对应 guest 返回，原生控制器 `status` 返回 `idle`、`active_target=null`、`operation_generation=8`。未执行 WSL 重启；续测只覆盖上述未完成分支。
