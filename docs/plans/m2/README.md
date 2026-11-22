# M2 执行记录：Windows 双跳拨号、白名单与受管系统 DNS

## 使用边界

`start` 进入单目标受管模式；原来的 M1 局部端点实验使用 `start-scoped`，不是代理模式。M2 不向 WSL 安装代理，不改 `.wslconfig` 或共享 `resolv.conf`。它管理已验证的 WSL2 NAT 布局中的目标发行版出站流量；不声称能迁移已建立的 TCP、控制 Windows 进程、容器的转发流量或抵御本机管理员。M2 不提供 GPUI。

## 从 PowerShell 启动

1. 准备 Windows 侧 JSON 策略文件。下面示例中的地址不是软件固定值。`dns_upstream` 为 **IPv4:端口**；程序经双跳到该地址，再以 `dns_tls_name` 作 TLS 名称校验，使用 HTTPS POST `/dns-query`。不会用 Windows 默认 DNS 解析上游。`health_domain` 必须是可通过链路访问且不在白名单的 HTTPS 主机。

   ```json
   {
     "first_hop": "127.0.0.1:7892",
     "credential": "my-residence",
     "dns_upstream": "8.8.8.8:443",
     "dns_tls_name": "dns.google",
     "health_domain": "ippure.com",
     "direct_ips": [],
     "direct_domains": [],
     "direct_suffixes": []
   }
   ```

2. 用 `wsl-proxyctl.exe import-credential --name my-residence --env-file <文件路径>` 导入现有 `.env`（`ip`、`port`、`username`、`password`）。策略文件只引用名称；凭据仅保存在当前 Windows 用户的凭据管理器，导入不覆盖同名记录。审阅策略后运行 `wsl-proxyctl.exe session`。
3. 在同一会话逐行提交，例如：

   ```jsonl
   {"command":"start","target":"WSLProxyLab-Target","port":43781,"profile":"D:\\WSL\\ProxyLab\\policy.json"}
   {"command":"status"}
   {"command":"stop"}
   ```

   `startup_verified` 是**启动时**的探测结果，不是实时可用性保证。只有来自目标的两个独立未缓存 DNS 探测（UDP、强制 TCP）在 Windows 端经认证上游收到对应回答、双跳 SOCKS5 UDP 关联可以建立，以及目标的非白名单 HTTPS 探测通过，才返回 `forwarding_managed`。UDP 关联探测只建立并关闭代理关联，不发送业务数据。住宅端拒绝 UDP 时启动进入恢复状态，查看状态后显式 `stop` 恢复；不通过删除日志或改成只代理网页来跳过失败。正常结束拥有活动入口的会话会执行停止；若控制器崩溃，另行运行 `wsl-proxyctl.exe status`、`wsl-proxyctl.exe stop`。
4. 停止不会删除用户凭据。如不再使用，可运行 `wsl-proxyctl.exe forget-credential --name my-residence`。不得把密码放进命令行或策略文件。

## 分流与故障语义

| 输入 | 行为 |
|---|---|
| 精确 IP / IPv4 CIDR 白名单 | Windows 直接拨号；不会覆盖宿主已有 VPN/TUN 的路由。 |
| 域名 / 后缀白名单 | 通过受管 DNS 的有效正向 A 回答建立专用合成地址关联。只凭已核实的关联走直连；不从客户端 Host 猜目标，不把共享同一 CDN IP 的其他域名整体放行。域名白名单不豁免 DNS。 |
| 其他 IPv4 TCP | 先从宿主机已有 SOCKS5 客户端拨住宅服务器，再在同一隧道内完成住宅认证、CONNECT 原目标。任一跳失败就失败，不退化成单跳或直连。 |
| UDP / QUIC | 受管 DNS 由专用处理路径接收；白名单业务 UDP 可直连。其余业务 UDP 通过嵌套 SOCKS5 UDP 关联走双跳；任一住宅端拒绝关联或链路失败，启动和新流量均失败，不用裸 UDP 补发。 |
| 系统 DNS | Target 解析器 UDP/TCP 53 在同一组规则下接管，必要时仅对已转向入口的这类流量做 SNAT。上游 DoH 使用经过住宅链的已连接 socket 和系统信任根，禁止明文/本机 DNS 回退。应用自带 DoH/DoT 是普通业务连接，不等于使用指定解析器。 |
| IPv6 / 非支持环境 | 目标存在全局 IPv6 地址和默认 IPv6 路由时启用受管 IPv6 入口、规则、TCP 和 UDP 链路。缺少这些证据时对目标外部 IPv6 出站作受限阻断，保留本地回环和非目标发行版。预检不认识的布局拒绝启动，不改整台机的网络设置。 |

Windows 在读取应用数据前核对内核的连接标记、正反向地址/端口及目标所属实例。M2 的恢复日志只含网络归属，不含住宅配置或密码。关窗、上游故障及强杀控制器均不是恢复直连的命令。主动停止后检查自有 IPv4、IPv6 规则及映射，确认新请求和系统 DNS 回原路径；UDP 只清本次已核实的映射，TCP 不能无缝迁移，需要重新连接。

域名白名单只对有认证来源的可安全映射的公网 A 答案发放 `198.18.0.0/15` 合成地址。响应 TTL 为零，运行期授权不超过上游有效期；已有应用若自行长期保留合成地址，停止后须重查域名。Windows 用户目录下 `dns-alias.highwater` 记录地址高水位，`dns-alias.map` 只保存名称/IP 摘要与别名偏移，不保存域名、原 IP 或凭据；相同名称/IP 可跨会话复用原别名，不同名称/IP 永不共享。返回私网地址的名称不会因 DNS 白名单获得别名。普通 DNSSEC 查询不篡改签名以强制直连。

## 已实测的公网链路

Windows x64 控制器、D 盘 `WSLProxyLab-Target` / `WSLProxyLab-Control`，使用现有 TrojanX 入口和临时导入 Windows 凭据管理器的真实住宅凭据。在 `run-20261119-125710` 的真实策略阶段，目标命令和启用前已有的服务分别访问 IPPure 与 Net.Coffee，两个服务端观察到的出口均与住宅配置完整匹配（仅记录布尔比对）；Control 保持原出口。目标的系统 DNS 经真实链完成普通 UDP 及强制 TCP 查询。该阶段正常停止成功；不能把同目录中后续**受控 DNS 转发器无法直连公共上游**的失败尝试也算作通过。

真实测试证明 TrojanX 本地 SOCKS5 接受了对住宅端点的请求且认证后的最终出口正确。未获得 TrojanX 针对此住宅连接的内部策略命中记录，不能用最终出口 IP 代替机场节点独立证明。故障注入不更改 TrojanX 设置或停掉用户的现有服务。

## 受控故障与关闭恢复

发行文件 `D:\WSL\ProxyLab\m2-20261119-lab\wsl-proxyctl.exe`，SHA-256 `7f1885fe1f715b43574895e18f1e2ff501b7f04a252afa00a3b496f4221d03ee`。同一二进制的受控矩阵在 `run-20261119-130556`，**174 个断言通过 173 个**，不记作全部通过。

| 验收项 | 观测 |
|---|---|
| 受控双跳与 DNS | 两跳均有真实 SOCKS5 转发，接收端区分两跳的源地址；Windows 经指定上游完成认证 DoH。分别断首跳、住宅及 DNS 上游后，新请求未通过替代路径到达目标；Control 与 Windows 对照可用，恢复节点后重新可达。 |
| 白名单 | IP/CIDR 的 TCP、UDP 直连。精确域名与后缀在受管 DNS 下生效；对于同 IP 的非白名单名称，Windows 路由计数及第二跳记录仍显示走链。未列入白名单的 UDP/QUIC 测试包未到达接收端。 |
| 保留的失败样本 | `child.exact.104-21-79-4.sslip.io` 的首次原始 DNS 查询返回 `SERVFAIL`、未取得 A 记录。后续独立 HTTPS 请求解析成功，直连计数增量 0、链路计数和第二跳计数各增 1。失败原因未定位；不能当作域名绕过，也不能抹掉这次可用性失败。 |
| 停止与异常退出 | 主动停止后，持有的白名单 UDP socket 恢复原路径，新请求和 DNS 恢复。强杀控制器时保护规则保留，Target 的新 TCP、UDP、DNS 均未绕过；独立 `stop` 恢复后再次 `stop` 仍为空闲。 |
| 最终核查 | Target、Control 的 DNS、双栈路由与规范化防火墙规则同基线；Windows DNS、路由恢复。无活动恢复日志、测试监听或临时服务。测试导入的凭据已删除，原 `.env` 与 TrojanX 配置未改动。核查见 `final-resource-cleanup.json` 和 `final-guest-listener-cleanup.json`。 |

构建与回归：57 项 Rust 测试、25 项内核辅助逻辑测试通过；Windows x64 release 构建与 Clippy（告警按错误处理）通过。下一次诊断上述 `SERVFAIL` 应记录上游响应码、传输失败阶段和解析记录类型，而不是重复探测直到得到 A 记录。

## 单次 DNS `SERVFAIL` 的定位

历史样本 `run-20261119-130556/target/00089.result.json` 是直接向系统解析器端点发送的 UDP A 查询：`ok=true`、`rcode=2`、答案为空、耗时 1.467 秒。它**收到了一份 DNS 失败回答**，不是 UDP 超时，也不是把 HTTP 状态或 glibc 错误码误读为 DNS RCODE。`child.exact.104-21-79-4.sslip.io` 既不等于精确白名单项 `exact.104-21-79-4.sslip.io`，也不在该实验的 `suffix.…` 白名单内。

在该次请求前后两条 `status` 之间（05:07:54.257–05:07:55.832 UTC），`dns_udp` 从 10 增至 11，连接跟踪查询及成功数同时从 33 增至 35，UDP 处理失败、元数据失败和容量拒绝均未增加。同期两跳完成 CONNECT，DNS 包装器于 05:07:54.386 连到 `223.5.5.5:443`。状态中已有的 `TCP DNS frame read failed` 在这一区间没有变化，不是这次 UDP 请求的新错误。

在该构建的 `src/managed_dns.rs` 中，DoH 交换或应答校验失败会返回错误；`src/ingress.rs` 的 UDP 路径这时不会构造失败响应。对于这类非白名单名称，已校验的正常大小 DoH 应答原样传回；截断路径也保留原 RCODE。因此历史证据将问题定位到**受管路径返回的上游 DNS 失败响应**，不能据此定位 AliDNS 内部的递归、DNSSEC、限流或权威服务器故障。历史日志只保留了客户端 RCODE 和连接元数据，没有那一包的 DoH 明文、扩展 DNS 错误（EDE）或上游运营日志。稍后服务查询获得 `104.21.79.4`、耗时 0.135 秒，此结果不覆盖失败样本。

**D 盘双组对照。** 使用独立诊断构建，在受限测试域名上观察 TLS 校验后的 DoH 应答与最终 DNS 报文，不改变策略、应答、重试行为或正式 EXE。受管窗口 `05:33:43–05:34:14 UTC`。Target 与 Control 对原名的 UDP/TCP A 查询均为 `NOERROR`，得到 `104.21.79.4`；Target 原名耗时分别为 0.487 秒、0.098 秒。四个未使用过的同类子域名也成功，未复现原名的 `SERVFAIL`。取 DNS 事务 ID、问题名、输入传输方式关联后，14 份可配对的 Target 客户端应答均与该请求的 DoH 响应体、控制器最终报文逐字节一致。没有收到 EDE；本轮不能据此判定 DNSSEC 或权威侧的历史状态。

**故障反证。** 只停实验自有的 DoH 转发器一次：Target 的新 UDP 查询在 TLS 握手阶段失败，无上游 DNS 响应体、无控制器应答，客户端约 18 秒超时；同期 Control 查询同一名称仍成功。该故障路径与历史 `rcode=2` 不同。不修改产品、不增加自动重试、不回退本地 DNS。原 173/174 验收数字保持不变。

**恢复与证据。** 正常停止、重复停止后状态为 `idle`；Target、Control 的 DNS、路由、规范化防火墙规则及 Windows 网络基线均恢复，活动日志、测试监听和临时凭据不存在。没有读取真实 `.env` 或修改 TrojanX。证据目录 `D:\WSL\ProxyLab\m2-dns-investigation\`：`analysis/historic.json`、`analysis/matched-wires.json`、`lab/run-20261119-133331/` 和 `lab/lab-summary.json`。早先一次启动就绪探测失败和一次 WSL 启动超时均保留，未计入成功的受管请求。
