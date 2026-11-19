# `src/` 结构化重构总结

## 目标

在不改变控制器公开模块、IPC 协议、WSL 探针、UDP/TCP 转发和连接归属校验的前提下，把职责已经明确的实现从 `src/` 根目录移入对应子目录。

## 当前结构

```text
src/
├── ingress.rs                  # ingress 生命周期、共享状态、调度与路由
├── ingress/
│   ├── tcp.rs                  # TCP relay、半关闭、空闲与超时处理
│   ├── metadata_lane.rs        # metadata 查询排队与物理批次
│   ├── metadata_timing.rs      # metadata 时序统计
│   ├── flow_stats.rs           # 流统计与近期记录
│   ├── udp_admission.rs        # UDP 空闲/安静流回收
│   ├── udp_pump.rs             # UDP 回包收集与按流转发
│   └── tests.rs                # ingress 集成与生命周期测试
├── managed_dns.rs              # DNS session、alias 表和上层编排
├── managed_dns/
│   ├── http.rs                 # DoH HTTP framing 与 deadline stream
│   ├── wire.rs                 # DNS wire parser、CNAME/A answer 校验与 alias answer
│   ├── ledger.rs               # durable alias high-water ledger
│   └── tests.rs                # DNS wire、alias、ledger 与 transport 测试
├── probe/
│   ├── mod.rs                  # 只读 WSL capability/identity probe
│   ├── probe.sh                # 固定 Linux probe 程序
│   ├── dns_probe.py
│   ├── https_probe.py
│   └── exit_probe.py
├── ipc.rs                      # IPC 公共 API 和测试入口
├── ipc/
│   ├── framing.rs              # 有界 JSON frame 与 ACK
│   └── windows.rs              # Windows named-pipe、SID、image identity 和 daemon transport
├── query_bridge.rs             # guest 查询协议与 transport 生命周期
├── query_bridge/
│   ├── bootstrap.rs            # 固定、只读的嵌入式 guest bootstrap
│   └── tests.rs                # query bridge 协议测试
├── transition.rs               # durable transition intent 状态机
├── transition/
│   └── tests.rs                # transition 状态机测试
└── 其他控制器模块              # m1、m2、lifecycle、policy、kernel 等保持原入口
```

## 保持不变的契约

- `crate::ingress`、`crate::managed_dns`、`crate::probe`、`crate::ipc` 的模块入口不变。
- IPC 公共函数仍为 `request`、`ensure_daemon`、`serve`。
- WSL 探针仍通过固定脚本和 `include_str!` 嵌入，不安装 guest helper。
- TCP/UDP 调度、UDP admission、DNS alias ledger、Windows pipe 身份核对均只做文件边界移动。
- `kernel.py` 的逐包归属校验、全量 owned-row 校验、foreign tuple 歧义检查和 zone/status/ID 校验未改变。

## 验证

- Python 内核测试：54/54 通过。
- `query_bridge::`：6/6 通过。
- `ingress::`：36/36 通过。
- `managed_dns::`：16/16 通过。
- 完整 controller 测试：101/101 通过。
- controller package `cargo fmt --check` 通过。
- `git diff --check` 通过。

Rust 构建使用完整 MinGW-W64 组件目录；没有把单个运行时 DLL 复制进仓库或产品目录。

## 有意保留在根模块的部分

`transition.rs`、`query_bridge.rs` 和 `managed_dns.rs`/`ingress.rs` 的核心编排仍保留为根模块；低耦合的测试、query bootstrap、DNS HTTP/wire/ledger、ingress 子职责已移入对应目录。继续拆分核心实现需要同时改变较多私有可见性和生命周期边界，当前没有为“文件更小”引入额外耦合。

## 当前工作区注意事项

源代码结构重构和内核解码优化是本轮预期改动。`desktop/src/app.rs`、`desktop/src/main.rs` 及 `desktop/src/app/` 的改动来自用户工作区，提交时应单独核对，不要由本重构自动归属。
