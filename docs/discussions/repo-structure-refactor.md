# 仓库结构重构方案

> 讨论稿，2026-11-20，基于 `main` @ `fc42d6d`。只提方案，不改代码。
>
> **范围：**控制器 crate（`src/`）、workspace 清单、仓库级文件。
>
> **不在范围内：**
> - 桌面端 `desktop/src/app/` 的内部结构，归 [`desktop-gpui-ui-refactor.md`](desktop-gpui-ui-refactor.md) 第 7 节；
> - `docs/arch/`、`docs/decisions.md`；
> - 任何运行行为。

## 结论

**需要重构，但范围比"重新分层"小得多。**

- **顶层布局不用改。**对照 Rust/Cargo 官方约定，顶层基本合规，不需要搬 crate，也不需要换 workspace 形态。
- **要改的是 `src/` 里的 5 处结构问题。**全部能用"移动文件 + 改 `use`/`mod`/嵌入路径"完成，不改任何运行行为。

| # | 问题 | 改法 |
|---|---|---|
| 1 | `m1.rs`、`m2.rs` 按里程碑命名，名字看不出职责。`m1.rs` 同时放着最底层的数据类型 `Plan` 和最上层的 `Controller`：`Plan` 被 ingress、kernel、lease、query_bridge、transition、m2、lifecycle 共 7 个模块引用；`Controller` 本身又依赖其中的 ingress、kernel、lease。结果是上下层互相依赖，而且依赖在同一个文件上 | 拆成 `plan.rs` 和 `controller.rs`；`m2.rs` 改名为 `managed.rs` |
| 2 | 两处依赖方向反了：`policy.rs` 读策略文件时调用桌面通道模块的 `desktop_control::decode_policy`；`desktop_control.rs` 又调用二进制入口 `main.rs` 里的 `crate::dispatch_result` | 桌面策略文档的格式移到 `policy/profile.rs`；命令分发从 `main.rs` 移到 `command.rs` |
| 3 | `impl Controller` 分散在两个平级文件 `m1.rs` 和 `lifecycle.rs` 里，两边互相调用 | `lifecycle.rs` 下沉为 `controller/lifecycle.rs`；恢复日志 `m1-active.json` 的读写独立成 `controller/journal.rs` |
| 4 | 6 个在 WSL 里以 root 运行的 guest 脚本分在两处。`kernel.py` 和它的测试在 `src/` 根目录；其余 4 个在 `probe/`，但其中 3 个其实是 `m1`/`m2` 的就绪探测脚本，跟 `probe` 模块无关 | 统一放进 `src/guest/`。测试文件改名为 `test_kernel.py`，用 `python3 -I -m unittest discover -s src/guest` 运行 |
| 5 | 模块文件的写法不统一：`probe/mod.rs` 是旧写法，其余 6 个带子目录的模块都是 `foo.rs` + `foo/`。另外，有 16 处 `#[path = "…"]` 把编译器默认就会去找的路径又写了一遍：ingress 7 处、managed_dns 4 处、ipc 2 处、query_bridge 2 处、transition 1 处 | `probe/mod.rs` 改成 `probe.rs`，删掉这 16 处多余的 `#[path]`。已在临时副本实测：删掉后编译通过，告警不变 |

改完后，模块之间"你引用我、我也引用你"的情况从 7 对降到 2 对（3.3）。

**可选项**（建议单独决定，不和上面 5 处绑在一起）：两份 `Cargo.toml` 各写了一遍 `version = "0.1.3"`，可以改成 workspace 继承。代价是要连带改发布脚本里的版本校验，收益只是版本号少写一处。

**不建议做的：**
- 拆出 `crates/` 目录，或改成虚拟 workspace；
- 把控制器逻辑搬进 `lib.rs`；
- 拆出独立的 IPC crate；
- 改 `scripts/` 里的文件名；
- 继续拆 `ingress.rs` 这类核心编排。

理由见第 5 节。

**最大的风险不在重构本身，而在重构后没有复验。**两份复审（[`project-review-f97b25e.md`](project-review-f97b25e.md)、[`project-review-8ce39d8.md`](project-review-8ce39d8.md)）的头号结论都是：HEAD 上的两次重构没有实机复验，HEAD 已经不等于验收过的 0.1.3。本方案又叠一次重构，所以第 7 节给每一步写死了合并门槛，并分开列出能验和不能验的项：

| 类别 | 内容 |
|---|---|
| **这台机器能验** | 控制器 Windows 目标的 `cargo check`（今天实测基线：通过，9 条告警）；Python 54 项；`sh -n`；嵌入脚本逐字节一致；用 `git diff --color-moved` 确认移动的代码块没被改过 |
| **这台机器验不了** | Rust 单元测试（上次记录 101 项）和桌面端编译：Linux 缺 OpenSSL 开发包，Windows 目标缺 mingw 链接器。要验就得用 `scripts/build-desktop-windows.sh` 下载工具链，需要你同意。另外，`#[cfg(not(windows))]` 分支的代码在这台机器上没有任何检查能覆盖 |
| **打包前仍须做** | 按复审建议，在 Windows 上重跑 M4 桌面冒烟和 M3 启停恢复 |

## 1. 项目是什么

仓库是一个 Cargo workspace（Cargo 的多包工程），含两个 Rust 2024 edition 的 crate，另有三类非 Rust 文件：

| 部分 | 语言 | 作用 | 规模 |
|---|---|---|---|
| 根包 `wsl-proxyctl`（`src/`） | Rust | Windows 控制器：CLI、后台 daemon、数据面转发、受管 DNS、策略 | 34 个 `.rs`，11,713 行 |
| `desktop/`（`wsl-proxy-desktop`） | Rust + GPUI | Windows 桌面控制台，只通过 `wsl_proxyctl::ipc` 和后台通信 | 14 个 `.rs`，2,410 行 |
| `src/kernel.py`、`src/probe/` 下的脚本 | Python、POSIX sh | guest 脚本：编译时用 `include_str!` 嵌进控制器；运行时经 `wsl.exe` 在目标发行版里以 root 执行 | 6 个脚本 + 1 个测试 |
| `scripts/` | bash、Python、C | 从 WSL 交叉编译 Windows 版、组装发布 ZIP，以及打包测试 | 5 个文件 |
| `packaging/windows/` | PowerShell | 按用户安装、升级、卸载 | 3 个文件 |

`include_str!` 是 Rust 的编译期宏，把一个文件的内容作为字符串常量编进二进制。它的路径**相对于写这行代码的 `.rs` 文件**，所以移动 `.rs` 文件或脚本都要同步改路径。

还有一个结构上的特点，后面会用到：**控制器的 15 个模块都在 `main.rs` 里声明，只编进二进制；`lib.rs` 只导出 `ipc` 一个模块。**桌面端依赖的就是这个 lib，所以它只能看到 IPC，看不到控制器内部。

## 2. 规范怎么说，本仓库现在怎样

下表只列官方文档有明确说法的条目。

**核对程度：**
- **逐字核对过官方文档：**Package Layout；Workspaces 中的虚拟清单、`default-members`、`[workspace.package]`、`[workspace.dependencies]`、`[workspace.lints]`；Reference 的 `path` 属性；Book 7.5、11.3、12.3；`rust-version`；manifest 的 `readme` 字段（第 8 节用到）。
- **实测过：**unittest 的默认匹配模式和导入路径行为（见 4.2）；删掉 16 处 `#[path]` 后能否编译（见 4.2）。
- **没能核对：**PEP 8。peps.python.org 本次访问被拒，这一行按通用知识引用。

| 出处 | 规范要求 | 本仓库现状 | 结论 |
|---|---|---|---|
| [Cargo Book《Package Layout》](https://doc.rust-lang.org/cargo/guide/project-layout.html) | `Cargo.toml`、`Cargo.lock` 放在包根；源码在 `src/`；默认库 `src/lib.rs`，默认可执行 `src/main.rs`，其他可执行放 `src/bin/`；集成测试放 `tests/`，基准测试放 `benches/`，示例放 `examples/` | 符合：根包一个 lib、一个 bin；没有 `tests/`、`benches/`、`examples/` | 不改 |
| [Cargo Reference《Workspaces》](https://doc.rust-lang.org/cargo/reference/workspaces.html) | 工作区可以是"根包 + 成员"，也可以是只有 `[workspace]` 的虚拟清单；`default-members` 指定默认构建哪些成员 | 根包 + `desktop` 成员，`default-members = ["."]`。在根目录执行 `cargo build` 只构建控制器。按文档，有根包时不写 `default-members` 也只操作根包，所以这一行和默认行为相同，只是把默认值写明了 | 不改（5.1） |
| [Rust Book 7.5《Separating Modules into Different Files》](https://doc.rust-lang.org/book/ch07-05-separating-modules-into-different-files.html) | 惯用写法是 `src/foo.rs` + `src/foo/bar.rs`；`src/foo/mod.rs` 是"仍受支持的旧写法"；同一模块两种都写会编译失败；不同模块混用是允许的，但会让人困惑，`mod.rs` 一多，在编辑器里也分不清是哪个 | `ingress`、`managed_dns`、`ipc`、`query_bridge`、`transition`、桌面端的 `app` 都用新写法，只有 `probe/mod.rs` 是旧写法 | **改**：`probe/mod.rs` → `probe.rs` |
| [Rust Reference《Modules》中的 `path` 属性](https://doc.rust-lang.org/stable/reference/items/modules.html) | `#[path]` 用来改写模块从哪个文件加载，路径相对于写这条声明的源文件所在目录。不写时，编译器按上一行的默认规则找文件 | 16 处 `#[path]` 的值正好等于默认路径，例如在 `src/ingress.rs` 里写 `#[path = "ingress/tcp.rs"] mod tcp;`。看到 `#[path]` 的人会以为文件位置和默认规则不同，只能逐条核对；以后移动父模块时，这些字符串也要手改 | **改**：全部删掉 |
| [Rust Book 12.3《Separating Concerns in Binary Projects》](https://doc.rust-lang.org/book/ch12-03-improving-error-handling-and-modularity.html) | `main` 变大时，把逻辑移到 `lib.rs`。`main` 只保留四件事：解析命令行、做配置、调用 `run`、处理 `run` 返回的错误。理由是 `main` 本身没法测试 | `main.rs` 573 行：声明全部 15 个模块，另有预检、命令分发和 5 种进程模式。`desktop_control.rs` 还反过来调用 `main.rs` 里的函数 | **部分采纳**：分发和预检移到 `command.rs`，`main.rs` 只留进程模式和入口；**不**把控制器搬进 `lib.rs`（5.2） |
| [Rust Book 11.3《Test Organization》](https://doc.rust-lang.org/book/ch11-03-test-organization.html) | 单元测试放在 `src/` 里、和被测代码同一个文件，惯例是建一个带 `#[cfg(test)]` 的 `tests` 模块，可以测私有项 | 基本符合。多数模块的测试就写在本文件里；`ingress`、`managed_dns`、`query_bridge`、`transition` 4 个模块仍是带 `#[cfg(test)]` 的 `tests` 子模块，只是正文放在 `foo/tests.rs`，这是上一轮为缩小大文件做的选择 | 不改 |
| [Cargo Reference《Workspaces》](https://doc.rust-lang.org/cargo/reference/workspaces.html)中的 `[workspace.package]`、`[workspace.dependencies]`（Cargo 1.64+） | 版本、edition 等字段和依赖可以在工作区根只写一次，成员用 `version.workspace = true` 这类写法继承 | 两份清单各写一遍 `version = "0.1.3"`、`edition = "2024"`、`publish = false`；`serde_json` 也各声明一次 | 可选（4.6） |
| [Cargo Reference《The Manifest Format》](https://doc.rust-lang.org/cargo/reference/manifest.html)中的 `[lints]`（Cargo 1.74+） | 可以在清单里统一设定 lint 级别 | 没用。文档要求的 `clippy -D warnings` 门槛现在就不过（9 条告警） | 本轮不做：清告警是代码改动，不能混进移动提交 |
| [Cargo Reference《The Manifest Format》](https://doc.rust-lang.org/cargo/reference/manifest.html)中的 `rust-version` | 声明最低支持的 Rust 版本 | 没声明，README 只写"支持 2024 edition" | 本轮不做：最低版本没实测过，现在填就是猜 |
| [Python 标准库文档《unittest》中的 test discovery](https://docs.python.org/3/library/unittest.html#test-discovery) | `discover` 默认只收集文件名匹配 `test*.py` 的测试，并把起始目录加进导入路径 | `kernel_test.py` 不匹配默认模式，只能直接 `python3 src/kernel_test.py`。加 `-I` 就找不到 `kernel` 模块，复审已记录这一点 | **改**：改名 `test_kernel.py`，用 `discover` 运行 |
| [PEP 8](https://peps.python.org/pep-0008/) | 模块名全小写，可以带下划线 | guest 脚本都符合。`scripts/package-windows.py` 带连字符，不能被 `import`。这一点有仓库自己的证据：它的测试 `scripts/test_package_windows.py` 第 12–14 行就是用 `importlib` 绕路加载的 | 不改（5.5） |

**以下三条不是 Rust/Cargo 的规定，是我根据本项目代码做的判断：**

- **按职责命名，不按里程碑命名。**`m1`/`m2` 只在 M1、M2 开发期有意义。现在 `m1.rs` 的模块注释已经写着它同时服务"scoped M1 和 policy-managed M2"。
- **依赖只往下走。**入口 → 命令分发和桌面通道 → 控制器 → 数据面、guest 交互、Windows 宿主。下层不回头调用上层，更不调用二进制入口。Rust 本身允许同一 crate 内的模块互相引用，所以这是可读性要求，不是编译要求。
- **guest 脚本单独放一个目录。**理由有三条：
  - 它们以 root 身份在目标发行版里执行，是 [接管架构](../arch/README.md) 所说"WSL 内的特权操作"的全部代码，集中放便于审计；
  - `kernel.py` 同时被 `kernel.rs` 和 `query_bridge.rs` 嵌入，没有唯一的"所属模块"，无法和某一个模块放在一起；
  - 上一轮按"跟着模块放"把就绪探测脚本放进了 `probe/`，而实际嵌入它们的是 `m1.rs`、`m2.rs`。可见"跟着模块放"已经放偏了。

  目录放在 `src/` 下而不是仓库根，是因为 `build-desktop-windows.sh` 只把 `src` 和 `desktop/src` 链进构建目录（见 4.7）。

## 3. 目标结构

```text
src/
├── main.rs               # 改：只留 mod 声明、Cli、进程模式（session/daemon/rpc/maintenance/lease-worker）和 main
├── lib.rs                # 不变：只导出 ipc，是桌面端唯一能链接的面
├── command.rs            # 新：自 main.rs 移入 Command、Failure、emit、预检、dispatch/dispatch_result
├── plan.rs               # 新：自 m1.rs 移入 Plan 及其范围校验
├── controller.rs         # 原 m1.rs 的其余部分：Controller 结构，probe_exit/settled_status/activate/retire
├── controller/
│   ├── journal.rs        # 自 m1.rs 移入：m1-active.json 的读、写、删（磁盘文件名不变）
│   └── lifecycle.rs      # 原 src/lifecycle.rs：status/start/switch/stop
├── managed.rs            # 原 m2.rs：Runtime、Readiness、系统解析器校验
├── desktop_control.rs    # 改：桌面通道的请求处理、策略文档读写、诊断导出
├── policy.rs             # 改：增加 `pub(crate) mod profile;`
├── policy/
│   └── profile.rs        # 自 desktop_control.rs 移入：desktop-policy.json 的文档格式（Document、Preferences）和 decode_policy
├── probe.rs              # 原 probe/mod.rs
├── guest/                # 新：所有在目标发行版里以 root 运行的脚本
│   ├── kernel.py         # 原 src/kernel.py
│   ├── test_kernel.py    # 原 src/kernel_test.py
│   ├── probe.sh          # 原 src/probe/probe.sh
│   ├── dns_probe.py      # 原 src/probe/dns_probe.py
│   ├── https_probe.py    # 原 src/probe/https_probe.py
│   └── exit_probe.py     # 原 src/probe/exit_probe.py
└── （其余不动）credential.rs、host.rs、ports.rs、lease.rs、kernel.rs、query_bridge.rs + query_bridge/、
    ingress.rs + ingress/、managed_dns.rs + managed_dns/、transition.rs + transition/、ipc.rs + ipc/
```

"不动"的文件里：
- `kernel.rs`、`query_bridge.rs` 只改 `include_str!` 路径；
- `ingress.rs`、`managed_dns.rs`、`ipc.rs`、`query_bridge.rs`、`transition.rs` 只删 `#[path]` 行；
- 其余只改 `use` 路径。

步骤 1–4 中，根目录的 `Cargo.toml`、`desktop/`、`scripts/`、`packaging/` 都不动，仓库根只有 `.gitignore` 要加一行。

### 3.1 旧路径 → 新路径

`docs/plans/` 是执行记录，记的是当时的实现，**不改里面的旧路径**。读旧记录时按此表对照：

| 旧路径（执行记录里出现的） | 新路径 |
|---|---|
| `src/m1.rs` | `src/plan.rs`（`Plan`）、`src/controller.rs`（`Controller`）、`src/controller/journal.rs`（恢复日志） |
| `src/m2.rs` | `src/managed.rs` |
| `src/lifecycle.rs` | `src/controller/lifecycle.rs` |
| `src/desktop_control.rs` | `src/desktop_control.rs`（请求处理、文档读写）+ `src/policy/profile.rs`（文档格式） |
| `src/main.rs` | `src/main.rs`（入口、进程模式）+ `src/command.rs`（命令、预检、分发） |
| `src/kernel.py` | `src/guest/kernel.py` |
| `src/kernel_test.py` | `src/guest/test_kernel.py` |
| `src/probe.sh`（M0 记录，`be0fe1d` 起已是 `src/probe/probe.sh`） | `src/guest/probe.sh` |
| `src/probe/mod.rs`（`be0fe1d` 前是 `src/probe.rs`） | `src/probe.rs` |
| `src/probe/{dns,https,exit}_probe.py` | `src/guest/{dns,https,exit}_probe.py` |

`src/kernel.rs`、`src/query_bridge.rs`、`src/ingress.rs`、`src/lease.rs`、`src/managed_dns.rs`、`src/transition.rs` 的路径不变。

### 3.2 `m1.rs` 逐条去向

拆文件需要放宽一些可见性，原因是父模块看不到子模块的私有项。下表和后面几段逐项列出，除此之外不改任何可见性。

`controller.rs` 里把两个子模块声明为 `pub(crate) mod journal;` 和 `pub(crate) mod lifecycle;`，下表中的调用点写法都以此为前提。

| `m1.rs` 里的条目（行号） | 去向 | 可见性和调用点变化 |
|---|---|---|
| `Plan` 结构及其 derive（12–27） | `plan.rs` | 无。**serde 属性一个字都不动**：恢复日志用 `deny_unknown_fields` 反序列化，字段名变了，升级时带着活动日志的用户就无法恢复 |
| `fn scope`（29–63） | `plan.rs` | 无（只被 `Plan` 用） |
| `impl Plan`（65–124） | `plan.rs` | 无 |
| `fn journal`、`fn read_regular`（125–156） | `controller/journal.rs` | 无（只在文件内用） |
| `pub fn load`（157–165） | `controller/journal.rs` | 调用点从 `m1::load` 改为：`controller.rs` 内写 `journal::load`；`lifecycle.rs` 内写 `super::journal::load`（6 处）；`main.rs` 内写 `controller::journal::load`（4 处，步骤 4 之后其中 2 处随 `dispatch_result` 移到 `command.rs`，另 2 处留在 `run`） |
| `fn persist`、`fn forget`（166–196） | `controller/journal.rs` | 私有改为 `pub(super)`，供 `controller.rs` 调用 |
| `Controller` 结构和它的 `impl`：`probe_exit`、`settled_status`、`activate`、`retire`（197–369） | `controller.rs` | 无。`retire` 里两处 `crate::lifecycle::verify_gone` 改为 `lifecycle::verify_gone` |
| 测试 `reject_loop_and_outside_destinations`（371–399） | `plan.rs` | 只测 `scope`。测试名前缀从 `m1::tests::` 变为 `plan::tests::` |

`desktop_control.rs` 的拆分**只搬文档格式，不搬文件读写**：

- **移到 `policy/profile.rs`：**`Preferences`（含 `Default`、`validate`）、`Document`、`decode_policy`。
- **留在原处：**
  - `Save`、`profile_path`、`MAX`、`read_doc`、`view`、`save`；
  - `sanitized`、`export`、`handle`；
  - 两个测试。
- **可见性：**`Document`、`Preferences`、它们的字段以及 `Preferences::validate` 改成 `pub(crate)`，因为留下的 `read_doc`、`view`、`save` 要读写这些字段。
- **为什么不把 `save` 一起搬：**`save` 调用 `transition::atomic_replace`（`desktop_control.rs:160`）。搬进 `policy` 就会新增一条 `policy → transition` 的依赖，等于修一条反向依赖、又造一条。只搬格式，已经足够断开 `policy → desktop_control`。

`main.rs` 的拆分：

- **移到 `command.rs`：**`Command`、`default_port`、`Failure`、`emit`、`find`、`Observation`、`observe`、`Preflight`、`preflight`、`dispatch_result`、`dispatch`。
- **留在原处：**`Cli`、`run`、`main`。
- **可见性：**`main.rs` 和 `desktop_control.rs` 会用到 `Command`、`Failure`（含字段 `code`、`message` 和 `Failure::new`）、`emit`、`dispatch`、`dispatch_result`，这些改成 `pub(crate)`。它们原来在 crate 根，任何子模块都能看到；移进子模块后就不行了。
- **要一起移的两项：**`Command` 上的 `#[serde(default = "default_port")]` 是按名字查找函数的，`default_port` 必须和 `Command` 放在同一个模块里。

拆完后仍有两个小的互相引用：

- `Plan::validate` 调用 `kernel::validate`，而 `kernel` 又用 `Plan`；
- `plan.rs` 的 `scope` 调用 `managed::valid_resolver`。

消除它们要移动函数本身，不是纯文件移动，本轮保留。

### 3.3 拆完后谁还互相引用

Rust 允许同一 crate 里的模块互相引用，编译不会报错，问题出在读代码的人分不清谁是底层。

下表列出现在所有"A 引用 B、B 也引用 A"的模块对。数据来源是用脚本扫描各模块的 `crate::` 引用。父子模块之间的互相引用不算，比如 `managed_dns` 和 `managed_dns::wire`。

| 现在（7 对） | 为什么互相引用 | 拆完后 |
|---|---|---|
| `main.rs` ⇄ `desktop_control` | `main` 调 `handle`；`desktop_control` 调 `crate::dispatch_result` | 消失：`desktop_control` 改调 `command`，`command` 不引用 `desktop_control` |
| `desktop_control` ⇄ `policy` | `desktop_control` 用 `policy::Config`；`policy` 调 `decode_policy` | 消失：`decode_policy` 移进子模块 `policy::profile` |
| `m1` ⇄ `ingress` | `Controller` 持有 `Ingress`；`ingress` 用 `Plan` | 消失：`ingress` 改为引用 `plan` |
| `m1` ⇄ `lease` | `Controller` 调 `lease::release` 等；`lease` 用 `Plan` | 消失 |
| `m1` ⇄ `lifecycle` | `impl Controller` 分在两个文件里，互相调用 `load`、`verify_gone` | 变成父子模块 `controller` ⇄ `controller::lifecycle`，属于常规写法 |
| `m1` ⇄ `kernel` | `Controller` 调 `kernel::remove` 等；`kernel` 用 `Plan` | 变成 `plan` ⇄ `kernel`：`Plan::validate` 调 `kernel::validate`。保留 |
| `m1` ⇄ `m2` | `Controller` 持有 `Runtime`；`m2` 用 `Plan` | 变成 `plan` ⇄ `managed`：`scope` 调 `managed::valid_resolver`。保留 |

另有两个三方循环也随之消失：
- `m1` → `lifecycle` → `transition` → `m1`；
- `m1` → `ingress` → `query_bridge` → `m1`。

拆完后，`plan` 只被别人引用、自己只向下引用 `host`，外加上表保留的那两个校验函数。

## 4. 分步做法

每一步单独提交。每一步**只做**"移动文件 + 改 `mod`/`use`/`include_str!` 路径 + 必要的可见性修饰符"。这样做是吸取 `be0fe1d` 的教训：那个"重构"提交里夹带了 `kernel.py` 的热路径修改，被复审点名。

**每一步都不做：**清 clippy 告警、补测试、改注释措辞、改格式。真要做这些，另开提交。

各步的改动规模（估算）。"要人读的改动"指整块移动以外的行，整块移动的部分用 `git diff --color-moved` 机械核对：

| 步骤 | 移动或改名的文件 | 新建文件（内容全部从原文件剪切） | 要人读的改动 |
|---|---|---|---|
| 1 guest/、写法统一 | 7 个（6 个脚本、`probe/mod.rs`） | 无 | 约 23 行、10 个文件：6 处 `include_str!`、16 处 `#[path]`、`.gitignore` 1 行 |
| 2 `m2` → `managed` | 1 个 | 无 | 约 17 行 `use`、6 个文件 |
| 3 拆 `m1` | 2 个（`m1.rs` → `controller.rs`，`lifecycle.rs` 下沉） | `plan.rs` 约 140 行（含测试），`controller/journal.rs` 约 72 行 | 约 40 行、11 个文件：`use`、调用路径、2 处可见性 |
| 4 `profile`、`command` | 无 | `command.rs` 约 420 行，`policy/profile.rs` 约 60 行 | 约 30 行、5 个文件：`use`、调用路径、约 12 处可见性 |
| 5（可选）版本继承 | 无 | 无 | 约 15 行、4 个文件：两份 `Cargo.toml`、打包脚本及其测试 |

### 4.1 步骤 0：留基线（不提交）

在改动前记下以下内容，供后面每一步比对：

- `cargo check --locked --target x86_64-pc-windows-gnu --all-targets -p wsl-proxyctl --message-format short` 的告警清单，**按文件和消息记录，不只记条数**。今天实测：通过，9 条告警，全部在被拆的文件之外：
  - `ingress.rs` 2 条：第 31 行未使用的 `relay` 导入，第 1113 行的 `fetch_update` 弃用；
  - `managed_dns.rs` 7 条：第 2–5、24、27 行未使用的导入。
- 6 个 guest 脚本各自的 SHA-256。
- `python3 src/kernel_test.py` 的结果：54 项。
- 如果你同意装工具链：再记下 `cargo test --locked --target x86_64-pc-windows-gnu -p wsl-proxyctl -- --list` 的测试名清单。

### 4.2 步骤 1：guest 脚本归到 `src/guest/`，统一模块文件写法

三件事放在一个提交里：
- 移动 guest 脚本；
- `probe/mod.rs` 改成 `probe.rs`；
- 删掉多余的 `#[path]`。

前两件都要改 `probe` 的 `include_str!`，分开提交就得把同一行改两次。三件都只涉及"文件在哪、编译器去哪找"，不碰任何逻辑。

| 要改的地方 | 改动 |
|---|---|
| `src/kernel.rs:6` | `include_str!("kernel.py")` → `"guest/kernel.py"` |
| `src/query_bridge.rs:325` | `include_str!("kernel.py")` → `"guest/kernel.py"` |
| `src/probe/mod.rs:5`（移成 `src/probe.rs`） | `include_str!("probe.sh")` → `"guest/probe.sh"` |
| `src/m1.rs:213` | `include_str!("probe/exit_probe.py")` → `"guest/exit_probe.py"` |
| `src/m2.rs:87`、`:107` | `"probe/dns_probe.py"`、`"probe/https_probe.py"` → `"guest/…"` |
| `src/kernel_test.py` → `src/guest/test_kernel.py` | 文件内容不变，`import kernel` 照样可用（同目录） |
| `src/ingress.rs` 7 处、`src/managed_dns.rs` 4 处、`src/ipc.rs` 2 处、`src/query_bridge.rs` 2 处、`src/transition.rs` 1 处 | 删掉 `#[path = "…"]` 这一行，下一行的 `mod …;` 和它上面的 `#[cfg(…)]` 保留 |
| `scripts/build-desktop-windows.sh` | 不用改：它整体链接 `src`，`src/guest` 自然在内 |
| `.gitignore` | 加一行 `__pycache__/`。现在跑 `kernel` 测试就会在 `src/` 下生成未跟踪的 `__pycache__/kernel*.pyc`，起草本方案时实测出现过；换成 `discover` 后会生成在 `src/guest/` 下 |

文档里会失效的命令：`python3 src/kernel_test.py`（handoff 和第一份复审）、`sh -n src/probe.sh`（M0 记录）。新命令是：
- `python3 -I -m unittest discover -s src/guest`
- `sh -n src/guest/probe.sh`

旧文档按 3.1 节对照，不回头改。

**已实测：**
- 把 `kernel.py` 和改名后的 `test_kernel.py` 复制到临时目录的 `src/guest/`，运行 `python3 -I -m unittest discover -s src/guest`，54 项全部通过。
- 把整个 `src/` 复制到临时目录，删掉全部 16 处 `#[path]`，再跑一遍 Windows 目标的 `cargo check --all-targets`：通过，告警还是那 9 条，只有行号平移。
  - 这次检查覆盖了全部 16 处：`#[cfg(windows)]` 和 `#[cfg(test)]` 下的模块在这个目标和 `--all-targets` 下都会被加载。
  - 如果哪一处其实不多余，编译器会直接报找不到文件。

这 16 处的来历：
- **`4b159ab`：**ingress 的 5 个子模块文件当时平铺在 `src/` 根目录，需要 `#[path]` 才能把它们挂到 `ingress` 下面，那时这 5 处是必要的。
- **`be0fe1d`：**
  - 把文件挪进 `src/ingress/` 等子目录时，只改了这 5 处的路径，没有删掉属性；
  - 又照这个样子，给新拆出来的 11 个子模块也写了 `#[path]`。

从 `be0fe1d` 起，16 处全部多余。

### 4.3 步骤 2：`m2.rs` → `managed.rs`

纯改名，要改的 `use` 有：

- `main.rs`：`mod m2` 一处，`m2::` 4 处；
- `m1.rs:3`、`:48`；
- `lifecycle.rs:6`；
- `ingress.rs`：7 处 `crate::m2::Runtime`；
- `ingress/tcp.rs:14`；
- `ingress/udp_pump.rs:115`。

测试名前缀从 `m2::tests::` 变为 `managed::tests::`。

### 4.4 步骤 3：拆 `m1.rs`，下沉 `lifecycle.rs`

按 3.2 节的表执行。要改的引用：

- `crate::m1::Plan` → `crate::plan::Plan`：
  - `kernel.rs`；
  - `lease.rs`（两处：Windows 实现和非 Windows 桩）；
  - `query_bridge.rs`；
  - `ingress.rs`；
  - `transition.rs`（`transition/tests.rs` 经 `use super::*` 拿到 `Plan`，自动跟随）；
  - `managed.rs`。
- `m1::Controller` → `controller::Controller`：`desktop_control.rs`、`main.rs`。
- `lifecycle::checked`：`main.rs` 两处。
- `lifecycle.rs` 头部的 `use crate::m1::{self, Controller, Plan}` 改成 `use super::{journal, Controller}` 和 `use crate::plan::Plan`。

### 4.5 步骤 4：抽出 `policy/profile.rs` 和 `command.rs`

按 3.2 节的表执行。这一步修掉两处方向反了的依赖：

- `policy.rs:69` 的 `crate::desktop_control::decode_policy` 改成 `profile::decode_policy`。这样一来，`profile` 是 `policy` 的子模块，父子模块互相引用属于常规写法。
- `desktop_control.rs:274` 及附近的 `crate::dispatch_result`、`crate::Command`、`crate::Failure` 改成 `crate::command::…`。

做完后 `main.rs` 约 160 行：模块声明、`Cli`、约 105 行的 `run`（5 种进程模式），以及 `main`。

### 4.6 步骤 5（可选）：workspace 版本继承

根 `Cargo.toml` 增加 `[workspace.package]`（`version`、`edition`、`publish`），两个包都改为 `version.workspace = true` 这类继承写法。`serde_json` 放进 `[workspace.dependencies]`。

**连带改动：**

- `scripts/package-windows.py:95-96` 现在逐个读两份清单的 `["package"]["version"]`。改成继承后，读到的值是 `{"workspace": true}`，不是 `"0.1.3"`，发布会被拒绝。要改成读根清单的 `["workspace"]["package"]["version"]`，或者删掉这项文本检查，只保留第 97–99 行的 `cargo metadata` 版本检查（继承写法会被它正确解析）。
- `scripts/test_package_windows.py` 要相应调整。
- `desktop/Cargo.toml` 有改动，所以这一步必须跑一次桌面端构建。

**收益：**发布要求"控制器和桌面端同版本成对"：打包脚本检查两份清单的版本都等于发布版本，`release.json` 记为 `same declared version`。继承之后，这一点由结构保证，不再靠人记得改两处。

**与桌面重构的交集：**[`desktop-gpui-ui-refactor.md`](desktop-gpui-ui-refactor.md) 第 7 节建议把桌面端的 `serde_json` 从 `cfg(windows)` 依赖挪成普通依赖。两件事改的是同一行，谁后做谁顺手调整。

### 4.7 每一步都不受影响的耦合（已核对）

- `scripts/build-desktop-windows.sh` 只复制两份 `Cargo.toml` 和 `Cargo.lock`，并软链 `src`、`desktop/src`。步骤 1–4 不新增根级文件，也不在 `src/` 之外放源码，所以不受影响。这也是 guest 脚本放 `src/guest/` 而不放仓库根 `guest/` 的原因。
- `scripts/package-windows.py` 读 `ROOT/Cargo.toml`、`ROOT/desktop/Cargo.toml`、`ROOT/packaging/windows`，只有步骤 5 涉及。
- `src/ipc/windows.rs:270` 写死同目录的 `wsl-proxyctl.exe`；包名和 exe 名不变，所以不受影响。
- 文档里的测试过滤条件 `cargo test … query_bridge::`、`ingress::`、`transition::`、`managed_dns::` 对应的模块都不移动，继续有效。
- 桌面端只用 `wsl_proxyctl::ipc::{request, ensure_daemon}`，`ipc` 不移动。

## 5. 不做的，以及理由

### 5.1 不改成虚拟 workspace，不建 `crates/` 目录

改成虚拟 workspace 意味着把整个 `src/` 搬到 `crates/wsl-proxyctl/src/`，下面这些都要跟着改：

- `build-desktop-windows.sh` 的复制和软链；
- `package-windows.py` 的清单路径；
- README 和 M0–M5 记录里的 `cargo build --locked --release`、`.\target\release\wsl-proxyctl.exe` 用法（`target/` 位置不变，但所有 `src/…` 路径都会失效）。

两个 crate 的规模还用不着这套布局，Cargo 也没有要求。

### 5.2 不把控制器逻辑搬进 `lib.rs`

Rust Book 12.3 建议把逻辑放进 `lib.rs`，目的是可测试。本项目在 bin 目标里已经有约 100 项单元测试，这个目的已经达到了。

更要紧的是，`lib.rs` 是桌面端链接的面。把控制器放进去，桌面端就能绕过后台直接调用 `Controller`。这违背了[接管架构](../arch/README.md)里的"单目标约束由 Windows 后台执行，不依赖窗口是否打开"。现在"lib 只导出 `ipc`"是一条有用的边界，应该保留。

所以只采纳 12.3 的一半：把分发逻辑移出 `main.rs`，但仍留在 bin crate 里。

### 5.3 不拆出独立的 IPC crate

拆出来的好处：桌面端不必再依赖整个 `wsl-proxyctl` 包，也就不会顺带编译 `clap`、`native-tls` 等依赖。

代价：
- 构建脚本要多复制一份清单、多链接一个目录；
- 打包脚本的清单列表和许可证清单要跟着改。

现在没有人因为这一点受影响。**以后什么时候值得拆：**如果要写针对控制器公开接口的集成测试（`tests/`），就得先把控制器放进 lib，这时才需要先拆出 IPC crate，保证桌面端看不到 `Controller`。

### 5.4 不继续拆核心编排

`ingress.rs`（1,148 行）、`query_bridge.rs`、`managed_dns.rs`、`transition.rs` 的主体不动。

上一轮的 [`src-structure-refactor.md`](src-structure-refactor.md) 已经说明：再拆这些文件，要同时改动较多私有可见性和生命周期边界。本方案沿用这个结论。

本方案也要放宽一些可见性，全部列在 3.2 节，都是"文件拆开后，原来同文件、同 crate 根能看到的项"。数据面和 DNS 的私有项一个都不放宽。

### 5.5 不动 `scripts/` 和 `packaging/`

`scripts/` 混放了 bash、C、Python 和测试，但总共只有 5 个文件，而且 M4/M5 执行记录里的命令直接引用这些路径。

把 `package-windows.py` 改成可导入的 `package_windows.py`，能省掉测试里的 `importlib` 绕路，但会让 M5 发布记录里的命令失效。不值得。

### 5.6 `transition::atomic_replace` 的位置

这是一个通用的"原子替换文件"工具函数，却放在 transition 状态机模块里，桌面策略保存也借用它。位置不理想，但只有两个调用方，搬走只增加改动量，本轮不动。

## 6. 不能变的运行时契约

重构只改源码组织。下面这些名字以字符串形式写在代码里，或者已经落在用户磁盘、guest 规则里，**一个都不改**，即使它们带着 `m1`/`m2`/`m3` 字样：

| 契约 | 位置 | 为什么不能动 |
|---|---|---|
| 恢复日志 `m1-active.json`，临时文件 `m1-{cookie}.tmp` | 现 `m1.rs:126`、`:171` | 进程崩溃后的恢复依赖它；安装器和 M5 文档要求"不手删恢复日志"，升级时可能正带着活动日志 |
| 切换日志 `m3-operation.json` | `transition.rs:11` | 同上 |
| 桌面策略 `desktop-policy.json`、诊断 `diagnostics-*.json` | `desktop_control.rs` | 用户已有的保存文件 |
| `Plan` 的全部 serde 字段名和属性 | `m1.rs:12-27` | 恢复日志的格式，使用 `deny_unknown_fields` |
| iptables 链前缀 `wsl-proxyctl-m1:`、`wsl-proxyctl-m2:`，链名 `WPM2G_` | `kernel.py:503` 等 | 用来识别并精确删除本实例已经装在 guest 里的规则 |
| 预检标记 `wsl-proxy-m0-v1` | `probe/mod.rs:87` | guest 侧协议 |
| 线程名 `m1-ingress`、`m1-tcp`、`m2-dns-udp` | `ingress.rs` | 不是契约，但诊断和日志里会出现，改了没有收益 |
| CLI 子命令和参数、IPC JSON 的 `command` 取值、退出码 | `main.rs` 的 `Command` | M0–M5 文档、桌面端、安装器都依赖 |
| 包名、exe 名、`wsl_proxyctl::ipc` 的 `request`/`ensure_daemon`/`serve` | `Cargo.toml`、`ipc.rs` | 桌面端和发布脚本依赖 |
| 6 个 guest 脚本的内容 | `src/guest/` | 必须逐字节不变；内容一变，就是 guest 行为变了 |

## 7. 验证门槛

**合并门槛**（每一步都要过；除最后两行外，都能在这台机器上跑）：

| 检查 | 通过条件 | 适用步骤 |
|---|---|---|
| `cargo check --locked --target x86_64-pc-windows-gnu --all-targets -p wsl-proxyctl --message-format short` | 通过；告警按"文件 + 消息"逐条和基线一致，不新增，也不消失。行号允许因 `use` 行增减而平移。步骤 2、3 要改 `ingress.rs` 的 `use crate::m1`/`m2` 行，不得顺手删掉第 31 行未使用的 `relay`，那属于清告警 | 全部 |
| 非 Windows 分支（`#[cfg(not(windows))]`，例如 `lease.rs:190` 起的 `unsupported` 桩） | **本机没有覆盖。**Windows 目标的 check 不编译这些分支；Linux 本机 check 被 `openssl-sys` 挡住（缺 OpenSSL 开发包）；改用已装的 `aarch64-apple-darwin` 目标离线 check 也失败（缺 `core-foundation` 等 crate 源码，今天实测）。补法需你同意，二选一，都没验证过：装 `libssl-dev` 后在 Linux 跑 `cargo check`；或者 `cargo fetch` 拉取 crate 后用 macOS 目标 check。不补的话，步骤 3 改 `lease.rs` 桩代码时只能靠人工核对 | 步骤 3（改 `lease.rs` 桩） |
| `git diff -M --stat` | 移动的文件显示为 rename | 全部 |
| `git diff -M --color-moved=zebra` | 除 `mod`/`use`/`include_str!` 路径和可见性修饰符外，没有新增或删除的代码行；整块移动的代码在移动标记内没有改动 | 全部 |
| guest 脚本 SHA-256 | 和基线一致 | 步骤 1 |
| `python3 -I -m unittest discover -s src/guest` | 54/54 | 步骤 1 起 |
| `sh -n src/guest/probe.sh` | 通过 | 步骤 1 起 |
| `python3 -I scripts/test_package_windows.py`，以及 `cargo metadata` 中两个包的版本 | 测试 2/2 通过；两个包都是 `0.1.3`；`Cargo.lock` 无变化 | 步骤 5 |
| `cargo test --locked --target x86_64-pc-windows-gnu -p wsl-proxyctl`（**需工具链，命令未在本机验证**） | 测试数和基线相同（上次记录 101）；测试名只在模块前缀上变化，且符合 3.2 节和 4.3 节的映射。`build-desktop-windows.sh` 本身只构建、不跑测试；跑测试前要像脚本那样，把工具链加进 `PATH`，并导出 `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER`。测试 `.exe` 经 WSL 互操作执行 | 全部 |
| `scripts/build-desktop-windows.sh`（**需工具链**） | 桌面端和控制器都能构建 | 步骤 5；步骤 1–4 合起来至少跑一次 |

最后两行要用 `build-desktop-windows.sh` 的那套 mingw 工具链。这个脚本会用 `apt-get download` 下载 mingw 包，用 `curl` 下载 gpui 源码。这台机器目前没有这套工具链，也没有 OpenSSL 开发包，所以 Linux 本机的 `cargo test` 也跑不起来。**是否下载由你决定。**不下载的话，这两项要在 Windows 或装好工具链的机器上补跑，补跑前不要合并步骤 3、4。

**发布门槛**（不是合并门槛）：重构后的二进制和 0.1.3 不是同一份。打包前按 [`project-review-8ce39d8.md`](project-review-8ce39d8.md) 的建议 1：

- 在 Windows 上重跑 M4 桌面冒烟：打开 → 选择 → 预检 → 启动 → 关窗 → 重开 → 停止；
- 在实验发行版上重跑 M3 的启停和崩溃恢复；
- 额外验一次"0.1.3 留下的活动恢复日志能被新二进制正确读出并恢复"，直接证明 `Plan` 的格式没被移动破坏；
- 升版本号。

重构本身不升版本号。

## 8. 仓库级文件和文档

| 项 | 现状 | 处理 |
|---|---|---|
| `README.MD` 扩展名大写 | 仓库里其他文档都叫 `README.md`；handoff 有一处链接写的是 `../../README.MD`；`AGENTS.md` 的正文写的是 `README.md`。Cargo 只自动识别 `README.md`/`README.txt`/`README`，但本项目 `publish = false`，没有实际影响 | **报负责人**。我倾向于改成 `README.md`，同时修掉 handoff 里那一处链接；收益只是一致性，优先级低 |
| `docs/clash链式代理教程.docx` | 没有任何文档引用，也不属于 arch/discussions/plans 中的任何一类（第一份复审第 9 条） | **报负责人**，不在本方案里处理 |
| `AGENTS.md` 提到的 `docs/contracts/` | 目录不存在（第一份复审第 3 条） | **报负责人**。按 `AGENTS.md` 的约定，改文档体系属于设计变更 |
| `docs/plans/` 里的旧源码路径 | M0 的 `src/probe.sh` 在 `be0fe1d` 后就已失效；本方案执行后，M1/M3 里的 `src/m1.rs`、`src/lifecycle.rs` 等也会失效 | **不改**，执行记录保持原样，用 3.1 节的对照表 |
| `docs/discussions/` 里讨论、复审、交接、重构总结混放 | 共 10 份，命名能区分各自的类型 | 不改 |
| `scripts/`、`packaging/windows/` | 见 5.5 | 不改 |
| `.gitignore` | 只忽略 `/target/` 和 `/.env`，Python 测试生成的 `__pycache__/` 没被忽略 | 步骤 1 顺带加 `__pycache__/` |
| `desktop/` | 已经是 `app.rs` + `app/` 的新写法 | 内部结构按 [`desktop-gpui-ui-refactor.md`](desktop-gpui-ui-refactor.md) 第 7 节处理；本方案的步骤 1–4 不碰桌面端 |

## 9. 和已有文档的关系

- **[`src-structure-refactor.md`](src-structure-refactor.md)**（`be0fe1d`）把低耦合的子职责移进子目录，有意把核心编排留在根模块。本方案不推翻这个结论，不拆核心编排，只做两类事：
- **处理那一轮没碰的东西：**里程碑命名、`Plan` 的位置、两处反向依赖。
- **收尾那一轮留下的东西：**
  - 它建的 `probe/` 目录装进了不属于 `probe` 的脚本；
  - 它保留了 `probe/mod.rs` 的旧写法；
  - 它搬文件时只改了 `#[path]` 的值，没有删掉这些属性。

  这三处都在步骤 1 处理。
- **[`desktop-gpui-ui-refactor.md`](desktop-gpui-ui-refactor.md)** 第 7 节负责桌面 crate 的内部结构，与本方案只在 `serde_json` 依赖声明上有交集（4.6）。
- **两份复审：**本方案不修复其中任何一条行为问题（H1、M1–M9、N1–N6 等）。这些修复要另开提交，并且不能和移动文件的提交混在一起，否则移动是否完整就无法核对。

## 10. 需要负责人拍板

每项都给了默认选项，同意默认就不用逐项回复。

1. **是否执行，从哪一步开始。**默认：执行步骤 1–4，按顺序做，每步一个提交。
2. **是否下载 mingw 工具链来跑 Rust 测试和桌面构建。**默认：下载，存放在 `build-desktop-windows.sh` 默认的 `/tmp/wsl-proxy-desktop-build`。不下载的话，步骤 3、4 合并前要在别处补跑。
3. **模块名。**
   - 默认 `controller`，不用 `session`。原因：`Session` 已经是一个 CLI 子命令（持锁读取 JSON 行命令的进程模式），再用作模块名会混淆。候选名：`owner`。
   - `m2` 默认改为 `managed`，与状态里的 `forwarding_managed` 一致。候选名：`runtime`。
   - 新模块默认叫 `command`。它和 `Cli.command` 字段、`run(command)` 参数、JSON 的 `"command"` 标签同名，但这些名字指的都是同一个东西，也就是这个模块里放的 `Command` 类型。`session` 不一样，它指的是另一个概念（进程模式），所以前者可以接受，后者不行。`lease.rs` 里的 `std::process::Command` 不会引用这个模块，不冲突。如果仍嫌混淆，候选名：`dispatch`。
4. **步骤 5 做不做。**默认：本轮不做，等下次发布前顺手做。
5. **第 8 节"报负责人"的三项。**默认：本方案不处理。
