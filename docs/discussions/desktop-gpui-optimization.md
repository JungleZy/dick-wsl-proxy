# GPUI 桌面端全量优化总结

## 范围

本轮只处理 `desktop/src/`、Windows 桌面构建脚本和本桌面端相关文案；不改变控制器 IPC 协议、WSL 规则、TCP/UDP 转发或凭据存储契约。

`main.rs` 与 `app.rs` 保持分离：`main.rs` 负责平台入口分发，`app.rs` 负责 Windows GPUI 编排。这样可以让非 Windows 构建停留在轻量入口，不把 GPUI 和 Windows API 扩散到跨平台入口。

## 最终模块结构

```text
desktop/src/
├── main.rs                 # 平台入口
├── app.rs                  # GPUI 应用初始化、主题、窗口
└── app/
    ├── backend.rs          # IPC worker、Job、Reply、后台操作类型
    ├── bootstrap.rs        # 窗口初始化、后台轮询、回复归并
    ├── actions.rs          # 校验、保存、启停、切换、凭据操作
    ├── state.rs            # Desktop 运行状态
    ├── model.rs            # 页面、输入、确认、UI 操作模型
    ├── theme.rs            # 视觉令牌
    ├── components.rs       # 无状态组件与格式化
    ├── chrome.rs           # 共用按钮、字段、路径摘要
    ├── views.rs            # Render 壳层、导航、确认栏、底栏
    ├── overview.rs         # 总览、目标/对照选择、预检
    ├── policy.rs           # 策略、DNS、直连例外、凭据
    └── diagnostics.rs      # 流量、DNS、连接记录、导出
```

每个模块都有 `//!` 职责说明。页面模块只负责页面布局；后台模块不创建 UI；无状态组件不读取 `Desktop`；操作控制器不拼接页面结构。

## 显示层改进

- 顶栏显示后台状态、最近观测时间、刷新和重连操作。
- 链路摘要固定展示：目标 WSL → 宿主代理 → 住宅出口 → DNS。
- 页面状态统一使用徽标和状态色：在线、未知、运行中、未保存、需要处理。
- 总览页明确区分：
  - 目标 WSL：实际准备接管的发行版。
  - 对照 WSL：只用于隔离检查，不接管流量。
- 预检结果分为通过、阻断项、目标身份、对照环境，避免把“选择”误显示为“已接管”。
- 策略页按连接解析、直连例外、凭据三个区域组织。
- 诊断页使用指标卡和结构化连接记录，记录数量保持有界。
- 高风险操作使用独立确认区，显示操作代数和重新检查提示。
- 底部提示区区分提示文本与后台活动状态。
- 文案改为短句和通用术语：
  - “见证”统一为“对照 WSL / 对照环境”。
  - “重新枚举”改为“刷新列表”。
  - “开始接管”改为“启动接管”。
  - “显式保存策略与选择”改为“保存策略”。
  - “能力预检”在按钮中简化为“运行预检”。

## 操作与正确性改进

- 目标、对照、端口、策略输入变化都会使旧预检失效。
- 保存的目标选择和当前草稿分别维护基线。
- 输入变更使用无 JSON 分配的字段比较，不再每次键入都完整构造 `draft()`。
- 目标和对照恢复到保存值后，脏状态可以恢复为干净。
- 高风险操作继续校验后台操作代数，避免确认旧状态。
- 后台变更失败后仍读取最新状态，不自动重放可能已生效的操作。
- 关闭窗口仍不发送停止命令。
- 凭据操作只在后台确认空闲时启用；秘密值不会进入输入框或界面。
- 状态未知时禁用接管操作，不把过期状态显示为绿色成功。

## 性能改进

- GPUI UI 定时器从 100ms 调整为 200ms，降低空闲轮询开销。
- 后台状态刷新仍保持 2 秒间隔。
- 网络 IPC 和后台操作继续运行在独立 worker，不阻塞 GPUI 渲染线程。
- 输入脏状态判断改为字段级、无完整 JSON 草稿分配。
- 诊断连接记录最多渲染 384 条，后台本身仍保持有界记录。
- 诊断页面只在 GPUI 状态变化时通知重绘；定时器本身不强制刷新静态页面。
- 页面职责拆开后，单个页面更新不会继续扩大主应用文件的编译和维护范围。

## 构建与验证

已执行：

```text
cargo check -p wsl-proxy-desktop
cargo test -p wsl-proxyctl --locked
bash -n scripts/build-desktop-windows.sh
cargo metadata --no-deps --format-version 1
git diff --check -- desktop/src scripts/build-desktop-windows.sh
```

控制器回归测试结果：

```text
IPC tests: 5 passed
controller tests: 102 passed, 0 failed
doc tests: 0
```

测试和 Windows 构建使用了临时解压的宿主工具链及 OpenSSL 开发文件，因为当前基础环境没有系统级 `cc`、`gcc`、`pkg-config` 和 OpenSSL 开发包；这些文件未写入仓库。

Windows GNU release 构建使用：

```text
scripts/build-desktop-windows.sh
```

脚本现在明确要求宿主 `cc` 和 `gcc`，因为 GPUI 的 Windows 资源编译会调用宿主 `gcc` 预处理资源文件。构建脚本仍使用独立 MinGW 目录、GPUI 固定版本和 HLSL bridge，不修改全局 Cargo 注册表或仓库锁文件。

已完成完整 Windows release 构建，产物为：

```text
wsl-proxy-desktop.exe  47,401,600 bytes
wsl-proxyctl.exe        4,526,659 bytes
```

GPUI、gpui-component、Windows 资源、桌面程序和控制器均完成 release 编译。

## 已知警告与边界

- GPUI 0.2.2 上游存在 `f32` 推断的 future-incompatible warning；未修改临时 GPUI 源码以外的仓库依赖。
- 控制器其他模块仍有已有的未使用导入和弃用 API warning；本轮没有扩大到无关控制器清理。
- 当前环境没有真实 Windows 桌面会话，因此完成的是 Windows GNU 编译验证，不是假称完成 HWND 截图或鼠标操作验收。
- 没有把“公网健康”“出口检测结果”或“DNS 启动时检查”扩展解释成持续线路保证。
- `rustfmt` 组件未安装；已执行 `git diff --check`、Linux Cargo 检查、控制器回归测试和 Windows release 编译。

## 结论

桌面端已从单文件实现细化为职责明确的 GPUI 模块树；显示层、操作反馈、脏状态判断、预检失效、后台轮询和构建入口均已收敛。Windows release 完整构建通过，剩余 warning 主要来自固定版本 GPUI 和控制器其他模块，不影响桌面目标生成。
