# AGENTS.md

给在这个仓库里干活的 Coding Agent 看的规矩。

## 文档写作规矩

- 架构文档（`docs/arch/`）只写现行设计和最终结论，不写历史，也不写决策编号（`README.md`「文档导航」）。
- 讨论记在 `docs/discussions/`；定下来的结论并入 `docs/arch/` 的对应文档，不另起新文档；每条决策登记在 `docs/decisions.md`，被取代的保留编号并注明取代者（`README.md`「文档导航」；03；`docs/decisions.md` 开头）。
- 审查记录（项目审查、复审、Rust 代码审查、界面审查）放在 `docs/review/`，不放进 `docs/discussions/`（维护者约定）。
- `docs/discussions/` 和 `docs/review/` 的文件名写成 `日期-类别-内容.md`，第三段按文档内容命名，例如 `2026-11-24-项目审查-fake-ip与DNS及住宅隧道池.md`；不用提交号，审查对应的提交号写在正文开头（维护者约定）。
- 实现过程中定下来的决定先记在 `docs/plans/m0/README.md` 这类执行记录里，最后并进 `decisions.md`、`docs/arch/`、`docs/contracts/`（`docs/plans/m0/README.md` 开头）。
- 文档、注释、测试数据里举例不用真人的名字，用角色或虚构的名字（维护者约定）。
- `docs/arch/` 和 `docs/decisions.md` 的改动是设计变更，不要在实现任务里顺手改；发现文档缺口或不一致，报给负责人。

## 构建与验证规矩

- 不管在 WSL 里还是在 Windows 宿主机上改代码，最终的编译、测试、运行都在 Windows 上、用 Windows 的 Rust 工具链完成，构建的必须是同一份工作区代码（从 WSL 触发时用 `wslpath -w` 换算仓库路径）。只有这样得到的结果才能写成「已验证」「已通过」（维护者约定）。
- 原因：控制器和桌面端都是 Windows 程序，`src/` 里多个文件的 `cfg(windows)` 代码在 Linux 上不参与编译，WSL 里通过说明不了 Windows 版本能编译、能跑。
- WSL 里的 `cargo build`/`cargo test`、`--target x86_64-pc-windows-*` 交叉编译、`scripts/build-desktop-windows.sh` 只算开发中途的检查，不算最终验证。
- 发布打包同样在 Windows 上做：进包的 EXE 必须是 Windows 上编译出来的，`scripts/package-windows.py` 也在 Windows 上运行；WSL 交叉编译的 EXE 不能进发布包（维护者约定）。
- 构建命令用现有文档里的原生 Windows 命令（`README.md`「从源码构建」；`docs/plans/m4/README.md` 原生 Windows 构建；发布包以 `.github/workflows/release.yml` 为准）。
- 调不到 Windows（interop 报错、Windows 侧缺工具链）就停下，如实报告「未在 Windows 验证」，把要在 PowerShell 里跑的命令交给用户，不要拿 WSL 的结果代替。

## 发布规矩

- GitHub Releases 上的发布信息全部用中文：tag 注释、Release 正文的每一节，包括「变更」。产品名、文件名、命令、版本号、提交号这类原样保留（维护者约定）。
- 「变更」取自根目录 `CHANGELOG.md` 里这一版的一节：上一个 `v*` tag 以来每个提交（合并提交除外）一条中文说明，带提交号，和改版本号放在同一个提交里写好。缺条目或某条没有中文，试跑和发布都会失败（`scripts/release-notes.py`）。提交信息不受这条影响。
- Release 正文不放「构建」和「发布前的检查」两节，它们只写进 Actions 运行的摘要页（维护者约定；`docs/plans/m5/README.md` 发布流水线第 7 步）。
