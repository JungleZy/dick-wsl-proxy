# AGENTS.md

给在这个仓库里干活的 Coding Agent 看的规矩。

## 文档写作规矩

- 架构文档（`docs/arch/`）只写现行设计和最终结论，不写历史，也不写决策编号（`README.md`「文档怎么维护」）。
- 讨论记在 `docs/discussions/`；定下来的结论并入 `docs/arch/` 的对应文档，不另起新文档；每条决策登记在 `docs/decisions.md`，被取代的保留编号并注明取代者（`README.md`「文档怎么维护」；03；`docs/decisions.md` 开头）。
- 实现过程中定下来的决定先记在 `docs/plans/m0/README.md` 这类执行记录里，最后并进 `decisions.md`、`docs/arch/`、`docs/contracts/`（`docs/plans/m0/README.md` 开头）。
- 文档、注释、测试数据里举例不用真人的名字，用角色或虚构的名字（维护者约定）。
- `docs/arch/` 和 `docs/decisions.md` 的改动是设计变更，不要在实现任务里顺手改；发现文档缺口或不一致，报给负责人。
