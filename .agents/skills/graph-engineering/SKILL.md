---
name: graph-engineering
description: >
  Continuous autonomous engineering loop for the current repository
  (OBSERVE, MODEL, EVALUATE, SELECT, EXECUTE, VERIFY, LEARN, REPEAT),
  backed by a typed knowledge graph (RIL) as cross-session memory.
  Use when the user wants the agent to keep iterating on the repo by
  itself, asks for autonomous/continuous engineering mode, "graph
  engineering", "loop engineering", "keep improving the repository",
  "feature evolution", "功能演进", or wants issues tracked as typed nodes
  with weighted priority scoring. Covers graph schema and
  lifecycle, cross-session loading, concurrency locking, scoring,
  deep-dive budgets, human-intervention boundaries, quality-convergence
  stop conditions, a feature-evolution mode (see §11), and a
  converged-idle QUIESCE so the loop parks instead of running idle rounds.
---

# Graph Engineering（长期自主工程循环）

## 运行总览

作为长期运行的 Autonomous Engineering Agent，目标不是完成某个预先定义的任务，而是持续自主推进当前 Git 仓库，使项目在每一轮迭代后都变得更正确、更稳定、更安全、更高性能、更易维护。

默认行为：**OBSERVE → MODEL → EVALUATE → SELECT → EXECUTE → VERIFY → LEARN → REPEAT**。
除非触发"人工介入边界"（见第 9 节），不等待确认，不询问"是否继续"。

**运行模式**：引擎有且仅有两种运行模式，共享同一 RIL schema 与骨架：

- **质量收敛模式**（默认）：第 1-8、10 节，反应式 —— 修 bug、还技术债、加固、性能优化；致力于让仓库
  正确、稳定、安全、可维护（引导到第 10 节停止条件）。
- **功能演进模式**（第 11 节）：第 10 节 bug 收敛条件全部满足后，若存在"功能演进已启用"的 decision
  （operator 指令，或用户明示 roadmap），引擎**不停止**，切换为主动交付用户可见的新能力。

两种模式差异仅在 SOURCE（功能/问题从哪来）与验收强度（功能端到端 + 用户可验证）；OBSERVE/EXECUTE/
VERIFY/LEARN 与图谱写入规则完全一致。切换以不可变 decision 记录在图中。

**核心不变量：收敛即停表（QUIESCE），不空转。** 引擎的目标是让仓库收敛到"正确、稳定、可维护"
的状态，**不是"永远产出提交"**。两种模式、任意一轮，一旦进入"无高价值工作可做"的静止态
（判定见第 10 / 11.5 节），就写一条 `converged-idle` decision 并**停止再发仅做轮次拨号的
chore 提交**。重新激活只来自新的 operator 指令（supersedes decision）或真实外部信号（新 issue、
实质变化）；激活首轮必须先复跑 VERIFY 确认真实基线绿，再继续。

## 1. OBSERVE

每轮基于仓库最新状态重新观察：

- 代码/架构/依赖
- git status/diff/log
- Issue/TODO/FIXME
- 测试/CI/构建
- 性能/稳定性/安全性/可观测性
- 文档
- 最近变更
- 已有工程知识（见 MODEL）

不要只找孤立 TODO；理解组件、API、数据流、测试、配置、运行时行为之间的关系。

## 2. MODEL 工程图谱

### 2.1 Schema（绑定到 RIL，而不是自然语言描述）

图谱是类型化的节点+边，不是自由文本笔记。RIL（repository-intelligence-layer）的 schema 由本技能自带的 CLI `.agents/skills/graph-engineering/scripts/ril.py`（下称 `ril.py`）强制校验，`.planning/ril/graph.json` 是唯一事实源；一律通过 `ril.py` 读写，**禁止手改 graph.json、禁止新建平行的知识存储**。完整 schema 与 CLI 清单以 `references/ril-schema.md` 为准；`.planning/ril/README.md` 只描述数据存储。

**节点类型**（每个节点必有 `id`, `type`, `status`, `version`, `created_at`, `updated_at`, `touched_round`；下表为各类型的额外必填字段）：

| 节点类型   | 额外必填字段                                                                                                            | 说明                                                                   |
| ---------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| component  | —                                                                                                                       | 模块/服务/文件级实体                                                   |
| issue      | —                                                                                                                       | 已识别问题（bug/风险/债务）                                            |
| hypothesis | `confidence`（0-1）                                                                                                     | 未验证的根因猜测                                                       |
| evidence   | `source`（commit hash / 测试名 / 文件行号），append-only                                                                | 支持或反驳某个 hypothesis 的具体观测（测试结果、日志、profiling 数据） |
| decision   | `rationale`、`alternatives_rejected`，不可变                                                                            | 已做出的选择                                                           |
| change     | `commit` hash                                                                                                           | 实际代码修改                                                           |
| task       | `category`（correctness/security/stability/critical-bug/core-feature/performance/test-quality/maintainability/dx/docs） | 可执行的下一步行动，带 priority_score（见 EVALUATE）                   |

**边类型**（有向，语义明确，禁止用无类型的"关联"边）：

| 边类型              | 允许的端点                                        | 语义                                              |
| ------------------- | ------------------------------------------------- | ------------------------------------------------- |
| depends_on          | task→task, component→component                    | 硬依赖                                            |
| causes              | issue→issue                                       | 根因/症状链接，标注是根因还是症状                 |
| blocks              | task→task                                         | 执行阻塞                                          |
| validates / refutes | evidence→hypothesis                               | 证据支持/反驳假设                                 |
| resolves            | change→issue                                      | change 修复 issue                                 |
| supersedes          | decision→decision                                 | 决策变更历史而不是覆盖                            |
| addresses           | task→issue                                        | task 处理某个 issue                               |
| located_in          | issue→component                                   | 问题所在位置                                      |
| part_of             | component→component                               | 子系统层级                                        |
| implements          | change→task                                       | change 交付 task                                  |
| governs             | decision→component/task                           | decision 约束目标                                 |

一个 hypothesis 在没有任何 validates/refutes 边之前，不得被 EVALUATE 当作 fact 使用。

**常用命令**（`ril.py` 即 `.agents/skills/graph-engineering/scripts/ril.py`）：

```bash
ril.py check                      # 一致性检查（孤立节点/循环/无证据 hypothesis）
ril.py tasks --top 10             # active task 按 priority_score 排序取 top-K
ril.py show --id <id> --hops 2    # 拉取节点及其 1-2 跳邻域
ril.py node add --type task --field category=correctness --field severity=...  # 建节点（id 自动分配 TASK-N）
ril.py node set --id <id> --expect-version <v> --field status=resolved         # 乐观更新，版本不匹配会报错
ril.py edge add --type addresses --from <task> --to <issue>                    # 建边
ril.py lock --id <task> --owner <instance> [--minutes 30]                      # 分布式锁
ril.py unlock --id <task>                                                      # 释放锁
ril.py round | ril.py stale --rounds 10                                        # 生命周期维护
```

### 2.2 生命周期与淘汰

- 每个节点有 status：`active` / `stale` / `resolved` / `superseded` / `abandoned`。
- 每轮 MODEL 阶段用 `ril.py round` 推进轮次；`ril.py stale --rounds 10` 把超过 N 轮（默认 10）未被触碰的 hypothesis/task 标记为 `stale`（不删除，保留审计轨迹），EVALUATE 阶段默认跳过 stale 节点，除非新证据重新激活它。
- decision 永不删除，只能被新 decision 通过 `supersedes` 边替代，保留决策演化历史。
- 图谱本身要定期（例如每 50 次 commit 或每周）跑一次 `ril.py check`（孤立节点、循环 depends_on、无证据 hypothesis、长期未闭环的 blocks 边），发现问题作为一个具体 task 提交处理，而不是无限累积。

### 2.3 跨 session 的加载策略

每次 agent 启动是全新 context，不能靠"重读整个图谱"来恢复状态，成本不可控。规则：

- 启动时用 `ril.py tasks --top K` 加载 `status=active` 的 task（按 priority_score 排序取 top-K），用 `ril.py show --id <id> --hops 2` 拉取这些 task 直接关联的 component/issue/hypothesis 子图（1-2 跳），以及最近 N 次 decision。
- 不做全图扫描，除非本轮任务明确是"图谱一致性检查"或"深度探索"（见第 8 节）。
- 如果某个 task 需要更大范围的上下文，允许按需扩展加载（跟着边走），但要在 LEARN 阶段记录"本轮实际使用的子图范围"，供后续 session 参考典型的加载半径。

### 2.4 并发语义（仅当多实例并行时生效）

> **单一实例（默认、常见）跳过本节全部锁与乐观更新**：直接顺序读写，无需 lock/unlock、
> 无需 `--expect-version`。本节只为"确有多个 agent instance 并行"的架构保留——若仓库
> 只有单一提交源与顺序轮次，就不具备多实例前提，锁是无意义的仪式。

若确实存在多个 agent instance 同时运行（Loop Engineering 并行架构）：

- 写入图谱前，对目标节点/边执行乐观锁：`ril.py node set` 必须带 `--expect-version <当前 version>`；版本冲突时 CLI 报错并把节点输出到 stderr，此时重新读取并 diff 合并，而不是覆盖。
- 两个 instance 不得同时对同一 component 下的代码发起 EXECUTE；开始 EXECUTE 前，用 RIL 分布式锁占用对应 task 节点：`python3 .agents/skills/graph-engineering/scripts/ril.py lock --id TASK-x --owner <instance_id>`（默认 30 分钟超时，过期自动释放），结束时 `python3 .agents/skills/graph-engineering/scripts/ril.py unlock --id TASK-x`。**不要**手写 `status=in_progress` 或 `owner=` 字段——RIL schema 没有这些字段，`ril.py` 会直接拒绝。
- evidence 节点只增不改，天然无冲突，鼓励优先通过增加 evidence 而不是编辑已有节点来记录新发现。

## 3. EVALUATE

用加权评分而非严格字典序判断优先级，每个 task 计算：

```text
priority_score = category_weight × severity × confidence × (1 / sqrt(effort)) × unlock_factor
```

- category_weight：正确性/安全性=10，稳定性/关键 bug=8，核心功能=6，性能=5，测试质量=4，可维护性=3，DX=2，文档=1（默认值，可按仓库调整）
- severity：影响范围 × 触发概率
- confidence：该 task 关联的根因判断有多少 validates 证据支撑，未经验证的 hypothesis 打折
- effort：预估实现成本，用于避免"为了刷分做琐碎高权重类别的事"
- unlock_factor：完成后解锁的下游 task 数量/价值，鼓励优先做能解锁后续工作的事

只有当新 task 的 priority_score 显著高于（默认 1.5x）当前正在做的 task 时才切换方向，避免频繁跳变；切换必须在 decision 节点记录原因。

## 4. SELECT

选 priority_score 最高且 `status=active` 的 task，一次聚焦一个主线。允许根据新证据切换，但受上面的切换阈值约束。

## 5. EXECUTE

正常仓库内工程操作（改代码、修 bug、加测试、重构、性能优化、错误处理、可观测性、依赖更新、配置、CI、文档、删除废弃代码）默认自主执行，只要限定在当前仓库且可通过 Git 回滚。

开始前：**单实例无需加锁**；仅当多实例并行时按第 2.4 节对 task 节点加锁。

## 6. VERIFY

运行测试/lint/formatter/类型检查/构建/benchmark/静态分析。失败时：分析根因 → 修根因 → 重新验证。

硬性禁止：删测试、跳测试、降低断言/阈值、注释失败用例、修改质量标准来制造"通过"。无法可靠修复时回滚本轮改动，并在图谱中把对应 hypothesis（如果修复基于某个根因假设）标记为 `refuted`，附上 evidence。

## 7. LEARN

按第 2.1 节的 schema 写入节点和边，而不是自由文本日志。区分 Fact/Hypothesis/Evidence/Decision 必须体现在节点类型上，不是靠文字语气区分。

Commit 时在 message 里引用相关 task/issue 节点 id，保证代码历史和图谱可以互相追溯。

## 8. 深度探索（无明显 TODO 时）—— 质量收敛模式的兜底

> 本节是**质量收敛模式**（反应式）的兜底扫描。功能演进模式不依赖本节，见第 11 节。

主动做 Repository Intelligence Deep Dive，寻找隐藏 bug、边界问题、并发问题、错误处理缺陷、资源泄漏、性能瓶颈、测试缺口、安全风险、架构耦合、技术债务，优先形成"证据 → 根因 → 修复 → 验证"闭环。

硬性预算约束：

- 单轮深度探索最多产出 3 个新 task 节点，否则说明范围没收敛，需要先合并/归类。
- 单次 commit 的 diff 不超过某个阈值（默认 300 行，特殊重构除外并需在 decision 中说明理由）。
- 若连续 2 轮深度探索新增 task 的 priority_score 均低于当前阈值（默认 3.0），停止深度探索，转入停止条件评估（第 10 节）——若评估通过且功能演进已启用，转第 11 节。

## 9. 人工介入边界

只有以下情况暂停等待人工确认：

- push 到 main/master 或强制 push
- 删除远程分支
- 正式发布版本或包
- 不可逆的生产环境操作
- 不可逆的数据删除或破坏性数据库迁移
- 需要访问无权限的秘密/凭据/敏感数据
- 明显超出当前仓库权限范围
- 无法合理回滚且可能造成重大外部影响的操作

## 10. 停止条件

满足全部以下条件才停止：

1. 图谱中不存在 `status=active` 且 priority_score 高于阈值（默认 3.0）的 task。
2. 所有 severity 高的 issue 节点，status 为 `resolved` 或有明确 decision 记录暂缓原因。
3. 最近一次 VERIFY 全绿。
4. 连续 2 轮深度探索无法产出高于阈值的新 task（见第 8 节）。
5. 图谱一致性检查（第 2.2 节）无未处理的孤立/循环节点超过 N 个。

否则继续 REPEAT，直到用户主动中止或以上全部满足。

> 第 1-5 条是**质量收敛**的停止条件。若功能演进已启用（存在对应 decision，见第 11 节），第 1-5 条全部
> 满足后并不整体停止 —— 而是切换进功能演进模式继续交付能力；功能模式下每轮结束仍须复核第 1-5 条
> 不变式未被破坏（回归护栏）。

**QUIESCE（停表）程序**：当第 1-5 条全部满足（或功能模式下第 11.5 节任一满足），且本轮
**未交付任何 `change`**、**没有新增 `priority_score ≥ 阈值(默认 3.0)` 的 task** 时：

1. 写一条不可变 `decision`：`converged-idle`，rationale 记录收敛证据与被拒绝的替代工作；
2. 停止 REPEAT——**不再发出仅轮次拨号的 `chore(ril)` 提交**；
3. 进入静止态。重新激活：出现新的 operator 方向（supersedes decision）、真实用户问题 / 新的
   高价值 issue、或仓库发生实质性变化时重启；但**重启首轮先复跑 VERIFY 确认真实基线绿**，
   未通过验证不得声称"恢复迭代"。

> 目的：堵住"任务全部 ≤ 阈值却仍在每轮发验证审计提交"的空转（曾发生：仅剩 1 个 0.81 分任务，
> 却持续刷到 round 100+）。停滞态本身是一个 `converged-idle` decision，不是缺陷。

## 11. 功能演进模式（Feature Evolution Mode）

> 本节是主动交付用户可见新能力的模式。仅当质量收敛（第 10 节）已达成**且**存在"功能演进已启用"的
> decision 时才进入；切换用不可变 decision 记录。

### 11.1 触发与切换

- 默认在质量收敛模式运行（第 1-8、10 节）。当第 10 节的 bug 收敛条件全部满足，且仓库存在
  `decision` 装载"功能演进已启用"（通常来自 operator 指令或用户明示 roadmap），引擎**不停止**，
  转入本节。
- 切换本身必须写一条不可变 `decision`：`rationale`（为什么在此阶段做功能 / 功能来源）
  与 `alternatives_rejected`（为什么不做别的）。切换不可逆，但可被新的 supersedes decision 中止回退。

### 11.2 功能来源（SOURCING）

功能候选按序优先，来自：

1. **operator 产品方向**：用户明示的 roadmap / 期望能力（最高优先级）；
2. **图谱 backlog**：`category=core-feature` 的 task 节点（含已记录未排期的功能）；
3. **差距分析**：对照现有功能面（公开页、admin、评论、搜索、SEO、导出、订阅、国际化、用户体系、
   分析面板……）找缺失或有明显短板的用户可见能力；
4. **使用信号**：来自 views / likes / comments / 搜索词等真实信号（若可观测）。

禁止凭空堆砌功能。每个候选必须一句话说清"为哪个用户、解决什么、为什么现在"，否则不进 SELECT。

**价值闸门（防琐碎化）**：候选必须**同时**满足最低线才进 SELECT：

- **用户价值**：解决一个**真实用户的、可感知**的问题（不是代码一致性/内部润色层面的修补）；
  验收标准须能在 1 句内描述。
- **范围**：能落成一个垂直切片且是**净增量**。把"缺一个选项 / 少一个按钮"级别的修补直接判
  `rejected`（记决策，不建 task）。

未过闸门的候选记为 `rejected` decision 并**计入停止条件**（见 11.5）。不要"退而求其次做更小的
同类"——那是补丁堆积的起点。

### 11.3 选择、范围与架构

- 每个功能先用一条 `decision` 固化：范围、目标用户、为什么现在、被拒绝的替代方案。
- 再建一条 `category=core-feature` 的 task，沿用 priority_score 排序；单轮只聚焦一个功能主线。
- **垂直切片**：一个功能一次端到端落地（后端 + 前端 + 测试 + 文档），不留半成品。
- 沿用 §8 diff 预算（默认 300 行/commit，特殊重构在 decision 中说明）；功能过大须拆 rounds，每轮
  交付可独立验证的切片。
- 涉及既有架构决策（缓存、认证、数据库）时，先读相关 supersedes decision 链，不得静默违背
  （如 DEC-004 多 worker 缓存、DEC-009 的 DDL 保持约束）。

### 11.4 验收（比质量模式更严）

功能是用户可见行为，VERIFY 须**同时**满足：

1. 单元/集成测试覆盖新契约与边界（§6 不变，禁削断言、禁删测试）；
2. **浏览器/UI 验证**：真实驱动页面确认功能可用（不是只看测试通过）；
3. 端到端（Playwright）覆盖关键用户旅程；
4. 回归护栏：每轮结束仍跑全量 VERIFY，确保功能演进不破坏既有质量收敛结果。

### 11.5 功能模式的停止条件

满足以下任一即停（不必继续 push 功能）：

1. 图谱中 `active` 的 `core-feature` task 已被 `change` 交付并验证完毕（backlog 空）；
2. operator 主动中止或改变方向（新增 supersedes decision）；
3. 连续 2 轮功能候选均因**未过价值闸门**被 `rejected`（见 11.2），无合适功能可做。

不满足时继续 REPEAT。任一功能轮结束后，仍须确认第 10 节 bug 收敛不变式未被破坏（回归护栏）。

> 当 1-3 任一满足、且本轮未交付任何 `change` 时，执行第 10 节的 **QUIESCE 程序**：写
> `converged-idle` decision，停止空转提交。不要陷入"没有功能可做却每轮发验证审计"的轮次空转。
