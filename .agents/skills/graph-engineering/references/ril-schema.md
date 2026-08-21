# RIL Schema & CLI Reference

Authoritative source: `.agents/skills/graph-engineering/scripts/ril.py`
(enforcement). `.planning/ril/README.md` only describes the data store.
Store: `.planning/ril/graph.json` (committed, single source of truth).

**All reads/writes go through the CLI
`.agents/skills/graph-engineering/scripts/ril.py` (referred to below as
`ril.py`). Never edit `graph.json` by hand and never create a parallel
knowledge store.** The CLI validates schema, edge typing, optimistic locking,
lifecycle, and consistency.

## Node schema

Every node carries `id`, `type`, `status`, `version`, `created_at`,
`updated_at`, `touched_round`.

| Type       | ID prefix | Extra required fields                                                             |
| ---------- | --------- | --------------------------------------------------------------------------------- |
| component  | `COMP`    | —                                                                                 |
| issue      | `ISS`     | —                                                                                 |
| hypothesis | `HYP`     | `confidence` (0..1)                                                               |
| evidence   | `EV`      | `source` (commit / test name / file:line); append-only; `confidence` defaults 1.0 |
| decision   | `DEC`     | `rationale`, `alternatives_rejected`; immutable                                   |
| change     | `CHG`     | `commit` hash                                                                     |
| task       | `TASK`    | `category` (see weights below)                                                    |

`status` ∈ `active | stale | resolved | superseded | abandoned`.
There is **no** `in_progress` status and no `owner` field.

## Edge types (directed, typed — no untyped edges)

| Edge       | Allowed pairs                  | Semantics                          |
| ---------- | ------------------------------ | ---------------------------------- |
| depends_on | task→task, component→component | hard dependency                    |
| causes     | issue→issue                    | root-cause / symptom link          |
| blocks     | task→task                      | execution blocker                  |
| validates  | evidence→hypothesis            | evidence supports hypothesis       |
| refutes    | evidence→hypothesis            | evidence contradicts hypothesis    |
| resolves   | change→issue                   | change fixes the issue             |
| supersedes | decision→decision              | decision history (never overwrite) |
| addresses  | task→issue                     | task works the issue               |
| located_in | issue→component                | where the issue lives              |
| part_of    | component→component            | subsystem hierarchy                |
| implements | change→task                    | change delivers the task           |
| governs    | decision→component/task        | decision constrains target         |

A hypothesis with no `validates`/`refutes` evidence must not be treated as
fact by EVALUATE (enforced by `ril.py check`).

## CLI commands

```bash
ril.py init                       # create the store
ril.py node add --type task --field category=correctness --field priority_score=... # add node (id auto-assigned TASK-N)
ril.py node set --id TASK-1 --expect-version 3 --field status=resolved   # optimistic update; mismatch aborts and dumps node to stderr
ril.py edge add --type addresses --from TASK-1 --to ISS-2
ril.py edge rm  --type addresses --from TASK-1 --to ISS-2
ril.py tasks --top 10             # active tasks sorted by priority_score (top-K)
ril.py show --id TASK-1 --hops 2  # neighbourhood load
ril.py lock --id TASK-1 --owner <instance-id> [--minutes 30]   # execution lock
ril.py unlock --id TASK-1         # release lock
ril.py round                      # bump loop counter
ril.py stale --rounds 10          # mark untouched hypothesis/task stale
ril.py check                      # orphans, cycles, evidence-less hypotheses
```

In this repo `ril.py` = `.agents/skills/graph-engineering/scripts/ril.py`.

Notes:

- `node set` requires `--expect-version` matching the node's current `version`;
  on mismatch it prints the node to stderr and exits non-zero — re-read and
  merge instead of clobbering.
- Locking writes `lock_owner` + `lock_until` (ISO-8601) and bumps `version`;
  expired locks are auto-released. Locking is the distributed-lock mechanism —
  do not hand-write `status=in_progress`/`owner` fields (ril.py rejects them).
- Decisions are immutable except `status`; evidence is append-only.
- Commit messages reference node ids, e.g.
  `fix(core): ... (RIL TASK-001, ISS-001)`.

## Priority scoring

```text
priority_score = category_weight × severity × confidence × (1 / √effort) × unlock_factor
```

`category` weights: correctness 10, security 10, stability 8, critical-bug 8,
core-feature 6, performance 5, test-quality 4, maintainability 3, dx 2, docs 1.
