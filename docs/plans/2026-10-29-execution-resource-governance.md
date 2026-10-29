# Execution and resource governance implementation plan

**Goal:** Integrate the approved core execution capabilities into ARTEX and prevent local workloads exhausting the server.

**Architecture:** Keep Norma, PostgreSQL, the existing permission hooks, independent finding verification and manual pause/cancel barriers. Add one shared resource governor at worker admission and costly tool entry, bounded execution records and artifact manifests. Enforce descendant resource ceilings through the existing systemd/Docker deployment boundaries; admission alone cannot contain already running or detached children.

**Tech stack:** Go standard library, existing x/sys, React dashboard, cgroup v2/systemd and Docker Compose.

## Decisions and acceptance

- Display-only monitoring cannot prevent exhaustion. Per-command polling alone misses detached children. Use host/container pressure admission plus OS service/container ceilings. No extra monitoring database or local embedding model.
- Sample CPU deltas, available memory and the data filesystem every two seconds. Linux also measures the effective memory cgroup (including ancestors). Invalid/stale samples block new costly work. Hysteresis prevents rapid pause/resume oscillation. Bounded history and transition alerts avoid unbounded monitoring cost.
- Global worker/tool leases are atomic and context-aware. Pressure never changes user pause/cancel states or marks an intent failed. Read/report/stop tools remain usable. Tool lease completion does not mean background execution completion.
- Record tool return/error/cancellation/timeout separately from vulnerability verification or goal attainment. Preserve the SDK's existing task-owned background manager and session cleanup. Do not transplant CyberStrikeAI's default `EvidenceVerified=true` behavior.
- Continue deterministic intent transcripts and include bounded, non-symlink artifact inventories on continuation. File existence is a reference, never success evidence. Avoid automatic replay of human-stopped work.
- Bound local Python output and return actual process failure rather than a successful text result containing an exit error; kill owned process groups on timeout/cancel.
- Research open corpora with source, version and license provenance. Corpus retrieval must not execute commands or treat document instructions as trusted agent instructions. Full RAG infrastructure is outside the approved core scope.

## Implementation sequence

1. Create `resourceguard/` policy, samplers and deterministic tests (pressure, stale/error, hysteresis, concurrency, cgroup parsing). Configure through `config/config.go` and `config.example.json`.
2. Integrate `server/resources.go`, engine admission and `agent/execution_governance.go`. Test blocked calls never reach handlers; cleanup/reporting are available under pressure; execution outcomes stay distinct.
3. Add bounded artifact continuation in `agent/artifact_manifest.go`; test file/symlink/count/size limits. Improve `server/customtool.go` subprocess lifecycle with `execution/` and real exit-status tests.
4. Add authenticated resource API and dashboard panel; show metrics, pressure reason, active leases and recent transition alerts. No overlapping polling.
5. Enable service/container CPU/memory/PID ceilings and whole-service termination. Document actual deployment activation, limitations and knowledge-source shortlist in `docs/RESOURCE-GOVERNANCE.md` and `docs/KNOWLEDGE-SOURCES.md`.
6. Run targeted Go tests using D: build/temp caches, then backend compilation, Linux cross-compilation and frontend type checking when dependencies are available. Never run database tests against an unidentified DSN or deliberately exhaust the host.

## Scope limits

An API tool return does not prove a remote process stopped. These changes do not assert remote kill confirmation, vulnerability validity or goal success. New deployment limits require service/container recreation; repository edits do not change the user's running server. Final verification must distinguish deterministic simulation from a deployed load test.
