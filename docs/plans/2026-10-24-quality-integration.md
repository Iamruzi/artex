# 二开版质量整合 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 保留二开全部装配能力，补齐上游遗漏的质量改进。

**Architecture:** 从官方快照提取独立实现和小型修复，手工接入二开现有装配点。功能分别提交，实验能力默认关闭，工具管理保留用户选择。

**Tech Stack:** Go 1.26.3、norma v0.4.3、PostgreSQL、Next.js/React、TypeScript。

---

### Task 1: 鉴权与连接池

Files: `server/auth.go`, `server/auth_test.go`, `db/settings.go`, `db/settings_insert_test.go`, `db/db.go`, `web/src/app/(auth)/setup/page.tsx`。

1. 参考上游 a951e4a 的原子首设、密码校验与数据库错误测试，保留二开现有会话签发接口。
2. 在 settings 增加 InsertSettingIfAbsent，保留 DeleteSetting。
3. 给密码读取添加错误分支，给初始化和改密添加统一校验；首设只在 inserted 时签发会话。
4. setup 状态查询失败时不展示表单；添加连接池容量与寿命。
5. 执行 `go test ./db ./server`，区分数据库跳过和实际执行。
6. 提交本批次。

### Task 2: 静态列表页布局

File: `web/src/app/(main)/_components/main-content.tsx`。

1. 在详情页判断前去除尾斜杠，沿用上游 564096c 的实现。
2. 核对列表及详情路径；由前端类型与构建检查覆盖此小修。
3. 提交本批次。

### Task 3: 探索播报板

Files: `db/exploration.go`, `server/server.go`, `web/src/lib/{api,types}.ts`, `web/src/app/(main)/function/tasks/detail/{page.tsx,_tabs/broadcast-tab.tsx}`。

1. 从 e6ec569 提取 NodeFilter、NodesPage、NodesByIDs、EdgesTouching。
2. 提取 explorationNodes/nodeAnchoredAssets/csvValues 并接入现有路由。
3. 增加类型、API、页签与现有上游组件，保留二开所有其他页签和卡片。
4. 补充分页、检索、任务隔离的必要回归验证。
5. 执行 Go 相关包测试、TypeScript 检查及前端构建。
6. 提交本批次。

### Task 4: 可选 Worker 回看

Files: `agent/tools_insert.go`, `server/orchestration.go`, 相关工具绑定测试与文档。

1. 将上游三个回看工具接入可配置目录，确保默认仍遵循用户已有绑定。
2. 不运行强制重绑迁移，保留二开 confirm_fact 等工具。
3. 给新库提供明确的工具绑定入口并说明启用方式。
4. 检查 nil store、工具目录和二开 Worker 约束测试。
5. 提交本批次。

### Task 5: noa 默认关闭的实验接入

Files: `agent/noa.go`, `agent/{chat,mainagent,planner,worker}.go`, `server/{manager,server,task_llm}.go`, `web/src/lib/types.ts`, `web/src/app/(main)/system/settings/page.tsx`。

1. 移植上游最终 noa adapter helper 与各角色 resolver。
2. 接入 settings 读写和 UI，默认关闭；保留二开既有 resolver、超时与系统尾规则。
3. 增加关闭路径与接入回退等必要验证。
4. 运行受影响 Go 包测试与前端检查。
5. 提交本批次。

### Task 6: 集成审查

1. 检查与 361ae73 的差异中没有删除二开子系统、工具和 guard。
2. 运行 `go test ./...`、`go vet ./...`、`go build ./cmd/artex`，说明环境性跳过或失败。
3. 运行 `npx tsc --noEmit` 和静态前端构建。
4. 更新说明，记录已完成项、默认值、启用方法与验证边界。
5. 提交最终文档并向用户交付本地工作副本与结果。

## 执行结果

六项已实现，另恢复任务/企业范围上下文。定向 PostgreSQL 测试、核心保留子系统测试、类型/构建/vet 检查完成；27 项领域工具目录及默认绑定与基线完全一致。完整测试并非全绿，失败及视觉验收限制已写入根目录 INTEGRATION.md。
