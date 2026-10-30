# 框架经验接入 review（2026-10-30）

类型：本轮实现者自查与安全路径审查，不是独立 reviewer 或真实靶场验收。按 security-auditor 技能检查最终 diff、数据边界、取消/错误、资源释放与兼容性。

## 已发现并处理

| 问题 | 处理与回归 |
| --- | --- |
| 同服务并发时，旧请求晚成功可能把新熔断清掉 | 按代际处理结果；旧结果只释放自己的槽位，不能修改新故障状态。`TestLateSuccessCannotCloseNewCircuit` |
| HTTP 适配器原先未核对响应 ID/协议版本，可能接受其他请求的结果 | 调用边界校验 JSON-RPC 2.0 和请求 ID；错配响应作为协议错误，不进入成功结果。真实本地 HTTP 夹具覆盖错误 ID 与版本 |
| 远端 `isError` 文本可能伪造 `mcp_blocked:` 宿主状态 | 使用 `ErrBlocked` 错误类型判断台账状态；远端文字仍是普通失败。`TestMCPBlockedJournalRequiresHostOwnedError` |
| stdio SDK 将传输和应用错误压成同形文本 | 不做字符串分类；stdio 只限并发。HTTP/SSE 由实际传输路径标记，应用错误、4xx 和调用方取消不熔断 |
| 读完巨型 JSON/SSE 再截断仍可能先耗尽内存 | HTTP 解析器限制读取，SSE 单行与多行事件均限 8 MiB。正常 60KB 结果仍可读取；超限返回错误 |
| 多个小文本块逐次字符串拼接造成重复复制 | HTTP 工具适配器改用 strings.Builder，保持原结果和 Capture 语义 |
| 关闭/取消或 panic 时可能遗留本地并发槽位 | 在调用退出的 defer 中一次释放；取消、panic 不计为远端传输故障；单次恢复探测不允许并行扩大 |
| 配置变更或反复装配错误共享健康状态 | 相同配置跨 Agent 共享；URL/凭据变更使用独立摘要键；不输出明文配置。跨 Agent 装配测试验证零次误派发 |

## 验证记录

| 检查 | 结果与证据 |
| --- | --- |
| `go test -p 1 ./mcpguard ./mcphttp ./agent/chainskel ./config ./resourceguard -count=1 -v` | 通过。覆盖冷却、单恢复探测、晚完成、并发、取消、panic、状态容量、正常业务错误、网络协议/大小边界与身份前置指引。日志 `D:/CodexWorkspaces/artex-build-cache/framework-governance-tests.log` |
| 最终响应 ID/版本补丁后的 `go test -p 1 ./mcphttp -count=1 -v` | 通过，包含错误 ID/版本、5xx、无效 JSON、4xx、RPC 应用错误、响应上限、请求中途取消。日志 `framework-http-final-tests.log` |
| `go test -p 1 ./agent -count=1` | 整包通过，使用独立测试库。日志 `framework-agent-tests.log` |
| server 定向装配、共享熔断、端点更新、Skill 正文链与自动复核开关测试 | 通过；响应归属补丁后再次运行 MCP 装配/端点测试也通过。使用明确的隔离库，未向预览库写测试漏洞、调用或虚假成功记录。日志 `framework-server-tests.log` |
| `go vet ./mcpguard ./mcphttp ./agent ./server ./config` | 通过；最后仅改动的 HTTP 包再次 vet 通过 |
| Windows 后端与 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 后端编译 | 最终源码均通过；Linux 是交叉编译，未进行 Linux 实机负载测试 |
| 最终 diff/依赖/权限复查 | whitespace 检查通过；无新增运行依赖。原权限/行为透传有回归测试，人工配置与停机状态未改写。此前未提交的模型/Skill 功能保持原样 |
| 本地部署 | 后端更新为 `D:/CodexWorkspaces/artex-local-preview/artex-framework-governance-final.exe`，PID 99960。经 3097 网关访问认证状态、LLM/Skills 静态路由均为 200；未登录的资源 API 为 401，原登录初始化保留。没有完成浏览器视觉验收 |
| 模型状态 | 部署前确认任务为 0、默认模型为 0，部署后引擎日志保持 idle；Ollama 11434 没有监听。没有加载模型或消耗真实模型额度 |

结论：本批范围内的 review 修复、定向验证和本地后台更新已完成。没有独立 reviewer；没有将整包 server 回归、靶场成功率或真实模型遵循效果标成通过。当前主机内存偏高时，原有资源保护仍会暂停新派发，这不会自动改变人工暂停状态。

## 仍有边界

- 没有运行真实模型、Strix/CyberStrike 扫描或外部目标测试；本地模型继续保持未加载。
- 新 verifier checklist 只是始终注入的指引，不是身份矩阵执行器，也不能证明模型遵循指引。
- 未修改权限模式、范围拦截、目标验收或 finding 复核结论接口；没有导入外部报告后自动确认漏洞的捷径。
- MCP 初始化/发现、底层批处理调用和 stdio 传输错误分类不在本批工具调用熔断范围。
- 没有把超时包装成后台继续；远端不遵守取消时，本地准入层不能证明远端已停止，仍需部署级硬限制。
- 完整 server 回归存在此前已复现的 8 项失败（Windows 目录同步/分隔符、审查请求和 Bash 描述断言），见 `MODEL-PROMPT.md`。本批定向通过不能表示全项目测试全绿。

## 后续批次：现有目标证明与收尾修复（2026-10-30）

本轮仅修改原工具、证明数据库操作及其收尾调用。实施者自查最终 diff；没有独立 reviewer，也没有真实模型或外部靶场验证。

Review 发现并修复：

1. `goal_met` 原本只设置内存标志，完全绕过逐目标证明；现查询全部本地目标及有效证明，不接受空目标、裸 met、abandoned 或已失效证据。
2. `prove_goal` 原先在 findings 查询失败、无 AssetStore 或旧记录无独立行时放行；现使用真实数据库状态，要求 finding confirmed。起点和 dismissed fact 也不再合格。
3. 原先忽略 Link/SetNodeState 错误；现事务提交两者，模拟最终状态更新被约束拒绝后，验证没有遗留证明边。
4. 初版修复后继续追踪发现 frontier 抽干旁路；现与最终成功路径复用同一证据判据，裸 met/撤销证据不能经此自动完成。人工放弃和无目标任务保留“执行结束”行为，收尾文字不称其为目标成功。
5. 最终写入前再次核对证明与任务生命周期；拒绝暂停、排队、删除、已有终态或取消上下文。超时终局规划出错/取消时不返回先前成功标志。

第一次使用旧隔离库运行整包 db 回归遇到遗留 profile 唯一键/CIDR 数据冲突，因此新建独立测试库复跑；未清空或向预览库写入测试数据。最终验证：

| 检查 | 结果 |
| --- | --- |
| 新增 DB/工具正反例 | 通过。覆盖线索/起点/驳回/无独立记录/待确认/误报、合法 fact 与 finding、1001 个较新目标不能掩盖旧 open 目标、写入回滚、取消、关联来源撤销及跨任务拒绝。日志 `goal-proof-tests.log` |
| `go test -p 1 ./db -count=1` | 全新隔离库整包通过，73.095 秒。日志 `goal-proof-db-fresh.log` |
| `go test -p 1 ./agent -count=1` | 另一全新隔离库整包通过，10.293 秒。日志 `goal-proof-agent-fresh.log` |
| server 相关证明、HTTP 测量、准入、暂停、取消、终态测试 | 定向通过，17.616 秒。日志 `goal-proof-server-regression.log`；未宣称整包 server 全绿，原有 8 项失败见前述记录 |
| `go vet ./db ./agent ./server`、Windows 编译、Linux amd64 CGO=0 交叉编译 | 通过。Linux 仅为编译，未作实机负载验证 |
| 本地更新 | 后端 `artex-goal-proof.exe`，PID 54112；3097 网关的认证状态、LLM 和 Tools 页面均 200，未登录 `/api/tools` 为 401，登录初始化仍为 true。没有浏览器视觉验收 |
| 模型/资源 | 更新前任务 0、默认模型 0；新后端日志为 engine idle，Ollama 无监听。内存压力触发原有暂停派发保护，未解除保护或加载模型 |

日志及测试库索引 `goal-proof-test-dbs.json` 均在 `D:/CodexWorkspaces/artex-build-cache/`。最终 diff 自查与 whitespace 检查通过；没有新增依赖、表结构或配置，没有运行外部目标利用。

边界：普通 confirmed fact 的语义与目标条件仍由现有规划者判断；未实现独立目标评审。完成判断使用 SQL 语句的当前一致性快照；之后更改目标/证据不会自动追溯重开已经结束的任务。旧工具描述/用户绑定和手动关闭项没有强制覆盖；宿主处理逻辑始终执行上述检查。

## 后续批次：用户可控资源保护（2026-10-30）

沿用仪表盘资源卡片、现有 Guard 和 PostgreSQL settings，仅加一个「自动保护」开关。首次使用默认开启；`PUT /api/resources/protection` 保存 `enabled` 后立即应用，重启时读取 `resource_protection_enabled`。关闭只取消资源压力/采样失效的准入拦截；监测、并发计数和上限继续生效，不调用任务恢复接口，也不解除部署级 systemd/Docker 限制。没有新增运行依赖、页面或表结构。

实施者自查完成；没有独立 reviewer。Review 检查并处理：

- 除入口准入外，HTTP 测量已有租约时的逐次检查也改用同一开关判据，避免主开关关闭后仍被 raw snapshot 状态拦截。
- 保留 pressure/unknown 观测及历史；将资源原因与“暂停”动作分开，关闭时界面标注“仅监测”，不伪装健康状态。
- 先持久化再改内存状态，写失败返回错误；更新串行化，避免并发保存顺序与当前状态不一致。没有登录的请求不能修改设置；参数须为明确布尔值。
- 开关变化唤醒等待中的准入，但不抹掉已持有租约；重新开启不杀正在运行的进程。取消上下文仍拒绝执行。
- 前端等待服务端确认才更新选择，显示保存失败；轮询响应按版本过滤，避免旧响应覆盖刚保存的开关。

| 验证 | 结果 |
| --- | --- |
| resourceguard 整包回归 | 通过，`resource-toggle-guard-regression.log`；覆盖监测保留、并发上限、等待唤醒、取消及租约释放 |
| server 开关/资源准入与 HTTP 测量相关测试 | 通过，9.716 秒，`resource-toggle-tests.log`；使用独立测试库，覆盖开关往返/重新初始化、无权限拒绝、保存失败及人工 paused/stopped 项不复活 |
| TypeScript、组件 Biome、Go vet、Windows 后端编译 | 通过，日志前缀 `resource-toggle-`，位于 D:/CodexWorkspaces/artex-build-cache/ |
| 前端正式静态构建 | 通过，单构建 worker、Node 堆上限 1024 MiB；日志 `resource-toggle-web-build.log` |
| 本地更新 | 后端 `artex-resource-toggle.exe`，PID 9240；仪表盘 200，并引用新 dashboard bundle；实际返回的 bundle 含开关与持久化说明。未登录 PUT 为 401，登录初始化保留 |

页面资源通过 HTTP 核对，没有完成浏览器内点击或视觉验收；开关实际写入、恢复及准入效果由隔离库集成测试验证，没有绕过预览登录或擅自关闭用户当前保护。未加载本地模型，Ollama 无监听。没有将 server 全量测试、真实模型或靶场验证标为通过。
