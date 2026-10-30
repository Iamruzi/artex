# 知识库与 PoC 发现交付复核（2026-10-30）

## 本轮范围及审查性质

本轮为实现者自查，不冒充独立 agent 审查。此前两个 agent 对 Friend 压缩包的独立安全/差异审查另有报告，本轮不沿用其结论作为新代码已独立 review 的证明。检查对象为新增 db/knowledge、pocsearch、agent/knowledge、server/knowledge 与对应测试，以及 planner/worker、原生工具装配、schema、前端知识库/API/类型/导航相关改动。保留此前资源开关、目标验收、测量和 MCP 治理的未提交修改。

## 自查发现及修正

- 仅检索 NVD 首个窗口会遗漏其他候选：改为最多首尾两个窗口，去重并优先版本候选；保留来源总数、实际窗口和 partial。第二窗口失败只保留部分证据，不当作完整扫描或空结果。
- 仅按产品查知识会漏掉无产品标签的 CVE 笔记：补充按公开候选 CVE 查本地知识，并限制去重后的条目数量。
- 工具目录读取失败或移除绑定时，自动预检可能绕过用户选择：使用最终工具集合，知识/测量原生工具须有有效目录行；加入禁用后的零查询测试。
- 准备参考块不代表进入模型请求：拆分 prepared 与 model_request，核对实际 provider 消息中完整参考块的 SHA256；流式请求需实际消费迭代器后才记。
- 知识草稿不能由模型变为全局有效或“已验证”：严格字段解码、当前有效任务强制私有草稿，跨任务/过期/停用资料不可读取。
- 公开源码必须能追溯到该 CVE 的当前搜索候选：拒绝任意 URL/仓库、路径越界、重定向、非完整/超限文本；固定 API 来源，文本显示、不执行。
- 过期缓存只隐藏会占磁盘：增加过期索引及每次写入最多 100 条的惰性清理，不增加常驻进程。
- 切换 CVE 后旧仓库/源码会让页面含义混淆：新查询清空旧结果；源码整理成草稿时明确 32KiB 条目上限。
- 注入 JSON 不能截断、记录不能虚报已被丢弃的条目：超过预算删除尾部完整行，再计算实际 entry IDs。

## 已运行验证

测试均为显式独立测试库，不使用预览库执行测试。

- `go test -p 1 ./db -count=1`：通过，82.301 秒，含知识可见性、来源/正文哈希、到期、取消、缓存大小和过期回收。
- `go test -p 1 ./agent/... ./pocsearch ./guard ./httpmeasure ./resourceguard ./mcpguard ./mcphttp ./llmrec -count=1`：全部通过。包含 provider 实际参考块/流式消费、版本候选/不符/未知、公开接口失败不伪装空结果、请求预算/取消/不重试等。
- server 定向回归：`Test(Knowledge|HTTPMeasurement|MCPAssembly|MCPEndpoint|GoalCompletion|Resource|ModelPrompt|SkillGuidance)` 全部通过，15.032 秒。planner 与 worker 假模型端到端接线验证：自动候选进入首个请求，poc_get 原文进入下一请求，未产生 finding/目标成功。
- `go vet -p 1 ./pocsearch ./agent ./db ./server`：通过。
- 新页面 Biome、TypeScript 与 Next webpack 静态生产构建通过（单 worker、Node 堆 1GiB）；后端 `go build -p 1 ./cmd/artex` 通过。
- 实际公开元数据冒烟：查询 CVE-2024-3400，NVD 返回 1 个候选，GitHub 返回 5 个仓库候选。没有执行 PoC、加载模型或访问渗透目标。
- 部署后 HTTP 检查：3097 的 dashboard/knowledge 均 200；知识页引用并能加载包含新功能的 JS；未登录 knowledge API 为 401；原登录初始化状态保留。起初冒烟脚本只检查前 20 个脚本漏掉第 24 个页面 chunk，修正枚举上限后确认实际 bundle，未据 200 状态码单独判定 UI 正常。
- 预览数据库只读核对：6 个原生工具均已 seed，4 条原创参考，任务数 0、默认模型配置数 0。新后端日志确认 engine idle。没有加载本地模型。

日志：`D:/CodexWorkspaces/artex-build-cache/knowledge-*.log`、`knowledge-public-smoke.json`、`knowledge-preview-smoke.json`、`knowledge-preview-db.json`。

## 部署与剩余边界

预览新后端 `D:/CodexWorkspaces/artex-local-preview/artex-knowledge.exe`，PID 66368；前端 gateway 保留 PID 82300。保持原 data、数据库、登录和资源开关选择。旧 `artex-resource-toggle.exe` 保留作为回退二进制，新增 schema 为加法迁移；回退旧程序不会移除知识表。

尚未完成真实模型/靶场验证、浏览器点击/视觉检查、大规模知识语料导入或 19 万条检索基准。自动化接线测试使用合成资料及假模型。未重跑整个 server 套件，其此前已确认的 8 个 Windows/旧断言失败不在本批修复范围，不能宣称全项目所有测试通过。

公网限流和网络错误会使本轮仅使用已取得资料，未知版本保持未知；源码只能作为待审查参考。本批不是自动 PoC 执行器，不改变现有目标证明和验收标准。任务私有知识暂不进入任务导出快照；使用说明列出此限制及日志保留策略。
