# HTTP 测量 review（2026-10-30）

本轮是实现者代码自查，使用 Code / brainstorming / writing-plans 与 security-auditor 工作流；没有独立 reviewer。范围包括采样器、分析器、宿主工具装配、任务与权限边界、资源/代理/取消、数据库上下文和保存后的成功状态。

## 发现与处理

- 只计响应头会漏掉慢正文：总耗时包含受限正文读取，首字节单独记录，慢正文夹具验证。
- 默认连接复用可能引入隐藏重试：使用新 HTTP/1 连接，禁用 keepalive、自动重定向和 cookie jar；清楚区分客户端尝试与成功写出。
- 大抖动下可能产生过强结论：保留完整样本；强噪声返回 inconclusive。公开模拟漏检数，不把高弃判率包装成高召回。
- 普通 fact 可以用于 prove_goal，因此不把采样直接写成 fact：使用 host-origin hint，并测试它不能直接标记目标 met。
- 初次接线误用了 hint 的 open 状态：真实数据库约束测试发现后改为合法 active，未放宽数据库约束。测试 scope 来源也改为已有合法的 agent。
- 取消后原 ctx 无法可靠写入收尾观测：增加上下文化的 AddNodeContext/ListTaskScopeContext；既有入口保持原语义；采样取消后只保留最多 5 秒的元数据写入上下文。
- 工具表读取失败时既有框架会默认保留未知 host 工具：对本批两个新工具改为缺记录/读取失败均不暴露，保持其他工具原行为。手动禁用重启后保留。
- 目标重定向、无有效 scope、无任务、跨任务读记录、平台秘密（含 URL 编码）、非法代理均在本地夹具中验证拒绝；不通过改参数偷偷绕过用户审核。
- 新库的归档快照依赖 LLM 记录表：测试显式初始化该已有表，不修改生产归档语义或跳过快照检查。

## 最终检查

| 检查 | 实际结果 |
| --- | --- |
| `go test -p 1 ./httpmeasure ./guard ./intercept ./db ./agent -count=1` | 五个包通过；数据库/Agent 用明确的独立测试库。日志 `D:/CodexWorkspaces/artex-build-cache/http-measurement-regression.log` |
| 最终 `httpmeasure` 与 `agent/chainskel` 包测试 | 通过；最后补充的实际 POST 变体与 14 次上限也通过。日志 `http-measurement-final-tests.log`、`http-measurement-sampler-final.log` |
| 500 组固定种子耗时样本 | 稳定阳性 100/100；300 阴性无正信号；强抖动阳性 7/100，93 组弃判。弃判计漏检时总漏检 93/200；没有拿这些数字代表真实漏洞指标 |
| server 定向 HTTPMeasurement / MCPAssembly / SkillGuidance | 通过。实际本地 HTTP 采样、任务隔离、hint 不能 prove_goal、取消后的保存、归档快照、手动禁用、闭库后目录失败不暴露工具、verifier 关联任务、错误代理均检查。日志 `http-measurement-server-tests.log` |
| 数据库取消上下文新增测试 | `TestMeasurementMetadataHonorsCancelledDBContext` 通过，取消写入不遗留 hint，取消查询不忽略 ctx |
| `go vet ./httpmeasure ./db ./guard ./intercept ./agent ./server` | 通过 |
| Windows 后端编译、Linux amd64 无 CGO 交叉编译 | 通过；不等于 Linux 服务器实际负载测试 |
| 本地更新与鉴权 | PID 36280 运行 `D:/CodexWorkspaces/artex-local-preview/artex-http-measurement.exe`。经 3097 网关访问认证状态和工具页面为 200，未登录工具 API 为 401；原密码初始化保留，没有读取/生成 JWT 绕过鉴权 |
| 原生工具注册 | 预览数据库中 measure_http_pair / get_http_measurement 均已启用，默认绑定 worker / verifier；没有插入演示漏洞、任务或成功记录 |
| 模型与任务 | 更新前后预览任务为 0、默认启用模型为 0；Ollama 11434 未监听，没有真实推理或外部目标请求 |

结论：本批实现、代码自查、定向验证和本地后端更新已完成。前端界面无改动，使用已有工具管理页和任务线索/节点详情，不声称完成新的 UI 或视觉验收。

## 保留的边界

- 不生成 payload，不确认漏洞、不自动达成目标，不宣称发现率提升。重新写成其他事实或报告后的结论仍要走既有独立复核与验收。
- 以 URL 主机匹配任务范围，不额外提供完整 DNS 重绑定防护或端口级 scope；沿用现有 scope 模型，跳转禁用。
- 复核会话支持 finding_checks；未为旧 finding_retests 的不同会话映射额外接线。
- 60 秒是采样预算；准备代理与受限观测写入也有开销。任意不遵守 context 的自定义 RoundTripper 不在生产接入路径。
- 无新增 UI；没有浏览器视觉验收、真实模型遵循或外部靶场结果。此前 server 完整回归的既有 8 项失败仍见 MODEL-PROMPT.md，不能把本批定向测试写成全项目全绿。
