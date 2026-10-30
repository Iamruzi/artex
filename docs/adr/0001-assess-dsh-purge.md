# ADR-0001：选择性借鉴 dsh-purge 的可观测性与证据管理

状态：提议，源码评估已完成；本次没有安装插件或修改运行逻辑。

评估日期：2026-10-29。

## 背景与结论

用户希望判断 dsh-purge 是否能够增强现有 ARTEX。此次核对上游 `YuJunZhiXue/dsh-purge` 的 `package.json`、证据账本、工具挂载、Skill 检查、规则、续跑、回退和报告代码，并与 ARTEX 当前源码比较。

- 上游版本：1.1.82，固定提交 `0c933dc7d3252698f3f0f9756932dcc88355f532`。
- ARTEX 基线：`c2ce703687e936f05320823c89104ecc5f2707be`。
- 上游是针对 DeepSeek Harness 的 Node/Cordis 插件，宿主目标写为 `0.2.1-rc.2`；ARTEX 使用 Go/Norma/PostgreSQL。无法按 ARTEX Skill 或 MCP 插件直接安装。
- 值得移植的是能力诊断、证据来源和未解决问题管理的设计。没有证据证明安装它能提高真实漏洞发现率或利用成功率；本次没有做这类效果基准。
- 上游公开 README 明确说此开源版本不下发技能库和知识库，因此它不能补齐 ARTEX 的渗透语料检索。

## 候选项与现状

| 优先级 | 借鉴项 | ARTEX 已有能力与缺口 | 建议实现与验收 | 成本 |
| --- | --- | --- | --- | --- |
| P0 | Skill 可用性检查与调用证明 | 已有文件管理、可见性、调用记录和执行事件。但 `meteredSkill.Call` 在实际调用前记录，`found` 仅表示注册表命中，不证明正文返回、依赖就绪或后续动作成功。 | 分开记录请求、正文加载结果、依赖检查、关联工具调用和结果引用。无依赖的技能仍可阅读；需要缺失依赖的具体动作应明确阻塞。以不存在文件、缺 CLI、缺配置、正文读取失败及正常夹具分别验收。只保存配置名称与是否存在，不保存密钥值。 | 中 |
| P0 | 证据置信度与未解决问题登记 | 已有 finding 独立复核、真实流量快照、SHA-256、证据版本和导出。还可扩展子 Agent 的陈述与未解决条件之间的显式关联。 | 增补声明、观测、推导及推测的来源分类；由执行器写观测，复核器绑定实际执行记录。登记待验证、阻塞、反证和解决原因。无新证据或依赖变化时，不因续派自动重开。哈希用于一致性与去重，漏洞成立仍走独立验收。 | 中至高 |
| P1 | 报告复现材料来源标记 | 已有原始请求/响应附件与证据版本，价值主要在说明材料来源。 | 标注原始捕获、由已知信息生成、待填写模板；生成请求不能进入真实抓包证明集合。请求生成只是准备材料，重放返回也须对照具体断言。导出前脱敏，实际重放走现有权限、范围与资源准入。 | 低至中 |
| P1 | 按模型与任务选择规则并保存快照 | 已有 Agent/Skill 可见性及提示词装配，不应另建全局提示词覆盖器。 | 规则版本、内容摘要和适用模型随任务保存；子任务继承同一版本和限制。不同规则不能覆盖人工停止、预算和目标验收。小模型上下文有限，应只装配必要规则。 | 中 |
| P2 | 会话回退与队列清理 | 有暂停、取消、归档及确定性意图会话；通用 rewind 未在本次检索中确认。 | 如增加回退，先停止当前运行并清理待执行队列；保留审计与证据。明确回退对话不能撤销已经发生的请求或文件修改。涉及工具调用的回退不得自动重复执行。 | 高 |

建议顺序：先补 Skill 运行状态与依赖诊断，再扩展证据分级和未解决问题登记，之后补复现来源标签。保留现有执行器与数据库，不引入第二个运行时或第二套任务调度。

## 上游实现中不能直接照搬的语义

1. `lib/redteam/skill-availability.js:337` 起的返回逻辑，只要正文可读取就返回 `available`；缺环境变量、缺路径等仍可以存在于 issues 中。ARTEX 应区分“能读取说明”和“某个动作能执行”，不能把该状态直接显示成“技能已正常工作”。该检查主要依据文档、配置名称和路径，也不能替代 CLI/MCP 的实际就绪检查。
2. `lib/redteam/evidence-ledger.mjs:232` 的 `verify` 是规范化内容哈希查库；它不执行独立验证。`record` 的缺省 confidence 为 `observed`，`upgrade` 接受调用者给定的验证结果，未提供时还能沿用已有结果。ARTEX 不能把这些 API 名称当成漏洞成立的证明。
3. 证据账本确实由 `lib/redteam/tools.js` 挂载，不只是孤立示例文件。但调用者可填写 confidence，进一步说明需要在 ARTEX 中使用受信执行记录约束状态迁移。
4. `lib/continue-retry.js` 默认关闭自动继续，限制重试次数，并区别人工取消、永久错误与临时错误。ARTEX 已有模型重试、停滞检测与终态处理；应对照补缺，不叠加一套发送“继续”的循环。
5. `lib/redteam/report-replay.js` 能拼装复现材料，`store-core.js` 区分真实材料、生成材料与模板；这不等于独立重放已经成功。其命令拼装也不能直接跨用到 Windows PowerShell，ARTEX 应沿用现有平台引用策略。
6. 宿主包补丁、默认身份注入和强制破甲提示词不纳入本次推荐。它们与 DSH 内部实现绑定，不能据此推定 ARTEX 的误报、漏报或成功率会改善。

## 非功能要求与失败处理

- 检查按用户操作或任务准入触发，缓存结果并有容量上限，避免循环扫描磁盘或频繁启动 CLI。MCP 探测要有超时和清理。
- 事件关联采用 task/intent/session/tool-call 标识，不通过时间、域名或自然语言猜测。加载失败和运行失败分别记录。
- 证据与问题必须按任务及来源范围隔离；继承关系只读规则沿用原有实现。
- 资源不足、配置缺失、预算结束和人工停止保留原原因，不算阴性，也不进入成功状态。
- 不扫描实际外部目标来验证管理功能；先使用本机合成夹具，效果评价另用独立、授权的基准。

## 方案取舍

- 采用：按现有 Go/Norma/PostgreSQL 接口实现所需语义，保留 ARTEX 的独立复核与资源保护。收益是运行状态更透明、减少重复无效调用；代价是事件关联、状态迁移、界面和迁移均需要开发验证。
- 未采用：整包嵌入。需要带入 DSH 宿主、Cordis、Node 内建 SQLite 和宿主补丁维护，收益与现有 ARTEX 功能高度重叠。
- 未采用：只加一份强制使用 Skill 或破甲提示词。提示词不会自动形成执行证据或独立验收。

授权文字核对：该提交的 `LICENSE` 与 `package.json` 标为 Apache-2.0，另有 `NOTICE`；README 与 `LICENSE-COMMERCIAL.md` 还包含倒卖、商业使用等额外说明。本次只评估，没有复制实现代码。未来直接复用或对外分发前需核对这些文字的适用范围并保留来源记录，不能仅沿用聚合站的 MIT 标签。

## 验证范围

本次是固定提交的静态源码对照，不是插件运行测试、性能测试或漏洞效果测试。未运行上游安装脚本、未应用宿主补丁、未修改当前 ARTEX 配置。没有启动或加载本地模型。此 ADR 为待用户评阅的实现建议。

## 来源

- [上游固定提交](https://github.com/YuJunZhiXue/dsh-purge/tree/0c933dc7d3252698f3f0f9756932dcc88355f532)
- [宿主与包定义](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/package.json)
- [Skill 可用性](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/redteam/skill-availability.js)
- [证据账本](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/redteam/evidence-ledger.mjs)
- [工具挂载](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/redteam/tools.js)
- [报告材料生成](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/redteam/report-replay.js)
- [续跑与重试](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/continue-retry.js)
- [规则管理](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/rules.js)
- [会话回退](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/lib/rewind.js)
- [README](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/README.zh-CN.md)
- [许可证](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/LICENSE)、[商业说明](https://github.com/YuJunZhiXue/dsh-purge/blob/0c933dc7d3252698f3f0f9756932dcc88355f532/LICENSE-COMMERCIAL.md)
- ARTEX：`server/skill_usage.go`、`db/skill_usage.go`、`server/assembly.go`、`server/finding_checks.go`、`agent/stuck.go`、`agent/terminalreason.go`、`docs/漏洞流量证据.md`、`docs/RESOURCE-GOVERNANCE.md`。
