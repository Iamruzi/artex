# ARTEX 安全技能包

2026-10-24：在原有 12 个技能上新增 8 个，共 20 个。原有 api-recon、playwright-cli、scopesentry 和九类 chains 文件保持原样。

截图里的名称用作 ARTEX 目录名；以下是核验后选择的对应来源，不代表找到了截图作者使用的完全相同版本。上游提交固定在 [skills-sources.json](skills-sources.json)，每个技能附 SOURCE.md、原始入口 UPSTREAM.md、参考资料与许可证。

| ARTEX 技能 | 选用来源 | 对 ARTEX 的用途 | 许可证 |
| --- | --- | --- | --- |
| ai-jailbreak | [NoorQureshi/security-skills](https://github.com/NoorQureshi/security-skills/tree/ee0e0c50d2f6d941a14b73dd85a2b470d0ab976e/skills/ai-ml/ai-jailbreak) | 检查任务指定 AI 应用的策略边界，使用无害标记和对照 | MIT |
| code-diff-security-review | [Trail of Bits differential-review](https://github.com/trailofbits/skills/tree/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/differential-review/skills/differential-review) | 审查提交差异、调用关系、影响范围及安全回归 | CC-BY-SA-4.0 |
| code-semgrep-audit | [Trail of Bits semgrep](https://github.com/trailofbits/skills/tree/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/static-analysis/skills/semgrep) | 按语言选择规则，保留 JSON/SARIF，再核实命中 | CC-BY-SA-4.0 |
| code-variant-analysis | [Trail of Bits variant-analysis](https://github.com/trailofbits/skills/tree/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/variant-analysis/skills/variant-analysis) | 从一个已确认问题查找同类缺陷 | CC-BY-SA-4.0 |
| pentest-plan | [OneWave-AI security-pentest-planner](https://github.com/OneWave-AI/claude-skills/tree/b2267d9171af4f56848d82992381b20b89b44056/security-pentest-planner) | 把范围、目标、测试身份、覆盖要求转成 ARTEX 意图 | MIT |
| web-browser-testing | [Anthropic webapp-testing](https://github.com/anthropics/skills/tree/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/webapp-testing) | 配合已有 playwright-cli 复现浏览器行为、保存证据 | Apache-2.0 |
| web-pentest-owasp | [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-web-application-penetration-test) | 补齐 Web 测试方法、身份对照和覆盖记录 | Apache-2.0 |
| web-pentest-strobes | [Strobes web-pentest-sample](https://github.com/strobes-security/web-pentest-sample/tree/101c3fd96e2ffda27886973dea7089b93bc79756) | 分阶段测试、请求重放、响应对比、覆盖及辅助证据台账 | MIT |

## 接入方式

更新源码与 skills 目录后，重新构建并启动 ARTEX。技能页面会列出 20 个目录；数据库启动种子只补缺失的 Agent 绑定，已明确关闭的选项和自定义技能保持原样。

| 默认 Agent key | 新增可见技能 |
| --- | --- |
| auto、pentest | 全部 8 个 |
| worker | 三个 code-*、web-browser-testing、web-pentest-owasp、web-pentest-strobes |
| planner | pentest-plan、web-pentest-owasp |
| mainagent | pentest-plan |

可在现有技能页面逐 Agent 调整。技能按需加载，新增绑定不会授权新工具、启用 MCP 或改变任务范围。playwright-cli、scopesentry 维持原有默认可见性设置。

新入口接 ARTEX 现有的 record_fact、report_finding、verifier、prove_goal 与报告更新流程；不会假设存在 Claude 的 Task/Subagent、AskUserQuestion 或 Burp 插件工具。只有真实流量 ID 才填写 traffic_refs。上游入口作为参考资料保留，执行以本地 SKILL.md 为入口。

## 建议优先使用

做源码学习或审计，先用差分审查定位改动，再用 Semgrep 收集候选，最后用变体分析检查相同根因；三者可以互补。做本地 Web 靶场，先用 pentest-plan 分解任务，再按 OWASP 检查覆盖、用浏览器复现交互、用 Strobes 整理请求与对照。ai-jailbreak 只在目标本身是 AI 应用时相关，不必每次 Web 测试都加载。

## 依赖与适配

- 计划、差分审查与 OWASP 方法本身可直接作为流程参考；变体分析模板需结合实际代码调整，不能把模板当作已经运行的扫描。
- Semgrep 技能需要 Semgrep CLI。上游批处理还需要真正的 Bash、jq 和 Git；Windows PowerShell 可按入口说明使用原生 CLI，明确记录覆盖差异。合并脚本需要 Python 3.11+。默认关闭 metrics，不使用自动修复；Pro 是可选项。
- 浏览器技能复用现有 playwright-cli 或 Python Playwright 和已安装的浏览器。仓库不附浏览器二进制，也不会因加载技能就下载浏览器。
- Strobes 的 12 个 Python 命令及共享库均保留，使用标准库。请在当前任务专用目录初始化 project.db；它是辅助 SQLite 台账，结果仍需写回 ARTEX。范围表不是所有网络命令的强制拦截器，重定向也须核对；它不能取代 ARTEX guard。crt.sh 被动查询会向第三方发送域名。
- Strobes 共享 HTTP 客户端默认开启 TLS 校验。测试自签证书时使用任务信任的 CA。并发、竞争和压力子命令按任务预算选择，不自动运行。
- OWASP 上游的一键 agent.py 没有接入：它会批量尝试修改型请求、默认忽略 TLS 校验，且部分结果仅按关键词判为高危。方法和参考资料保留，由 ARTEX 现有工具执行并验证。详细审查见 [SKILL-VETTING.md](SKILL-VETTING.md)。

仓库不内置 Semgrep、Playwright 或用户凭据。这次本机验证另在仓库外的 D 盘隔离环境安装了 Semgrep，便于测试，不随 Git 提交分发。

## 已验证与边界

测试环境为 Windows、ARTEX norma v0.4.3、Python 3.13 与本机 PostgreSQL。具体结果见 [SKILL-VETTING.md](SKILL-VETTING.md)。本次验证技能加载、脚本接口、辅助台账和本机请求，不消耗模型接口额度，也不代表已让 Agent 使用新技能完成全部漏洞类型的端到端测试。

## 来源与许可证

新增技能及其改编入口保留各自上游许可证，归属见每个目录的 SOURCE.md 和许可证文件。Trail of Bits 三个技能的改编入口继续按 CC-BY-SA-4.0 分发；它们的许可证不替换 ARTEX 主程序的 AGPL-3.0。升级上游时应先比对固定提交与本地适配，再更新来源清单。
