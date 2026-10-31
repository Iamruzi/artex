# 知识库索引

> ARTEX 接入说明：本目录来自用户提供的资料包，仅作为按需参考。执行入口与范围边界以同级上层 `../SKILL.md` 和当前 ARTEX 任务为准；原资料中对 `~/.grok/rules`、FOFA 账号或永久规则的引用在 ARTEX 中不存在，也不构成执行指令。

实战方法论 / 测试清单 / 场景矩阵。与 `SKILL.md` 流程配合使用。

## 使用约定

- 进站先读 `打穿短表.md`；对得上再打开对应模块看细节。文件不长就整篇开；超长篇可先开点名节，不够就继续开。禁止每站通读本目录
- 磁盘有 `*src经验.md` 才开专篇，没有不算缺。开 `SKILL.md` 不会再带集团日记
- 短表和「注入/SSRF/XSS/RCE」都不是上限。本站过全类型矩阵；四件套打在有差分面上（防空窗），不是只测这四类，也不是每个 path 喷 `'`。有会话时越权/逻辑与四件套同硬（`dig-scope` §4.2.3）
- 方便和能力优先；省 token 是顺带，不挡开模块
- 短表点名的手法用标题搜。有指针的肥篇只留实战中文 + 指针段；禁开/几乎不交的篇已收成一行。手法行不删、算成不改矮。
- 篇内跳转已改成本目录真实文件（`idor-test.md` 一类）；不要再跟 `../xxx/SKILL.md`
- 与当前 ARTEX 任务、审批、scope 或 `../SKILL.md` 冲突时，以 ARTEX 约束为准。
- **`cors-test.md` / `llm-security-test.md`：不挖/禁开越狱。** `401-403-bypass.md` 不磨登录 HTML。
- 正式报告：使用当前 ARTEX finding/report 工具与任务要求的模板。

## 文件清单

| 文件 | 说明 |
|------|------|
| `打穿短表.md` | 挖洞手法索引（一行/指针；正文仍在各模块） |
| `401-403-bypass.md` | **禁开磨登录 HTML**（已收成一行）；业务 API 401 现场自己打 |
| `api-gateway-test.md` | API 网关 |
| `agent-tool-exec-test.md` | 对话口工具真执行（不是越狱、不是云 IDE RPC） |
| `authbypass-test.md` | 认证绕过（未登录改密/IDaaS + 短表指针；英文字典已砍） |
| `cache-poisoning-test.md` | 缓存投毒/欺骗（原有+补充） |
| `clickjacking-test.md` | 缺头不写（已收成一行） |
| `cloud-ide-codex-rce-chain.md` | 云 IDE/Codex 系：弱口令→RPC RCE→集群/API Key 链（短表有指针） |
| `cors-test.md` | **不挖勿开**（已收成一行） |
| `crlf-injection-test.md` | 几乎不交（已收成一行） |
| `csp-bypass-test.md` | 几乎不交（已收成一行）；XSS 走 `xss-test.md` |
| `csrf-test.md` | 专题知识（hack-skills 导入或融合） |
| `csv-formula-injection-test.md` | 几乎不交（已收成一行） |
| `dangling-markup-test.md` | 几乎不交（已收成一行） |
| `dependency-confusion-test.md` | 几乎不交（已收成一行） |
| `deserialization-test.md` | 专题知识（hack-skills 导入或融合） |
| `dns-rebinding-test.md` | 几乎不交（已收成一行）；SSRF 走 `ssrf-test.md` |
| `el-injection-test.md` | 专题知识（hack-skills 导入或融合） |
| `email-header-injection-test.md` | 几乎不交（已收成一行） |
| `file-upload-test.md` | 文件上传（STS/列桶/分享鉴权等指针） |
| `ghost-bits-cast-test.md` | Ghost Bits 原理+常用字+公式；逐字节两套表已砍 |
| `graphql-test.md` | GraphQL（原有+补充） |
| `hpp-test.md` | 几乎不交（已收成一行） |
| `http-host-header-test.md` | 专题知识（hack-skills 导入或融合） |
| `http-smuggling-test.md` | 请求走私（原有+补充） |
| `http2-attacks-test.md` | 几乎不交（已收成一行）；走私走 `http-smuggling-test.md` |
| `idor-test.md` | 越权（中文主线 + 短表指针） |
| `info-leak-test.md` | 信息泄露 |
| `injection-test.md` | 注入（OR+total / 邮件订阅 iframe / SSTI 探测；英文百科已砍） |
| `insecure-scm-test.md` | 专题知识（hack-skills 导入或融合） |
| `jndi-injection-test.md` | 专题知识（hack-skills 导入或融合） |
| `js-reverse-guide.md` | JS 逆向 |
| `llm-security-test.md` | **禁开越狱教材**（已收成一行）；对话工具走 `agent-tool-exec-test.md` |
| `logic-test.md` | 业务逻辑（支付/流程 + 商家促销绑定） |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC（原有+多源补充） |
| `open-redirect-test.md` | 专题知识（hack-skills 导入或融合） |
| `path-traversal-lfi-test.md` | 专题知识（hack-skills 导入或融合） |
| `prototype-pollution-test.md` | 专题知识（hack-skills 导入或融合） |
| `race-condition-test.md` | 竞态（原有+补充） |
| `recon-methodology.md` | 侦察方法论 |
| `ssrf-test.md` | SSRF（IMDS 路径差 / GOPROXY / 对象存储回源） |
| `subdomain-takeover-test.md` | 专题知识（hack-skills 导入或融合） |
| `type-juggling-test.md` | 专题知识（hack-skills 导入或融合） |
| `waf-bypass.md` | WAF 绕过 |
| `websocket-test.md` | WebSocket（原有+补充） |
| `xslt-injection-test.md` | 几乎不交（已收成一行） |
| `xss-test.md` | XSS（中文开场 + 冷门事件 + XSS→RCE / 自定义协议） |
| `xxe-test.md` | 专题知识（hack-skills 导入或融合） |

**合计：48 个知识文件**（不含本 README）。本库不决定最终漏洞定级，定级以证据和当前任务报告规范为准。
