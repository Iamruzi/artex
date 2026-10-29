# ARTEX 轻量知识源接入评估

评估日期：2026-10-29。优先保护服务器资源。以下是候选知识源和接入设计，**不是已经安装或检索接通的知识库**。

| 来源 | 适合解决的问题 | 已核对的仓库许可 | 建议 |
| --- | --- | --- | --- |
| [OWASP WSTG](https://github.com/OWASP/wstg) | 测试步骤、前置条件、覆盖度和证据标准 | [CC BY-SA 4.0](https://github.com/OWASP/wstg/blob/master/LICENSE) | 首批接入。保留版本化 WSTG 编号，分别呈现测试方法与实际测试结果 |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Web 漏洞知识、变体和排障参考 | [MIT](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LICENSE)，保留版权与许可 | 首批按技术栈/漏洞类型筛选 Markdown，按需检索，避免把整个目录塞进上下文 |
| [MITRE CTI / ATT&CK](https://github.com/mitre/cti) | 技术分类、平台/前置条件与行为关联 | [MITRE 自有许可](https://github.com/mitre/cti/blob/master/LICENSE.txt)，允许研究、开发和商业使用并要求保留版权和许可 | 第二批作为结构化标签和关系数据，不能当作漏洞 POC 或已触发利用链 |

WSTG 官方特别建议使用版本化编号与链接，避免 `latest/stable` 漂移，见 [官方引用说明](https://github.com/OWASP/wstg#how-to-reference-wstg-scenarios)。这里的许可是各仓库根目录声明，后续导入仍要保留各文件原有署名、第三方来源与例外声明。语料衍生内容的许可与项目代码许可分别管理。

## 推荐接法

先复用已有 PostgreSQL 做词法检索和标签过滤，不新增 Dify、RAGFlow、向量数据库或本地 embedding 模型。现有 ARTEX chains、已审查 skills 和自身事实/产物索引先成为可检索来源，再引入上述外部知识源。中文检索要单独评估分词/关键词别名效果，不能把 PostgreSQL 默认英文分词当作中文支持已解决。

导入是显式、可追溯的离线操作：固定仓库 commit，记录原 URL、相对路径、标题、段落、许可、文件哈希、更新时间、技术栈/CWE/WSTG/ATT&CK 标签和导入批次。Markdown 只解析为数据，不安装其中 skills，不执行代码块，不沿文档链接自动下载依赖，不定时跟随 main 分支。

每次检索最多返回 4 个片段、总计约 6 KB，附带来源及 commit。内容以不可信参考资料交给规划者或 worker；权限、任务范围和执行审核继续由原机制决定。不要把检索命中、POC 生成、工具退出码 0 和最终目标达成混为一谈。

先选 30–50 个跨类别问题建立离线检索集，记录来源是否命中、片段相关性、引用是否准确、延迟、内存和上下文/token 开销。词法检索确有漏召回且有可用预算时，再考虑远程 embedding 或限制线程的本地实现。完整 RAG 平台目前不值得优先部署：它会引入额外常驻服务和运维成本，而执行可靠性和资源保护是当前更直接的问题。
