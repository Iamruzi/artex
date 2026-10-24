# 技能来源审查与验证记录

日期：2026-10-24。目标是给 ARTEX 增加适合现有工具、Agent 和证据流程的技能。没有把第三方 SKILL.md 当作安装期间的指令执行，也没有运行其一键安装或远程 shell 命令。

## 来源核验

来源及固定 Git 提交见 [SKILLS.md](SKILLS.md)；逐文件原始 SHA-256 和本地改编记录见 [skills-sources.json](skills-sources.json)。清单中的 upstream_files_reviewed 描述下载时的原始文件，包括被排除的 agent.py；不能把它当作改编后安装文件的哈希表。

检查了 85 份上游文件：程序化读取 UTF-8 内容、检索高风险调用和外部地址、解析 Python AST，并人工审阅技能入口及脚本的关键输入输出、网络、子进程和持久化路径。该记录不等于逐行形式化审计，也不保证第三方代码不存在未知问题。安装的 25 个 Python 文件均能解析。

| 发现 | 处理 |
| --- | --- |
| 多个来源面向 Claude/Burp，假设专用工具、子代理和交互式批准 | 新写 ARTEX 入口，沿用实际工具 schema、planner 意图与既有 guard；原文仅供按需参考 |
| 上游示例包含固定域名、账户、Linux 临时路径 | 明确替换为当前任务目标、测试身份和任务工作目录；Windows 区分 PowerShell/Bash |
| OWASP 一键 agent.py 包含 PUT/DELETE 等修改型探测、破坏型 SQL 示例、verify=False 和按错误关键词升级严重性 | 不安装该文件；保留方法和参考资料，经 ARTEX 现有工具执行、对照和验证 |
| Strobes 根入口无技能 YAML 元数据 | 增加符合 ARTEX 加载器的本地入口，原入口存为 UPSTREAM.md |
| Strobes 辅助数据库会从父目录寻找 project.db | 入口要求每个任务独立工作目录，避免读写别的任务台账；不直接写 ARTEX PostgreSQL |
| Strobes scope 不是每个网络脚本的强制网关 | 明确登记不等于强制限制，调用与重定向仍检查 ARTEX 任务范围 |
| Strobes HTTP 客户端默认关闭 TLS 校验 | 修改共享客户端默认值为 verify_ssl=True，SOURCE.md 记录该改编 |
| Strobes crt.sh 查询会发送域名；intruder/turbo 有并发和压力能力 | 不列为默认动作；仅按当前任务允许的查询方式和请求预算选择 |
| Strobes decoder 包含 base64、JWT 解析等功能 | 核对为显式输入的数据变换；没有发现解码后自动执行代码的安装逻辑 |
| Semgrep 批处理含 eval | 核对其为脚本内部固定变量名的数组赋值；不用于执行下载的编码内容。批处理仍要求可信 shell 环境与确定的参数 |
| 浏览器 with_server.py 使用 shell=True 启动用户给定服务 | 明确只用任务确定的服务命令；复用现有服务优先，检查自建服务退出后的子进程 |
| 第三方说明中的安装示例和示例密钥 | 不自动执行安装示例，不保存用户模型密钥；缺依赖如实记录 |

没有给新增技能声明额外 MCP，也没有修改 ARTEX 的工具授权、目标范围或现有 12 个技能。AI 测试入口限定任务指定的 AI 应用和无害标记，不把该技能当作覆盖 ARTEX 自身任务约束的权限。

## 验证结果

- 实际 norma v0.4.3 skill.LoadDir 加载 20 个技能；新增 8 个名称、目录、description、license 和 instructions 均有效。
- 本机运行中的 ARTEX GET /api/skills 能列出 20 个技能，新增项有完整元数据。
- Strobes 12 个顶层命令 --help、离线项目初始化、范围登记与检查、45 条 OWASP 测试模板导入及进度查询、本机受控 HTTP GET 共 19 项通过。网络烟雾测试仅访问脚本自行启动的 127.0.0.1 HTTP 服务。
- 25 个已安装 Python 文件 AST 解析通过；确认排除的一键 agent.py 不存在、Strobes TLS 默认校验开启。
- PostgreSQL 隔离测试 TestSecuritySkillSeedPreservesUserChoices 连续两次通过：关闭的旧/新技能不被重新打开，自定义技能绑定保留；测试清理在关闭连接前恢复原值。
- go vet ./db 通过。
- Semgrep 1.182.1 原生 Windows CLI 配合 Python 3.13，在隔离虚拟环境运行上游 test_merge_sarif.py：32 项全部通过，包含绝对/相对路径下真实 Semgrep JSON/SARIF 键的一致性测试。使用本地测试规则、关闭 metrics 和版本检查，不上传目标源码。
- go build ./cmd/artex 通过，构建产物置于仓库外；git diff --check 在提交前检查。

Semgrep 初次运行缺少 CLI，另有 Windows 默认编码导致的失败；安装隔离依赖并设置 PYTHONUTF8=1 后完整重跑通过。没有以跳过依赖测试代表完整运行，也没有运行外部目标扫描或调用 DeepSeek。Bash/jq 批处理、Playwright 浏览器启动和 Semgrep Pro 未在本次验证。

## 使用时仍需核实

技能是流程和工具资源，不代表所有依赖已经部署。浏览器、Semgrep Pro、Bash/jq 批处理及真实 Agent 全流程各有独立前提。原生 Semgrep 的本地样例扫描不能证明全部第三方规则集均可运行；Strobes HTTP GET 通过也不能证明每个主动测试子命令都适合当前目标。每次任务都应保留真实执行结果与未完成项。
