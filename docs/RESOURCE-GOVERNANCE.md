# 资源保护与执行治理

本批实现保留 ARTEX 的 Norma、PostgreSQL、权限与操作审核、独立 finding 验证、确定性意图会话和原有暂停/取消流程。参考 [CyberStrikeAI 快照 5affb4d](https://github.com/AIPentest/CyberStrikeAI/tree/5affb4df1b178c893ae099fcc54ba052ca4afaff) 的执行状态、任务生命周期及续派思路，按现有接口实现；没有引入 Eino、SQLite、独立平台或新的后台执行器。

## 现在接入的位置

- 每个服务只有一个采样循环，每 2 秒读取一次主机 CPU 差分、可用内存、数据盘空间。Linux 读取可见 cgroup v2 及其祖先的有效内存限制、CPU 配额和 PID 上限。内存按 host 与 cgroup 可用空间的较小值计算，不用 MemFree 误判页缓存。
- `GET /api/resources` 通过原有 API 鉴权。总览页每 5 秒拉取，页面隐藏时跳过，前一个请求结束后才安排下一个。最多 90 个采样点、32 条告警/恢复记录，重启后清空；状态变化写入服务日志。没有额外监控数据库、embedding 模型或外发告警服务。
- 默认全服务最多 2 个 worker、4 个正在调用的高开销工具。worker 在 claim 之前拿许可；人工继续意图也受同一许可约束。Bash、交互 shell 的创建/发送、MCP、网络工具和自定义 command/script/http 执行受准入保护，自定义工具编辑器的测试按钮也受保护。
- 资源压力不会改变任务或意图状态。用户暂停/停止的意图不会因此重新打开。Read、事实写回、TaskStop、shell_close 等清理和记录工具可继续使用。
- CPU 达 90%、内存达 85%、有效可用内存低于 256 MiB 或数据盘低于 1 GiB 时停止新执行。CPU 降到 75%、内存降到 75%，并且内存/磁盘预留恢复到阈值的 125% 后重新放行。配置见 `config.example.json` 的 `resource_guard`，修改后重启生效。
- 采样失败、无效或超过 6 秒未更新时停止新执行。工具最多等待 30 秒，随后明确返回 `resource_blocked`，本次未执行；不会虚构阴性或成功。

## 必须启用的 OS 硬限制

应用准入无法限制已经运行或已脱离前台调用的进程。SDK 后台 Bash/PTY 仍由其会话管理器管理并在 Session.Close 时回收；前台工具许可在调用返回时释放，**不代表后台命令已结束**。

已有 systemd unit 现在包含 CPUQuota=200%、MemoryHigh=65%、MemoryMax=75%、MemorySwapMax=0、TasksMax=256、KillMode=control-group 和 20 秒停止宽限。CPUQuota=200% 指两颗逻辑 CPU 的总算力。实际 CPU、内存预算必须为 PostgreSQL、SSH、其他服务和内核留余量；百分比是服务所在主机的物理内存比例。systemd 的这些限制覆盖服务所有后代，停止服务清理整个 cgroup。官方语义见 [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)。

已有 Docker Compose 的 ARTEX 服务包含 `cpus`（默认 2）、`mem_limit`（默认 2g）、等额 `memswap_limit`、`pids_limit=256` 和 `init=true`。可通过 `ARTEX_CPU_LIMIT`、`ARTEX_MEMORY_LIMIT` 调整。2 GiB 是容器上限，不是对任意小内存主机都安全的主机预算；同机 PostgreSQL 还需单独预算。官方字段说明见 [Compose services](https://docs.docker.com/reference/compose-file/services/)。

升级已有部署：

1. 构建并安装新后端和前端；合并 `resource_guard` 配置。
2. systemd 用户更新实际安装的 unit（保留部署用户、路径、参数和已有定制），执行 `systemctl daemon-reload` 后在维护窗口重启服务；Compose 用户用新文件重建 ARTEX 容器。
3. 对运行中的 ARTEX PID 执行 `sh scripts/check-resource-limits.sh PID`，确认 CPU、内存、PID 控制器确实具有有限值，同时检查 `/api/resources`。
4. 在隔离的低限额环境验证拒绝派发、恢复、手动暂停保持、停止后子进程清理。不要在生产机上故意耗尽内存。

这些文件修改不会自动重启或修改当前服务器。没有硬限制的 Linux/Windows 裸进程只有准入保护。Windows 的 Python 超时取消使用系统 taskkill /T，尚无 Job 对象强约束；不宣称能够约束逃逸进程。当前采样支持 Linux/Windows，其他系统明确报告不可用并暂停高开销执行。

## 产物续派与结束状态

worker 在上下文里获得当前意图和同任务的有限产物清单：最多遍历 256 项、列出 24 个常规文件，不跟随符号链接，不读取文件正文；提示限制 5 KB，记录路径、大小和修改时间。意图结束后生成元数据 checkpoint；下一次运行显示元数据变化。这不是哈希完整性证明、完整磁盘盘点或进展判定器。模型按需读取已保存的事实和产物，记录具体修改、依赖与适用条件，不能把文件存在当成利用成功。

每个工作目录的 `execution-events.jsonl` 记录调用 ID、task/intent、耗时和状态，单文件约 2 MiB，保留一个轮转副本；不保存工具入参或返回正文。`returned` 只表示一次工具调用返回，`failed`、`cancelled`、`timeout`、`resource_blocked` 分开记录。后台完成状态仍看 SDK TaskOutput/TaskList；finding 以独立复核为准，目标达成仍走原有目标验收。没有把 CyberStrikeAI 中默认 `EvidenceVerified=true` 的语义搬入 ARTEX。

自定义 Python 执行现在限制输出缓冲为 2 MiB，非零退出、超时、取消返回错误并保留已有输出；Linux 对自建进程组进行清理，Windows 取消时清理进程树。任意 `setsid` 逃逸仍需要上述 OS 边界。自定义命令模板按实际 shell 引用参数：Windows PowerShell 用单引号加倍，POSIX 用原有单引号转义。

## 验证边界

自动测试覆盖压力/恢复回差、未知/陈旧采样、全局并发竞争、取消、告警和历史容量、Linux CPU/内存/cgroup 祖先夹具、真实 Windows 采样、进程退出/超时/输出上限、资源阻断先于意图领取、人工续派准入、Python 退出状态、SDK 后追加网络工具的保护、续派元数据和终态原因回归。

本地 Windows 测试、Linux 交叉编译与前端类型检查不等于 Linux 服务器的实际负载验收。当前本机 WSL 发行版的 VHD 路径失效，不能据此声称 Linux cgroup/子进程实机验收已经通过。Windows 的 race 运行器启动时报 0xc0000139，普通测试可运行，因此不能宣称 race 检查通过。远程 MCP 的取消确认、跨任务公平队列、独立后台执行 ID 服务、持久化外发告警及全量知识库检索不属于本批已经实现的能力。
