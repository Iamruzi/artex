# ARTEX 分布式详细设计（M0)

> 状态：待评审。前置文档：FUTURE.md（可行性与耦合点评估，本文的"为什么"都在那里）。
> 目标读者：维护者。目标：评审通过后，按本文档可直接开工 M1。
> 2026-09-20。

---

## 1. 目标与范围

**做什么**：把 worker 的**工具执行面**从 server 进程拆到远程节点（node),server 保留大脑（LLM/planner/审批/探索图/双图存储）。node 只出网连接 server，无需入站端口。

**不做什么（本期）**:LLM 调用不下发（key 不出 server);planner 不下发；不做多 server 联邦；不动探索图/资产图数据模型。

**关键架构决策（与 FUTURE.md 一致，此处定稿）**:

- **瘦节点（thin node)**:node 上没有 agent loop，只有"工具执行器"。工具调用以 RPC 粒度下发（一条 Bash 命令、一次 WebFetch),LLM 循环、意图认领、收尾写回全在 server。
  - 理由：① LLM key 不出 server 天然成立；② node 被控的爆炸半径最小（只见单条调用，不见全局作战图）;③ node 实现极简（一个静态二进制 + 武器库）。
  - 代价：每个工具调用一次网络往返。LLM 调用本身秒级，工具调用往返增加 <1s，可接受。
  - 被否决的备选：胖节点（整个 worker 下放）——node 要持 LLM 代理凭证、能看到任务全貌，被控损失大；留给远期。

## 2. 总体架构

```
┌────────────────────────────── server ──────────────────────────────┐
│ Web UI │ planner │ worker(LLM loop) │ guard PDP │ PG │ 调度器      │
│ 节点管理:注册审批/吊销/指纹;工具调用分发;结果回收;会话/隧道台账   │
└───▲──────────────────────────────────────────▲────────────────▲────┘
    │ ① SSE 下行流(mTLS):tool_call / cancel /   │ ② HTTPS POST:   │ ③ HTTPS POST:
    │   config.sync                              │   tool_result   │   心跳/日志/制品
    │                                            │   ask 申请      │   /流量包
┌───┴────────────┐                     ┌─────────┴──┐
│ node-A(外网 VPS)│                     │ node-B(内网跳板)│
│ ToolRunner:Bash │                     │ ToolRunner  │
│ /WebFetch/投递  │                     │ 会话驱动/隧道  │
│ 本地 MITM 录制  │                     │ 本地 MITM    │
└────────────────┘                     └─────────────┘
```

- 通道全部 **TLS 1.3 + mTLS**;node 侧零监听端口。
- 三条逻辑通道复用一个 mTLS 连接面（独立端口，默认 :9800)，不挂伪装门控（mTLS 即隐匿：无客户端证书连 TLS 握手都过不去）。

## 3. 节点协议

### 3.1 注册与认证（enrollment)

```
admin(UI)                server                       node
  │  添加节点 → 生成一次性注册令牌(10min,一次一密)     │
  │◀── token ──│                                        │
  │            │                    ./artex-node --server https://S:9800 --token T
  │            │◀──── TLS(只验 server 证书) POST /node/v1/enroll {token, CSR, hostname, 能力} ──│
  │            │  令牌有效 → 签发客户端证书,状态 pending_approval
  │  UI 出现"待批准节点"(证书指纹/hostname/来源 IP)      │
  │  人工批准 ──→│ 状态 active                           │
  │            │◀──── 节点长轮询 enroll 状态 → 拿到签名证书 ────│
  │            │                     之后全部流量走 mTLS ◀────▶│
```

- CA:server 首启自签 CA(`dataDir` 外的 keyDir,与 jwt.key/gate.key 同规约）。
- 吊销 = 删指纹（拒绝该证书的后续握手）;node 侧证书 30 天期，在线自动轮换。
- **人工批准不可省略**（防令牌泄漏即入网）；审批动作写审计。

### 3.2 工作分发（claim 模型，对齐现有 ClaimIntent CAS)

- node 上行：`GET /node/v1/claim?node_id=N&wait=30s`(SSE 长连接挂着）;
- 调度器按**亲和规则**(§4）挑一个 tool_call，经 SSE 下发；
- node 执行后 `POST /node/v1/result`(含 stdout/stderr/exit/截断标记）;server 侧 worker 的工具调用点拿到结果，流程与本地执行完全一致；
- 大输出沿用现有 spill 语义：超阈值落 node 本地文件 + 回传路径句柄，worker 需要内容时按需拉（`GET /node/v1/artifact`)。

### 3.3 控制面

- **取消**:server 经 SSE 下发 `cancel{call_id}`,node kill 进程组；node 掉线时 server 端调用点按"节点失联"错误返回给 worker(等价于本地工具被 kill);
- **纠偏/暂停**:pause 在 server 的 worker loop 层实现（不再下发新调用即可），无需 node 配合；
- **心跳**:node 每 15s 心跳（含负载、版本、武器库清单哈希）;server 判定失联 = 45s 无心跳。

### 3.4 guard 下放（审批不形同虚设的关键）

原则：**决策在 server，执行在 node，node 无条件服从 server 下发的判定**。

- 工具调用下发**前**,server 侧先过 guard PDP(RoE 检查 + intercept 规则 + 出口指纹检查，全部现有逻辑原样跑——它们读的都是 server 侧数据）;
- 判定 allow → 调用才下发；deny → 直接拦截（与本地一致）;
- ask → 走现有 `intercept_pending` 流程，server 侧等待审批结果后再决定下不下发——**对 node 完全透明**，现有阻塞-唤醒机制一行不改（阻塞发生在 server 的 worker goroutine，和现在一模一样）;
- node 侧只保留一道兜底：**出口敏感指纹本地拦**（指纹哈希集随 config.sync 下发）——防 server 端逻辑旁路（如 node 本地排障直跑）;
- 这个设计把 FUTURE.md 里"guard 钩子要下放"的最大风险点化解了：审批流零改动。

### 3.5 LLM 代理面

瘦节点模型下**不需要**:LLM 调用全在 server。node 与 LLM 无任何接触。（保留扩展位：若将来做胖节点，再加 `/node/v1/llm` 代理端点，key 仍不出 server。)

## 4. 状态归属与节点亲和

有状态资产创建在哪个节点，就死在哪个节点：

- **台账扩展**:`sessions`/`tunnels`/`stage` 条目加 `node_id`(0=server 本地，向后兼容）;
- **亲和规则**:
  - `session_exec`、`tunnel_deploy` 的 via_session、portfwd 目标等 → 强制路由到该会话/隧道所在 node;
  - 无状态调用（扫描、HTTP 探测）→ 按任务路由策略自由分配（见 §5);
  - 节点失联 → 其上 alive 会话/隧道**诚实标 dead**（复用现有启动卫生/探活机制），依赖它们的意图由 planner 重新规划（已有重建路径）;
- **拓扑展示**:node 作为拓扑图的一类节点（平台→node→目标链路可视化），顺手把"哪台机器在打谁"看清楚。

## 5. 调度器

- 调度粒度 = **工具调用**（不是意图）；意图仍由 server 侧 worker 认领（现有 ClaimIntent 不动）;
- 任务→节点路由策略（每任务可配，默认 auto):
  - `local`：只跑 server 本机（现状，默认）;
  - `auto`：外网期任务 → 任意有外网出口的 node（打 tag：节点注册时声明 `egress=internet/intranet`)；拿到立足点意图 → 该意图及后续强制亲和到目标可达的 node;
  - `pinned:<node_id>`：整任务钉死某节点（合规/出口要求场景）;
- 并发：每节点可调最大并行调用数（node 自报 capacity,server 端令牌桶）。

## 6. 文件面与流量录制

- **武器库分发**:node 注册后按 `tools-manifest.json` 从 server 拉工具包（server 侧打包 data/tools → node 校验 sha256 → 落本地 tools/)；清单热更新时下差量。节点零预装。
- **工作区**:node 本地 `<nodeData>/tasks/<task>/<intent>/`;stage 投递改三段式：node `PUT /node/v1/stage`（上传）→ server 暂存（现有 stage.Manager)→ 目标从 server `/s/<token>` 拉取（现有机制不动）。
- **流量录制（最难项，定稿方案）**:MITM 下沉 node——node 本地起录制代理（同一套 traffic 包），自己的 CA(node 本地生成，私钥不出 node)，录制文件**批量回传** server 落索引。回放/检索统一在 server UI。
  - 备选（被否决）:node 流量回连 server 的 MITM——要求 server MITM 监听可达地址、CA 私钥要下发 node，破坏 loopback 假设且扩大攻击面。
- **transcript/断点续跑**:LLM loop 在 server,transcript 本来就在 server——零改动。

## 7. 故障语义

| 故障 | 行为 |
|---|---|
| node 失联（<45s) | 在途调用挂起等待；心跳恢复即续 |
| node 失联（>45s) | 在途调用报错（worker 视为工具失败，model_error 通道）;其上会话/隧道标 dead;open 意图可被其他节点认领（无亲和的） |
| server 重启 | node 指数退避重连；server 从 PG 恢复任务（现有机制），亲和状态从台账重建 |
| node 时钟漂移 | 握手时校验（±5min 拒绝，防回放） |
| node 被吊销 | 立即断连；其产出可按 node_id 批量标记存疑（UI 提供"隔离该节点产出"动作） |

## 8. 安全基线（汇总，不可裁剪）

1. mTLS 双向认证 + 人工批准入网 + 指纹吊销；
2. node 不持 LLM key、不持 PG DSN、不见全局作战图；
3. 全部 node 产出落库记 `node_id`;
4. 出口敏感指纹集下发 node 本地兜底拦截（哈希，不含原文）;
5. 节点通信口（:9800）不挂伪装门控，mTLS 即隐匿；
6. 武器库分发带钉版校验，node 侧拒绝执行清单外二进制的"自定义工具"（防 node 被用来跑私货——它跑的一切来自 server 下发的工具调用，本地无 shell 入口）;
7. 日志：node 操作审计（enroll/claim/result 元数据）落 server 审计流。

## 9. 实施分期（修订版，替代 FUTURE.md §7)

| 阶段 | 内容 | 验收标准 | 量级 |
|---|---|---|---|
| **M1 垂直切片** | `artex-node` 二进制 + mTLS 注册审批 + SSE 分发 + 单工具类型（Bash)+ 结果回传 + guard 服务器侧前置 + 调度器 local/auto 两档 | 一台空 VPS 注册后，web 任务的 Bash 调用全程在 node 上执行，审批流不变，流量录制回传可查 | 大（预计 2-3 周，新代码为主） |
| **M2 有状态亲和** | sessions/tunnels/stage 加 node_id + 亲和路由 + 失联标死 + 拓扑节点可视化 + 武器库分发 | 外网 node 拿 webshell → 内网操作自动亲和；node 断线诚实降级 | 中 |
| **M3 弹性与噪声** | node 容器镜像/用完即焚；可选诱饵角色（独立出口放假攻击流量，HONEYPOT-DETECTION-DESIGN 二-C);per-node 限速策略 | 节点随任务开关；诱饵不连坐真节点 | 中 |

M1 里没有：WebFetch 以外的工具类型逐批接入（M1 只接 Bash+WebFetch，投递/会话类工具在 M2 随亲和一起做）。

## 10. DB 与接口变更清单（预估）

- 新表：`nodes`(id, name, fingerprint, status, tags, capacity, last_beat, created_at)、`node_audit`(…);`sessions`/`tunnels`/`stage` 加 `node_id BIGINT NOT NULL DEFAULT 0`；
- 新端点（全部挂在独立 mTLS 监听口 + 管理 UI 走现有 JWT 口）:
  - 节点侧：`POST /node/v1/enroll`、`GET /node/v1/claim`(SSE)、`POST /node/v1/result`、`GET /node/v1/artifact`、`POST /node/v1/heartbeat`、`PUT /node/v1/stage`;
  - 管理侧：`GET/POST /api/nodes`、`POST /api/nodes/{id}/approve|revoke`、节点详情页（拓扑入口）;
- worker 工具执行层：`harness` 的工具调用点包一层 `ToolTransport` 接口（local 直连 / node RPC)——**这是整个设计里唯一侵入 agent 核心的点**，已确认现有工具调用收敛在单一 dispatch 形状（FUTURE.md §2 抽象缝），接口层加在这里。

## 11. 开放问题（评审时拍板）

1. **SSE vs WebSocket vs gRPC**：倾向 SSE（下行）+POST（上行）——零新依赖、Go net/http 原生、穿透性好；gRPC 引入 protobuf 依赖，收益不大。评审确认。
2. **node 二进制形态**：单静态二进制（artex-node)+ 武器库按需拉取；是否提供官方 docker 镜像（M3 再定）。
3. **多 server 联邦**（跨团队共享节点池）：本期明确不做。
4. node 侧 MITM 的 CA 信任链在回传包上如何标记（防伪造录制）:M1 内定——录制包带 node 证书签名。

## 12. 风险回顾（与 FUTURE.md 对齐后的净结论)

- 最大工程风险（控制面远程化）被"瘦节点"消解大半：意图认领/取消/纠偏全部留在 server，只是工具调用的传输层变了；
- 剩余难点收敛为：① ToolTransport 接口的干净插入；② 流量录制下沉与回传；③ 亲和调度。三者都有现成基础（工具 dispatch 单形状、traffic 包可复用、台账机制现成）;
- 工期上 M1 是大头，建议独立排期、先在 VPS+内网 VM 双节点环境验证再合主干。

---

## 13. 评审问答（2026-09-20 评审讨论归档)

### Q1 分布式 vs 代理池？

不是二选一，是两层。**代理池只解决出口 IP 分散**：对内网渗透无能为力（内网要的是执行体在目标网络内，不是 IP 多）；长寿命状态（会话/隧道）挂不了轮换代理；机房代理 IP 还容易被反欺诈标记。**分布式 node 解决执行面+出口+状态的全分散**。结论：代理池可作为 node 之下的"出口轮换层"叠加（node egress 再走代理池）；只做外网扫描 IP 轮换时代理池可单独先行（纯 server 端改动，一周内）；内网只能走分布式。诱饵噪声两者都能承载，代理池更便宜。

### Q2 server↔node 同步机制

双向但不对等，server 永远是权威（PG 是唯一事实源）:
- 下行（SSE):config 同步带 **epoch 版本号**;node 心跳自报本地 epoch，落后即全量拉取；
- 上行（POST)：结果/制品带 `call_id`,**at-least-once 投递 + server 幂等去重**;
- 重连对账：node 上报本地存活的会话/隧道/进程清单，server 拿台账对账，对不上的诚实标 dead（复用现有探活语义）。

### Q3 节点隐蔽

诚实边界：防守方拿到 node 的 root 后，用户态没有可靠隐身术；rootkit 级手段不做。目标是"**不显眼 + 可快速销毁 + 找到了也没东西可挖**":
- 程序面：单静态二进制、无害命名、单目录、日志可全关；武器库缓存支持 `ephemeral` 标记（任务后自清）;**用完即焚容器节点**（方案 M3）是终极答案——溯源上去时什么都没有；瘦节点天然反收割（无 key/无 PG/无作战图）。
- 流量/端口面：node 零监听端口（扫描无面）;mTLS 长连接外形如普通 web 客户端；心跳间隔加抖动（固定节拍本身是 C2 指纹）;server 节点口可选在 443 挂正常内容静态站 + SNI 分流，无客户端证书者连握手都过不去；
- 可选增强（M3 再议）:server 挂 CDN 隐藏真实 IP(ECH+CDN 站点；经典 domain fronting 已被主流 CDN 禁掉，不承诺）。

### Q4 节点做成云厂商监控 agent 形态（类安骑士）?

可行且推荐，作为 Q3(a)"不显眼"的具体实现——定义为**可切换的伪装画像(persona profile)**:
- 要素：类厂商监控 agent 的进程/服务名与 systemd 描述、标准目录布局(/usr/local/share/…)、心跳做成指标上报形状(JSON telemetry、443、抖动间隔)、装完即忘(自启/自愈/低日志);
- **画像必须按环境选**:阿里云机器用安骑士风、AWS 用 SSM 风、小厂 VPS 用通用 systemd 风——在 Vultr 上跑"阿里云盾"反而是最大异常，选错不如不装;
- 边界：防"路过式排查"(ps/服务列表/日常巡检),防不了 root 级取证；兜底仍是瘦节点+用完即焚;
- 适用面：node 只部署在**自己租的 VPS**,不进目标网络；目标侧存在感由 webshell/会话承担,不在此列。

---

## 14. 模式选型调研（2026-09-20，为什么要"瘦节点"而不是别的）

调研了业界 8 种"中心调度+远程执行"模式（各模式的来源详见调研笔记，此处只留结论）:

| 模式 | 代表 | 节点可见度 | 有状态长连接 | 一句话判断 |
| --- | --- | --- | --- | --- |
| C2 框架 | Sliver / Cobalt Strike / Mythic | 单命令级(最小) | implant 内一等公民 | **与本设计同构**——把 operator 换成 LLM 循环 |
| CI runner | GitHub Runner / GitLab Runner | 整 job+secrets | 无跨 job 状态 | 认领/租约机制可抄,job 模型不合用 |
| 队列解耦 | Temporal / NATS JetStream | 单 task 输入 | 框架不管,需自建 | 编排持久化可借鉴,会话层要自己建 |
| 云沙箱 | E2B / Modal / Daytona | 最小(只见自己任务) | TTL 限制,弱 | 适合不可信代码/PoC 一次性池,不适合常驻 node |
| 侦察机队 | Axiom | 任务分片 | 无 | 无状态扫描扇出的补充组件 |
| 自治探针 | NodeZero / Pentera | 整任务(最大) | 探针内自治 | 自治引擎需下沉 node,与"LLM 在中心"冲突 |
| 多 agent 框架 | AutoGen / CrewAI | 消息流 | 管消息不管隧道 | 只解 LLM 编排,不解执行 |
| P2P/链式 | CS SMB Beacon 链 | 逐跳放大 | 链即状态,脆 | 仅"node 互相中继"拓扑思想可取 |

**结论：瘦节点 = C2 模式的合法防御侧同构**(Sliver 的 operator→LLM 循环、implant→node、session/beacon 双模→交互期/潜伏期),被控损失最小、隧道会话原生、出站回连天然适配 NAT——这是选它的根本原因，不是拍脑袋。

**从其他模式吸收的部分**:
- CI runner:`acquirejob`+`renewjob` 租约认领、label/tag 匹配 → 进 §3.2/§5 调度器;
- Temporal：事件溯源思想已由我们的 PG activity 流承担，不重引入框架;若未来要做跨任务编排持久化，优先评估 Temporal Go SDK 而非自建;
- Axiom 机队：无状态重活(大规模扫描扇出)可后接"临时机队"组件,与 node 池互补(M3 后);
- E2B/Modal 沙箱：不可信样本/PoC 的一次性执行池(远期);
- NodeZero 的"自治探针"：作为弱网/断连场景的降级模式备选,不进主线。

### Q5 职能型分布式（实战见闻：按杀伤链阶段分机器)

> 来源:用户 2026-09 应急中遇到的实战部署——1 号机做信息收集+指纹识别+凭证收集(爆破/短信绕过),2 号机做漏洞验证打 payload,3 号机承接成果做交互式深入渗透。

**本质**:按**噪声等级与归因风险**分层的职能分工——1 号机最吵、可牺牲(被封 IP 无所谓);3 号机最干净,从头到尾不出现在 noisy 流量里,蓝队封不到、溯源连坐不到。与我们的"位置型分布式"(按网络位置/出口分工)正交。

**吸收方式(改动小,排 M2 扩展项)**:
- node 加角色标签:`recon` / `exploit` / `ops`(可叠加),注册时声明;
- 意图按 chains 的 chain_tags(已有阶段语义)路由到对应角色节点;侦察意图去 recon 节点、利用验证去 exploit、会话/横向去 ops;
- 收益直接兑现:噪声隔离(recon 被封不伤 ops 立足点)+ 归因隔离;
- **我们比人工三机强的点**:他们的"承接"靠人工搬运成果,我们的承接由共享双图自动完成——recon 角色写回的资产/凭据,ops 角色的 worker 直接可用;
- 边界:小规模任务/靶场是杀鸡用牛刀,价值在真实行动与多目标规模场景;节点池 <2 时无意义。
