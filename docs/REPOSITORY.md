# 仓库与版本管理

`main` 维护二开集成版；官方版本用带说明的 tag 固定原始提交，不额外建立无人维护的版本分支。只有将来需要分别回补修复时，才从相应 tag 建立维护分支。

## 官方快照

| 标签 | 定版提交 | 源码树 |
| --- | --- | --- |
| `upstream/v0.3.12` | `0ec51e37993aa50047317b009a05593c61bbdf1e` | `af221fb065b76ab8fd3803059e6d94dbdd14e8f6` |
| `upstream/v0.3.15` | `e6ec56999175509551a1e43a3ee3b053d0941bd9` | `bcee5171ddb6ce4d8daacbd13b6b36d5f7601b2b` |

核对日期：2026-10-24（Asia/Shanghai）。两个提交的作者均为 Autumn-27，提交信息分别为“定版 0.3.12”“定版 0.3.15”。本地 Git 对象与独立镜像 [RuoJi6/ARTEX 的 0312 提交](https://github.com/RuoJi6/ARTEX/commit/0ec51e37993aa50047317b009a05593c61bbdf1e)、[0315 提交](https://github.com/RuoJi6/ARTEX/commit/e6ec56999175509551a1e43a3ee3b053d0941bd9) 的 SHA 和源码树一致。

原上游 `Autumn-27/ARTEX` 在核对时返回 404。因此这里保留的是可交叉核对的历史定版提交，不声称重新从当前原站下载或验证了签名。

此前本地镜像带来的 `v0.3.15` 指向 `9db945e`，与原始定版在 README 和 Docker 镜像配置上有差异；它不作为本仓库官方快照的依据。两个 `upstream/` 标签均指向原始定版提交，不包含二开代码。标签发布后不移动；后续修订应使用新标签。

```sh
git fetch origin --tags
git switch --detach upstream/v0.3.12
# 或查看 0315
git switch --detach upstream/v0.3.15
# 回到二开版
git switch main
```

切换前应提交或暂存本地修改。若要同时查看多个版本，可从标签创建独立工作区：

```sh
git worktree add --detach ../artex-official-0312 upstream/v0.3.12
git worktree add --detach ../artex-official-0315 upstream/v0.3.15
```

对比源码：`git diff upstream/v0.3.12 upstream/v0.3.15`；对比二开：`git diff upstream/v0.3.15 main`。

## 目录约定

| 位置 | 内容 |
| --- | --- |
| 根目录 | 安装、构建、配置示例、许可，以及 README、整合、测试和 skills 入口 |
| `docs/design/` | chains、内网、蜜罐和分布式设计资料 |
| `docs/reports/` | 已发布的实战复盘与 A/B 报告 |
| `docs/validation/` | 有明确日期和适用范围的验证记录 |
| `docs/ROADMAP.md` | 后续路线与已知问题 |
| `docs/plans/`、`docs/drafts/`、`docs/local/`、`.local/` | 本地计划和草稿，Git 忽略 |

已完成的临时实施计划从当前版本移出，原内容仍可从 Git 历史恢复。设计与复盘按目录归档。移除 `web/media/dashboard.png`：它是 Studio Admin 模板宣传图，全仓未引用，约 1.19 MiB；项目截图、logo、依赖锁文件、技能来源和第三方许可证保留。

## 可再生产物与本地数据

Git 和 Docker 构建上下文排除依赖目录、Next.js 缓存、静态导出、Python 缓存、日志、临时文件和本地配置。Strobes 生成的 evidence/reports 内容也被排除，保留目录占位文件。

`web/.next/` 是可删除重建的缓存；`web/out/` 与 `server/webui/dist/` 是前端导出和内嵌构建输入，删除后应先重新构建前端再执行 `go build -tags embedui`。`node_modules/` 可通过 `npm ci` 恢复，日常开发无需反复清空。

`data/`、数据库、`config.json`、`.env`、`jwt.key` 需要独立备份，不能当作垃圾清除。Docker 的 `dist/<架构>/artex` 是发行镜像必需的构建输入，仍允许进入构建上下文。

这次整理不重写 Git 历史；历史提交中的旧路径仍然可见。历史工作分支也保留，避免影响已有工作区。
