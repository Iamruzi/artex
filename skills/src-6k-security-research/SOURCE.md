# 来源与静态审查

- 用户提供：`src-6k-skill.zip`，2026-11-01 接入。
- 原包包含 102 个文件。ARTEX 仅导入原 `skills/skill/知识库/` 下的 49 个 Markdown 文件，并用新的 `SKILL.md` 作为受控入口。
- 未导入：外层 `AGENTS.md`、`config.toml`、`rules/`、Grok 用户手册、Playwright 启动器、FOFA MCP、`.env`、账号说明与辅助脚本。
- 原包 `fofa_dual.ps1` 含三组硬编码 FOFA 凭据；这些凭据没有复制、调用或写入 Git。原包的 `.env` 为空。
- 原包包含 `permission_mode = "always-approve"`、默认授权语境和永久规则声明；这些内容没有进入本技能，也不能覆盖 ARTEX 的任务和审批边界。
- 知识文件包含攻击样例与高风险测试方法，只能在当前 ARTEX 任务明确的授权 scope 内按最小影响方式使用。

原材料未声明许可证，因此本目录仅作为用户自己的 ARTEX 实例中的导入内容；不要把它当成已获第三方再分发许可的公共素材。
