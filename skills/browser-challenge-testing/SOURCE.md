# 来源与取舍

核对日期：2026-11-01。

- Microsoft Playwright MCP：<https://github.com/microsoft/playwright-mcp>，用于可见浏览器、DOM/可访问性快照、网络观察和持久会话。ARTEX 固定使用已验证版本，避免运行时跟随 `latest` 漂移。
- Cloudflare Turnstile 官方测试文档：<https://github.com/cloudflare/cloudflare-docs/blob/production/src/content/docs/turnstile/troubleshooting/testing.mdx>，用于自有站点的成功、失败、交互和重复 token 测试。
- Tesseract.js：<https://github.com/naptha/tesseract.js>，Apache-2.0，作为本地简单图片 OCR 的可选依赖。
- FlareSolverr：<https://github.com/FlareSolverr/FlareSolverr> 已评估但没有接入。它把自己定位为 Cloudflare bypass proxy，依赖独立浏览器/服务且挑战适配容易随 Cloudflare 变化；ARTEX 采用可见 Playwright 持久会话与官方测试键，证据链和会话归属更清楚。

本技能不包含第三方验证码代解 API、共享代理池、窃取浏览器 profile/Cookie 的扩展或反检测补丁。
