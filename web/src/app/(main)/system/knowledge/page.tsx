"use client";

import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { KnowledgeEntry, KnowledgeEvent, PoCSource, PublicCVEResult, PublicPoCResult } from "@/lib/types";

const emptyEntry = (): Partial<KnowledgeEntry> => ({
  id: 0,
  title: "",
  kind: "context",
  product: "",
  versions: "",
  cves: [],
  tags: [],
  summary: "",
  content: "",
  source_url: "",
  source_ref: "",
  state: "draft",
  scope_task_id: null,
});
const stateNames = { draft: "草稿", active: "允许检索", retired: "已停用" };
const kinds = {
  poc: "PoC 参考",
  advisory: "漏洞公告",
  methodology: "验证方法",
  negative: "负面经验",
  context: "背景资料",
};
function errorText(e: unknown) {
  return e instanceof Error ? e.message : "操作失败，请重试";
}
function date(s: string) {
  return s ? new Date(s).toLocaleString() : "—";
}

function applicabilityName(value: string) {
  const names: Record<string, string> = {
    version_candidate: "版本范围候选，仍需核对前提",
    version_mismatch: "版本不匹配",
  };
  return names[value] ?? "适用性未知";
}

function cveMentionDescription(value: string) {
  if (value === "mentioned") return "原文提到了当前 CVE，仍需核对适用性。";
  if (value === "other_cve_only") return "原文只提到了其他 CVE，请检查是否选错候选。";
  return "原文未提到当前 CVE，关联关系尚不明确。";
}

export default function KnowledgePage() {
  const [entries, setEntries] = useState<KnowledgeEntry[]>([]);
  const [events, setEvents] = useState<KnowledgeEvent[]>([]);
  const [query, setQuery] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [cve, setCve] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState<Partial<KnowledgeEntry>>(emptyEntry);
  const [publicCVEs, setPublicCVEs] = useState<PublicCVEResult | null>(null);
  const [publicPoCs, setPublicPoCs] = useState<PublicPoCResult | null>(null);
  const [bulk, setBulk] = useState("");
  const [source, setSource] = useState<PoCSource | null>(null);
  const [sourcePath, setSourcePath] = useState("");

  const load = useCallback(async (q = "", p = "", id = "") => {
    const data = await api.knowledge(q, p, id);
    setEntries(data.entries);
    setEvents(data.events);
  }, []);
  useEffect(() => {
    void load().catch((e) => setError(errorText(e)));
  }, [load]);
  async function action(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await work();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function save() {
    await action(async () => {
      const saved = await api.saveKnowledge(draft);
      setDraft(saved);
      setMessage("知识已保存。允许检索代表可以作为参考，不代表独立验证成功。");
      await load(query, product, cve);
    });
  }
  async function importDrafts() {
    await action(async () => {
      if (bulk.length > 500_000) throw new Error("本页每批导入上限约 500KB");
      const rows: unknown = JSON.parse(bulk);
      if (!Array.isArray(rows) || rows.length < 1 || rows.length > 20)
        throw new Error("请输入 1–20 个条目的 JSON 数组");
      let saved = 0;
      try {
        for (const value of rows) {
          if (typeof value !== "object" || value === null) throw new Error("条目须为 JSON 对象");
          const row = value as Partial<KnowledgeEntry>;
          await api.saveKnowledge({
            title: row.title,
            kind: row.kind ?? "context",
            product: row.product ?? "",
            versions: row.versions ?? "",
            cves: row.cves ?? [],
            tags: row.tags ?? [],
            summary: row.summary ?? "",
            content: row.content,
            source_url: row.source_url ?? "",
            source_ref: row.source_ref,
            state: "draft",
            scope_task_id: null,
            expires_at: row.expires_at ?? null,
          });
          saved += 1;
        }
        setBulk("");
        setMessage(`已导入 ${saved} 条草稿，请逐条检查来源、适用条件和敏感内容后启用。`);
      } catch (e) {
        throw new Error(`已保存 ${saved} 条；后续导入停止：${errorText(e)}`);
      } finally {
        await load(query, product, cve);
      }
    });
  }
  function candidateDraft(item: PublicCVEResult["candidates"][number]) {
    setDraft({
      ...emptyEntry(),
      title: `${item.cve} 公开参考`,
      kind: "advisory",
      product,
      versions: item.version_conditions.join("\n").slice(0, 300),
      cves: [item.cve],
      summary: item.summary,
      content: `${item.summary}\n\n${item.references.map((r) => `${r.kind}: ${r.url}`).join("\n")}\n\n仅公开候选，需核对版本、配置和补丁前提，尚未在当前目标验证。`,
      source_url: `https://nvd.nist.gov/vuln/detail/${item.cve}`,
      source_ref: `NVD:${item.cve}`,
    });
    setMessage("候选已填入编辑区，保存后仍为草稿。");
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="font-semibold text-xl">知识库与 PoC 发现</h1>
        <p className="mt-1 text-muted-foreground text-sm">
          产品 / 版本 → 公开 CVE → PoC 候选 → 条件核对 → 既有验证流程。检索命中与验证成功分别记录。
        </p>
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="text-muted-foreground text-sm">
          {message}
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">查资料与找 PoC</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <label htmlFor="knowledge-field-1" className="space-y-1 text-sm">
              知识关键词
              <Input
                id="knowledge-field-1"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="负面经验、验证方法…"
              />
            </label>
            <label htmlFor="knowledge-field-2" className="space-y-1 text-sm">
              公开产品名
              <Input
                id="knowledge-field-2"
                value={product}
                onChange={(e) => setProduct(e.target.value)}
                placeholder="PAN-OS / nginx"
              />
            </label>
            <label htmlFor="knowledge-field-3" className="space-y-1 text-sm">
              实际版本
              <Input
                id="knowledge-field-3"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="未知留空"
              />
            </label>
            <label htmlFor="knowledge-field-4" className="space-y-1 text-sm">
              CVE 编号
              <Input
                id="knowledge-field-4"
                value={cve}
                onChange={(e) => setCve(e.target.value.toUpperCase())}
                placeholder="CVE-2024-3400"
              />
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={busy} onClick={() => void action(() => load(query, product, cve))}>
              查本地知识
            </Button>
            <Button
              disabled={busy || (!product && !cve)}
              onClick={() =>
                void action(async () => {
                  setPublicPoCs(null);
                  setSource(null);
                  setPublicCVEs(null);
                  const r = await api.searchPublicCVE(product, version, cve);
                  setPublicCVEs(r.result);
                  setMessage(r.cached ? "已读取缓存；请留意资料时间。" : "已查询公开 CVE 资料。");
                })
              }
            >
              查公开 CVE
            </Button>
            <Button
              variant="secondary"
              disabled={busy || !cve}
              onClick={() =>
                void action(async () => {
                  setSource(null);
                  setPublicPoCs(null);
                  const r = await api.searchPublicPoC(cve);
                  setPublicPoCs(r.result);
                })
              }
            >
              找公开 PoC
            </Button>
          </div>
          <p className="text-muted-foreground text-xs">
            公开检索只发送产品名或 CVE，不发送目标地址、会话或凭据。结果最多 5 项并缓存 24
            小时；限流、超时和没有结果均不等于目标没有漏洞。未预置朋友包的历史知识库。
          </p>
          {publicCVEs && (
            <div className="space-y-3 border-t pt-3">
              <p className="text-muted-foreground text-xs">
                {publicCVEs.source} · {date(publicCVEs.retrieved_at)} · {publicCVEs.partial ? "结果不完整" : "本次结果"}
                {typeof publicCVEs.total_results === "number" &&
                  ` · 来源共 ${publicCVEs.total_results} 项，本次最多查询两个窗口`}
              </p>
              {publicCVEs.candidates.length === 0 && (
                <p className="text-sm">本次查询未返回 CVE，可调整公开产品名或精确编号。</p>
              )}
              {publicCVEs.candidates.map((item) => (
                <div key={item.cve} className="space-y-2 rounded-md border p-3 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <strong>{item.cve}</strong>
                    <span className="text-muted-foreground text-xs">{applicabilityName(item.applicability)}</span>
                  </div>
                  <p>{item.summary}</p>
                  <details>
                    <summary className="cursor-pointer text-xs">版本条件与来源</summary>
                    <pre className="mt-2 whitespace-pre-wrap break-all text-xs">
                      {item.version_conditions.join("\n") || "资料未提供可判定的版本条件"}
                    </pre>
                    {item.references.map((ref) => (
                      <a
                        key={ref.url}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-1 block break-all text-xs underline"
                      >
                        {ref.kind === "poc_candidate" ? "PoC 来源候选 · " : "参考 · "}
                        {ref.url}
                      </a>
                    ))}
                  </details>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || item.applicability === "version_mismatch"}
                      onClick={() =>
                        void action(async () => {
                          setCve(item.cve);
                          setSource(null);
                          setPublicPoCs(null);
                          const r = await api.searchPublicPoC(item.cve);
                          setPublicPoCs(r.result);
                        })
                      }
                    >
                      继续找 PoC
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => candidateDraft(item)}>
                      存为知识草稿
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {publicPoCs && (
            <div className="space-y-3 border-t pt-3">
              <p className="font-medium text-sm">{publicPoCs.cve} · PoC 仓库候选</p>
              <p className="text-muted-foreground text-xs">
                {publicPoCs.notice} {date(publicPoCs.retrieved_at)}
                {publicPoCs.partial ? " · 结果不完整" : ""}
              </p>
              {publicPoCs.repositories.length === 0 && (
                <p className="text-sm">本次没有找到仓库候选，不能据此判断无可用 PoC。</p>
              )}
              {publicPoCs.repositories.map((repo) => (
                <div key={repo.url} className="rounded-md border p-3 text-sm">
                  <a
                    href={repo.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all font-medium underline"
                  >
                    {repo.name}
                  </a>
                  <p className="mt-1">{repo.summary}</p>
                  <p className="mt-1 text-muted-foreground text-xs">未审计、未执行 · 更新 {date(repo.updated)}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    className="mt-2"
                    disabled={busy}
                    onClick={() =>
                      void action(async () => {
                        setSource(null);
                        const name = new URL(repo.url).pathname.slice(1);
                        const r = await api.readPoCSource(publicPoCs.cve, name);
                        setSource(r.result);
                        setSourcePath("");
                      })
                    }
                  >
                    阅读说明与源码
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      {source && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">候选原文 · {source.repository}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-muted-foreground text-xs">
              {source.notice} · {date(source.retrieved_at)}
            </p>
            <p className="break-all text-xs">
              {source.path} · blob {source.blob_sha}
            </p>
            {source.review && (
              <div className="space-y-2 rounded-md border p-3 text-sm">
                <p className="font-medium">源码待审查</p>
                <p className="text-muted-foreground text-xs">
                  {cveMentionDescription(source.review.cve_mention)}
                  字面提示不能替代代码审计，未命中提示也不代表安全。
                </p>
                <ul className="list-disc space-y-1 pl-5 text-xs">
                  {source.review.observations.map((observation) => (
                    <li key={observation}>{observation}</li>
                  ))}
                  {source.review.required_checks.map((check) => (
                    <li key={check}>{check}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <Input
                className="max-w-sm"
                aria-label="候选源码相对路径"
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                placeholder="源码相对路径；留空读 README"
              />
              <Button
                variant="outline"
                disabled={busy || !publicPoCs}
                onClick={() =>
                  void action(async () => {
                    if (!publicPoCs) return;
                    const r = await api.readPoCSource(publicPoCs.cve, source.repository, sourcePath);
                    setSource(r.result);
                  })
                }
              >
                读取文本
              </Button>
              <Button
                variant="secondary"
                disabled={busy || !publicPoCs}
                onClick={() => {
                  if (!publicPoCs) return;
                  if (new TextEncoder().encode(source.content).length > 32768) {
                    setMessage("原文超过知识条目 32KiB 上限，请在知识编辑区整理摘要和必要原文后保存，并保留来源。");
                    return;
                  }
                  setDraft({
                    ...emptyEntry(),
                    title: `${publicPoCs.cve} · 候选原文`,
                    kind: "poc",
                    cves: [publicPoCs.cve],
                    content: source.content,
                    source_url: source.url,
                    source_ref: `GitHub:${source.repository}@${source.blob_sha}`,
                    summary: "公开仓库候选原文，待审查适用条件和副作用；未执行、未验证。",
                  });
                  setMessage("已填入知识草稿编辑区；检查内容后保存。");
                }}
              >
                整理为知识草稿
              </Button>
            </div>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
              {source.content}
            </pre>
          </CardContent>
        </Card>
      )}
      <div className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="text-base">本地条目</CardTitle>
            <Button size="sm" variant="outline" onClick={() => setDraft(emptyEntry())}>
              新增
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {entries.length === 0 && (
              <p className="text-muted-foreground text-sm">没有匹配条目。公开候选可另行检索；人工审核资料后再启用。</p>
            )}
            {entries.map((entry) => (
              <button
                type="button"
                key={entry.id}
                disabled={busy}
                onClick={() =>
                  void action(async () => {
                    setDraft(await api.knowledgeEntry(entry.id));
                  })
                }
                className="w-full rounded-md border p-3 text-left hover:bg-muted/50"
              >
                <div className="flex justify-between gap-2 text-sm">
                  <span className="font-medium">{entry.title}</span>
                  <span className="shrink-0 text-muted-foreground text-xs">{stateNames[entry.state]}</span>
                </div>
                <p className="mt-1 text-muted-foreground text-xs">
                  {kinds[entry.kind]} · {entry.product || "通用参考"}
                  {entry.scope_task_id ? ` · 任务 #${entry.scope_task_id}` : " · 全局"}
                </p>
                <p className="mt-2 line-clamp-2 text-sm">{entry.summary}</p>
              </button>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{draft.id ? `编辑 #${draft.id}` : "新增知识草稿"}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <label htmlFor="knowledge-field-5" className="block space-y-1 text-sm">
              标题
              <Input
                id="knowledge-field-5"
                value={draft.title ?? ""}
                onChange={(e) => setDraft({ ...draft, title: e.target.value })}
              />
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-1 text-sm">
                类别
                <select
                  className="block h-9 w-full rounded-md border bg-background px-2"
                  value={draft.kind}
                  onChange={(e) => setDraft({ ...draft, kind: e.target.value as KnowledgeEntry["kind"] })}
                >
                  {Object.entries(kinds).map(([key, name]) => (
                    <option key={key} value={key}>
                      {name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="space-y-1 text-sm">
                状态
                <select
                  className="block h-9 w-full rounded-md border bg-background px-2"
                  value={draft.state}
                  onChange={(e) => setDraft({ ...draft, state: e.target.value as KnowledgeEntry["state"] })}
                >
                  {Object.entries(stateNames).map(([key, name]) => (
                    <option key={key} value={key}>
                      {name}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label htmlFor="knowledge-field-6" className="space-y-1 text-sm">
                适用产品
                <Input
                  id="knowledge-field-6"
                  value={draft.product ?? ""}
                  onChange={(e) => setDraft({ ...draft, product: e.target.value })}
                />
              </label>
              <label htmlFor="knowledge-field-7" className="space-y-1 text-sm">
                版本 / 前置条件
                <Input
                  id="knowledge-field-7"
                  value={draft.versions ?? ""}
                  onChange={(e) => setDraft({ ...draft, versions: e.target.value })}
                />
              </label>
            </div>
            <label htmlFor="knowledge-field-8" className="block space-y-1 text-sm">
              CVE（逗号分隔）
              <Input
                id="knowledge-field-8"
                value={(draft.cves ?? []).join(", ")}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    cves: e.target.value
                      .split(",")
                      .map((v) => v.trim().toUpperCase())
                      .filter(Boolean),
                  })
                }
              />
            </label>
            <label htmlFor="knowledge-field-9" className="block space-y-1 text-sm">
              摘要
              <Textarea
                id="knowledge-field-9"
                value={draft.summary ?? ""}
                onChange={(e) => setDraft({ ...draft, summary: e.target.value })}
              />
            </label>
            <label htmlFor="knowledge-field-10" className="block space-y-1 text-sm">
              参考正文（最多 32KiB）
              <Textarea
                id="knowledge-field-10"
                rows={7}
                value={draft.content ?? ""}
                onChange={(e) => setDraft({ ...draft, content: e.target.value })}
              />
            </label>
            <label htmlFor="knowledge-field-11" className="block space-y-1 text-sm">
              来源引用（必填）
              <Input
                id="knowledge-field-11"
                value={draft.source_ref ?? ""}
                onChange={(e) => setDraft({ ...draft, source_ref: e.target.value })}
                placeholder="公告、仓库 commit、文件或任务证据引用"
              />
            </label>
            <label htmlFor="knowledge-field-12" className="block space-y-1 text-sm">
              来源链接
              <Input
                id="knowledge-field-12"
                value={draft.source_url ?? ""}
                onChange={(e) => setDraft({ ...draft, source_url: e.target.value })}
              />
            </label>
            {draft.scope_task_id && (
              <label className="flex items-start gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={false}
                  onChange={() => setDraft({ ...draft, scope_task_id: null, state: "draft" })}
                />
                移出任务私有范围，作为全局草稿；发布前须先脱敏。
              </label>
            )}
            <label htmlFor="knowledge-field-13" className="block space-y-1 text-sm">
              到期时间（可选，ISO 格式）
              <Input
                id="knowledge-field-13"
                value={draft.expires_at ?? ""}
                placeholder="2027-01-01T00:00:00Z"
                onChange={(e) => setDraft({ ...draft, expires_at: e.target.value || null })}
              />
            </label>
            <p className="text-muted-foreground text-xs">
              资料内容按不可信参考处理。“允许检索”不代表验证成功；模型提交的经验只能创建当前任务草稿。
            </p>
            <Button disabled={busy || !draft.title || !draft.content || !draft.source_ref} onClick={() => void save()}>
              保存知识
            </Button>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">最近检索与注入记录</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-muted-foreground text-xs">
            returned：工具返回资料；prepared：预检已准备；model_request：在模型请求中观察到相同原文。记录哈希和字节数，不代表模型遵从或漏洞成功。
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr>
                  <th className="pb-2">时间 / 任务</th>
                  <th>动作 / 状态</th>
                  <th>条目 / 大小</th>
                  <th>内容 SHA256</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className="border-t">
                    <td className="py-2 pr-3">
                      {date(event.created_at)}
                      <br />
                      {event.task_id ? `#${event.task_id} ${event.agent}` : event.agent}
                    </td>
                    <td className="pr-3">
                      {event.action}
                      <br />
                      {event.status}
                    </td>
                    <td className="pr-3">
                      {event.entry_ids.join(", ") || "公开候选"} · {event.bytes} B
                    </td>
                    <td className="font-mono" title={event.sha256}>
                      {event.sha256.slice(0, 16)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {events.length === 0 && <p className="py-3 text-muted-foreground text-sm">尚无 agent 检索或注入记录。</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">导入已整理的 JSON 草稿</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-muted-foreground text-xs">
            每批 1–20 条，需含 title、content、source_ref。全部作为草稿，丢弃外部 verified
            标记。不要导入凭据、会话或历史目标资料。
          </p>
          <Textarea
            rows={5}
            value={bulk}
            onChange={(e) => setBulk(e.target.value)}
            placeholder={
              '[{"title":"经验标题","kind":"negative","content":"适用条件与证据摘要","source_ref":"来源引用"}]'
            }
          />
          <Button variant="outline" disabled={busy || !bulk} onClick={() => void importDrafts()}>
            导入为草稿
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
