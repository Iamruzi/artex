"use client";

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ModelPromptConfig, ModelPromptEvaluation, ModelPromptPreview } from "@/lib/types";

const modes = [
  { value: "off", label: "关闭（保持原提示词）" },
  { value: "authorized-testing", label: "授权安全测试" },
  { value: "compact-tools", label: "小模型工具调用" },
  { value: "custom", label: "自定义提示词" },
] as const;
const cases: Record<string, string> = {
  allowed_code_review: "允许的代码审查",
  failed_tool_is_not_success: "失败不得记为成功",
  tool_roundtrip: "工具实际执行与结果回传",
};
const statuses: Record<string, string> = {
  passed: "通过",
  assertion_failed: "未通过",
  invalid_response: "格式不符合要求",
  request_failed: "请求失败",
  cancelled: "已取消",
  resource_blocked: "资源不足，未发送",
};

export function ModelPromptFields({
  value,
  onChange,
  profileId,
  savedValue,
}: {
  value: ModelPromptConfig;
  onChange: (value: ModelPromptConfig) => void;
  profileId?: string;
  savedValue?: ModelPromptConfig;
}) {
  const [preview, setPreview] = React.useState<ModelPromptPreview | null>(null);
  const [result, setResult] = React.useState<ModelPromptEvaluation | null>(null);
  const [stale, setStale] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [previewBusy, setPreviewBusy] = React.useState(false);
  const [historyError, setHistoryError] = React.useState("");
  const running = React.useRef<AbortController | null>(null);
  const sameAsSaved = value.mode === (savedValue?.mode ?? "") && (value.text ?? "") === (savedValue?.text ?? "");

  React.useEffect(() => {
    let alive = true;
    setResult(null);
    setStale(false);
    setHistoryError("");
    if (profileId)
      void api
        .modelPromptLastEvaluation(profileId)
        .then((r) => {
          if (alive) {
            setResult(r.result);
            setStale(r.stale);
          }
        })
        .catch(() => {
          if (alive) setHistoryError("最近评测暂时无法读取，请稍后重新打开此配置。");
        });
    return () => {
      alive = false;
      running.current?.abort();
    };
  }, [profileId]);

  function change(next: ModelPromptConfig) {
    setPreview(null);
    onChange(next);
  }
  async function showPreview() {
    setPreviewBusy(true);
    try {
      setPreview(await api.modelPromptPreview(value));
    } catch (error) {
      toast.error(`预览失败：${(error as Error).message}`);
    } finally {
      setPreviewBusy(false);
    }
  }
  async function evaluate() {
    if (!profileId || busy || !sameAsSaved) return;
    const controller = new AbortController();
    running.current = controller;
    setBusy(true);
    try {
      setResult(await api.modelPromptEvaluation(profileId, controller.signal));
      setStale(false);
    } catch (error) {
      if (controller.signal.aborted) toast.message("已停止等待并取消本次请求");
      else toast.error(`评测失败：${(error as Error).message}`);
    } finally {
      running.current = null;
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid gap-2">
        <Label>模型提示词调试（可选）</Label>
        <p className="text-muted-foreground text-xs">
          按当前模型附加任务说明。自定义模式可对照不同写法；保存和预览不会调用模型。
        </p>
        <Select
          value={value.mode || "off"}
          onValueChange={(mode) =>
            change({ ...value, mode: (mode === "off" ? "" : mode) as ModelPromptConfig["mode"] })
          }
          disabled={busy || previewBusy}
        >
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {modes.map((mode) => (
              <SelectItem key={mode.value} value={mode.value}>
                {mode.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {value.mode === "custom" && (
        <div className="grid gap-2">
          <Label htmlFor="model-prompt-text">自定义提示词正文</Label>
          <Textarea
            id="model-prompt-text"
            rows={7}
            maxLength={8192}
            value={value.text ?? ""}
            onChange={(event) => change({ ...value, text: event.target.value })}
            disabled={busy || previewBusy}
            placeholder="填写当前模型的任务适配说明，不要包含密钥。"
          />
          <p className="text-muted-foreground text-xs">
            最多 8192 字节；中文会占多个字节。任务范围、工具权限与验收继续由 ARTEX 控制。
          </p>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={previewBusy || busy}
          onClick={() => void showPreview()}
        >
          {previewBusy ? "正在预览…" : "预览附加内容（不调用模型）"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!profileId || !value.mode || !sameAsSaved || busy}
          onClick={() => void evaluate()}
        >
          {busy ? "正在对照测试…" : "对照测试已保存配置"}
        </Button>
        {busy && (
          <Button type="button" size="sm" variant="outline" onClick={() => running.current?.abort()}>
            取消测试
          </Button>
        )}
      </div>
      {!sameAsSaved && (
        <p className="text-muted-foreground text-xs">提示词有修改，请先保存，再重新打开此配置进行对照测试。</p>
      )}
      <p className="text-muted-foreground text-xs">
        对照测试会调用模型，最多 8 次请求、总计 120
        秒；本地模型可能被加载。仅使用合成数据和本地算术工具，不运行渗透任务。
      </p>
      {preview && (
        <div className="grid gap-2 text-xs">
          <p className="break-all">配置摘要：{preview.digest || "关闭，无附加内容"}</p>
          <p className="text-muted-foreground">
            开启 LLM 请求记录后，可在实际请求正文搜索这个摘要，核对发送版本。预览本身不证明模型已经使用。
          </p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3">
            {preview.text || "当前不附加提示词。"}
          </pre>
        </div>
      )}
      {historyError && <p className="text-muted-foreground text-xs">{historyError}</p>}
      {result && (
        <div className="grid gap-2 border-t pt-3 text-xs">
          <p>
            最近评测：{new Date(result.started_at).toLocaleString()} ·{" "}
            {result.completed ? "已执行全部样本" : "未完成全部样本"}
          </p>
          {(stale || !sameAsSaved) && <p className="text-amber-600">结果对应旧配置，请勿作为当前配置的评测结论。</p>}
          <p>
            原始提示词通过 {result.baseline_passed}/3；适配后通过 {result.adapted_passed}/3；请求尝试 {result.requests}{" "}
            次。
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th className="p-1">样本</th>
                  <th className="p-1">版本</th>
                  <th className="p-1">结果</th>
                  <th className="p-1">工具执行</th>
                  <th className="p-1">耗时</th>
                </tr>
              </thead>
              <tbody>
                {result.samples.map((sample) => (
                  <tr key={`${sample.case}-${sample.variant}`}>
                    <td className="p-1">{cases[sample.case] ?? sample.case}</td>
                    <td className="p-1">{sample.variant === "baseline" ? "原始" : "适配"}</td>
                    <td className="p-1">{statuses[sample.status] ?? sample.status}</td>
                    <td className="p-1">{sample.tool_executions}</td>
                    <td className="p-1">{(sample.elapsed_ms / 1000).toFixed(1)}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary className="cursor-pointer">查看响应与用量</summary>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
          <p className="text-muted-foreground">
            这是单次合成样本对照，不能证明越狱成功率、漏洞发现率或实际利用能力提升。
          </p>
        </div>
      )}
    </div>
  );
}
