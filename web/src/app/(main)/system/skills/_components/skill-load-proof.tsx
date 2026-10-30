import { Badge } from "@/components/ui/badge";
import type { SkillCall } from "@/lib/types";

const labels: Record<string, string> = {
  loaded: "正文已返回",
  failed: "读取失败",
  missing: "未找到",
  no_guidance: "未返回指引",
  cancelled: "已取消",
  timeout: "已超时",
  panicked: "读取异常",
  legacy_requested: "仅有调用请求",
};

export function SkillLoadProof({ call }: { call: SkillCall }) {
  const status = call.load_status ?? "legacy_requested";
  return (
    <div className="min-w-0 space-y-1">
      <div className="flex flex-wrap items-center gap-1">
        <Badge variant="outline" className="font-normal">
          {labels[status] ?? status}
        </Badge>
        {status === "loaded" && <span className="text-muted-foreground">{call.guidance_bytes ?? 0} 字节</span>}
      </div>
      {(Boolean(call.content_sha256) || Boolean(call.tool_use_id)) && (
        <details className="text-muted-foreground">
          <summary className="cursor-pointer">读取证明</summary>
          <div className="max-w-80 space-y-1 break-all">
            {call.tool_use_id && <p>工具调用 ID：{call.tool_use_id}</p>}
            {call.intent_id ? <p>意图：#{call.intent_id}</p> : null}
            {call.content_sha256 && <p>返回指引 SHA-256：{call.content_sha256}</p>}
            <p>读取耗时：{call.elapsed_ms ?? 0} ms</p>
          </div>
        </details>
      )}
    </div>
  );
}
