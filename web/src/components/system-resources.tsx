"use client";

import { useEffect, useState } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { api } from "@/lib/api";
import type { ResourceStatus } from "@/lib/types";

function bytes(n: number) {
  return n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)} GiB` : `${(n / 1024 ** 2).toFixed(0)} MiB`;
}

export function SystemResources() {
  const [data, setData] = useState<ResourceStatus | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    let request: AbortController | undefined;
    async function refresh() {
      if (!alive) return;
      if (!document.hidden) {
        request = new AbortController();
        const timeout = setTimeout(() => request?.abort(), 8000);
        try {
          const next = await api.resources(request.signal);
          if (alive) {
            setData(next);
            setError("");
          }
        } catch {
          if (alive) setError("资源状态暂不可用，请检查服务器连接");
        } finally {
          clearTimeout(timeout);
        }
      }
      if (alive) timer = setTimeout(refresh, 5000);
    }
    void refresh();
    return () => {
      alive = false;
      clearTimeout(timer);
      request?.abort();
    };
  }, []);

  const ready = data && data.memory_total > 0 && data.disk_total > 0;
  const rows = ready
    ? [
        { label: "主机 CPU", value: data.cpu_percent, detail: `${data.cpu_percent.toFixed(1)}%` },
        {
          label: "内存（计入容器限制）",
          value: data.memory_percent,
          detail: `可用 ${bytes(data.memory_available)} / ${bytes(data.memory_total)}`,
        },
        {
          label: "数据盘",
          value: 100 * (1 - data.disk_free / data.disk_total),
          detail: `剩余 ${bytes(data.disk_free)} / ${bytes(data.disk_total)}`,
        },
      ]
    : [];

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-sm">服务器资源保护</CardTitle>
          <span
            role="status"
            className={`text-xs ${error || data?.state !== "normal" ? "text-amber-600 dark:text-amber-400" : "text-emerald-600 dark:text-emerald-400"}`}
          >
            {error || (data ? data.reason : "等待采样…")}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <div className="grid gap-4 sm:grid-cols-3">
          {rows.map((row) => (
            <div key={row.label} className="space-y-1.5">
              <div className="flex justify-between gap-2">
                <span>{row.label}</span>
                <span className="text-muted-foreground">{row.detail}</span>
              </div>
              <Progress value={Math.max(0, Math.min(100, row.value))} aria-label={row.label} />
            </div>
          ))}
        </div>
        {data && (
          <p className="text-muted-foreground">
            工作器 {data.workers}/{data.limits.max_workers} · 正在调用的高开销工具 {data.tools}/{data.limits.max_tools}{" "}
            · 资源紧张时暂停新执行，恢复后自动放行。手动暂停保持不变。
            {ready ? ` 最近采样 ${new Date(data.at).toLocaleTimeString()}。` : " 尚无有效采样。"}
          </p>
        )}
        {data && (
          <p className="text-muted-foreground">
            {data.cgroup_memory_max
              ? `检测到 cgroup 内存硬上限 ${bytes(data.cgroup_memory_max)}`
              : "未检测到 cgroup 内存硬上限；请应用 systemd / Docker 资源限制"}
            {data.cgroup_pids_max ? ` · 进程上限 ${data.cgroup_pids_max}` : ""}。后台进程不计入当前工具调用数。
          </p>
        )}
        {data && data.alerts.length > 0 && (
          <details>
            <summary className="cursor-pointer text-muted-foreground">近期资源告警与恢复记录</summary>
            <ul className="mt-2 space-y-1">
              {data.alerts
                .slice(-5)
                .reverse()
                .map((alert) => (
                  <li key={alert.at}>
                    {new Date(alert.at).toLocaleTimeString()} · {alert.reason}
                  </li>
                ))}
            </ul>
          </details>
        )}
      </CardContent>
    </Card>
  );
}
