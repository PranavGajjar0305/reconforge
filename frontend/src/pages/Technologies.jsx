import { useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { Loading, Section, useLoad, Pending } from "../components/ui";

const ORDER = ["Web server", "Backend framework", "Frontend framework", "CMS", "Programming language", "CDN", "WAF",
  "Cloud provider", "Database indicators", "JavaScript library", "Analytics", "Payments", "API", "API documentation", "Identity"];

export default function Technologies() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  const [q, setQ] = useState("");
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const groups = Object.entries(data.technologies).sort(([a], [b]) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99));
  return (
    <div className="space-y-4">
      <input className="input w-72" placeholder="Filter technologies…" value={q} onChange={(e) => setQ(e.target.value)} />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {groups.map(([group, rows]) => {
          const vis = rows.filter((t) => !q || t.name.toLowerCase().includes(q.toLowerCase()));
          if (!vis.length) return null;
          return (
            <Section key={group} title={group}>
              {vis.map((t) => (
                <div key={t.id + group} className="mb-2 cursor-pointer rounded-[3px] border border-slate-800 p-2 hover:bg-slate-800/40" onClick={() => openAsset(t.id)}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-100">{t.name}</span>
                    <span className="text-xs text-slate-400">{t.versions.join(", ") || "version unknown"}</span>
                  </div>
                  <div className="mt-1 space-y-0.5">{t.apps.map((a) => <div key={a} className="mono text-[11px] text-slate-400">{a}</div>)}</div>
                </div>
              ))}
            </Section>
          );
        })}
      </div>
    </div>
  );
}
