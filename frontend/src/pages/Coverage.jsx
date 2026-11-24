import { useApp } from "../App";
import { api } from "../api";
import { DataTable, Loading, Pills, Section, Stat, useLoad, Pending } from "../components/ui";

const PH = { completed: "text-emerald-300", partial: "text-amber-300", failed: "text-[#ff8da0]", skipped: "text-slate-500", not_run: "text-slate-600" };
const ST = { ok: "text-emerald-300", error: "text-[#ff8da0]", unavailable: "text-slate-500", disabled: "text-slate-600" };

export default function Coverage() {
  const { target } = useApp();
  const rd = useLoad(() => api.reportData(target), [target]);
  const tools = useLoad(() => api.tools(), []);
  if (rd.loading || tools.loading || rd.error) return <Pending loading={rd.loading || tools.loading} error={rd.error} reload={rd.reload} />;
  const c = rd.data.coverage || {};
  const m = c.metrics || {};
  return (
    <div className="space-y-4">
      <div className={`rounded-[3px] border p-3 text-sm ${c.level === "partial" ? "border-amber-500/40 bg-amber-500/10 text-amber-100" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-100"}`}>
        <b className="uppercase">{c.level === "partial" ? "Partial coverage" : "Complete for profile"}</b> — {c.statement}
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
        {Object.entries(m).filter(([, v]) => typeof v === "number").map(([k, v]) => <Stat key={k} label={k.replaceAll("_", " ")} value={v} />)}
      </div>
      <Section title="Phase completion">
        <div className="grid gap-2 md:grid-cols-4">
          {Object.entries(c.phases || {}).map(([ph, p]) => (
            <div key={ph} className="rounded-[3px] border border-slate-800 p-2">
              <div className="flex justify-between text-sm"><span className="text-slate-200">{ph}</span><span className={PH[p.status]}>{p.status}</span></div>
              <div className="mt-1 text-[11px]">{Object.entries(p.modules).map(([mod, st]) => <div key={mod} className={PH[st] || "text-slate-400"}>{mod}: {st}</div>)}</div>
            </div>
          ))}
        </div>
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Intelligence sources">
          <table className="tbl"><thead><tr><th>Source</th><th>Kind</th><th>Status</th><th>Results</th><th>Note</th></tr></thead><tbody>
            {Object.entries(c.sources || {}).map(([n, s]) => (
              <tr key={n}><td>{n}</td><td>{s.kind}</td><td className={ST[s.status]}>{s.status}</td><td>{s.results ?? ""}</td><td className="text-xs text-slate-500">{s.error}</td></tr>
            ))}
          </tbody></table>
        </Section>
        <Section title="Discovery source comparison (unique contribution)">
          <table className="tbl"><thead><tr><th>Source</th><th>Hosts</th><th>Unique</th><th>Unique hosts</th></tr></thead><tbody>
            {rd.data.source_comparison.map((s) => (
              <tr key={s.source}><td>{s.source}</td><td>{s.hosts}</td><td className={s.unique ? "text-emerald-300" : ""}>{s.unique}</td><td><Pills items={s.unique_hosts} /></td></tr>
            ))}
          </tbody></table>
        </Section>
      </div>
      <Section title="Tool registry & selection engine">
        <DataTable
          rows={tools.data}
          filters={[{ key: "cat", label: "Category", get: (r) => r.category }, { key: "prof", label: "Profile", get: (r) => r.profile },
                    { key: "sel", label: "Selected", get: (r) => (r.status.selected ? "selected" : "not selected") }]}
          columns={[
            { key: "name", label: "Tool" }, { key: "category", label: "Category" }, { key: "purpose", label: "Purpose", className: "text-xs" },
            { key: "profile", label: "Execution profile" }, { key: "maintenance", label: "Maintenance" },
            { key: "installed", label: "Installed", render: (r) => (r.status.installed ? <span className="text-emerald-300">{r.status.version || "yes"}</span> : "no") },
            { key: "api", label: "API env", render: (r) => <Pills items={r.api_env} /> },
            { key: "sel", label: "Selection", render: (r) => (r.status.selected ? <span className="text-emerald-300">selected</span> : <span className="text-xs text-slate-500">{r.status.reason}</span>) },
            { key: "install", label: "Install", render: (r) => <span className="mono text-[11px] text-slate-500">{r.install}</span> },
          ]}
        />
      </Section>
    </div>
  );
}
