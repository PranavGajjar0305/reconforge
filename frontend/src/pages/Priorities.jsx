import { useApp } from "../App";
import { api } from "../api";
import { Loading, Section, TIER_STYLE, useLoad, Pending } from "../components/ui";

export default function Priorities() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <Section title="Asset prioritisation">
      <p className="mb-4 rounded-[3px] border border-slate-700 bg-slate-800/40 p-3 text-xs text-slate-300">{data.priority_disclaimer}</p>
      <div className="space-y-2">
        {data.priorities.map((p) => (
          <div key={p.asset.id} className="cursor-pointer rounded-[3px] border border-slate-800 p-3 hover:bg-slate-800/30" onClick={() => openAsset(p.asset.id)}>
            <div className="flex items-center gap-3">
              <span className={`text-lg font-bold ${TIER_STYLE[p.tier]}`}>{p.tier}</span>
              <div className="h-2 w-40 rounded bg-slate-800"><div className="h-2 rounded bg-indigo-500" style={{ width: `${p.score}%` }} /></div>
              <span className="text-sm text-slate-300">{p.score}</span>
              <span className="text-xs text-slate-500">{p.asset.type}</span>
              <span className="mono text-slate-100">{p.asset.key}</span>
            </div>
            <ul className="mt-2 space-y-0.5 pl-1 text-xs">
              {p.factors.map((f, i) => (
                <li key={i} className={f.points > 0 ? "text-slate-300" : f.points < 0 ? "text-emerald-300" : "text-slate-500"}>
                  <span className="inline-block w-12 font-mono">{f.points > 0 ? "+" : ""}{f.points}</span>{f.reason}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}
