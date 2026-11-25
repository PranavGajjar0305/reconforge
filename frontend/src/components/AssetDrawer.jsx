import { useState } from "react";
import { api } from "../api";
import { EvidenceLink, JsonView, Loading, Sev, TIER_STYLE, TYPE_COLORS, useLoad } from "./ui";

export default function AssetDrawer({ id, onClose, onNavigate }) {
  const { data, loading, reload } = useLoad(() => api.asset(id), [id]);
  const [tab, setTab] = useState("details");
  const [reason, setReason] = useState("");
  if (!id) return null;
  const toggleFP = async () => {
    await api.setFP(id, !data.false_positive, reason || "marked by analyst in dashboard");
    reload();
  };
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div className="h-full w-full max-w-2xl overflow-auto border-l border-slate-800 bg-slate-950 p-5" onClick={(e) => e.stopPropagation()}>
        {loading || !data ? <Loading /> : (
          <>
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 text-xs uppercase tracking-wide">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLORS[data.type] }} />
                  <span className="text-slate-400">{data.type}</span>
                  <span className="text-slate-500">· {data.scope}</span>
                  {data.status !== "active" && <span className="text-red-400">· {data.status}</span>}
                  {data.false_positive && <span className="text-yellow-300">· false positive</span>}
                </div>
                <div className="mono mt-1 text-base text-white">{data.display}</div>
                <div className="mt-1 text-xs text-slate-500">id {data.id} · first seen {data.first_seen} · last seen {data.last_seen} · confidence {data.confidence}</div>
              </div>
              <button className="btn" onClick={onClose}>✕</button>
            </div>
            {data.type === "finding" && (
              <div className="card mb-4">
                <div className="mb-1 flex items-center gap-2"><Sev s={data.attributes.severity} /><span className="font-medium">{data.attributes.title}</span></div>
                <p className="text-sm text-slate-300">{data.attributes.description}</p>
                <p className="mt-2 text-sm text-slate-400"><b>Recommended review:</b> {data.attributes.recommendation}</p>
              </div>
            )}
            <div className="mb-3 flex gap-1">
              {["details", "related", "history", "sources"].map((t) => (
                <button key={t} className={`btn ${tab === t ? "border-indigo-500 text-white" : ""}`} onClick={() => setTab(t)}>{t}</button>
              ))}
            </div>
            {tab === "details" && (
              <>
                <div className="mb-2 text-xs text-slate-400">Latest evidence: <EvidenceLink id={data.evidence} /></div>
                <JsonView value={data.attributes} />
                <div className="mt-4 card">
                  <div className="mb-2 text-sm font-medium">False-positive management</div>
                  <div className="flex gap-2">
                    <input className="input flex-1" placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
                    <button className="btn" onClick={toggleFP}>{data.false_positive ? "Unmark false positive" : "Mark as false positive"}</button>
                  </div>
                  {data.fp_reason && <div className="mt-2 text-xs text-slate-400">Reason: {data.fp_reason}</div>}
                  <div className="mt-1 text-[11px] text-slate-500">Flags persist across future scans; flagged items are excluded from reports, notifications and prioritisation.</div>
                </div>
              </>
            )}
            {tab === "related" && (
              <table className="tbl">
                <thead><tr><th>Relation</th><th>Asset</th><th>Kind</th><th>Evidence</th></tr></thead>
                <tbody>
                  {data.related.map((r, i) => (
                    <tr key={i} className="cursor-pointer" onClick={() => onNavigate?.(r.asset.id)}>
                      <td className="text-slate-400">{r.direction === "out" ? `→ ${r.relation}` : `← ${r.relation}`}</td>
                      <td><span className="mr-1 text-[11px] text-slate-500">{r.asset.type}</span><span className="mono">{r.asset.display}</span></td>
                      <td>{r.confirmed ? <span className="text-emerald-300">confirmed</span> : <span className="text-amber-300">inferred</span>} <span className="text-slate-500">({r.confidence})</span></td>
                      <td>{(r.evidence_ids || []).slice(0, 2).map((e) => <div key={e}><EvidenceLink id={e} /></div>)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {tab === "related" && (data.related_counts || []).filter((c) => c.total > c.shown).map((c) => (
              <div key={c.direction + c.relation} className="mt-2 text-[12px] text-amber-200/80">
                Showing {c.shown.toLocaleString()} of {c.total.toLocaleString()} “{c.relation}” links
                {c.relation === "historical_url" ? " — browse all of them on the Endpoints page (Origin: Archive, Host filter)." : "."}
              </div>
            ))}
            {tab === "history" && (
              <div className="space-y-3">
                <div className="text-xs text-slate-400">State per scan ({data.history.states.length})</div>
                {data.history.states.map((s) => (
                  <div key={s.scan_id} className="card">
                    <div className="text-xs text-slate-400">{s.started_at} · {s.scan_id} {s.carried && <span className="text-amber-300">(carried forward)</span>} · {s.modules.join(", ")}</div>
                    <pre className="mono mt-1 whitespace-pre-wrap text-slate-300">{JSON.stringify(s.state)}</pre>
                  </div>
                ))}
                {data.history.changes.length > 0 && <div className="text-xs text-slate-400">Changes</div>}
                {data.history.changes.map((c) => <div key={c.id} className="text-sm">• {c.summary}</div>)}
              </div>
            )}
            {tab === "sources" && (
              <table className="tbl">
                <thead><tr><th>Observed</th><th>Module</th><th>Source</th><th>Confidence</th><th>Evidence</th></tr></thead>
                <tbody>
                  {data.history.observations.map((o) => (
                    <tr key={o.id}><td>{o.observed_at}</td><td>{o.module}</td><td>{o.source}</td><td>{o.confidence}</td><td><EvidenceLink id={o.evidence_id} /></td></tr>
                  ))}
                </tbody>
              </table>
            )}
            {data.priority && (
              <div className="card mt-4">
                <div className={`text-sm font-semibold ${TIER_STYLE[data.priority.tier]}`}>{data.priority.tier} · {data.priority.score}</div>
                {data.priority.factors.map((f, i) => <div key={i} className="text-xs text-slate-300">{f.points > 0 ? "+" : ""}{f.points} {f.reason}</div>)}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
