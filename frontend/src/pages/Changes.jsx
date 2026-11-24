import { useMemo, useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { EvidenceLink, Loading, Section, useLoad, Pending } from "../components/ui";

const SIG = { high: "border-red-500/50 text-[#ffb3c0]", medium: "border-orange-500/40 text-orange-300", low: "border-slate-600 text-slate-400" };
const GROUPS = {
  "New assets": (c) => c.startsWith("new_") && c !== "new_security_observation",
  "Removed assets": (c) => c.startsWith("removed_") || c === "closed_port" || c === "subdomain_unresolved",
  "Technology changes": (c) => c.startsWith("tech_") || c === "new_technology",
  "Certificate changes": (c) => c.includes("certificate"),
  "DNS changes": (c) => c.startsWith("dns_") || c === "subdomain_now_resolves",
  "Security observation changes": (c) => c.includes("security") || c.startsWith("resolved_"),
};

export default function Changes() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.changes(target), [target]);
  const [cat, setCat] = useState("all");
  const [group, setGroup] = useState("all");
  const byScan = useMemo(() => {
    const m = new Map();
    (data || []).filter((c) => (cat === "all" || c.category === cat) && (group === "all" || GROUPS[group](c.category)))
      .forEach((c) => { if (!m.has(c.scan_id)) m.set(c.scan_id, { started: c.scan_started, items: [] }); m.get(c.scan_id).items.push(c); });
    return [...m.entries()];
  }, [data, cat, group]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const cats = [...new Set(data.map((c) => c.category))].sort();
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select className="input" value={group} onChange={(e) => setGroup(e.target.value)}>
          <option value="all">All change groups</option>
          {Object.keys(GROUPS).map((g) => <option key={g}>{g}</option>)}
        </select>
        <select className="input" value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="all">All categories</option>
          {cats.map((c) => <option key={c}>{c}</option>)}
        </select>
        <span className="ml-auto self-center text-xs text-slate-500">{data.length} changes recorded across scans</span>
      </div>
      {!byScan.length && <div className="text-sm text-slate-500">No changes match.</div>}
      {byScan.map(([scan, g]) => (
        <Section key={scan} title={<span>Scan <span className="mono">{scan}</span> · {g.started} · {g.items.length} change(s)</span>}>
          <div className="space-y-1">
            {g.items.map((c) => (
              <div key={c.id} className={`cursor-pointer rounded-[3px] border-l-4 bg-slate-900/50 px-3 py-2 hover:bg-slate-800/40 ${SIG[c.significance]}`} onClick={() => c.asset_id && openAsset(c.asset_id)}>
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="text-[11px] font-semibold uppercase">{c.significance}</span>
                  <span className="pill">{c.category}</span>
                  <span className="text-slate-100">{c.summary}</span>
                  {c.notified && <span className="text-[11px] text-emerald-400">notified</span>}
                </div>
                <div className="mt-1 grid gap-2 text-[11px] md:grid-cols-2">
                  <div><span className="text-slate-500">previous </span><span className="mono text-slate-400">{JSON.stringify(c.previous)?.slice(0, 220)}</span></div>
                  <div><span className="text-slate-500">current </span><span className="mono text-slate-300">{JSON.stringify(c.current)?.slice(0, 220)}</span></div>
                </div>
                <div className="text-[11px] text-slate-500">first observed {c.first_observed} {c.evidence && <>· evidence <EvidenceLink id={c.evidence} /></>}</div>
              </div>
            ))}
          </div>
        </Section>
      ))}
    </div>
  );
}
