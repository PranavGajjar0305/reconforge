import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { EvidenceLink, Pending, SEV_COLOR, useDebounced, useLoad } from "../components/ui";

const STEP = 150;  // rows added each time you reach the end of the list

/* Calls onVisible when scrolled into view: renders the next rows only when they are needed. */
function MoreRows({ onVisible, colSpan, label }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const io = new IntersectionObserver((e) => e[0].isIntersecting && onVisible(), { rootMargin: "400px" });
    io.observe(el);
    return () => io.disconnect();
  }, [onVisible]);
  return <tr ref={ref}><td colSpan={colSpan} className="text-center"><button className="btn-ghost my-1" onClick={onVisible}>{label}</button></td></tr>;
}

const SEVS = ["critical", "high", "medium", "low", "info"];
const STATE_LABEL = { new: "New", investigating: "Investigating", confirmed: "Confirmed", false_positive: "False positive",
  accepted_risk: "Accepted risk", fixed: "Fixed" };
const STATE_TONE = { new: "text-indigo-200 border-indigo-400/40", investigating: "text-amber-200 border-amber-400/40",
  confirmed: "text-[#ff8da0] border-[#ff3d71]/50", false_positive: "text-slate-400 border-slate-600",
  accepted_risk: "text-slate-300 border-slate-600", fixed: "text-emerald-300 border-emerald-400/40" };
const CLOSED = new Set(["false_positive", "accepted_risk", "fixed"]);

function ScoreBar({ score }) {
  const pct = Math.min(100, (score / 130) * 100);
  return (
    <div className="flex items-center gap-2" title={`review priority ${score}`}>
      <div className="h-1.5 w-14 overflow-hidden rounded-[1px] bg-slate-800">
        <div className="h-full" style={{ width: `${pct}%`, background: score > 90 ? SEV_COLOR.critical : score > 55 ? SEV_COLOR.high : score > 30 ? SEV_COLOR.medium : "#5d7397" }} />
      </div>
      <span className="tabular w-8 font-mono text-[11px] text-slate-400">{Math.round(score)}</span>
    </div>
  );
}

function Detail({ item, states, onSet, openAsset }) {
  const [note, setNote] = useState(item?.note || "");
  useEffect(() => setNote(item?.note || ""), [item?.id]);
  if (!item) return <div className="hud p-6 text-[13px] text-slate-500">Select an observation to see the evidence, the recommendation and to record a decision.</div>;
  return (
    <div className="hud sticky top-20 max-h-[calc(100vh-7rem)] overflow-auto">
      <div className="hud-head">
        <span className="inline-flex items-center gap-2 text-[12px] font-semibold uppercase" style={{ color: SEV_COLOR[item.severity] }}>
          <span className="h-2 w-2" style={{ background: SEV_COLOR[item.severity] }} />{item.severity}
        </span>
        <ScoreBar score={item.score} />
      </div>
      <div className="space-y-3 p-4 text-[13px]">
        <h2 className="display text-[19px] font-semibold leading-snug text-slate-50">{item.title}</h2>
        <div className="font-mono text-[12px] break-all text-indigo-200">{item.subject}</div>
        <div className="flex flex-wrap gap-1.5 text-[11px]">
          {item.category && <span className="pill">{item.category}</span>}
          {item.rule && <span className="pill">{item.rule}</span>}
          {item.host_tier && <span className="pill">host {item.host_tier}</span>}
          {item.new && <span className="pill text-amber-200">new in last scan</span>}
          {item.cves.map((c) => <a key={c} className="pill text-indigo-200 hover:underline" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer noopener">{c}</a>)}
        </div>
        {item.description && <p className="leading-relaxed text-slate-300">{item.description}</p>}
        {item.recommendation && (
          <div className="rounded-[2px] border-l-2 border-emerald-400/60 bg-emerald-400/[0.05] px-3 py-2 text-slate-300">
            <div className="mb-0.5 text-[11.5px] text-emerald-300">Recommendation</div>{item.recommendation}
          </div>
        )}
        <div className="grid grid-cols-2 gap-2 text-[12px] text-slate-400">
          <div>Confidence <span className="text-slate-200">{item.confidence}</span></div>
          <div>Sources <span className="text-slate-200">{item.sources.join(", ") || "–"}</span></div>
          <div>First seen <span className="text-slate-200">{item.first_seen?.slice(0, 10)}</span></div>
          <div>Evidence <EvidenceLink id={item.evidence}>view</EvidenceLink></div>
        </div>
        <button className="btn w-full justify-center" onClick={() => openAsset(item.id)}>Open asset details</button>
        <div className="border-t border-slate-800 pt-3">
          <div className="mb-1.5 text-[12px] text-slate-400">Decision</div>
          <div className="grid grid-cols-2 gap-1.5">
            {states.map((s) => (
              <button key={s} onClick={() => onSet([item.id], s, note)}
                className={`rounded-[2px] border px-2 py-1.5 text-[12px] transition-colors ${item.status === s ? STATE_TONE[s] + " bg-slate-800" : "border-slate-700 text-slate-300 hover:border-slate-500"}`}>
                {STATE_LABEL[s]}
              </button>
            ))}
          </div>
          <textarea className="input mt-2 h-20 w-full text-[12.5px]" placeholder="Analyst note (saved with the decision)" value={note} onChange={(e) => setNote(e.target.value)} />
          {item.updated_at && <div className="mt-1 text-[11px] text-slate-500">Last decision {item.updated_at.replace("T", " ").slice(0, 16)}</div>}
        </div>
      </div>
    </div>
  );
}

export default function Triage() {
  const { target, openAsset } = useApp();
  const { data, error, loading, reload } = useLoad(() => api.triage(target), [target]);
  const [items, setItems] = useState(null);
  const [sev, setSev] = useState(new Set(SEVS.filter((s) => s !== "info")));
  const [state, setState] = useState("open");
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, 250);
  const [limit, setLimit] = useState(STEP);
  const [open, setOpen] = useState(new Set());  // groups shown in full
  const [host, setHost] = useState(null);
  const [groupBy, setGroupBy] = useState("none");
  const [sel, setSel] = useState(new Set());
  const [focus, setFocus] = useState(null);
  const [msg, setMsg] = useState("");
  useEffect(() => { if (data) setItems(data.items); }, [data]);
  const all = items || [];
  const counts = useMemo(() => Object.fromEntries(SEVS.map((s) => [s, all.filter((i) => i.severity === s && !CLOSED.has(i.status)).length])), [all]);
  const stateCounts = useMemo(() => all.reduce((a, i) => ({ ...a, [i.status]: (a[i.status] || 0) + 1 }), {}), [all]);
  const shown = useMemo(() => all.filter((i) => sev.has(i.severity))
    .filter((i) => state === "all" ? true : state === "open" ? !CLOSED.has(i.status) : i.status === state)
    .filter((i) => !host || i.host === host)
    .filter((i) => !q || `${i.title} ${i.subject} ${i.rule} ${i.category} ${i.cves.join(" ")}`.toLowerCase().includes(q.toLowerCase())), [all, sev, state, host, q]);
  const hosts = useMemo(() => {
    const m = {};
    all.filter((i) => !CLOSED.has(i.status) && i.host).forEach((i) => {
      const h = (m[i.host] = m[i.host] || { host: i.host, score: 0, n: 0, top: "info" });
      h.score += i.score; h.n += 1;
      if (SEVS.indexOf(i.severity) < SEVS.indexOf(h.top)) h.top = i.severity;
    });
    return Object.values(m).sort((a, b) => b.score - a.score).slice(0, 12);
  }, [all]);
  const grouped = useMemo(() => {
    if (groupBy === "none") return [["", shown]];
    const g = {};
    shown.forEach((i) => { const k = (groupBy === "host" ? i.host : groupBy === "category" ? i.category : i.title) || "—"; (g[k] = g[k] || []).push(i); });
    return Object.entries(g).sort((a, b) => b[1].reduce((n, i) => n + i.score, 0) - a[1].reduce((n, i) => n + i.score, 0));
  }, [shown, groupBy]);
  useEffect(() => { setLimit(STEP); }, [sev, state, host, q, groupBy]);
  // render budget: rows (and group headers) up to `limit`; each group shows 10 rows unless opened
  const page = useMemo(() => {
    const out = [];
    let used = 0, cut = false;
    for (const [g, rows] of grouped) {
      if (used >= limit) { cut = true; break; }
      const cap = !g || open.has(g) ? rows.length : Math.min(10, rows.length);
      const take = rows.slice(0, Math.max(0, Math.min(cap, limit - used - (g ? 1 : 0))));
      if (take.length < cap) cut = true;
      out.push([g, rows, take]);
      used += take.length + (g ? 1 : 0);
    }
    return { groups: out, more: cut, rowsShown: out.reduce((n, x) => n + x[2].length, 0) };
  }, [grouped, limit, open]);

  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const setStatus = async (ids, status, note) => {
    setMsg("");
    try {
      await api.setTriage(ids[0], status, note, ids);
      setItems((cur) => cur.map((i) => ids.includes(i.id) ? { ...i, status, note: note ?? i.note, updated_at: new Date().toISOString() } : i));
      setSel(new Set());
      setMsg(`${ids.length} observation(s) marked ${STATE_LABEL[status].toLowerCase()}.`);
    } catch (e) { setMsg(e.message); }
  };
  const focused = all.find((i) => i.id === focus);
  const maxHost = hosts[0]?.score || 1;
  const toggleSev = (s) => { const n = new Set(sev); n.has(s) ? n.delete(s) : n.add(s); setSev(n); };

  return (
    <div className="space-y-4">
      {/* severity bar: the board's controls are the counts themselves */}
      <div className="grid gap-2 sm:grid-cols-5">
        {SEVS.map((s) => (
          <button key={s} onClick={() => toggleSev(s)} aria-pressed={sev.has(s)}
            className={`hud px-3.5 py-2.5 text-left transition-opacity ${sev.has(s) ? "" : "opacity-40"}`}>
            <div className="readout text-[26px] leading-none" style={{ color: SEV_COLOR[s] }}>{counts[s]}</div>
            <div className="mt-1 flex items-center gap-1.5 text-[12px] capitalize text-slate-400"><span className="h-1.5 w-1.5" style={{ background: SEV_COLOR[s] }} />{s} · open</div>
          </button>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-3">
          <div className="hud p-3">
            <div className="mb-2 flex items-center justify-between text-[12px] text-slate-400"><span>Most exposed hosts (open observations, weighted by priority)</span>
              {host && <button className="btn-ghost" onClick={() => setHost(null)}>Clear host filter</button>}</div>
            <div className="grid gap-x-6 gap-y-1 md:grid-cols-2">
              {hosts.map((h) => (
                <button key={h.host} onClick={() => setHost(host === h.host ? null : h.host)} className={`flex items-center gap-2 py-0.5 text-left ${host === h.host ? "text-indigo-100" : ""}`}>
                  <span className="w-48 truncate font-mono text-[11.5px] text-slate-300">{h.host}</span>
                  <span className="h-1.5 flex-1 overflow-hidden bg-slate-800"><span className="block h-full" style={{ width: `${(h.score / maxHost) * 100}%`, background: SEV_COLOR[h.top] }} /></span>
                  <span className="tabular w-8 text-right font-mono text-[11px] text-slate-500">{h.n}</span>
                </button>
              ))}
              {!hosts.length && <div className="text-[12.5px] text-slate-500">No open observations.</div>}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input className="input w-72" placeholder="Search title, subject, rule, CVE" value={qIn} onChange={(e) => setQ(e.target.value)} />
            <select className="input" value={state} onChange={(e) => setState(e.target.value)} aria-label="Status">
              <option value="open">Open ({all.filter((i) => !CLOSED.has(i.status)).length})</option>
              <option value="all">All states ({all.length})</option>
              {data.states.map((s) => <option key={s} value={s}>{STATE_LABEL[s]} ({stateCounts[s] || 0})</option>)}
            </select>
            <select className="input" value={groupBy} onChange={(e) => setGroupBy(e.target.value)} aria-label="Group by">
              <option value="none">No grouping</option><option value="host">Group by host</option><option value="category">Group by category</option><option value="title">Group by issue</option>
            </select>
            <span className="ml-auto font-mono text-[12px] text-slate-500">{shown.length} shown</span>
          </div>
          {sel.size > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-[3px] border border-indigo-400/40 bg-indigo-400/[0.06] px-3 py-2 text-[12.5px]">
              <span className="text-indigo-100">{sel.size} selected</span>
              {data.states.map((s) => <button key={s} className="btn px-2 py-1 text-[12px]" onClick={() => setStatus([...sel], s)}>{STATE_LABEL[s]}</button>)}
              <button className="btn-ghost ml-auto" onClick={() => setSel(new Set())}>Clear</button>
            </div>
          )}
          {msg && <div className="text-[12.5px] text-slate-300">{msg}</div>}
          <div className="hud overflow-hidden">
            <table className="tbl">
              <thead><tr>
                <th className="w-8"><input type="checkbox" aria-label="Select all shown" checked={shown.length > 0 && shown.every((i) => sel.has(i.id))}
                  onChange={(e) => setSel(e.target.checked ? new Set(shown.map((i) => i.id)) : new Set())} /></th>
                <th>Priority</th><th>Severity</th><th>Observation</th><th>Subject</th><th>Status</th>
              </tr></thead>
              <tbody>
                {page.groups.map(([g, rows, take]) => [
                  g ? <tr key={`g-${g}`}><td colSpan={6} className="bg-slate-950/60 font-mono text-[11.5px] text-indigo-200">{g} <span className="text-slate-500">· {rows.length}</span>
                    {rows.length > 10 && <button className="btn-ghost ml-2 py-0 text-[11px]" onClick={() => { const n = new Set(open); n.has(g) ? n.delete(g) : n.add(g); setOpen(n); }}>
                      {open.has(g) ? "show first 10" : `show all ${rows.length}`}</button>}</td></tr> : null,
                  ...take.map((i) => (
                    <tr key={i.id} className={`cursor-pointer ${focus === i.id ? "bg-indigo-400/[0.07]" : ""} ${CLOSED.has(i.status) ? "opacity-55" : ""}`} onClick={() => setFocus(i.id)}>
                      <td onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label={`Select ${i.title}`} checked={sel.has(i.id)}
                        onChange={() => { const n = new Set(sel); n.has(i.id) ? n.delete(i.id) : n.add(i.id); setSel(n); }} /></td>
                      <td><ScoreBar score={i.score} /></td>
                      <td><span className="inline-flex items-center gap-1.5 text-[12px] capitalize"><span className="h-2 w-2" style={{ background: SEV_COLOR[i.severity] }} />{i.severity}</span></td>
                      <td className="max-w-[340px]"><div className="text-slate-100">{i.title}</div>
                        <div className="text-[11px] text-slate-500">{i.category}{i.new ? <span className="ml-1.5 text-amber-300">new</span> : null}</div></td>
                      <td className="max-w-[260px] break-all font-mono text-[11.5px] text-slate-300">{i.subject}</td>
                      <td><span className={`whitespace-nowrap rounded-[2px] border px-1.5 py-0.5 text-[11px] ${STATE_TONE[i.status]}`}>{STATE_LABEL[i.status]}</span></td>
                    </tr>
                  )),
                ])}
                {page.more && <MoreRows colSpan={6} onVisible={() => setLimit((l) => l + STEP)}
                                        label={`Showing ${page.rowsShown.toLocaleString()} of ${shown.length.toLocaleString()} — load more`} />}
              </tbody>
            </table>
            {!shown.length && <div className="p-6 text-center text-[13px] text-slate-500">Nothing matches these filters.</div>}
          </div>
        </div>
        <Detail item={focused} states={data.states} onSet={setStatus} openAsset={openAsset} />
      </div>
    </div>
  );
}
