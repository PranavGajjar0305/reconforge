import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { Empty, EvidenceLink, Loading, Pending, Tabs, TYPE_COLORS } from "../components/ui";

const DIODE = { completed: "ok", running: "live", failed: "bad", skipped: "off", pending: "off" };
const STATUS_TEXT = { completed: "text-emerald-300", running: "text-amber-300", failed: "text-[#ff8da0]", skipped: "text-slate-500", pending: "text-slate-500" };

function lineClass(l) {
  if (/ ERROR /.test(l)) return "t-err";
  if (/ WARNING /.test(l)) return "t-warn";
  if (/\] (starting|completed)/.test(l)) return "text-slate-100";
  if (/exec:/.test(l)) return "t-mod";
  if (/->\s*(200|hit)|hit /.test(l)) return "t-hit";
  if (/skipped/.test(l)) return "text-slate-500";
  return "";
}

function fmtDur(s) {
  if (s == null) return "–";
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function ScanPicker({ target, scanId, onPick }) {
  const [scans, setScans] = useState(null);
  useEffect(() => { api.scans(target).then(setScans).catch(() => setScans([])); }, [target]);
  if (!scans?.length) return null;
  return (
    <select className="input max-w-md" aria-label="Execution" value={scanId} onChange={(e) => onPick(e.target.value)}>
      {scans.map((s) => (
        <option key={s.id} value={s.id}>
          {s.started_at?.replace("T", " ").slice(0, 16)}  ·  {s.profile}  ·  {s.status}{s.trigger === "dashboard-action" ? "  ·  single tool" : ""}
        </option>
      ))}
    </select>
  );
}

function ModuleDetail({ scanId, module, running, openAsset }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("console");
  const [q, setQ] = useState("");
  useEffect(() => { setData(null); setError(null); setQ(""); }, [scanId, module]);
  useEffect(() => {
    let alive = true;
    const load = () => api.moduleOutput(scanId, module).then((d) => alive && setData(d)).catch((e) => alive && setError(e));
    load();
    const t = running ? setInterval(load, 3000) : null;
    return () => { alive = false; t && clearInterval(t); };
  }, [scanId, module, running]);

  const logLines = useMemo(() => (data?.log || "").split("\n").filter((l) => l && (!q || l.toLowerCase().includes(q.toLowerCase()))), [data, q]);
  const obs = useMemo(() => (data?.observations || []).filter((o) => !q || JSON.stringify(o).toLowerCase().includes(q.toLowerCase())), [data, q]);
  const raw = (data?.evidence || []).filter((e) => e.kind === "tool_output");

  if (error) return <Pending error={error} reload={() => setError(null)} />;
  if (!data) return <Loading what={`Loading ${module} output`} />;
  const r = data.runs[data.runs.length - 1] || {};
  return (
    <div className="hud flex min-h-[70vh] flex-col">
      <div className="hud-head flex-wrap">
        <div className="flex min-w-0 items-center gap-3">
          <span className={`diode ${DIODE[r.status] || "off"}`} />
          <h2 className="display truncate text-[20px] font-semibold text-slate-50">{module}</h2>
          <span className={`text-[12.5px] ${STATUS_TEXT[r.status] || ""}`}>{r.status || "not run"}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <span className="mr-1 text-[12px] text-slate-500">Download</span>
          {["txt", "json", "csv"].map((f) => (
            <a key={f} className="btn px-2.5 py-1 text-[12px]" href={api.moduleExportUrl(scanId, module, f)} download>
              <Icon name="download" size={12} />{f.toUpperCase()}
            </a>
          ))}
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 border-b border-slate-800 px-4 py-3 text-[12.5px] md:grid-cols-5">
        <div><dt className="text-slate-500">Results</dt><dd className="readout text-[20px] text-slate-50">{data.observations_total}</dd></div>
        <div><dt className="text-slate-500">Evidence items</dt><dd className="readout text-[20px] text-slate-50">{data.evidence.length}</dd></div>
        <div><dt className="text-slate-500">Duration</dt><dd className="readout text-[20px] text-slate-50">{fmtDur(data.runs.reduce((a, x) => a + (x.duration_seconds || 0), 0) || null)}</dd></div>
        <div><dt className="text-slate-500">Passes</dt><dd className="readout text-[20px] text-slate-50">{data.runs.length}</dd></div>
        <div><dt className="text-slate-500">Engine</dt><dd className="mt-1 font-mono text-[12.5px] text-slate-200">{r.tool || "builtin"}</dd></div>
        {r.command && <div className="col-span-2 md:col-span-5"><dt className="text-slate-500">Command</dt><dd className="mono mt-0.5 text-indigo-200">{r.command}</dd></div>}
        {r.reason && <div className="col-span-2 md:col-span-5"><dt className="text-slate-500">Note</dt><dd className="mt-0.5 text-slate-300">{r.reason}</dd></div>}
        {Object.keys(data.asset_types).length > 0 && (
          <div className="col-span-2 flex flex-wrap items-center gap-1.5 md:col-span-5">
            {Object.entries(data.asset_types).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
              <span key={t} className="pill" style={{ borderColor: (TYPE_COLORS[t] || "#5d7397") + "66" }}>
                <span style={{ color: TYPE_COLORS[t] }}>{t.replace("_", " ")}</span> {n}
              </span>
            ))}
          </div>
        )}
      </dl>
      <div className="flex flex-wrap items-center gap-2 px-4 pt-3">
        <Tabs value={tab} onChange={setTab} items={[["console", `Console (${(data.log || "").split("\n").filter(Boolean).length})`],
          ["results", `Results (${data.observations_total})`], ["evidence", `Evidence (${data.evidence.length})`],
          ...(raw.length ? [["raw", `Raw tool output (${raw.length})`]] : [])]} />
        <input className="input ml-auto w-56" placeholder="Filter this output" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="flex-1 p-4">
        {tab === "console" && (
          <div className="term h-[52vh] text-[11.5px] leading-5">
            {logLines.map((l, i) => <div key={i} className={`whitespace-pre-wrap break-all ${lineClass(l)}`}>{l.replace(/^\d{4}-\d\d-\d\d /, "")}</div>)}
            {!logLines.length && <div className="text-slate-500">No log lines{q ? " match the filter" : " recorded for this module"}.</div>}
            {running && r.status === "running" && <div className="animate-pulse text-amber-300">▍</div>}
          </div>
        )}
        {tab === "results" && (
          <div className="max-h-[52vh] overflow-auto rounded-[3px] border border-slate-800">
            <table className="tbl">
              <thead><tr><th>Type</th><th>Asset</th><th>What this module recorded</th><th>Confidence</th><th>Evidence</th></tr></thead>
              <tbody>
                {obs.map((o, i) => (
                  <tr key={i} className="cursor-pointer" onClick={() => openAsset(o.asset_id)}>
                    <td className="whitespace-nowrap font-mono text-[11.5px]" style={{ color: TYPE_COLORS[o.type] }}>{o.type}</td>
                    <td className="min-w-[220px] max-w-[360px] break-all font-mono text-[12px] text-slate-100">{o.display || o.key}</td>
                    <td className="font-mono text-[11px] text-slate-400">
                      {Object.entries(o.data).slice(0, 6).map(([k, v]) => (
                        <div key={k} className="max-w-[460px] truncate"><span className="text-slate-500">{k.replace(/^\+/, "")}:</span> {typeof v === "object" ? JSON.stringify(v) : String(v)}</div>
                      ))}
                    </td>
                    <td className="tabular text-slate-300">{o.confidence}</td>
                    <td><EvidenceLink id={o.evidence_id}>view</EvidenceLink></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!obs.length && <Empty>{q ? "Nothing matches the filter." : "This module recorded no results in this execution."}</Empty>}
            {data.observations_total > data.observations.length && (
              <div className="border-t border-slate-800 px-3 py-2 text-[12px] text-slate-500">
                Showing {data.observations.length} of {data.observations_total}. Download JSON or CSV for all of them.
              </div>
            )}
          </div>
        )}
        {tab === "evidence" && (
          <div className="max-h-[52vh] overflow-auto rounded-[3px] border border-slate-800">
            <table className="tbl">
              <thead><tr><th>Evidence</th><th>Kind</th><th>Summary</th><th>Size</th></tr></thead>
              <tbody>
                {data.evidence.filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q.toLowerCase())).map((e) => (
                  <tr key={e.id}>
                    <td><EvidenceLink id={e.id} /></td>
                    <td className="font-mono text-[11.5px] text-slate-400">{e.kind}</td>
                    <td className="text-slate-200">{e.summary}</td>
                    <td className="tabular whitespace-nowrap text-slate-500">{e.size ? `${(e.size / 1024).toFixed(1)} KB` : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.evidence.length && <Empty>No evidence stored by this module.</Empty>}
          </div>
        )}
        {tab === "raw" && raw.map((e) => (
          <div key={e.id} className="mb-3">
            <div className="mb-1 flex items-center gap-2 text-[12px] text-slate-400">{e.summary}<EvidenceLink id={e.id}>open</EvidenceLink></div>
            <pre className="term max-h-[46vh] whitespace-pre-wrap break-all">{e.content || "(empty)"}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ToolOutput() {
  const { scanId } = useParams();
  const [params, setParams] = useSearchParams();
  const { target, meta, openAsset } = useApp();
  const nav = useNavigate();
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [q, setQ] = useState("");
  const module = params.get("module");

  // no id: the running scan for this target, else its latest execution
  useEffect(() => {
    if (scanId) return;
    const run = meta.running?.[target];
    if (run) { nav(`/output/${run}`, { replace: true }); return; }
    api.scans(target).then((s) => {
      const full = (s || []).find((x) => x.trigger !== "dashboard-action") || (s || [])[0];
      if (full) nav(`/output/${full.id}`, { replace: true }); else setError(new Error("no scans"));
    }).catch(setError);
  }, [scanId, target]);

  const running = ["running", "starting"].includes(summary?.status);
  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    setSummary(null); setError(null);
    const load = () => api.scanModules(scanId).then((d) => alive && setSummary(d)).catch((e) => alive && setError(e));
    load();
    const t = setInterval(() => { if (alive) load(); }, 4000);
    return () => { alive = false; clearInterval(t); };
  }, [scanId]);
  useEffect(() => {  // pick the most useful module by default: the running one, else the first with results
    if (!summary || module) return;
    const m = summary.modules.find((x) => x.status === "running") || summary.modules.find((x) => x.observations > 0) || summary.modules[0];
    if (m) setParams({ module: m.module }, { replace: true });
  }, [summary, module]);

  if (error) return <Pending error={error} reload={() => setError(null)} />;
  if (!summary) return <Loading what="Loading tool output" />;
  const mods = summary.modules.filter((m) => !q || m.module.includes(q.toLowerCase()));
  const totals = summary.modules.reduce((a, m) => ({ obs: a.obs + (m.observations || 0), ev: a.ev + (m.evidence || 0) }), { obs: 0, ev: 0 });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="mr-auto">
          <h1 className="display text-[28px] font-semibold leading-tight text-slate-50">Tool output</h1>
          <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-slate-400">
            What each module ran, logged and found in one execution. Pick a module to read its console, results, evidence and raw tool output.
          </p>
        </div>
        <ScanPicker target={target} scanId={scanId} onPick={(id) => nav(`/output/${id}`)} />
        <a className="btn" href={api.modulesZipUrl(scanId)} download><Icon name="zip" size={14} /> All modules (.zip)</a>
        {running && <Link className="btn border-amber-400/50 text-amber-200" to={`/live/${scanId}`}><span className="radar active" style={{ "--size": "16px" }} /> Watch live</Link>}
      </div>
      <div className="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
        <aside className="hud self-start">
          <div className="hud-head">
            <span className="panel-title">Modules</span>
            <span className="tabular font-mono text-[11.5px] text-slate-500">{summary.modules.length} · {totals.obs} results</span>
          </div>
          <div className="p-2">
            <input className="input mb-2 w-full" placeholder="Find module" value={q} onChange={(e) => setQ(e.target.value)} />
            <ul className="max-h-[68vh] space-y-0.5 overflow-auto" aria-label="Modules">
              {mods.map((m) => {
                const sel = m.module === module;
                return (
                  <li key={m.module}>
                    <button onClick={() => setParams({ module: m.module })} aria-current={sel ? "true" : undefined}
                      className={`group flex w-full items-center gap-2.5 px-2.5 py-1.5 text-left transition-colors ${sel
                        ? "bg-indigo-400/10 shadow-[inset_2px_0_0_var(--ion)]" : "hover:bg-slate-800/60"}`}>
                      <span className={`diode ${DIODE[m.status] || "off"}`} />
                      <span className={`min-w-0 flex-1 truncate font-mono text-[12px] ${sel ? "text-indigo-100" : m.status === "skipped" || m.status === "pending" ? "text-slate-500" : "text-slate-200"}`}>{m.module}</span>
                      <span className="tabular font-mono text-[11px] text-slate-500">{m.observations || ""}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        </aside>
        {module ? <ModuleDetail scanId={scanId} module={module} openAsset={openAsset}
                                running={running && summary.modules.find((m) => m.module === module)?.status === "running"} />
                : <Empty>Select a module.</Empty>}
      </div>
    </div>
  );
}
