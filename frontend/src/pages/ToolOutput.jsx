import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import LogView from "../components/LogView";
import { Empty, EvidenceLink, Loading, Pending, ServerTable, Tabs, TYPE_COLORS, useDebounced } from "../components/ui";

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

function RawOutput({ items }) {
  const [pick, setPick] = useState(items[0]?.id);
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, 350);
  useEffect(() => { if (!items.some((e) => e.id === pick)) setPick(items[0]?.id); }, [items]); // eslint-disable-line react-hooks/exhaustive-deps
  const fetchWindow = useCallback((start, limit) => api.evidenceLines(pick, { start, limit, q: q || undefined }), [pick, q]);
  const cur = items.find((e) => e.id === pick);
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <select className="input max-w-xl" value={pick || ""} onChange={(e) => setPick(e.target.value)} aria-label="Raw output">
          {items.map((e) => <option key={e.id} value={e.id}>{e.summary || e.id}{e.size ? ` · ${(e.size / 1024).toFixed(1)} KB` : ""}</option>)}
        </select>
        {cur && <EvidenceLink id={cur.id}>details</EvidenceLink>}
        {cur && <a className="btn-ghost" href={api.evidenceImageUrl(cur.id)} target="_blank" rel="noreferrer"><Icon name="download" size={12} /> full file</a>}
        <input className="input ml-auto w-56" placeholder="Filter lines" value={qIn} onChange={(e) => setQ(e.target.value)} />
      </div>
      {pick && <LogView fetchWindow={fetchWindow} resetKey={`${pick}|${q}`} tail={false} lineClass={lineClass} height="46vh"
                        empty={q ? "No lines match the filter." : "(empty)"} />}
    </div>
  );
}

function ModuleDetail({ scanId, module, running, openAsset }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("console");
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, 350);
  const [consoleTotal, setConsoleTotal] = useState(null);
  useEffect(() => { setData(null); setError(null); setQ(""); setConsoleTotal(null); }, [scanId, module]);
  useEffect(() => {  // summary only (counts, runs, first page); the tabs below load their own pages
    let alive = true;
    const load = () => api.moduleOutput(scanId, module).then((d) => alive && setData(d)).catch((e) => alive && setError(e));
    load();
    const t = running ? setInterval(load, 5000) : null;
    return () => { alive = false; t && clearInterval(t); };
  }, [scanId, module, running]);

  const fetchConsole = useCallback((start, limit) => api.logLines(scanId, { start, limit, module, q: q || undefined }), [scanId, module, q]);
  const fetchObs = useCallback(({ offset, limit, q: qq }) => api.moduleObservations(scanId, module, { offset, limit, q: qq }), [scanId, module]);
  const fetchEv = useCallback(({ offset, limit, q: qq }) => api.moduleEvidence(scanId, module, { offset, limit, q: qq }), [scanId, module]);

  if (error) return <Pending error={error} reload={() => setError(null)} />;
  if (!data) return <Loading what={`Loading ${module} output`} />;
  const r = data.runs[data.runs.length - 1] || {};
  const raw = data.raw_outputs || [];
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
        <div><dt className="text-slate-500">Results</dt><dd className="readout text-[20px] text-slate-50">{data.observations_total.toLocaleString()}</dd></div>
        <div><dt className="text-slate-500">Evidence items</dt><dd className="readout text-[20px] text-slate-50">{(data.evidence_total ?? data.evidence.length).toLocaleString()}</dd></div>
        <div><dt className="text-slate-500">Duration</dt><dd className="readout text-[20px] text-slate-50">{fmtDur(data.runs.reduce((a, x) => a + (x.duration_seconds || 0), 0) || null)}</dd></div>
        <div><dt className="text-slate-500">Passes</dt><dd className="readout text-[20px] text-slate-50">{data.runs.length}</dd></div>
        <div><dt className="text-slate-500">Engine</dt><dd className="mt-1 font-mono text-[12.5px] text-slate-200">{r.tool || "builtin"}</dd></div>
        {r.command && <div className="col-span-2 md:col-span-5"><dt className="text-slate-500">Command</dt><dd className="mono mt-0.5 break-all text-indigo-200">{r.command}</dd></div>}
        {r.reason && <div className="col-span-2 md:col-span-5"><dt className="text-slate-500">Note</dt><dd className="mt-0.5 text-slate-300">{r.reason}</dd></div>}
        {Object.keys(data.asset_types).length > 0 && (
          <div className="col-span-2 flex flex-wrap items-center gap-1.5 md:col-span-5">
            {Object.entries(data.asset_types).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
              <span key={t} className="pill" style={{ borderColor: (TYPE_COLORS[t] || "#5d7397") + "66" }}>
                <span style={{ color: TYPE_COLORS[t] }}>{t.replace("_", " ")}</span> {n.toLocaleString()}
              </span>
            ))}
          </div>
        )}
      </dl>
      <div className="flex flex-wrap items-center gap-2 px-4 pt-3">
        <Tabs value={tab} onChange={setTab} items={[["console", `Console${consoleTotal !== null ? ` (${consoleTotal.toLocaleString()})` : ""}`],
          ["results", `Results (${data.observations_total.toLocaleString()})`], ["evidence", `Evidence (${(data.evidence_total ?? data.evidence.length).toLocaleString()})`],
          ...(raw.length ? [["raw", `Raw tool output (${raw.length})`]] : [])]} />
        {tab === "console" && <input className="input ml-auto w-56" placeholder="Filter console lines" value={qIn} onChange={(e) => setQ(e.target.value)} />}
      </div>
      <div className="flex-1 p-4">
        {tab === "console" && (
          <LogView fetchWindow={fetchConsole} resetKey={`${scanId}|${module}|${q}`} live={running && r.status === "running"}
                   lineClass={lineClass} format={(l) => l.replace(/^\d{4}-\d\d-\d\d /, "")} height="52vh" onTotal={setConsoleTotal}
                   empty={q ? "No log lines match the filter." : "No log lines recorded for this module."} />
        )}
        {tab === "results" && (
          <ServerTable fetchPage={fetchObs} resetKey={`${scanId}|${module}`} pageSize={200} onRowClick={(o) => openAsset(o.asset_id)}
            searchPlaceholder="Search results…" poll={running ? 8000 : 0}
            empty="This module recorded no results in this execution."
            columns={[
              { key: "type", label: "Type", className: "whitespace-nowrap", render: (o) => <span className="font-mono text-[11.5px]" style={{ color: TYPE_COLORS[o.type] }}>{o.type}</span> },
              { key: "key", label: "Asset", className: "min-w-[220px] max-w-[360px]", render: (o) => <span className="break-all font-mono text-[12px] text-slate-100">{o.display || o.key}</span> },
              { key: "data", label: "What this module recorded", render: (o) => (
                <div className="font-mono text-[11px] text-slate-400">
                  {Object.entries(o.data).slice(0, 6).map(([k, v]) => (
                    <div key={k} className="max-w-[460px] truncate"><span className="text-slate-500">{k.replace(/^\+/, "")}:</span> {typeof v === "object" ? JSON.stringify(v) : String(v)}</div>
                  ))}
                </div>) },
              { key: "confidence", label: "Confidence", render: (o) => <span className="tabular text-slate-300">{o.confidence}</span> },
              { key: "evidence_id", label: "Evidence", render: (o) => <EvidenceLink id={o.evidence_id}>view</EvidenceLink> },
            ]} />
        )}
        {tab === "evidence" && (
          <ServerTable fetchPage={fetchEv} resetKey={`${scanId}|${module}`} pageSize={200} searchPlaceholder="Search evidence summaries…"
            empty="No evidence stored by this module."
            columns={[
              { key: "id", label: "Evidence", render: (e) => <EvidenceLink id={e.id} /> },
              { key: "kind", label: "Kind", render: (e) => <span className="font-mono text-[11.5px] text-slate-400">{e.kind}</span> },
              { key: "summary", label: "Summary", render: (e) => <span className="text-slate-200">{e.summary}</span> },
              { key: "size", label: "Size", render: (e) => <span className="tabular whitespace-nowrap text-slate-500">{e.size ? `${(e.size / 1024).toFixed(1)} KB` : ""}</span> },
            ]} />
        )}
        {tab === "raw" && <RawOutput items={raw} />}
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
