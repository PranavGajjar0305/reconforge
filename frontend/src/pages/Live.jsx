import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useApp } from "../App";
import { api, withToken } from "../api";
import Icon from "../components/icons";
import LogView from "../components/LogView";
import { Section, Stat, useDebounced } from "../components/ui";

const STATUS = { completed: "border-slate-700 text-slate-200", running: "border-amber-400 text-amber-200 bg-amber-400/10",
  failed: "border-[#ff3d71]/60 text-[#ff8da0]", skipped: "border-slate-800 text-slate-500 line-through decoration-slate-600", pending: "border-slate-800 text-slate-500" };
const TRACE = { completed: "done", running: "run", failed: "fail", skipped: "skip", pending: "" };
// filtering happens on the server (the log can be millions of lines); see reconforge/api/logview.py
const FILTERS = ["all", "commands", "modules", "errors"];

function colorize(line) {
  if (/ ERROR /.test(line)) return "text-[#ff8da0]";
  if (/ WARNING /.test(line)) return "text-amber-300";
  if (/exec:/.test(line)) return "text-indigo-300";
  if (/\] (GET|HEAD) /.test(line)) return "text-[#9fd3ff]";
  if (/\] (dns|tcp|tls|provider)/.test(line)) return "text-[#8fe3cf]";
  if (/\] (starting|completed)/.test(line)) return "text-slate-100";
  if (/skipped/.test(line)) return "text-slate-500";
  return "text-slate-400";
}

export default function Live() {
  const { scanId } = useParams();
  const { reloadMeta, setTarget } = useApp();
  const nav = useNavigate();
  const [done, setDone] = useState(false);
  const [prog, setProg] = useState(null);
  const [filter, setFilter] = useState("all");
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, 350);
  const [mod, setMod] = useState(null);          // null = all modules
  const [commands, setCommands] = useState(0);
  const [shownTotal, setShownTotal] = useState(0);
  const start = useRef(Date.now());
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    let alive = true;
    setDone(false);
    const tick = async () => {
      try {
        const p = await api.progress(scanId);
        if (!alive) return;
        setProg(p);
        if (p.target) setTarget(p.target);
        if (!["running", "starting"].includes(p.status)) { setDone((d) => { if (!d) reloadMeta(); return true; }); }
      } catch { /* not created yet */ }
      api.logLines(scanId, { kind: "commands", limit: 0 }).then((w) => alive && setCommands(w.total)).catch(() => {});
      setNow(Date.now());
    };
    tick();
    const t = setInterval(tick, done ? 10000 : 2000);
    return () => { alive = false; clearInterval(t); };
  }, [scanId, done]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setMod(null); }, [scanId]);

  const fetchWindow = useCallback((s, limit) =>
    api.logLines(scanId, { start: s, limit, module: mod || undefined, kind: filter === "all" ? undefined : filter, q: q || undefined }),
  [scanId, mod, filter, q]);
  const running = prog && ["running", "starting"].includes(prog.status) && !done;
  const modRunning = mod && (prog?.modules || []).some((r) => r.module.split("#")[0] === mod && r.status === "running");
  const modState = useMemo(() => {
    const m = {};
    (prog?.modules || []).forEach((r) => {  // merge rediscovery passes (name#2) into one chip
      const k = r.module.split("#")[0];
      const prev = m[k];
      m[k] = prev ? { ...r, observations: prev.observations + r.observations,
                      status: r.status === "running" ? "running" : prev.status === "completed" || r.status === "completed" ? "completed" : r.status } : r;
    });
    return m;
  }, [prog]);
  const current = Object.values(modState).find((r) => r.status === "running")?.module?.split("#")[0];
  const elapsed = prog?.duration_seconds ?? Math.round((now - start.current) / 1000);
  const c = prog?.asset_counts || {};

  return (
    <div className="space-y-4">
      <div className={`hud px-5 py-4 ${running ? "scanbar" : ""}`}>
        <div className="flex flex-wrap items-center gap-4">
          <div className={`radar ${running ? "active" : "idle"}`} style={{ "--size": "56px" }} />
          <div className="min-w-0 flex-1">
            <h1 className="display text-[26px] font-semibold leading-none text-slate-50">
              {running ? `Scanning ${prog?.target || ""}` : prog?.status === "failed" ? "Run failed" : prog?.status === "cancelled" ? "Run stopped" : "Run complete"}
            </h1>
            <div className="mt-1.5 text-[12px] text-slate-400">
              <span className="font-mono text-slate-300">{scanId}</span>, {prog?.profile} profile, {elapsed}s elapsed
              {prog?.planned?.length ? `, ${Object.values(modState).filter((r) => r.status !== "running").length} of ${prog.planned.length} modules done` : ""}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <a className="btn" href={withToken(`/api/scans/${scanId}/log?download=1`)} download><Icon name="download" size={13} /> Download log</a>
            <Link className="btn" to={`/output/${scanId}`}><Icon name="terminal" size={13} /> Tool output</Link>
            {running && <button className="btn border-[#ff3d71]/50 text-[#ff8da0]" onClick={() => api.cancel(scanId)}><Icon name="stop" size={13} /> Stop after current module</button>}
            {!running && prog && <>
              <Link className="btn" to={`/scans/${scanId}`}>Execution details</Link>
              <button className="btn-primary" onClick={() => nav("/")}>View results</button>
            </>}
          </div>
        </div>
        {/* signal trace: one segment per planned module */}
        <div className="trace mt-4" aria-hidden="true">
          {(prog?.planned || []).map((m) => {
            const r = modState[m];
            const st = r ? (r.status === "running" ? "running" : r.status) : (running ? "pending" : "skipped");
            return <span key={m} className={TRACE[st]} title={`${m}: ${st}`} />;
          })}
        </div>
      </div>
      {prog?.error && <div className="rounded-[3px] border border-[#ff3d71]/50 bg-[#ff3d71]/10 p-3 text-[13px] text-[#ffb3c0]">{prog.error}</div>}
      {!running && prog?.coverage && <div className="hud p-3 text-[12px] text-slate-300">{prog.coverage}</div>}
      <div className="grid grid-cols-3 gap-2 md:grid-cols-9">
        <Stat label="Hostnames" value={(c.subdomain || 0) + (c.domain || 0)} />
        <Stat label="IPs" value={c.ip || 0} />
        <Stat label="Open ports" value={c.service || 0} />
        <Stat label="Web services" value={c.web_app || 0} />
        <Stat label="Endpoints" value={c.endpoint || 0} />
        <Stat label="Technologies" value={c.technology || 0} />
        <Stat label="Certificates" value={c.certificate || 0} />
        <Stat label="Observations" value={c.finding || 0} />
        <Stat label="Actions logged" value={commands} accent="text-indigo-300" />
      </div>
      <Section title="Modules" right={<span className="text-[12px] text-slate-500">Select a module to see only its log and download its output</span>}>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter console by module">
          <button aria-pressed={!mod} onClick={() => setMod(null)}
            className={`flex items-center gap-2 rounded-[2px] border px-2.5 py-1 text-[12px] ${!mod ? "border-indigo-400 bg-indigo-400 font-semibold text-slate-950" : "border-slate-700 text-slate-200 hover:border-slate-500"}`}>
            All modules
            {current && <span className={`font-mono text-[11px] font-normal ${!mod ? "text-slate-900" : "text-amber-300"}`}>now: {current}</span>}
          </button>
          {(prog?.planned || []).map((m) => {
            const r = modState[m];
            const st = r ? (r.status === "running" ? "running" : r.status) : (running ? "pending" : "skipped");
            const sel = mod === m;
            return (
              <button key={m} aria-pressed={sel} title={r?.reason || st} disabled={!r} onClick={() => setMod(sel ? null : m)}
                className={`rounded-[2px] border px-2 py-1 font-mono text-[11px] transition-colors enabled:hover:border-slate-400 disabled:cursor-not-allowed ${STATUS[st] || STATUS.pending} ${sel ? "ring-2 ring-indigo-400 ring-offset-1 ring-offset-slate-900" : ""}`}>
                {st === "running" && <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-amber-400 align-middle" />}
                {m}{r && r.status !== "running" ? <span className="ml-1.5 text-slate-500">{r.observations}</span> : null}
              </button>
            );
          })}
        </div>
      </Section>
      <Section title={`${mod ? `${mod} log` : "Live console"} — ${shownTotal.toLocaleString()} line(s)`} right={
        <div className="flex items-center gap-2 text-xs">
          {mod && <>
            <a className="btn-ghost" href={api.moduleExportUrl(scanId, mod, "txt")} download><Icon name="download" size={13} /> {mod} output</a>
            <Link className="btn-ghost" to={`/output/${scanId}?module=${mod}`}>Inspect results</Link>
          </>}
          <div className="tabs" role="tablist">
            {FILTERS.map((f) => <button key={f} role="tab" aria-selected={filter === f}
              className="capitalize" onClick={() => setFilter(f)}>{f}</button>)}
          </div>
          <input className="input w-40" placeholder="filter text" value={qIn} onChange={(e) => setQ(e.target.value)} />
        </div>}>
        <LogView fetchWindow={fetchWindow} resetKey={`${scanId}|${mod}|${filter}|${q}`} live={!!(running && (!mod || modRunning))}
                 pollMs={1500} lineClass={colorize} format={(l) => l.replace(/^\d{4}-\d\d-\d\d /, "")} height="55vh"
                 onTotal={setShownTotal} empty={mod ? `No log lines for ${mod} yet.` : "Waiting for output…"} />
        {done && <div className="mt-2 text-[12px] text-slate-300">Run {prog?.status}.</div>}
      </Section>
    </div>
  );
}
