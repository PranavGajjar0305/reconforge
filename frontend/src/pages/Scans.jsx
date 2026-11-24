import { Fragment, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import Icon from "../components/icons";
import { useApp } from "../App";
import { api, withToken } from "../api";
import { Loading, Pills, Section, useLoad, Pending } from "../components/ui";

const STATUS = { completed: "text-emerald-300", partial: "text-amber-300", failed: "text-[#ff8da0]", running: "text-amber-300", skipped: "text-slate-500", cancelled: "text-slate-400" };

function ScanDetail({ scan }) {
  const reports = useLoad(() => api.scanReports(scan.id), [scan.id]);
  const [log, setLog] = useState(null);
  return (
    <div className="space-y-3 border-l-2 border-indigo-400/50 bg-slate-950/60 p-3">
      <div className="grid gap-3 md:grid-cols-3 text-xs">
        <div><div className="text-slate-500">Modules executed</div><Pills items={scan.modules_planned} /></div>
        <div><div className="text-slate-500">Tools executed</div><Pills items={scan.tools_executed} /></div>
        <div>
          <div className="text-slate-500">Reports</div>
          {(reports.data || []).filter((r) => r.format !== "csv").map((r) => (
            <a key={r.id} className="pill text-indigo-300" href={withToken(`/api/reports/${r.id}`)} target="_blank" rel="noreferrer">{r.format}</a>
          ))}
          <div className="mono mt-1 text-[11px] text-slate-500">{scan.report_dir}</div>
        </div>
      </div>
      <table className="tbl">
        <thead><tr><th>Module</th><th>Status</th><th>Tool</th><th>Observations</th><th>Started</th><th>Finished</th><th>Notes / command</th><th>Output</th></tr></thead>
        <tbody>
          {scan.module_runs.map((r, i) => (
            <tr key={i}>
              <td>{r.module}</td><td className={STATUS[r.status]}>{r.status}</td><td>{r.tool}</td><td>{r.observations}</td>
              <td className="text-xs">{r.started_at?.slice(11, 19)}</td><td className="text-xs">{r.finished_at?.slice(11, 19)}</td>
              <td className="text-xs text-slate-400">{r.reason}{r.skipped_inputs ? ` (incremental: ${r.skipped_inputs} input(s) fresh, skipped)` : ""}{r.command && <div className="mono">{r.command}</div>}</td>
              <td className="whitespace-nowrap">
                <Link className="btn-ghost" to={`/output/${scan.id}?module=${r.module.split("#")[0]}`}>Inspect</Link>
                <a className="btn-ghost" href={api.moduleExportUrl(scan.id, r.module.split("#")[0], "txt")} download aria-label={`Download ${r.module} output`}>
                  <Icon name="download" size={12} />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex flex-wrap gap-2">
        <button className="btn" onClick={async () => setLog(log ? null : await api.scanLog(scan.id))}>{log ? "Hide execution log" : "Show execution log"}</button>
        <a className="btn" href={withToken(`/api/scans/${scan.id}/log?download=1`)} download><Icon name="download" size={13} /> Download execution log</a>
        <a className="btn" href={api.modulesZipUrl(scan.id)} download><Icon name="zip" size={13} /> All module output (.zip)</a>
        <Link className="btn" to={`/output/${scan.id}`}><Icon name="terminal" size={13} /> Tool output</Link>
        {scan.status === "running" && <Link className="btn-primary" to={`/live/${scan.id}`}><Icon name="live" size={13} /> Watch live</Link>}
      </div>
      {log && <pre className="term max-h-96 whitespace-pre-wrap break-all text-[11px]">{log}</pre>}
    </div>
  );
}

export default function Scans() {
  const { target, meta, reloadMeta } = useApp();
  const { scanId } = useParams();
  const nav = useNavigate();
  const { data, loading, error, reload } = useLoad(() => api.scans(target), [target]);
  const [profile, setProfile] = useState("");
  const [msg, setMsg] = useState("");
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const configured = meta.configured_targets.includes(target);
  const start = async () => {
    setMsg("");
    try {
      await api.startScan(target, profile || null, null);
      setMsg("Scan started in the background — refresh in a moment.");
      setTimeout(() => { reload(); reloadMeta(); }, 3000);
    } catch (e) { setMsg(String(e.message)); }
  };
  return (
    <Section title="Reconnaissance execution history" right={
      configured && (
        <div className="flex items-center gap-2">
          <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="">target default profile</option>
            {Object.keys(meta.profiles).map((p) => <option key={p}>{p}</option>)}
          </select>
          <button className="btn-primary" onClick={start}>Run scan</button>
          <button className="btn" onClick={reload}>Refresh</button>
        </div>
      )}>
      {msg && <div className="mb-2 text-xs text-indigo-300">{msg}</div>}
      <table className="tbl">
        <thead><tr><th>Scan</th><th>Profile</th><th>Trigger</th><th>Status</th><th>Start</th><th>End</th><th>Duration</th><th>Completed</th><th>Failed</th><th>Skipped</th><th>Results</th><th>Changes</th></tr></thead>
        <tbody>
          {data.map((s) => (
            <Fragment key={s.id}>
              <tr className="cursor-pointer" onClick={() => nav(scanId === s.id ? "/scans" : `/scans/${s.id}`)}>
                <td className="mono">{s.id}</td><td>{s.profile}{s.incremental ? " (incr.)" : ""}</td><td>{s.trigger}</td>
                <td className={STATUS[s.status]}>{s.status}</td><td className="text-xs">{s.started_at}</td><td className="text-xs">{s.finished_at}</td>
                <td>{s.duration_seconds}s</td><td>{s.modules_completed.length}</td>
                <td className={s.modules_failed.length ? "text-[#ff8da0]" : ""}>{s.modules_failed.length}</td><td>{s.modules_skipped.length}</td>
                <td>{s.results_count}</td><td>{s.changes}</td>
              </tr>
              {scanId === s.id && <tr><td colSpan={12} className="p-0"><ScanDetail scan={s} /></td></tr>}
            </Fragment>
          ))}
        </tbody>
      </table>
    </Section>
  );
}
