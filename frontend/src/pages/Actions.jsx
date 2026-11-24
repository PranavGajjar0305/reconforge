import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { DataTable, Loading, Section, useLoad, Pending } from "../components/ui";

export default function Actions() {
  const { target, meta, reloadMeta } = useApp();
  const nav = useNavigate();
  const { data, loading, error, reload } = useLoad(() => api.actions(target), [target]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [installs, setInstalls] = useState({});   // tool name -> {status, lines, result}
  const [logFor, setLogFor] = useState(null);     // tool name whose install log is expanded
  const timers = useRef({});
  useEffect(() => () => Object.values(timers.current).forEach(clearInterval), []);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;

  const exec = async (a) => {
    setErr(""); setBusy(a.id);
    try {
      const r = await api.runAction(target, a.id);
      reloadMeta();
      nav(`/live/${r.scan_id}`);
    } catch (e) { setErr(`${a.name}: ${e.message}`); } finally { setBusy(""); }
  };

  const install = async (a) => {
    const name = a.install_name || a.name;
    setErr("");
    try {
      const job = await api.installTool(name);
      setInstalls((m) => ({ ...m, [a.name]: job }));
      setLogFor(a.name);
      clearInterval(timers.current[a.name]);
      timers.current[a.name] = setInterval(async () => {
        const s = await api.installStatus(job.id).catch(() => null);
        if (!s) return;
        setInstalls((m) => ({ ...m, [a.name]: s }));
        if (s.status !== "running") { clearInterval(timers.current[a.name]); reload(); reloadMeta(); }
      }, 1500);
    } catch (e) { setErr(`Install ${name}: ${e.message}`); }
  };

  const runningScan = meta.running?.[target];
  const missing = data.filter((r) => r.kind === "tool" && r.installable);

  return (
    <div className="space-y-4">
      <p className="text-[12px] text-slate-500">
        Execute runs one item as its own scan against <span className="text-slate-300">{target}</span>, using stored results as input, and streams it live.
        Install fetches a missing tool (reusing an existing copy or building one), then re-checks it. Only registered commands run; the browser cannot submit arbitrary shell commands.
      </p>
      {runningScan && <div className="text-sm text-indigo-300">A run is in progress for this target — <button className="underline" onClick={() => nav(`/live/${runningScan}`)}>open live console</button>. One run per target at a time.</div>}
      {err && <div className="rounded border border-[#ff3d71]/40 bg-[#ff3d71]/10 p-2 text-sm text-[#ffb3c0]">{err}</div>}
      {missing.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 hud px-3 py-2 text-[12.5px] text-slate-300">
          <Icon name="install" size={15} className="text-indigo-300" />
          {missing.length} tool{missing.length > 1 ? "s" : ""} not installed:
          {missing.map((m) => <code key={m.name} className="mono text-slate-400">{m.name}</code>)}
          <button className="btn-primary ml-auto" disabled={missing.some((m) => installs[m.name]?.status === "running")}
                  onClick={() => missing.forEach(install)}>Install all</button>
        </div>
      )}
      <Section title={`Tools & commands (${data.length})`}>
        <DataTable
          rows={data}
          pageSize={200}
          filters={[{ key: "kind", label: "Kind", get: (r) => r.kind }, { key: "phase", label: "Phase", get: (r) => r.phase || "" },
                    { key: "run", label: "State", get: (r) => (r.runnable ? "executable" : r.installable ? "installable" : "unavailable") }]}
          columns={[
            { key: "exec", label: "", className: "whitespace-nowrap", render: (r) => (
              <div className="flex items-center gap-1.5">
                <button className="btn text-indigo-200 enabled:hover:!border-indigo-400 enabled:hover:!bg-indigo-400 enabled:hover:!text-slate-950 disabled:opacity-40"
                        disabled={!r.runnable || !!busy || !!runningScan} title={r.runnable ? `Run ${r.name} now` : r.reason} onClick={() => exec(r)}>
                  <Icon name="play" size={12} />{busy === r.id ? "Starting" : "Execute"}</button>
                {r.installable && <InstallButton r={r} job={installs[r.name]} onClick={() => install(r)} onToggleLog={() => setLogFor(logFor === r.name ? null : r.name)} />}
              </div>) },
            { key: "name", label: "Name", render: (r) => <div><div className="text-slate-100">{r.name}</div><div className="text-[11px] text-slate-500">{r.kind}{r.active ? " · active" : ""}</div></div> },
            { key: "phase", label: "Phase" },
            { key: "command", label: "Command / action", className: "min-w-[280px]", render: (r) => (
              <>
                <code className="mono text-[11.5px] text-amber-200">{r.command}</code>
                {logFor === r.name && installs[r.name] && (
                  <pre className="mono mt-2 max-h-48 overflow-auto whitespace-pre-wrap rounded border border-slate-800 bg-[#09111d] p-2 text-[10.5px] text-slate-300">
                    {(installs[r.name].lines || []).join("\n") || "starting…"}
                  </pre>
                )}
              </>
            ) },
            { key: "description", label: "Purpose", className: "text-xs text-slate-400" },
            { key: "status", label: "Status", render: (r) => <ToolStatus r={r} job={installs[r.name]} /> },
          ]}
        />
      </Section>
    </div>
  );
}

function InstallButton({ r, job, onClick, onToggleLog }) {
  const st = job?.status;
  if (st === "running")
    return <button className="btn text-indigo-200" disabled title="Installing"><span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-indigo-300 align-middle" />Installing</button>;
  if (st === "installed" || st === "present")
    return <button className="btn text-emerald-300" onClick={onToggleLog} title="Installed — view log">✓ Installed</button>;
  return <button className="btn text-indigo-200 enabled:hover:!border-indigo-400" title={`Install ${r.install_name || r.name}`} onClick={onClick}>
    <Icon name="install" size={12} />{st === "failed" ? "Retry" : "Install"}</button>;
}

function ToolStatus({ r, job }) {
  if (job?.status === "failed") return <span className="text-xs text-[#ff8da0]">install failed — {job.result}</span>;
  if (job?.status === "installed") return <span className="text-emerald-300">installed just now{r.version ? ` · ${r.version}` : ""}</span>;
  if (r.runnable) return <span className="text-emerald-300">ready{r.version ? ` · ${r.version}` : ""}</span>;
  return (
    <span className="text-xs text-slate-500">
      {r.reason}
      {r.installable && !r.installed ? <span className="ml-1 text-indigo-300">· installable</span> : null}
    </span>
  );
}
