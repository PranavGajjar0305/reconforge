import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { Empty, Loading, Pending } from "../components/ui";

const GROUP_INFO = {
  "": "Index",
  all: "Everything found, by category",
  findings: "Security observations by severity",
  urls: "URL candidate lists (gf-style)",
  modules: "What each module / tool found",
  raw: "Raw output of every external tool",
  screenshots: "Screenshots",
  logs: "Execution log",
};
const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);

function ScanPicker({ target, scanId, onPick }) {
  const [scans, setScans] = useState(null);
  useEffect(() => { api.scans(target).then(setScans).catch(() => setScans([])); }, [target]);
  if (!scans?.length) return null;
  return (
    <select className="input max-w-md" aria-label="Execution" value={scanId || ""} onChange={(e) => onPick(e.target.value)}>
      {scans.map((s) => (
        <option key={s.id} value={s.id}>{s.started_at?.replace("T", " ").slice(0, 16)}  ·  {s.profile}  ·  {s.status}</option>
      ))}
    </select>
  );
}

function Preview({ scanId, file }) {
  const [text, setText] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    setText(null); setErr(null);
    if (!file || file.kind === "image") return;
    api.fileHead(scanId, file.path, 500).then(setText).catch(setErr);
  }, [scanId, file?.path]);
  if (!file) return <Empty>Select a file to preview it.</Empty>;
  return (
    <div className="hud flex h-full min-h-[60vh] flex-col">
      <div className="hud-head flex-wrap">
        <div className="min-w-0">
          <div className="truncate font-mono text-[13px] text-slate-100">{file.path}</div>
          <div className="text-[11.5px] text-slate-500">{fmtSize(file.size)}</div>
        </div>
        <div className="flex gap-1.5">
          <a className="btn px-2.5 py-1 text-[12px]" href={api.fileUrl(scanId, file.path)} target="_blank" rel="noreferrer">Open</a>
          <a className="btn px-2.5 py-1 text-[12px]" href={api.fileUrl(scanId, file.path, true)} download><Icon name="download" size={12} /> Download</a>
        </div>
      </div>
      <div className="flex-1 p-3">
        {file.kind === "image" ? (
          <img alt={file.path} className="max-h-[70vh] w-full rounded-[2px] border border-slate-800 object-contain" src={api.fileUrl(scanId, file.path)} />
        ) : err ? <div className="text-[13px] text-[#ff8da0]">{err.message}</div> : text === null ? <Loading /> : (
          <pre className="term h-[64vh] whitespace-pre text-[11.5px]">{text || "(empty)"}{text && text.split("\n").length >= 500 ? "\n… first 500 lines shown — download for the full file" : ""}</pre>
        )}
      </div>
    </div>
  );
}

export default function Files() {
  const { scanId } = useParams();
  const [params, setParams] = useSearchParams();
  const { target, meta } = useApp();
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState({ "": true, all: true, findings: true });
  const sel = params.get("f");

  useEffect(() => {  // no id: the latest full execution of this scan
    if (scanId) return;
    api.scans(target).then((s) => {
      const full = (s || []).find((x) => x.trigger !== "dashboard-action" && x.status !== "running") || (s || [])[0];
      if (full) nav(`/files/${full.id}`, { replace: true }); else setError(new Error("no scans"));
    }).catch(setError);
  }, [scanId, target]);

  const load = (refresh) => {
    setBusy(true); setError(null);
    return api.scanFiles(scanId, refresh).then(setData).catch(setError).finally(() => setBusy(false));
  };
  useEffect(() => { if (scanId) { setData(null); load(false); } }, [scanId]);

  const groups = useMemo(() => {
    const g = {};
    (data?.files || []).filter((f) => !q || f.path.toLowerCase().includes(q.toLowerCase())).forEach((f) => {
      const parts = f.path.split("/");
      const key = parts.length > 2 && ["modules", "raw", "urls"].includes(parts[0]) ? `${parts[0]}/${parts[1]}` : parts.length > 1 ? parts[0] : "";
      (g[key] = g[key] || []).push(f);
    });
    return Object.entries(g).sort(([a], [b]) => (a === "" ? -1 : b === "" ? 1 : a.localeCompare(b)));
  }, [data, q]);
  const file = (data?.files || []).find((f) => f.path === sel) || (data?.files || []).find((f) => f.path === "00_INDEX.txt");

  if (error) return (
    <div className="space-y-3">
      <Pending error={error} reload={() => load(false)} />
      {/written when the execution finishes/.test(error.message) && <button className="btn" onClick={() => load(true)}>Build output files now</button>}
    </div>
  );
  if (!data) return <Loading what="Preparing output files" />;
  const total = data.files.reduce((n, f) => n + f.size, 0);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="mr-auto">
          <h1 className="display text-[28px] font-semibold leading-tight text-slate-50">Output files</h1>
          <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-slate-400">
            Every result as plain files: one list per category, per module and per tool (for example
            <span className="font-mono text-slate-300"> modules/subfinder/subfinder_subdomains.txt</span>), raw tool output, screenshots and the log.
          </p>
        </div>
        <ScanPicker target={target} scanId={scanId} onPick={(id) => nav(`/files/${id}`)} />
        <button className="btn" disabled={busy} onClick={() => load(true)}>{busy ? "Rebuilding…" : "Regenerate"}</button>
        <a className="btn-primary" href={api.filesZipUrl(scanId)} download><Icon name="zip" size={14} /> Download all (.zip)</a>
      </div>
      <div className="font-mono text-[11.5px] text-slate-500">data/output/…/{data.folder}  ·  {data.files.length} files  ·  {fmtSize(total)}</div>
      <div className="grid gap-4 lg:grid-cols-[360px_minmax(0,1fr)]">
        <aside className="hud self-start">
          <div className="p-2"><input className="input w-full" placeholder="Find file" value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <div className="max-h-[70vh] overflow-auto px-1 pb-2">
            {groups.map(([g, files]) => {
              const isOpen = open[g] ?? (!!q || files.some((f) => f.path === sel));
              const top = g.split("/")[0];
              return (
                <div key={g} className="mb-0.5">
                  <button className="flex w-full items-center gap-2 px-2 py-1.5 text-left hover:bg-slate-800/50" onClick={() => setOpen({ ...open, [g]: !isOpen })}
                          aria-expanded={isOpen}>
                    <span className="w-3 text-slate-500">{isOpen ? "▾" : "▸"}</span>
                    <span className="font-mono text-[12.5px] text-slate-200">{g || "index"}</span>
                    <span className="ml-auto font-mono text-[11px] text-slate-500">{files.length}</span>
                  </button>
                  {isOpen && g.split("/").length === 1 && GROUP_INFO[top] && <div className="px-7 pb-1 text-[11px] text-slate-500">{GROUP_INFO[top]}</div>}
                  {isOpen && files.map((f) => (
                    <button key={f.path} onClick={() => setParams({ f: f.path })}
                      className={`flex w-full items-center gap-2 py-1 pl-7 pr-2 text-left ${f.path === file?.path ? "bg-indigo-400/10 shadow-[inset_2px_0_0_var(--ion)]" : "hover:bg-slate-800/40"}`}>
                      <span className={`min-w-0 flex-1 truncate font-mono text-[11.5px] ${f.path === file?.path ? "text-indigo-100" : "text-slate-300"}`}>
                        {f.path.split("/").pop()}
                      </span>
                      <span className="font-mono text-[10.5px] text-slate-500">{fmtSize(f.size)}</span>
                    </button>
                  ))}
                </div>
              );
            })}
            {!groups.length && <Empty>No files match.</Empty>}
          </div>
        </aside>
        <Preview scanId={scanId} file={file} />
      </div>
    </div>
  );
}
