import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import Icon from "./icons";
import { SEV_COLOR, TYPE_COLORS } from "./ui";

/* Ctrl/Cmd+K: jump to any page, host, URL or finding. */
export default function Palette({ pages, target, openAsset, open, setOpen }) {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [hits, setHits] = useState([]);
  const [idx, setIdx] = useState(0);
  const input = useRef(null);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => { if (open) { setQ(""); setHits([]); setIdx(0); setTimeout(() => input.current?.focus(), 0); } }, [open]);
  useEffect(() => {
    if (!open || q.trim().length < 2 || !target) { setHits([]); return; }
    const t = setTimeout(() => api.search(target, q.trim()).then(setHits).catch(() => setHits([])), 180);
    return () => clearTimeout(t);
  }, [q, open, target]);

  const items = useMemo(() => {
    const ql = q.toLowerCase();
    const pg = pages.filter(([, label]) => !ql || label.toLowerCase().includes(ql)).slice(0, q ? 6 : 12)
      .map(([to, label, icon]) => ({ kind: "page", label, icon, run: () => nav(to) }));
    const as = hits.map((a) => ({ kind: a.type, label: a.display || a.key, severity: a.severity, run: () => openAsset(a.id) }));
    return [...pg, ...as];
  }, [q, hits, pages]);
  useEffect(() => setIdx(0), [items.length]);

  if (!open) return null;
  const go = (it) => { setOpen(false); it?.run(); };
  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center bg-black/60 p-4 pt-[12vh] backdrop-blur-sm" onClick={() => setOpen(false)}>
      <div className="hud w-full max-w-2xl bg-slate-900" role="dialog" aria-modal="true" aria-label="Search" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-slate-800 px-3">
          <Icon name="scan" size={16} className="text-indigo-300" />
          <input ref={input} className="w-full bg-transparent py-3 text-[15px] text-slate-100 outline-none placeholder:text-slate-500"
                 placeholder="Jump to a page, or search hosts, URLs, findings…" value={q} onChange={(e) => setQ(e.target.value)}
                 onKeyDown={(e) => {
                   if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); }
                   if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
                   if (e.key === "Enter") go(items[idx]);
                 }} aria-label="Search" />
          <kbd className="rounded-[2px] border border-slate-700 px-1.5 font-mono text-[10.5px] text-slate-500">esc</kbd>
        </div>
        <ul className="max-h-[50vh] overflow-auto py-1" role="listbox">
          {items.map((it, i) => (
            <li key={i} role="option" aria-selected={i === idx}>
              <button onMouseEnter={() => setIdx(i)} onClick={() => go(it)}
                className={`flex w-full items-center gap-3 px-3 py-2 text-left ${i === idx ? "bg-indigo-400/10 shadow-[inset_2px_0_0_var(--ion)]" : ""}`}>
                {it.kind === "page"
                  ? <Icon name={it.icon} size={15} className="text-slate-400" />
                  : <span className="h-2 w-2 shrink-0" style={{ background: it.severity ? SEV_COLOR[it.severity] : TYPE_COLORS[it.kind] || "#5d7397" }} />}
                <span className={`min-w-0 flex-1 truncate ${it.kind === "page" ? "text-[13.5px] text-slate-100" : "font-mono text-[12.5px] text-slate-200"}`}>{it.label}</span>
                <span className="font-mono text-[11px] text-slate-500">{it.kind === "page" ? "page" : it.kind.replace("_", " ")}</span>
              </button>
            </li>
          ))}
          {q.trim().length >= 2 && !hits.length && <li className="px-3 py-2 text-[12.5px] text-slate-500">No assets match “{q}”.</li>}
        </ul>
      </div>
    </div>
  );
}
