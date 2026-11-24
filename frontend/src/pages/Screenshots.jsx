import { useCallback, useEffect, useMemo, useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { Empty, Pending, useLoad } from "../components/ui";

const STATUS_TONE = (s) => (!s ? "text-slate-400" : s < 300 ? "text-emerald-300" : s < 400 ? "text-indigo-200" : s < 500 ? "text-amber-300" : "text-[#ff8da0]");

/* Screenshots that look alike (same perceptual hash prefix) are grouped so default pages collapse together. */
function groupKey(s) { return s.phash ? String(s.phash).slice(0, 6) : s.url; }

function Lightbox({ items, index, onClose, onMove, openAsset }) {
  const s = items[index];
  const key = useCallback((e) => {
    if (e.key === "Escape") onClose();
    if (e.key === "ArrowRight") onMove(Math.min(items.length - 1, index + 1));
    if (e.key === "ArrowLeft") onMove(Math.max(0, index - 1));
  }, [index, items.length]);
  useEffect(() => { window.addEventListener("keydown", key); return () => window.removeEventListener("keydown", key); }, [key]);
  if (!s) return null;
  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-black/85 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={`Screenshot of ${s.url}`} onClick={onClose}>
      <div className="mx-auto flex w-full max-w-6xl items-center gap-3 pb-3" onClick={(e) => e.stopPropagation()}>
        <div className="min-w-0 flex-1">
          <a className="block truncate font-mono text-[14px] text-indigo-200 hover:underline" href={s.url} target="_blank" rel="noreferrer noopener">{s.url}</a>
          <div className="truncate text-[12px] text-slate-400"><span className={STATUS_TONE(s.status)}>{s.status || "–"}</span> · {s.title || "no title"} · {s.server || "server unknown"}</div>
        </div>
        <span className="font-mono text-[12px] text-slate-500">{index + 1} / {items.length}</span>
        <button className="btn" onClick={() => openAsset(s.asset_id)}>Asset details</button>
        <a className="btn" href={api.evidenceImageUrl(s.evidence_id)} download={`${s.url.replace(/[^a-z0-9.]+/gi, "_")}.png`}><Icon name="download" size={13} /> PNG</a>
        <button className="btn" onClick={onClose} aria-label="Close">Close</button>
      </div>
      <div className="relative mx-auto flex min-h-0 w-full max-w-6xl flex-1 items-center" onClick={(e) => e.stopPropagation()}>
        <button className="btn absolute left-0 z-10 -translate-x-1/2" disabled={index === 0} onClick={() => onMove(index - 1)} aria-label="Previous">‹</button>
        <img alt={`Screenshot of ${s.url}`} className="mx-auto max-h-full max-w-full rounded-[2px] border border-slate-700 object-contain" src={api.evidenceImageUrl(s.evidence_id)} />
        <button className="btn absolute right-0 z-10 translate-x-1/2" disabled={index === items.length - 1} onClick={() => onMove(index + 1)} aria-label="Next">›</button>
      </div>
    </div>
  );
}

export default function Screenshots() {
  const { target, openAsset } = useApp();
  const { data, error, loading, reload } = useLoad(() => api.screenshots(target), [target]);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [similar, setSimilar] = useState(false);
  const [size, setSize] = useState(260);
  const [open, setOpen] = useState(null);
  const items = useMemo(() => {
    let r = (data || []).filter((s) => !q || `${s.url} ${s.title || ""} ${s.server || ""} ${(s.technologies || []).join(" ")}`.toLowerCase().includes(q.toLowerCase()));
    if (status !== "all") r = r.filter((s) => String(s.status || "").startsWith(status));
    if (similar) {
      const seen = new Map();
      r.forEach((s) => { const k = groupKey(s); seen.set(k, [...(seen.get(k) || []), s]); });
      r = [...seen.values()].map((g) => ({ ...g[0], _count: g.length }));
    }
    return r;
  }, [data, q, status, similar]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <input className="input w-72" placeholder="Filter by URL, title, server, technology" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="all">All statuses</option><option value="2">2xx</option><option value="3">3xx</option><option value="4">4xx</option><option value="5">5xx</option>
        </select>
        <label className="flex items-center gap-1.5 text-[12.5px] text-slate-300"><input type="checkbox" checked={similar} onChange={(e) => setSimilar(e.target.checked)} /> Collapse look-alike pages</label>
        <label className="flex items-center gap-2 text-[12px] text-slate-400">Size
          <input type="range" min="160" max="460" step="20" value={size} onChange={(e) => setSize(+e.target.value)} aria-label="Thumbnail size" />
        </label>
        <span className="ml-auto font-mono text-[12px] text-slate-500">{items.length} of {data.length}</span>
        {data.length > 0 && <a className="btn" href={api.screenshotsZipUrl(target)} download><Icon name="zip" size={14} /> Download all</a>}
      </div>
      {!data.length && <div className="hud p-6"><Empty>No screenshots yet. They are taken by the screenshots module (standard and comprehensive profiles) when Chrome or Chromium is installed.</Empty></div>}
      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(auto-fill, minmax(${size}px, 1fr))` }}>
        {items.map((s, i) => (
          <figure key={s.evidence_id} className="hud group overflow-hidden">
            <button className="block w-full text-left" onClick={() => setOpen(i)} aria-label={`Open screenshot of ${s.url}`}>
              <div className="relative aspect-[16/10] overflow-hidden border-b border-slate-800 bg-slate-950">
                <img loading="lazy" alt="" className="h-full w-full object-cover object-top transition-transform duration-300 group-hover:scale-[1.03]" src={api.evidenceImageUrl(s.evidence_id)} />
                {s._count > 1 && <span className="absolute right-1.5 top-1.5 rounded-[2px] bg-slate-950/90 px-1.5 py-0.5 font-mono text-[10.5px] text-amber-200">×{s._count} look-alike</span>}
                {!s.active && <span className="absolute left-1.5 top-1.5 rounded-[2px] bg-slate-950/90 px-1.5 py-0.5 text-[10.5px] text-slate-400">no longer live</span>}
              </div>
              <figcaption className="px-2.5 py-2">
                <div className="truncate font-mono text-[11.5px] text-slate-100">{s.url.replace(/^https?:\/\//, "")}</div>
                <div className="truncate text-[11.5px] text-slate-400"><span className={STATUS_TONE(s.status)}>{s.status || "–"}</span> · {s.title || "no title"}</div>
              </figcaption>
            </button>
          </figure>
        ))}
      </div>
      {open !== null && <Lightbox items={items} index={open} onClose={() => setOpen(null)} onMove={setOpen} openAsset={openAsset} />}
    </div>
  );
}
