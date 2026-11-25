import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

const ROW = 20;            // px per line (lines never wrap, so every row has the same height)
const CHUNK = 500;         // lines fetched per request
const KEEP = 40;           // chunks kept in memory (20,000 lines); farther ones are dropped and re-fetched if needed
const MAX_PX = 8_000_000;  // browsers cap element height; past this the scrollbar maps proportionally

/**
 * Virtualised, lazily loaded text viewer for logs and tool output of any size.
 * fetchWindow(start, limit) -> Promise<{ total, start, lines }>; start === null asks for the newest lines.
 * Only the visible rows are rendered and only the chunks around them are fetched, so 1,000,000 lines cost the
 * same as 1,000. While `live`, it polls for the line count and follows the end unless you scroll up.
 */
export default function LogView({ fetchWindow, resetKey, live = false, pollMs = 1500, lineClass, format,
                                  height = "55vh", empty = "No lines yet.", onTotal, tail = true }) {
  const scroller = useRef(null);
  const chunks = useRef(new Map());     // chunk index -> string[]
  const inflight = useRef(new Set());
  const gen = useRef(0);                // bumps on reset so late responses from an old view are ignored
  const programmatic = useRef(false);
  const [total, setTotal] = useState(null);
  const [, setVersion] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(400);
  const [follow, setFollow] = useState(tail);
  const [picked, setPicked] = useState(null);
  const [err, setErr] = useState(null);

  const fullH = (total || 0) * ROW;
  const spacerH = Math.max(viewH, Math.min(fullH, MAX_PX));
  const rows = Math.ceil(viewH / ROW) + 1;
  const scaled = fullH > MAX_PX;
  const maxScroll = Math.max(1, spacerH - viewH);
  const first = !total ? 0 : scaled
    ? Math.min(total - 1, Math.round((scrollTop / maxScroll) * Math.max(0, total - rows + 1)))
    : Math.min(Math.floor(scrollTop / ROW), Math.max(0, total - 1));
  const shift = scaled ? 0 : scrollTop % ROW;
  const last = Math.min((total || 0) - 1, first + rows);

  const refreshTotal = useCallback(() => {
    const g = gen.current;
    return fetchWindow(null, 0).then((w) => {
      if (g !== gen.current) return;
      setErr(null);
      setTotal((t) => {
        if (t !== null && w.total < t) chunks.current.clear();  // log was rewritten: start over
        return w.total;
      });
      onTotal && onTotal(w.total);
    }).catch((e) => g === gen.current && setErr(e));
  }, [fetchWindow, onTotal]);

  // reset on a new source / filter
  useEffect(() => {
    gen.current += 1;
    chunks.current = new Map();
    inflight.current = new Set();
    setTotal(null); setPicked(null); setFollow(tail); setScrollTop(0);
    if (scroller.current) scroller.current.scrollTop = 0;
    refreshTotal();
  }, [resetKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // live: poll the line count only (cheap); visible chunks are fetched below when they become stale
  useEffect(() => {
    if (!live) return undefined;
    const t = setInterval(refreshTotal, pollMs);
    return () => clearInterval(t);
  }, [live, pollMs, refreshTotal]);

  // fetch the chunks that cover the visible rows (plus one on each side)
  useEffect(() => {
    if (!total) return undefined;
    const g = gen.current;
    const t = setTimeout(() => {
      const lo = Math.max(0, Math.floor(first / CHUNK) - 1), hi = Math.floor(Math.max(first, last) / CHUNK) + 1;
      for (let c = lo; c <= hi; c++) {
        const start = c * CHUNK;
        if (start >= total) break;
        const have = chunks.current.get(c);
        const want = Math.min(CHUNK, total - start);
        if ((have && have.length >= want) || inflight.current.has(c)) continue;
        inflight.current.add(c);
        fetchWindow(start, CHUNK).then((w) => {
          if (g !== gen.current) return;
          chunks.current.set(c, w.lines);
          if (chunks.current.size > KEEP) {  // drop the chunks farthest from where you are
            const here = Math.floor(first / CHUNK);
            const far = [...chunks.current.keys()].sort((a, b) => Math.abs(b - here) - Math.abs(a - here));
            far.slice(0, chunks.current.size - KEEP).forEach((k) => chunks.current.delete(k));
          }
          setVersion((v) => v + 1);
        }).catch((e) => g === gen.current && setErr(e)).finally(() => inflight.current.delete(c));
      }
    }, 40);
    return () => clearTimeout(t);
  }, [first, last, total, fetchWindow]);

  // follow the end while live output arrives
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el || !follow || !total) return;
    programmatic.current = true;
    el.scrollTop = el.scrollHeight;
    setScrollTop(el.scrollTop);
  }, [total, follow, spacerH]);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return undefined;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight || 400));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const onScroll = (e) => {
    const el = e.currentTarget;
    setScrollTop(el.scrollTop);
    if (programmatic.current) { programmatic.current = false; return; }
    const atEnd = el.scrollTop >= el.scrollHeight - el.clientHeight - ROW * 2;
    if (atEnd !== follow) setFollow(atEnd);
  };

  const jumpEnd = () => { setFollow(true); const el = scroller.current; if (el) { programmatic.current = true; el.scrollTop = el.scrollHeight; } };
  const jumpStart = () => { setFollow(false); const el = scroller.current; if (el) { el.scrollTop = 0; } };

  const lineAt = (i) => chunks.current.get(Math.floor(i / CHUNK))?.[i % CHUNK];
  const visible = [];
  for (let i = first; i <= last; i++) visible.push(i);

  return (
    <div>
      <div ref={scroller} onScroll={onScroll} className="term relative overflow-y-auto overflow-x-hidden p-0"
           style={{ height }} tabIndex={0} aria-label="Output lines">
        <div className="sticky top-0 overflow-hidden" style={{ height: viewH }}>
          <div style={{ transform: `translateY(${-shift}px)` }}>
            {visible.map((i) => {
              const l = lineAt(i);
              const shown = l === undefined ? "" : format ? format(l) : l;
              return (
                <div key={i} title={l && l.length > 160 ? l : undefined} onClick={() => l !== undefined && setPicked({ i, l })}
                     className={`flex cursor-text gap-3 whitespace-pre px-3 font-mono text-[11.5px] leading-5 hover:bg-slate-800/40 ${l === undefined ? "text-slate-700" : (lineClass ? lineClass(l) : "text-slate-300")}`}
                     style={{ height: ROW }}>
                  <span className="w-14 shrink-0 select-none text-right tabular text-slate-600">{i + 1}</span>
                  <span className="min-w-0 overflow-hidden text-ellipsis">{l === undefined ? "…" : shown}</span>
                </div>
              );
            })}
            {total === 0 && <div className="px-3 py-2 text-[12px] text-slate-500">{empty}</div>}
            {total === null && !err && <div className="px-3 py-2 text-[12px] text-slate-500">Loading…</div>}
            {err && <div className="px-3 py-2 text-[12px] text-[#ff8da0]">{err.message}</div>}
          </div>
        </div>
        <div style={{ height: Math.max(0, spacerH - viewH) }} aria-hidden="true" />
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11.5px] text-slate-500">
        <span className="tabular">{total ? `Lines ${(first + 1).toLocaleString()}–${(last + 1).toLocaleString()} of ${total.toLocaleString()}` : ""}</span>
        {live && <span className={follow ? "text-amber-300" : ""}>{follow ? "following new output" : "paused — scroll to the end to follow"}</span>}
        <span className="ml-auto flex gap-1.5">
          <button className="btn-ghost px-2 py-0.5" onClick={jumpStart} disabled={!total}>Start</button>
          <button className="btn-ghost px-2 py-0.5" onClick={jumpEnd} disabled={!total}>End</button>
        </span>
      </div>
      {picked && (
        <div className="mt-2 rounded-[3px] border border-slate-700 bg-slate-950/70 p-2">
          <div className="mb-1 flex items-center justify-between text-[11.5px] text-slate-500">
            <span>Line {picked.i + 1}</span>
            <span className="flex gap-1.5">
              <button className="btn-ghost px-2 py-0.5" onClick={() => navigator.clipboard?.writeText(picked.l)}>Copy</button>
              <button className="btn-ghost px-2 py-0.5" onClick={() => setPicked(null)}>Close</button>
            </span>
          </div>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[11.5px] text-slate-200">{picked.l}</pre>
        </div>
      )}
    </div>
  );
}
