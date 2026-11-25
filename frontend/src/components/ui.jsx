import { Component, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, withToken } from "../api";

export const SEV_COLOR = { critical: "#ff3d71", high: "#ff7a3d", medium: "#ffb547", low: "#e3d46a", info: "#6fa8dc" };
export const SEV_STYLE = Object.fromEntries(Object.keys(SEV_COLOR).map((k) => [k, ""]));
export const TIER_STYLE = { P1: "text-[#ff3d71]", P2: "text-[#ff7a3d]", P3: "text-[#e3d46a]", P4: "text-slate-400" };
export const TYPE_COLORS = {
  domain: "#dce4f0", subdomain: "#7cb7ff", ip: "#5fd0c5", asn: "#3aa39a", provider: "#2e7d77", certificate: "#b28cff",
  service: "#ff9f5a", web_app: "#2ee6ff", technology: "#d9c56b", endpoint: "#8fbf6a", js_file: "#c49a5a",
  cloud_resource: "#ff6fa8", third_party: "#5d7397", repository: "#8c9bb3", finding: "#ff3d71",
};

export function Sev({ s }) {
  const sev = s || "info";
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12px] font-medium text-slate-200">
      <span className="h-2 w-2 rounded-[1px]" style={{ background: SEV_COLOR[sev] || SEV_COLOR.info, boxShadow: `0 0 6px ${SEV_COLOR[sev] || SEV_COLOR.info}88` }} />{sev}
    </span>
  );
}

/* instrument readout: condensed numeral over a quiet label */
export function Stat({ label, value, sub, accent = "text-slate-50" }) {
  return (
    <div className="hud px-3.5 py-3">
      <div className={`readout text-[26px] font-semibold leading-none ${accent}`}>{value ?? "–"}</div>
      <div className="mt-1.5 text-[12px] text-slate-400">{label}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
    </div>
  );
}

export function Section({ title, right, children, className = "" }) {
  return (
    <section className={`hud ${className}`}>
      <div className="hud-head">
        <h3 className="panel-title flex items-center gap-2.5"><span className="diode" aria-hidden="true" />{title}</h3>
        {right}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHead({ title, children, aside }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="display text-[28px] font-semibold leading-tight text-slate-50">{title}</h1>
        {children && <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-slate-400">{children}</p>}
      </div>
      {aside}
    </div>
  );
}

export function Loading({ what = "Loading" }) {
  return (
    <div className="flex items-center gap-3 p-8 text-[13px] text-slate-400">
      <span className="radar active" style={{ "--size": "22px" }} />{what}…
    </div>
  );
}

/* Shown instead of a page when its data could not be loaded. Keeps navigation working. */
export function Pending({ loading, error, reload, what }) {
  if (loading) return <Loading what={what} />;
  const noScan = /no scans/i.test(error?.message || "");
  return (
    <div className="hud p-6">
      <div className="display text-[18px] font-semibold text-slate-100">{noScan ? "Nothing collected for this scan yet" : "This view could not be loaded"}</div>
      <p className="mt-1.5 max-w-2xl text-[13px] text-slate-400">
        {noScan ? "Start a scan and this page fills in as each module finishes. You can keep browsing while it runs."
                : (error?.message || "The server returned an error.")}
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        {noScan ? <Link className="btn-primary" to="/scanner">Open scanner</Link> : <button className="btn-primary" onClick={reload}>Try again</button>}
        <Link className="btn" to="/">Back to overview</Link>
      </div>
    </div>
  );
}

/* Catches a crashing page so the sidebar and header stay usable. */
export class PageBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidUpdate(prev) { if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null }); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="rounded-[3px] border border-[#ff3d71]/40 bg-[#ff3d71]/5 p-6">
        <div className="display text-[18px] font-semibold text-slate-100">This page hit an error</div>
        <p className="mt-1.5 font-mono text-[12px] text-slate-400">{String(this.state.error?.message || this.state.error)}</p>
        <div className="mt-4 flex gap-2">
          <button className="btn-primary" onClick={() => this.setState({ error: null })}>Reload page</button>
          <Link className="btn" to="/" onClick={() => this.setState({ error: null })}>Back to overview</Link>
        </div>
      </div>
    );
  }
}

export function Empty({ children }) {
  return <div className="p-6 text-center text-sm text-slate-500">{children}</div>;
}

export function useLoad(fn, deps) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    fn()
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((error) => alive && setState({ data: null, error, loading: false }));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

export function useDebounced(value, ms = 250) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

// lower-cased search text per row, built once per row object (not on every keystroke)
const SEARCH_TEXT = new WeakMap();
const searchText = (x) => {
  let t = SEARCH_TEXT.get(x);
  if (t === undefined) { t = JSON.stringify(x).toLowerCase(); SEARCH_TEXT.set(x, t); }
  return t;
};

/** Generic searchable / sortable / filterable table. columns: [{key, label, render?, sort?, className?}] */
export function DataTable({ rows, columns, search = true, filters = [], onRowClick, pageSize = 100, empty = "No data" }) {
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, rows && rows.length > 5000 ? 300 : 120);
  const [sort, setSort] = useState(null);
  const [fv, setFv] = useState({});
  const [page, setPage] = useState(0);
  const filterKeys = filters.map((f) => f.key).join("|");
  const options = useMemo(() => Object.fromEntries(filters.map((f) => [f.key,
    [...new Set((rows || []).flatMap((x) => String(f.get(x)).split("|")).filter(Boolean))].sort()])),
  [rows, filterKeys]); // eslint-disable-line react-hooks/exhaustive-deps
  const filtered = useMemo(() => {
    let r = rows || [];
    if (q) {
      const ql = q.toLowerCase();
      r = r.filter((x) => searchText(x).includes(ql));
    }
    for (const f of filters) {
      if (fv[f.key] && fv[f.key] !== "__all") r = r.filter((x) => String(f.get(x)).split("|").includes(fv[f.key]));
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      const get = col.sort || ((x) => x[col.key]);
      r = [...r].sort((a, b) => {
        const va = get(a), vb = get(b);
        const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va ?? "").localeCompare(String(vb ?? ""));
        return sort.dir * cmp;
      });
    }
    return r;
  }, [rows, q, sort, fv]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => setPage(0), [q, fv]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice(page * pageSize, (page + 1) * pageSize);
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {search && <input className="input w-72" placeholder="Search…" value={qIn} onChange={(e) => setQ(e.target.value)} />}
        {filters.map((f) => {
          const opts = options[f.key] || [];
          return (
            <select key={f.key} className="input" value={fv[f.key] || "__all"} onChange={(e) => setFv({ ...fv, [f.key]: e.target.value })}>
              <option value="__all">{f.label}: all</option>
              {opts.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          );
        })}
        <span className="ml-auto text-xs text-slate-500">{filtered.length} rows</span>
      </div>
      <div className="max-h-[70vh] overflow-auto rounded-[3px] border border-slate-800 bg-slate-950/40">
        <table className="tbl">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={`cursor-pointer select-none ${c.className || ""}`}
                    onClick={() => setSort(sort?.key === c.key ? { key: c.key, dir: -sort.dir } : { key: c.key, dir: 1 })}>
                  {c.label}{sort?.key === c.key ? (sort.dir > 0 ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((r, i) => (
              <tr key={r.id || i} className={onRowClick ? "cursor-pointer" : ""} onClick={() => onRowClick && onRowClick(r)}>
                {columns.map((c) => <td key={c.key} className={c.className || ""}>{c.render ? c.render(r) : String(r[c.key] ?? "")}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length && <Empty>{empty}</Empty>}
      </div>
      {pages > 1 && (
        <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
          <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
          page {page + 1} / {pages}
          <button className="btn" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </div>
  );
}

/**
 * Table whose rows live on the server: only the current page is fetched and rendered, so it stays fast with any
 * number of rows. fetchPage({offset, limit, q, filters, desc}) -> Promise<{total, rows}>.
 * filters: [{key, label, options: [[value, label]]}]
 */
export function ServerTable({ fetchPage, columns, filters = [], onRowClick, pageSize = 100, empty = "No data",
                              resetKey = "", searchPlaceholder = "Search…", sortLabel = null, poll = 0 }) {
  const [qIn, setQ] = useState("");
  const q = useDebounced(qIn, 350);
  const [fv, setFv] = useState({});
  const [page, setPage] = useState(0);
  const [desc, setDesc] = useState(false);
  const [state, setState] = useState({ rows: [], total: null, loading: true, error: null });
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const key = JSON.stringify([q, fv, desc, resetKey]);
  useEffect(() => setPage(0), [key]);
  useEffect(() => {
    const my = ++seq.current;
    setState((s) => ({ ...s, loading: true }));
    fetchPage({ offset: page * pageSize, limit: pageSize, q: q || undefined, filters: fv, desc })
      .then((r) => my === seq.current && setState({ rows: r.rows || [], total: r.total ?? 0, loading: false, error: null }))
      .catch((error) => my === seq.current && setState((s) => ({ ...s, loading: false, error })));
  }, [key, page, pageSize, tick]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!poll) return undefined;
    const t = setInterval(() => setTick((x) => x + 1), poll);
    return () => clearInterval(t);
  }, [poll]);
  const pages = Math.max(1, Math.ceil((state.total || 0) / pageSize));
  const [jump, setJump] = useState("");
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input className="input w-72" placeholder={searchPlaceholder} value={qIn} onChange={(e) => setQ(e.target.value)} />
        {filters.map((f) => (
          <select key={f.key} className="input max-w-[220px]" value={fv[f.key] || ""} onChange={(e) => setFv({ ...fv, [f.key]: e.target.value || undefined })}>
            <option value="">{f.label}: all</option>
            {(f.options || []).map(([v, l]) => <option key={v} value={v}>{l ?? v}</option>)}
          </select>
        ))}
        {sortLabel && <button className="btn" onClick={() => setDesc(!desc)}>{sortLabel} {desc ? "Z→A" : "A→Z"}</button>}
        <span className="ml-auto flex items-center gap-2 text-xs text-slate-500">
          {state.loading && <span className="radar active" style={{ "--size": "12px" }} />}
          {state.total === null ? "" : `${state.total.toLocaleString()} rows`}
        </span>
      </div>
      <div className={`max-h-[70vh] overflow-auto rounded-[3px] border border-slate-800 bg-slate-950/40 ${state.loading ? "opacity-70" : ""}`}>
        <table className="tbl">
          <thead><tr>{columns.map((c) => <th key={c.key} className={c.className || ""}>{c.label}</th>)}</tr></thead>
          <tbody>
            {state.rows.map((r, i) => (
              <tr key={r.id || i} className={onRowClick ? "cursor-pointer" : ""} onClick={() => onRowClick && onRowClick(r)}>
                {columns.map((c) => <td key={c.key} className={c.className || ""}>{c.render ? c.render(r) : String(r[c.key] ?? "")}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
        {!state.loading && !state.rows.length && !state.error && <Empty>{empty}</Empty>}
        {state.error && <div className="p-4 text-[13px] text-[#ff8da0]">{state.error.message}</div>}
      </div>
      {pages > 1 && (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <button className="btn" disabled={page === 0} onClick={() => setPage(0)}>First</button>
          <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
          <span className="tabular">page {(page + 1).toLocaleString()} / {pages.toLocaleString()}</span>
          <button className="btn" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</button>
          <button className="btn" disabled={page >= pages - 1} onClick={() => setPage(pages - 1)}>Last</button>
          <form className="flex items-center gap-1" onSubmit={(e) => { e.preventDefault(); const n = parseInt(jump, 10); if (n >= 1 && n <= pages) setPage(n - 1); setJump(""); }}>
            <input className="input w-20 py-0.5" inputMode="numeric" placeholder="go to" value={jump} onChange={(e) => setJump(e.target.value)} aria-label="Go to page" />
          </form>
        </div>
      )}
    </div>
  );
}

/** Long lists render `step` items at a time; returns [visible, button-or-null]. */
export function useStep(items, step = 100) {
  const [n, setN] = useState(step);
  const list = items || [];
  useEffect(() => setN(step), [items, step]);
  const more = list.length > n
    ? <button className="btn-ghost mt-1 text-[12px]" onClick={() => setN(n + step * 5)}>Show more ({(list.length - n).toLocaleString()} not shown)</button>
    : null;
  return [list.length > n ? list.slice(0, n) : list, more];
}

export function Pills({ items }) {
  return <>{(items || []).filter(Boolean).map((x, i) => <span key={i} className="pill">{x}</span>)}</>;
}

export function EvidenceLink({ id, children }) {
  const [open, setOpen] = useState(false);
  if (!id) return null;
  return (
    <>
      <button className="mono text-indigo-300 hover:underline" onClick={(e) => { e.stopPropagation(); setOpen(true); }}>{children || id}</button>
      {open && <EvidenceModal id={id} onClose={() => setOpen(false)} />}
    </>
  );
}

export function EvidenceModal({ id, onClose }) {
  const { data, loading } = useLoad(() => api.evidence(id), [id]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6" onClick={onClose}>
      <div className="hud max-h-[85vh] w-full max-w-4xl overflow-auto bg-slate-900 p-5" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-start justify-between">
          <div>
            <div className="text-sm font-semibold">Evidence <span className="mono">{id}</span></div>
            {data && <div className="text-xs text-slate-400">{data.kind} · {data.module} · {data.created_at} · sha256 {data.sha256?.slice(0, 16)}</div>}
          </div>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
        {loading && <Loading />}
        {data && <div className="mb-2 text-sm text-slate-300">{data.summary}</div>}
        {data?.kind === "screenshot" ? (
          <img alt="screenshot" className="rounded border border-slate-700" src={withToken(`/api/evidence/${id}?raw=1`)} />
        ) : (
          data && <pre className="term max-h-[60vh] whitespace-pre-wrap break-all">{data.content}</pre>
        )}
        {data?.has_file && data.kind !== "screenshot" && (
          <a className="text-xs text-indigo-300" href={withToken(`/api/evidence/${id}?raw=1`)} target="_blank" rel="noreferrer">Open full evidence file</a>
        )}
      </div>
    </div>
  );
}

export function JsonView({ value }) {
  return <pre className="term max-h-80 whitespace-pre-wrap break-all">{JSON.stringify(value, null, 2)}</pre>;
}

/* Download menu for a page's data. surfaces: [[surfaceId, label]]; extra: [[label, href]] for pre-built links. */
export function ExportMenu({ target, surfaces = [], extra = [], label = "Export" }) {
  if (!surfaces.length && !extra.length) return null;
  const url = (sf, fmt) => withToken(`/api/targets/${encodeURIComponent(target)}/export/${sf}?format=${fmt}`);
  return (
    <details className="menu relative">
      <summary className="btn" aria-label={`${label} this page's data`}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <path d="M12 3v12m0 0-4.5-4.5M12 15l4.5-4.5M4 17v3h16v-3" />
        </svg>{label}
      </summary>
      <div className="menu-pop">
        <div className="px-2 pb-1.5 pt-1 text-[11.5px] text-slate-500">Full data, not just the rows on screen</div>
        {surfaces.map(([sf, name, formats = ["csv", "json", "md"]]) => (
          <div key={sf} className="flex items-center gap-2 px-2 py-1.5 hover:bg-slate-800/60">
            <span className="mr-auto text-[13px] text-slate-200">{name}</span>
            {formats.map((f) => (
              <a key={f} className="font-mono text-[11.5px] text-indigo-300 hover:text-indigo-100 hover:underline" href={url(sf, f)}
                 download>{f === "md" ? "Markdown" : f.toUpperCase()}</a>
            ))}
          </div>
        ))}
        {extra.map(([name, href]) => (
          <a key={name} className="flex items-center px-2 py-1.5 text-[13px] text-slate-200 hover:bg-slate-800/60" href={href} download>{name}</a>
        ))}
      </div>
    </details>
  );
}

export function Tabs({ value, onChange, items }) {
  return (
    <div className="tabs" role="tablist">
      {items.map(([id, label]) => (
        <button key={id} role="tab" aria-selected={value === id} onClick={() => onChange(id)}>{label}</button>
      ))}
    </div>
  );
}
