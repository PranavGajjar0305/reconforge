import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../App";
import { api, withToken } from "../api";
import Icon from "../components/icons";
import { EvidenceLink, TYPE_COLORS, useLoad, Pending } from "../components/ui";

cytoscape.use(fcose);

const DEFAULT_ON = ["domain", "subdomain", "ip", "asn", "provider", "certificate", "service", "web_app", "technology",
  "endpoint", "js_file", "cloud_resource", "third_party", "repository"];
const SHAPES = { third_party: "diamond", cloud_resource: "hexagon", certificate: "round-tag", technology: "round-rectangle",
  ip: "ellipse", asn: "octagon", provider: "octagon", service: "triangle", endpoint: "ellipse", js_file: "rectangle", finding: "star" };
// Infrastructure/hub types are kept first when the node budget is tight.
const PRIORITY = { domain: 0, ip: 1, asn: 1, provider: 1, subdomain: 2, web_app: 2, certificate: 3, service: 3,
  cloud_resource: 3, third_party: 4, technology: 5, endpoint: 5, js_file: 5, repository: 4, finding: 2 };

function download(name, content, type) {
  const a = document.createElement("a");
  a.href = typeof content === "string" && content.startsWith("data:") ? content : URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
}

export default function GraphPage() {
  const { target, openAsset } = useApp();
  const [types, setTypes] = useState(new Set(DEFAULT_ON.filter((t) => !["endpoint", "technology"].includes(t))));
  const [showFindings, setShowFindings] = useState(false);
  const [layout, setLayout] = useState("fcose");
  const [limit, setLimit] = useState(600);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(null);
  const [focus, setFocus] = useState(null);       // node id to show only its neighborhood
  const [rendered, setRendered] = useState({ shown: 0, total: 0 });
  const typeParam = useMemo(() => [...DEFAULT_ON, "finding"].join(","), []);
  const { data, loading, error, reload } = useLoad(() => api.graph(target, typeParam), [target]);
  const ref = useRef(null);
  const cyRef = useRef(null);

  // Pick which nodes to draw: filtered by type, then (if over budget) the best-connected ones.
  const view = useMemo(() => {
    if (!data) return { nodes: [], edges: [], total: 0, truncated: false };
    const active = new Set([...types, ...(showFindings ? ["finding"] : [])]);
    let nodes = data.nodes.filter((n) => active.has(n.data.type));
    const total = nodes.length;
    // degree within the filtered set, so the budget keeps genuine hubs
    const deg = new Map();
    const present = new Set(nodes.map((n) => n.data.id));
    for (const e of data.edges) {
      if (present.has(e.data.source) && present.has(e.data.target)) {
        deg.set(e.data.source, (deg.get(e.data.source) || 0) + 1);
        deg.set(e.data.target, (deg.get(e.data.target) || 0) + 1);
      }
    }
    let truncated = false;
    if (focus) {
      const keep = new Set([focus]);
      for (const e of data.edges) {
        if (e.data.source === focus) keep.add(e.data.target);
        if (e.data.target === focus) keep.add(e.data.source);
      }
      nodes = nodes.filter((n) => keep.has(n.data.id));
    } else if (nodes.length > limit) {
      truncated = true;
      nodes = [...nodes].sort((a, b) => {
        const s = (PRIORITY[a.data.type] ?? 9) - (PRIORITY[b.data.type] ?? 9);
        if (s) return s;
        if ((a.data.scope === "in_scope") !== (b.data.scope === "in_scope")) return a.data.scope === "in_scope" ? -1 : 1;
        return (deg.get(b.data.id) || 0) - (deg.get(a.data.id) || 0);
      }).slice(0, limit);
    }
    const ids = new Set(nodes.map((n) => n.data.id));
    const edges = data.edges.filter((e) => ids.has(e.data.source) && ids.has(e.data.target));
    const withDeg = nodes.map((n) => ({ data: { ...n.data, deg: deg.get(n.data.id) || 0 } }));
    return { nodes: withDeg, edges, total, truncated };
  }, [data, types, showFindings, limit, focus]);

  useEffect(() => {
    if (!ref.current) return;
    const { nodes, edges } = view;
    setRendered({ shown: nodes.length, total: view.total });
    const n = nodes.length;
    // Spread the graph out more as it grows so clusters don't pile up.
    const big = n > 250;
    const fcoseOpts = {
      name: "fcose", quality: n > 900 ? "default" : "proof", animate: false, randomize: true,
      packComponents: true, tile: true, nodeSeparation: big ? 140 : 85,
      nodeRepulsion: () => (big ? 26000 : 11000), idealEdgeLength: () => (big ? 150 : 75),
      gravity: 0.25, gravityRange: 3.6, numIter: n > 1500 ? 1500 : 2500,
    };
    const cy = cytoscape({
      container: ref.current,
      elements: [...nodes, ...edges],
      wheelSensitivity: 0.25,
      pixelRatio: n > 1200 ? 1 : "auto",
      hideEdgesOnViewport: n > 500,
      textureOnViewport: n > 800,
      style: [
        { selector: "node", style: {
          "background-color": (el) => TYPE_COLORS[el.data("type")] || "#888", color: "#c5d0e0",
          "font-size": 9, "text-valign": "bottom", "text-margin-y": 3, "text-opacity": 0,
          width: (el) => 12 + Math.min(30, (el.data("deg") || 0) * 2.2),
          height: (el) => 12 + Math.min(30, (el.data("deg") || 0) * 2.2),
          shape: (el) => SHAPES[el.data("type")] || "round-rectangle",
          "border-width": (el) => (el.data("shared") ? 3 : 0), "border-color": "#f1f5fb",
          "min-zoomed-font-size": 7, opacity: (el) => (el.data("scope") === "third_party" ? 0.8 : 1) } },
        { selector: "node.lbl", style: { label: "data(label)", "text-opacity": 1 } },
        { selector: "edge", style: {
          width: 1, "line-color": "#2b3d58", "line-opacity": 0.75, "target-arrow-color": "#2b3d58",
          "target-arrow-shape": n > 600 ? "none" : "triangle", "arrow-scale": 0.7, "curve-style": "straight",
          "line-style": (e) => (e.data("confirmed") ? "solid" : "dashed") } },
        { selector: "edge.hl", style: { "line-color": "#ffb020", "line-opacity": 1, "target-arrow-color": "#ffb020", width: 2, label: "data(label)", "font-size": 8, color: "#ffd8a8" } },
        { selector: "node.hl", style: { "border-width": 3, "border-color": "#ffb020", "text-opacity": 1, label: "data(label)" } },
        { selector: "node.match", style: { "border-width": 4, "border-color": "#ffffff", "text-opacity": 1, label: "data(label)", "z-index": 99 } },
        { selector: ".faded", style: { opacity: 0.08, "text-opacity": 0 } },
      ],
      layout: layout === "fcose" ? fcoseOpts
        : layout === "concentric" ? { name: "concentric", concentric: (el) => el.degree(), levelWidth: () => 4, animate: false, minNodeSpacing: big ? 30 : 14 }
        : { name: layout, animate: false, spacingFactor: big ? 1.6 : 1.1 },
    });
    cyRef.current = cy;

    // Label strategy: at an overview zoom only hubs are labelled; zooming in reveals the rest.
    const hubCut = n > 400 ? 6 : n > 120 ? 3 : 1;
    const applyLabels = () => {
      if (cy.destroyed?.()) return;
      const z = cy.zoom();
      cy.batch(() => {
        cy.nodes().forEach((node) => {
          const show = z > 1.15 || (node.data("deg") || 0) >= hubCut;
          node[show ? "addClass" : "removeClass"]("lbl");
        });
      });
    };
    applyLabels();
    let raf = null;
    cy.on("zoom", () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(applyLabels); });

    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      cy.elements().removeClass("hl faded");
      const hood = node.closedNeighborhood();
      cy.elements().not(hood).addClass("faded");
      hood.addClass("hl");
      setSel({ ...node.data(), neighbors: node.neighborhood("node").map((x) => x.data()), edges: node.connectedEdges().map((e) => e.data()) });
    });
    cy.on("dbltap", "node", (evt) => setFocus(evt.target.id()));
    cy.on("tap", (evt) => { if (evt.target === cy) { cy.elements().removeClass("hl faded"); setSel(null); } });
    return () => { cancelAnimationFrame(raf); cy.destroy(); };
  }, [view, layout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass("match");
    if (q) {
      const m = cy.nodes().filter((node) => (node.data("key") || "").toLowerCase().includes(q.toLowerCase()));
      m.addClass("match");
      if (m.length) cy.animate({ fit: { eles: m, padding: 90 } }, { duration: 300 });
    }
  }, [q]);

  useEffect(() => { cyRef.current?.resize(); }, [sel]);

  if (loading || error) return <Pending loading={loading} error={error} reload={reload} what="Building graph" />;
  const stats = data.stats;
  const toggle = (t) => { const nxt = new Set(types); nxt.has(t) ? nxt.delete(t) : nxt.add(t); setTypes(nxt); };

  return (
    <div className="flex h-[calc(100vh-120px)] gap-4">
      <div className="flex w-64 shrink-0 flex-col gap-3 overflow-auto">
        <input className="input" placeholder="Search asset…" value={q} onChange={(e) => setQ(e.target.value)} />
        {focus && (
          <button className="btn justify-center text-amber-200" onClick={() => setFocus(null)}>← Exit focus · show all</button>
        )}
        <div className="card">
          <div className="mb-2 flex items-center justify-between text-xs font-semibold text-slate-300">
            <span>Asset types</span>
            <button className="font-normal text-slate-500 hover:text-slate-300" onClick={() => setTypes(new Set(DEFAULT_ON))}>all</button>
          </div>
          {DEFAULT_ON.map((t) => (
            <label key={t} className="flex items-center gap-2 py-0.5 text-xs">
              <input type="checkbox" checked={types.has(t)} onChange={() => toggle(t)} />
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLORS[t] }} />{t}
              <span className="ml-auto text-slate-500">{stats.by_type[t] || 0}</span>
            </label>
          ))}
          <label className="flex items-center gap-2 py-0.5 text-xs">
            <input type="checkbox" checked={showFindings} onChange={() => setShowFindings(!showFindings)} />
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLORS.finding }} />finding
            <span className="ml-auto text-slate-500">{stats.by_type.finding || 0}</span>
          </label>
        </div>
        <div className="card text-xs">
          <div className="mb-1 font-semibold text-slate-300">Layout</div>
          <select className="input w-full" value={layout} onChange={(e) => setLayout(e.target.value)}>
            <option value="fcose">Force-directed</option><option value="concentric">Concentric (by connections)</option>
            <option value="breadthfirst">Hierarchy</option><option value="circle">Circle</option>
          </select>
          <div className="mt-3 mb-1 font-semibold text-slate-300">Node budget</div>
          <input type="range" min="100" max="2000" step="100" value={limit} disabled={!!focus}
                 onChange={(e) => setLimit(+e.target.value)} className="w-full accent-[#2ee6ff]" />
          <div className="flex justify-between text-slate-500"><span>fewer, clearer</span><span className="text-slate-300">{limit}</span></div>
        </div>
        <div className="card text-xs">
          <div className="mb-2 font-semibold text-slate-300">Reading the map</div>
          <div className="space-y-1 text-slate-400">
            <div><span className="inline-block w-8 border-t-2 border-slate-400 align-middle" /> confirmed relation</div>
            <div><span className="inline-block w-8 border-t-2 border-dashed border-slate-400 align-middle" /> inferred relation</div>
            <div>node size = connections · white ring = shared</div>
            <div>◆ third party — referenced, not owned</div>
            <div className="text-slate-500">Zoom in for more labels · double-click a node to focus it</div>
          </div>
        </div>
        <div className="card text-xs">
          <div className="mb-2 font-semibold text-slate-300">Export</div>
          <div className="flex flex-wrap gap-1">
            <button className="btn" onClick={() => download(`${target}-graph.png`, cyRef.current.png({ full: true, scale: 2, bg: "#050a12" }))}>PNG</button>
            <button className="btn" onClick={() => download(`${target}-graph.json`, JSON.stringify(data, null, 1), "application/json")}>JSON</button>
            <a className="btn" href={withToken(`/api/targets/${target}/graph?format=graphml`)}>GraphML</a>
            <a className="btn" href={withToken(`/api/targets/${target}/graph?format=dot`)}>DOT</a>
          </div>
        </div>
        <div className="card text-xs text-slate-400">
          {stats.nodes} nodes · {stats.edges} edges<br />{stats.confirmed_edges} confirmed · {stats.inferred_edges} inferred · {stats.components} component(s)
          <div className="mt-2 font-semibold text-slate-300">Shared infrastructure</div>
          {stats.shared_infrastructure.slice(0, 8).map((s) => (
            <button key={s.label + s.type} className="block w-full truncate text-left hover:text-amber-200" title={s.label} onClick={() => setQ(s.label)}>
              {s.label} <span className="text-slate-500">({s.type}, {s.shared_by})</span>
            </button>
          ))}
        </div>
      </div>
      <div className="relative min-w-0 flex-1 hud">
        <div ref={ref} style={{ width: "100%", height: "100%" }} />
        {rendered.shown < rendered.total && !focus && (
          <div className="absolute left-2 top-2 rounded-[3px] border border-amber-500/30 bg-slate-950/85 px-2.5 py-1 text-[11px] text-amber-100 backdrop-blur">
            Showing {rendered.shown} best-connected of {rendered.total} — raise the budget, filter types, or search to see more.
          </div>
        )}
        <div className="absolute right-2 top-2 flex gap-1">
          <button className="btn" title="Zoom in" onClick={() => cyRef.current.zoom({ level: cyRef.current.zoom() * 1.3, position: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 } })}>＋</button>
          <button className="btn" title="Zoom out" onClick={() => cyRef.current.zoom({ level: cyRef.current.zoom() / 1.3, position: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 } })}>－</button>
          <button className="btn" title="Fit to view" onClick={() => cyRef.current.fit(undefined, 40)}><Icon name="fit" size={13} /></button>
        </div>
      </div>
      {sel && (
        <div className="w-80 shrink-0 overflow-auto hud p-4 text-sm">
          <div className="text-xs uppercase text-slate-400">{sel.type} · {sel.scope}</div>
          <div className="mono mb-2 break-all text-white">{sel.key}</div>
          <div className="text-xs text-slate-400">confidence {sel.confidence?.toFixed?.(2)} · {sel.deg} connection(s) · last {sel.last_seen?.slice(0, 16)}</div>
          {sel.shared && <div className="mt-1 text-xs text-amber-300">Shared by {sel.shared_by} assets — shared infrastructure does not imply common ownership.</div>}
          <div className="mt-3 flex gap-2">
            <button className="btn-primary flex-1" onClick={() => openAsset(sel.id)}>Open details</button>
            <button className="btn" onClick={() => setFocus(sel.id)} title="Show only this node and its neighbours"><Icon name="focus" size={13} /> Focus</button>
          </div>
          <div className="mt-4 text-xs font-semibold text-slate-300">Relations ({sel.edges.length})</div>
          {sel.edges.map((e) => {
            const other = e.source === sel.id ? e.target : e.source;
            const nb = sel.neighbors.find((node) => node.id === other);
            return (
              <div key={e.id} className="mt-1 border-b border-slate-800 pb-1 text-xs">
                <span className="text-slate-400">{e.source === sel.id ? "→" : "←"} {e.label}</span>{" "}
                <span className={e.confirmed ? "text-emerald-300" : "text-amber-300"}>{e.confirmed ? "confirmed" : "inferred"}</span>
                <button className="mono block text-left text-slate-200 hover:text-amber-200" onClick={() => nb && setFocus(nb.id)}>{nb?.label}</button>
                <div className="text-slate-500">sources: {(e.sources || []).join(", ")}</div>
                {(e.evidence_ids || []).slice(0, 2).map((x) => <EvidenceLink key={x} id={x} />)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
