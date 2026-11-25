"""Attack-surface relationship graph (NetworkX) with exports.

Edges keep `confirmed` (directly observed) vs inferred. Third-party nodes are kept
visually and semantically separate: an edge to a third party means "referenced by",
never "owned by".
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from xml.sax.saxutils import escape

import networkx as nx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import Asset, Relation

TYPE_COLORS = {
    "domain": "#dce4f0", "subdomain": "#7cb7ff", "ip": "#5fd0c5", "asn": "#3aa39a", "provider": "#2e7d77",
    "certificate": "#b28cff", "service": "#ff9f5a", "web_app": "#ffb733", "technology": "#d9c56b",
    "endpoint": "#8fbf6a", "js_file": "#c49a5a", "cloud_resource": "#ff6fa8", "third_party": "#6b7f9e",
    "repository": "#8c9bb3", "finding": "#ff4d6a",
}
DEFAULT_GRAPH_TYPES = ["domain", "subdomain", "ip", "asn", "provider", "certificate", "service", "web_app",
                       "technology", "endpoint", "js_file", "cloud_resource", "third_party", "repository"]


GRAPH_ENDPOINT_CAP = 5000  # endpoints drawn at most (live ones first); archive URLs are never graph nodes


def build_graph(s: Session, target_id: str, types: list[str] | None = None, include_removed: bool = False,
                include_fp: bool = False, endpoint_cap: int = GRAPH_ENDPOINT_CAP) -> nx.MultiDiGraph:
    from ..db.fastpath import not_historical
    from ..reports.data import BULK_RELATIONS

    types = types or DEFAULT_GRAPH_TYPES
    q = select(Asset).where(Asset.target_id == target_id)
    if not include_removed:
        q = q.where(Asset.status == "active")
    if not include_fp:
        q = q.where(Asset.false_positive.is_(False))
    g = nx.MultiDiGraph()
    g.graph["omitted"] = {}

    def add(a: Asset) -> None:
        g.add_node(a.id, type=a.type, label=_label(a), key=a.key, scope=a.scope, confidence=a.confidence,
                   status=a.status, first_seen=a.first_seen.isoformat(), last_seen=a.last_seen.isoformat())

    for a in s.execute(q.where(Asset.type.in_([t for t in types if t != "endpoint"]))).scalars():
        add(a)
    if "endpoint" in types:
        d = s.bind.dialect.name
        n = 0
        for a in s.execute(q.where(Asset.type == "endpoint", not_historical(d, Asset.attributes))
                           .order_by(Asset.key).limit(endpoint_cap)).scalars():
            add(a)
            n += 1
        total = s.execute(select(func.count()).select_from(Asset).where(Asset.target_id == target_id, Asset.type == "endpoint",
                                                                       Asset.status == "active")).scalar() or 0
        if total > n:
            g.graph["omitted"]["endpoint"] = {"shown": n, "total": total}
    rtypes = [t for (t,) in s.execute(select(Relation.type).where(Relation.target_id == target_id).distinct())
              if t not in BULK_RELATIONS]
    if rtypes:
        for r in s.execute(select(Relation).where(Relation.target_id == target_id, Relation.type.in_(rtypes))).scalars():
            if r.src_id in g and r.dst_id in g:
                g.add_edge(r.src_id, r.dst_id, key=r.id, id=r.id, type=r.type, confirmed=r.confirmed,
                           confidence=r.confidence, sources=r.sources, evidence_ids=r.evidence_ids)
    _mark_shared(g)
    return g


def _label(a: Asset) -> str:
    if a.type == "web_app":
        return a.key.split("://", 1)[1]
    if a.type == "certificate":
        return (a.attributes or {}).get("subject_cn") or a.key[:12]
    if a.type == "service":
        attrs = a.attributes or {}
        return f"{attrs.get('port')}/{attrs.get('service')}"
    if a.type == "endpoint":
        return (a.attributes or {}).get("path") or a.key
    return a.display[:60]


def _mark_shared(g: nx.MultiDiGraph) -> None:
    """Flag infrastructure nodes (IP, cert, ASN, provider, tech) shared by multiple hostnames."""
    for n, data in g.nodes(data=True):
        if data["type"] not in ("ip", "certificate", "asn", "provider", "third_party", "cloud_resource"):
            continue
        hosts = set()
        for u in nx.ancestors(g, n) if data["type"] in ("asn", "provider") else g.predecessors(n):
            if g.nodes[u]["type"] in ("subdomain", "domain", "web_app", "js_file"):
                hosts.add(u)
        if data["type"] == "certificate":
            hosts |= {v for v in g.successors(n) if g.nodes[v]["type"] in ("subdomain", "domain")}
        data["shared_by"] = len(hosts)
        data["shared"] = len(hosts) > 1


def to_cytoscape(g: nx.MultiDiGraph) -> dict:
    nodes = [{"data": {"id": n, **{k: v for k, v in d.items()}, "color": TYPE_COLORS.get(d["type"], "#999")}}
             for n, d in g.nodes(data=True)]
    edges = [{"data": {"id": d["id"], "source": u, "target": v, "label": d["type"], **{k: d[k] for k in ("confirmed", "confidence", "sources", "evidence_ids")}}}
             for u, v, d in g.edges(data=True)]
    return {"nodes": nodes, "edges": edges, "stats": stats(g)}


def stats(g: nx.MultiDiGraph) -> dict:
    by_type = defaultdict(int)
    for _, d in g.nodes(data=True):
        by_type[d["type"]] += 1
    shared = sorted(((d["label"], d["type"], d.get("shared_by", 0)) for _, d in g.nodes(data=True) if d.get("shared")),
                    key=lambda x: -x[2])
    und = nx.Graph(g)
    return {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(), "by_type": dict(by_type),
            "confirmed_edges": sum(1 for *_, d in g.edges(data=True) if d["confirmed"]),
            "inferred_edges": sum(1 for *_, d in g.edges(data=True) if not d["confirmed"]),
            "components": nx.number_connected_components(und) if und.number_of_nodes() else 0,
            "shared_infrastructure": [{"label": l, "type": t, "shared_by": n} for l, t, n in shared[:25]],
            "omitted": g.graph.get("omitted", {})}


def to_dot(g: nx.MultiDiGraph) -> str:
    lines = ["digraph attack_surface {", '  graph [rankdir=LR, fontname="Helvetica"];',
             '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fontcolor=white];']
    for n, d in g.nodes(data=True):
        shape = "ellipse" if d["type"] == "third_party" else "box"
        lines.append(f'  "{n}" [label="{_q(d["label"])}\\n({d["type"]})", fillcolor="{TYPE_COLORS.get(d["type"], "#999")}", shape={shape}];')
    for u, v, d in g.edges(data=True):
        style = "solid" if d["confirmed"] else "dashed"
        lines.append(f'  "{u}" -> "{v}" [label="{_q(d["type"])}", style={style}, fontsize=8];')
    lines.append("}")
    return "\n".join(lines)


def _q(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def to_graphml(g: nx.MultiDiGraph) -> str:
    h = nx.MultiDiGraph()
    for n, d in g.nodes(data=True):
        h.add_node(n, **{k: (v if isinstance(v, (str, int, float, bool)) else json.dumps(v)) for k, v in d.items()})
    for u, v, d in g.edges(data=True):
        h.add_edge(u, v, **{k: (v2 if isinstance(v2, (str, int, float, bool)) else json.dumps(v2)) for k, v2 in d.items()})
    return "\n".join(nx.generate_graphml(h))


def to_svg(g: nx.MultiDiGraph, width: int = 1100, height: int = 760, max_nodes: int = 140) -> str:
    """Static SVG rendering (spring layout) for HTML/PDF reports — no external renderer needed."""
    keep = sorted(g.nodes, key=lambda n: -g.degree(n))[:max_nodes]
    sub = g.subgraph(keep)
    if sub.number_of_nodes() == 0:
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="80"><text x="10" y="40">No graph data</text></svg>'
    pos = nx.spring_layout(nx.Graph(sub), seed=7, k=1.6 / math.sqrt(max(sub.number_of_nodes(), 1)), iterations=200)
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    sx = lambda x: 40 + (x - minx) / ((maxx - minx) or 1) * (width - 220)
    sy = lambda y: 30 + (y - miny) / ((maxy - miny) or 1) * (height - 60)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" font-family="Helvetica" font-size="9">',
           '<rect width="100%" height="100%" fill="#ffffff"/>']
    for u, v, d in sub.edges(data=True):
        dash = "" if d["confirmed"] else ' stroke-dasharray="4,3"'
        out.append(f'<line x1="{sx(pos[u][0]):.1f}" y1="{sy(pos[u][1]):.1f}" x2="{sx(pos[v][0]):.1f}" y2="{sy(pos[v][1]):.1f}" stroke="#94a3b8" stroke-width="0.8"{dash}/>')
    for n, d in sub.nodes(data=True):
        x, y = sx(pos[n][0]), sy(pos[n][1])
        r = 5 + min(8, sub.degree(n) * 0.6)
        stroke = ' stroke="#111" stroke-width="1.5"' if d.get("shared") else ""
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{TYPE_COLORS.get(d["type"], "#999")}"{stroke}><title>{escape(d["type"])}: {escape(d["key"])}</title></circle>')
        out.append(f'<text x="{x + r + 2:.1f}" y="{y + 3:.1f}" fill="#1f2937">{escape(d["label"][:34])}</text>')
    ly = 20
    for t, c in TYPE_COLORS.items():
        if any(d["type"] == t for _, d in sub.nodes(data=True)):
            out.append(f'<circle cx="{width - 160}" cy="{ly}" r="5" fill="{c}"/><text x="{width - 150}" y="{ly + 3}">{t}</text>')
            ly += 14
    out.append(f'<line x1="{width - 165}" y1="{ly + 6}" x2="{width - 145}" y2="{ly + 6}" stroke="#94a3b8"/><text x="{width - 140}" y="{ly + 9}">confirmed</text>')
    out.append(f'<line x1="{width - 165}" y1="{ly + 20}" x2="{width - 145}" y2="{ly + 20}" stroke="#94a3b8" stroke-dasharray="4,3"/><text x="{width - 140}" y="{ly + 23}">inferred</text>')
    out.append("</svg>")
    return "\n".join(out)
