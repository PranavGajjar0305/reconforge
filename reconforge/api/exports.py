"""Download helpers: surface exports (CSV / JSON / Markdown) and per-module output bundles.

Everything here reads ReconForge's own database and log files; nothing contacts a target.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from sqlalchemy import select

from ..db.models import Asset, Evidence, ModuleRun, Observation, Scan
from ..util import iso

FORMATS = {"csv": "text/csv; charset=utf-8", "json": "application/json", "md": "text/markdown; charset=utf-8",
           "txt": "text/plain; charset=utf-8"}

# surface -> report-data section (or a callable key handled by the API)
REPORT_SURFACES = {
    "subdomains": "hosts", "ports": "services", "web-apps": "web_apps", "endpoints": "endpoints", "js-files": "js_files",
    "api-hosts": "api_hosts", "technologies": "technologies", "ips": "ips", "dns": "dns_infrastructure",
    "certificates": "certificates", "third-parties": "third_parties", "cloud": "cloud", "findings": "findings",
    "cves": "cve_findings", "priorities": "priorities", "identity": "identity", "http-profiles": "http_profiles",
    "documents": "documents", "parameters": "parameter_inventory", "ip-intelligence": "ip_intelligence",
    "coverage": "coverage", "source-comparison": "source_comparison",
}
OTHER_SURFACES = ["inventory", "changes", "scans", "tools", "graph", "full"]


def _cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return "; ".join(_cell(x) if not isinstance(x, dict) else json.dumps(x, default=str) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, default=str, sort_keys=True)
    return str(v)


def flatten(row, prefix: str = "", depth: int = 0) -> dict:
    """Flatten nested dicts one or two levels deep into dotted columns; deeper values become JSON."""
    if not isinstance(row, dict):
        return {prefix or "value": row}
    out = {}
    for k, v in row.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and depth < 1 and len(v) <= 40:
            out.update(flatten(v, key, depth + 1))
        else:
            out[key] = v
    return out


def rows_of(data) -> list[dict]:
    if isinstance(data, list):
        return [flatten(r) for r in data]
    if isinstance(data, dict):
        if all(isinstance(v, list) for v in data.values()):  # {group: [rows]} -> rows with a group column
            return [{"group": g, **flatten(r)} for g, items in data.items() for r in items]
        return [flatten(data)]
    return [{"value": data}]


def to_csv(rows: list[dict]) -> str:
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_cell(r.get(c)) for c in cols])
    return buf.getvalue()


def to_markdown(rows: list[dict], title: str, max_cols: int = 10) -> str:
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    cols = cols[:max_cols]
    esc = lambda s: _cell(s).replace("|", "\\|").replace("\n", " ")[:300]
    lines = [f"# {title}", "", f"{len(rows)} row(s).", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(esc(r.get(c)) for c in cols) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def render(data, fmt: str, title: str) -> str:
    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    rows = rows_of(data)
    return to_markdown(rows, title) if fmt == "md" else to_csv(rows)


# --------------------------------------------------------------------------- module output

LOG_TAG = re.compile(r"\[([a-z0-9_\-]+)(?:#\d+)?\]", re.I)


def log_counts(log_path: str | None) -> Counter:
    c: Counter = Counter()
    if log_path and Path(log_path).exists():
        with open(log_path, errors="replace") as fh:
            for line in fh:
                m = LOG_TAG.search(line)
                if m:
                    c[m.group(1)] += 1
    return c


def module_log(log_path: str | None, module: str, limit: int = 2_000_000) -> str:
    if not log_path or not Path(log_path).exists():
        return ""
    tag = re.compile(r"\[" + re.escape(module) + r"(#\d+)?\]")
    with open(log_path, errors="replace") as fh:
        text = "".join(l for l in fh if tag.search(l))
    return text[-limit:]


def _run(r: ModuleRun) -> dict:
    dur = (r.finished_at - r.started_at).total_seconds() if r.finished_at and r.started_at else None
    return {"module": r.module, "tool": r.tool, "status": r.status, "started_at": iso(r.started_at),
            "finished_at": iso(r.finished_at), "duration_seconds": round(dur, 1) if dur is not None else None,
            "observations": r.observations, "inputs": r.inputs, "skipped_inputs": len(r.skipped_inputs or []),
            "command": r.command, "reason": r.skip_reason or r.error}


def module_summaries(s, sc: Scan) -> list[dict]:
    runs = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == sc.id).order_by(ModuleRun.id)).scalars())
    ev = Counter(m for (m,) in s.execute(select(Evidence.module).where(Evidence.scan_id == sc.id)).all())
    by_type: dict[str, Counter] = defaultdict(Counter)
    for mod, typ in s.execute(select(Observation.module, Asset.type).join(Asset, Asset.id == Observation.asset_id)
                              .where(Observation.scan_id == sc.id)).all():
        by_type[mod][typ] += 1
    lines = log_counts(sc.log_path)
    out: dict[str, dict] = {}
    for r in runs:
        cur = out.get(r.module)
        d = _run(r)
        if cur is None:
            out[r.module] = {**d, "passes": 1}
        else:  # rediscovery passes: aggregate
            cur["passes"] += 1
            cur["observations"] += d["observations"]
            cur["finished_at"] = d["finished_at"] or cur["finished_at"]
            if d["status"] in ("running", "failed") or cur["status"] == "skipped":
                cur["status"] = d["status"]
            cur["duration_seconds"] = round((cur["duration_seconds"] or 0) + (d["duration_seconds"] or 0), 1)
    for p in sc.modules_planned or []:
        out.setdefault(p, {"module": p, "status": "pending", "observations": 0, "passes": 0})
    for name, d in out.items():
        d["evidence"] = ev.get(name, 0)
        d["log_lines"] = lines.get(name, 0)
        d["asset_types"] = dict(by_type.get(name, {}))
    order = {m: i for i, m in enumerate(sc.modules_planned or [])}
    return sorted(out.values(), key=lambda d: (order.get(d["module"], 999), d.get("started_at") or ""))


def module_output(s, sc: Scan, module: str, obs_limit: int = 2000, full: bool = False) -> dict:
    runs = [_run(r) for r in s.execute(select(ModuleRun).where(ModuleRun.scan_id == sc.id, ModuleRun.module == module)
                                       .order_by(ModuleRun.id)).scalars()]
    q = (select(Observation, Asset).join(Asset, Asset.id == Observation.asset_id)
         .where(Observation.scan_id == sc.id, Observation.module == module).order_by(Asset.type, Asset.key))
    obs = []
    types: Counter = Counter()
    for o, a in s.execute(q).all():
        types[a.type] += 1
        if full or len(obs) < obs_limit:
            obs.append({"asset_id": a.id, "type": a.type, "key": a.key, "display": a.display, "scope": a.scope,
                        "source": o.source, "confidence": round(o.confidence or 0, 2), "observed_at": iso(o.observed_at),
                        "evidence_id": o.evidence_id,
                        "data": {k: v for k, v in (o.data or {}).items() if not str(k).startswith("_")}})
    evidence = []
    for e in s.execute(select(Evidence).where(Evidence.scan_id == sc.id, Evidence.module == module)
                       .order_by(Evidence.created_at)).scalars():
        item = {"id": e.id, "kind": e.kind, "summary": e.summary, "created_at": iso(e.created_at), "has_file": bool(e.path),
                "size": len(e.content or "") if e.content else (Path(e.path).stat().st_size if e.path and Path(e.path).exists() else 0)}
        if full or e.kind == "tool_output":
            item["content"] = (e.content or "")[: (5_000_000 if full else 200_000)]
            if not e.content and e.path and Path(e.path).exists() and not e.path.endswith(".png"):
                item["content"] = Path(e.path).read_text(errors="replace")[: (5_000_000 if full else 200_000)]
        evidence.append(item)
    return {"scan_id": sc.id, "module": module, "runs": runs, "observations_total": sum(types.values()),
            "asset_types": dict(types), "observations": obs, "evidence": evidence,
            "log": module_log(sc.log_path, module, 5_000_000 if full else 400_000)}


def module_bundle(out: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(out, indent=2, default=str)
    if fmt == "csv":
        return to_csv([{"type": o["type"], "key": o["key"], "display": o["display"], "scope": o["scope"],
                        "source": o["source"], "confidence": o["confidence"], "observed_at": o["observed_at"],
                        "evidence_id": o["evidence_id"], **{f"data.{k}": v for k, v in o["data"].items()}}
                       for o in out["observations"]])
    # txt: human-readable dump
    lines = [f"ReconForge module output — {out['module']} (scan {out['scan_id']})", "=" * 72, ""]
    for r in out["runs"]:
        lines.append(f"status={r['status']}  started={r['started_at']}  duration={r['duration_seconds']}s  "
                     f"observations={r['observations']}  tool={r['tool']}")
        if r.get("command"):
            lines.append(f"command: {r['command']}")
        if r.get("reason"):
            lines.append(f"note: {r['reason']}")
    lines += ["", f"## Results ({out['observations_total']} observations)", ""]
    for o in out["observations"]:
        lines.append(f"[{o['type']}] {o['display'] or o['key']}  (confidence {o['confidence']}, evidence {o['evidence_id'] or '-'})")
    lines += ["", f"## Evidence ({len(out['evidence'])})", ""]
    for e in out["evidence"]:
        lines.append(f"- {e['id']} [{e['kind']}] {e['summary']}")
        if e.get("content") and e["kind"] in ("tool_output",):
            lines += ["", e["content"], ""]
    lines += ["", "## Execution log", "", out["log"]]
    return "\n".join(lines)


def _host_regex(pattern: str) -> str | None:
    """Scope pattern (example.com, *.example.com, 192.0.2.10) -> Burp host regex."""
    import ipaddress

    p = pattern.strip().lower().rstrip(".")
    if not p:
        return None
    try:
        net = ipaddress.ip_network(p, strict=False)
        if net.num_addresses == 1:
            return "^" + re.escape(str(net.network_address)) + "$"
        if net.version == 4 and net.prefixlen >= 24:  # Burp has no CIDR syntax: enumerate small ranges
            return "^(" + "|".join(re.escape(str(ip)) for ip in net) + ")$"
        return None
    except ValueError:
        pass
    if p.startswith("*."):
        return r"^(.*\.)?" + re.escape(p[2:]) + "$"
    return "^" + re.escape(p) + "$"


def burp_scope_json(target: dict) -> str:
    """Burp Suite project-options JSON (advanced scope) built from a target's scope definition."""
    scope = target.get("scope") or {}
    include = list(dict.fromkeys([f"*.{d}" for d in target.get("root_domains", [])] + list(scope.get("include") or [])
                                 + list(target.get("ip_targets") or [])))
    rules = lambda pats: [{"enabled": True, "host": rx, "protocol": "any"} for rx in dict.fromkeys(filter(None, map(_host_regex, pats)))]
    doc = {"target": {"scope": {"advanced_mode": True, "include": rules(include), "exclude": rules(scope.get("exclude") or [])}}}
    return json.dumps(doc, indent=2)
