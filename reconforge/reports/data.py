"""Assemble a structured, evidence-referenced view of one scan (used by reports, API and AI)."""
from __future__ import annotations

from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.module import load_modules
from ..db.models import AIAnalysis, Asset, AssetScore, Change, Evidence, ModuleRun, Relation, Scan, Target
from ..prioritize.engine import DISCLAIMER
from ..util import iso

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CATEGORY_GROUPS = {
    "web_server": "Web server", "backend_framework": "Backend framework", "frontend_framework": "Frontend framework",
    "cms": "CMS", "language": "Programming language", "cdn": "CDN", "waf": "WAF", "cloud": "Cloud provider",
    "database": "Database indicators", "js_library": "JavaScript library", "analytics": "Analytics",
    "payment": "Payments", "api": "API", "api_documentation": "API documentation", "identity": "Identity",
}


def _a(asset: Asset) -> dict:
    attrs = {k: v for k, v in (asset.attributes or {}).items() if not k.startswith("_")}
    return {"id": asset.id, "type": asset.type, "key": asset.key, "display": asset.display, "scope": asset.scope,
            "confidence": round(asset.confidence or 0, 2), "status": asset.status, "first_seen": iso(asset.first_seen),
            "last_seen": iso(asset.last_seen), "sources": [x["source"] for x in asset.sources or []],
            "evidence": (asset.attributes or {}).get("_last_evidence"), "false_positive": asset.false_positive,
            "attributes": attrs}


API_KINDS = ("api", "graphql", "openapi", "websocket", "api_documentation", "oidc_metadata")
LIGHT_ENDPOINT_CAP = 20000          # API / document endpoints included in a light build
BULK_RELATIONS = ("historical_url",)  # archive URL -> host links; can be hundreds of thousands per target


def _active(q, include_fp: bool):
    q = q.where(Asset.status == "active")
    return q if include_fp else q.where(Asset.false_positive == False)  # noqa: E712 ("=" so the composite indexes apply)


def endpoint_summary(s: Session, target_id: str, include_fp: bool = False) -> dict:
    """Endpoint counts straight from the indexes (no row is loaded)."""
    from sqlalchemy import func

    from ..db.fastpath import is_historical, jfield

    d = s.bind.dialect.name
    base = _active(select(func.count()).select_from(Asset).where(Asset.target_id == target_id, Asset.type == "endpoint"), include_fp)
    kind = jfield(d, Asset.attributes, "kind")
    by_kind = dict(s.execute(_active(select(kind, func.count()).where(Asset.target_id == target_id, Asset.type == "endpoint"),
                                     include_fp).group_by(kind)).all())
    return {"total": s.execute(base).scalar() or 0,
            "historical": s.execute(base.where(is_historical(d, Asset.attributes))).scalar() or 0,
            "by_kind": {(k or "unknown"): n for k, n in sorted(by_kind.items(), key=lambda kv: -kv[1])},
            "api": sum(n for k, n in by_kind.items() if k in API_KINDS)}


AUTO_LIGHT_ENDPOINTS = 50000  # light=None (reports, AI) switches to the light build above this many endpoints


def build_report_data(s: Session, scan_id: str, include_fp: bool = False, light: bool | None = False) -> dict:
    """Everything known about one scan. `light` (dashboard views) leaves out archive URLs and caps endpoints, so a
    target with hundreds of thousands of historical URLs still builds in seconds; counts stay exact.
    light=None decides by size: full below AUTO_LIGHT_ENDPOINTS endpoints, light above."""
    scan = s.get(Scan, scan_id)
    if scan is None:
        raise KeyError(f"scan {scan_id} not found")
    if light is None:
        from sqlalchemy import func

        n = s.execute(select(func.count()).select_from(Asset).where(Asset.target_id == scan.target_id,
                                                                   Asset.type == "endpoint")).scalar() or 0
        light = n > AUTO_LIGHT_ENDPOINTS
    target = s.get(Target, scan.target_id)
    q = _active(select(Asset).where(Asset.target_id == scan.target_id), include_fp)
    ep_summary = None
    if light:
        d = s.bind.dialect.name
        types = [t for (t,) in s.execute(select(Asset.type).where(Asset.target_id == scan.target_id).distinct()) if t != "endpoint"]
        assets = list(s.execute(q.where(Asset.type.in_(types))).scalars()) if types else []
        from ..db.fastpath import jfield

        # API-ish and document endpoints (what the dashboard summarises); every endpoint is paged via /endpoints
        # no ORDER BY here: it would make SQLite walk the URL index and parse every row's JSON (minutes on 1M rows)
        api_eps = list(s.execute(q.where(Asset.type == "endpoint", jfield(d, Asset.attributes, "kind").in_([*API_KINDS, "document"]))
                                 .limit(LIGHT_ENDPOINT_CAP)).scalars())
        assets += sorted(api_eps, key=lambda a: a.key)
        ep_summary = endpoint_summary(s, scan.target_id, include_fp)
    else:
        assets = list(s.execute(q).scalars())
    by_type: dict[str, list[Asset]] = defaultdict(list)
    for a in assets:
        by_type[a.type].append(a)
    idx = {a.id: a for a in assets}
    rq = select(Relation).where(Relation.target_id == scan.target_id)
    if light:
        rtypes = [t for (t,) in s.execute(select(Relation.type).where(Relation.target_id == scan.target_id).distinct())
                  if t not in BULK_RELATIONS]
        rq = rq.where(Relation.type.in_(rtypes)) if rtypes else None
    rels = list(s.execute(rq).scalars()) if rq is not None else []
    out_edges, in_edges = defaultdict(list), defaultdict(list)
    for r in rels:
        out_edges[r.src_id].append(r)
        in_edges[r.dst_id].append(r)
    runs = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == scan_id).order_by(ModuleRun.id)).scalars())
    changes = list(s.execute(select(Change).where(Change.scan_id == scan_id)).scalars())
    scores = list(s.execute(select(AssetScore).where(AssetScore.scan_id == scan_id).order_by(AssetScore.score.desc())).scalars())
    ai = s.execute(select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at.desc())).scalars().first()

    ip_target_assets = [a for a in by_type["ip"] if (a.attributes or {}).get("target")]
    hosts = sorted(by_type["domain"] + by_type["subdomain"] + ip_target_assets,
                   key=lambda a: ({"domain": 0, "ip": 1}.get(a.type, 2), a.key))
    in_scope_hosts = [h for h in hosts if h.scope == "in_scope"]
    findings = sorted(by_type["finding"], key=lambda f: (SEV_ORDER.get((f.attributes or {}).get("severity"), 5), f.key))
    sec_findings = [f for f in findings if (f.attributes or {}).get("category") not in ("cve",)]
    cve_findings = [f for f in findings if (f.attributes or {}).get("category") == "cve"]

    def linked(aid: str, rtype: str, direction: str = "out") -> list[Asset]:
        edges = out_edges[aid] if direction == "out" else in_edges[aid]
        return [idx[(r.dst_id if direction == "out" else r.src_id)] for r in edges
                if r.type == rtype and (r.dst_id if direction == "out" else r.src_id) in idx]

    host_rows = []
    for h in hosts:
        at = h.attributes or {}
        apps = linked(h.id, "serves")
        host_rows.append({**_a(h), "resolved": bool(at.get("resolved")), "ips": at.get("ips", []),
                          "cname": (at.get("dns") or {}).get("CNAME", []), "discovered_via": at.get("discovered_via", []),
                          "web_apps": [x.key for x in apps], "dns": at.get("dns") or at.get("dns_public") or {}})
    ip_rows = []
    for ip in by_type["ip"]:
        at = ip.attributes or {}
        names = [x.key for x in linked(ip.id, "resolves_to", "in")]
        ip_rows.append({**_a(ip), "asn": at.get("asn"), "asn_name": at.get("asn_name"), "provider": at.get("provider"),
                        "cdn": at.get("cdn"), "ptr": at.get("ptr"), "hostnames": sorted(names),
                        "services": [x.key for x in linked(ip.id, "exposes")]})
    app_rows = []
    for app in sorted(by_type["web_app"], key=lambda a: a.key):
        at = app.attributes or {}
        app_rows.append({**_a(app), "status": at.get("status"), "title": at.get("title"), "server": at.get("server"),
                         "technologies": at.get("technologies", {}), "missing_headers": at.get("missing_security_headers", []),
                         "tls": at.get("tls"), "cdn": at.get("cdn"), "waf": at.get("waf"), "ip": at.get("ip"),
                         "screenshot": at.get("screenshot_evidence"), "is_api": at.get("is_api", False)})
    tech_groups: dict[str, list[dict]] = defaultdict(list)
    for t in by_type["technology"]:
        apps = linked(t.id, "uses", "in")
        versions = sorted({(r.attributes or {}).get("version") for r in in_edges[t.id] if r.type == "uses"} - {"", None})
        cats = (t.attributes or {}).get("categories") or ["other"]
        row = {**_a(t), "name": (t.attributes or {}).get("name", t.display), "versions": versions,
               "apps": sorted(a.key for a in apps), "categories": cats}
        for c in cats:
            tech_groups[CATEGORY_GROUPS.get(c, c.replace("_", " ").title())].append(row)
    endpoints = sorted(by_type["endpoint"], key=lambda a: a.key)
    ep_rows = [{**_a(e), "kind": (e.attributes or {}).get("kind"), "methods_documented": (e.attributes or {}).get("methods_documented", []),
                "methods_observed": (e.attributes or {}).get("methods_observed", []), "api_version": (e.attributes or {}).get("api_version"),
                "status": (e.attributes or {}).get("status"), "discovered_via": (e.attributes or {}).get("discovered_via", []),
                "host": (e.attributes or {}).get("host")} for e in endpoints]
    api_kinds = set(API_KINDS)
    api_hosts = sorted({e["host"] for e in ep_rows if e["kind"] in api_kinds and e["host"]} |
                       {a["attributes"].get("host") for a in app_rows if a["is_api"]})
    services = [{**_a(sv), **{k: (sv.attributes or {}).get(k) for k in ("ip", "port", "proto", "service", "product", "version", "banner", "hosts")}}
                for sv in sorted(by_type["service"], key=lambda a: a.key)]
    certs = [{**_a(c), **{k: (c.attributes or {}).get(k) for k in ("subject_cn", "issuer_cn", "sans", "not_before", "not_after",
                                                                     "days_remaining", "self_signed", "trusted", "key_type", "key_bits")},
              "presented_by": [x.key for x in linked(c.id, "presents", "in")]} for c in by_type["certificate"]]
    missing = [sc.asset_id for sc in scores if sc.asset_id not in idx]
    if light and missing:  # a scored asset that the light build left out (e.g. an archive URL)
        for i in range(0, len(missing), 500):
            for a in s.execute(select(Asset).where(Asset.id.in_(missing[i:i + 500]))).scalars():
                idx[a.id] = a
    priorities = [{"asset": _a(idx[sc.asset_id]), "score": sc.score, "tier": sc.tier, "factors": sc.factors}
                  for sc in scores if sc.asset_id in idx]
    completed = [r for r in runs if r.status == "completed"]
    gaps = []
    for r in runs:
        if r.status in ("skipped", "failed") and "#" not in r.module:
            gaps.append({"module": r.module, "status": r.status, "reason": r.skip_reason or r.error})
    registry = load_modules()
    not_run = sorted(set(registry) - {r.module.split("#")[0] for r in runs})
    for m in not_run:
        gaps.append({"module": m, "status": "not in profile", "reason": registry[m].description})
    unresolved = [h.key for h in in_scope_hosts if not (h.attributes or {}).get("resolved")]
    if unresolved:
        gaps.append({"module": "dns_resolve", "status": "coverage", "reason": f"{len(unresolved)} discovered host(s) did not resolve: {', '.join(unresolved[:15])}"})
    no_web = [h.key for h in in_scope_hosts if (h.attributes or {}).get("resolved") and not linked(h.id, "serves")]
    if no_web:
        gaps.append({"module": "http_probe", "status": "coverage", "reason": f"Resolved hosts with no web application on probed ports: {', '.join(no_web[:15])}"})
    ev_ids = sorted({x for x in [a.attributes.get("_last_evidence") for a in assets if a.attributes] if x} |
                    {c.evidence_id for c in changes if c.evidence_id})
    evidence = {}
    cols = (Evidence.id, Evidence.kind, Evidence.summary, Evidence.module, Evidence.sha256, Evidence.path, Evidence.created_at)
    for i in range(0, len(ev_ids), 900):  # metadata only (never the content), in batches below SQL parameter limits
        for e in s.execute(select(*cols).where(Evidence.id.in_(ev_ids[i:i + 900]))).all():
            evidence[e.id] = {"id": e.id, "kind": e.kind, "summary": e.summary, "module": e.module, "sha256": e.sha256,
                              "path": e.path, "created_at": iso(e.created_at)}
    sev_counts = Counter((f.attributes or {}).get("severity", "info") for f in findings)
    overview = {
        "domains": len(by_type["domain"]),
        "ip_targets": len(ip_target_assets),
        "subdomains": len([h for h in by_type["subdomain"] if h.scope == "in_scope"]),
        "resolved_hosts": sum(1 for h in in_scope_hosts if (h.attributes or {}).get("resolved")),
        "unresolved_hosts": len(unresolved),
        "live_web_services": sum(1 for a in app_rows if a["status"]),
        "ip_addresses": len(by_type["ip"]),
        "asns": len(by_type["asn"]),
        "open_ports": len(services),
        "technologies": len(by_type["technology"]),
        "api_endpoints": ep_summary["api"] if ep_summary else sum(1 for e in ep_rows if e["kind"] in api_kinds),
        "endpoints": ep_summary["total"] if ep_summary else len(ep_rows),
        "javascript_files": len(by_type["js_file"]),
        "certificates": len(certs),
        "cloud_references": len(by_type["cloud_resource"]),
        "third_parties": len(by_type["third_party"]),
        "security_observations": len(sec_findings),
        "cve_correlations": len(cve_findings),
        "changes": len(changes),
        "findings_by_severity": dict(sev_counts),
    }
    data = {
        "scan": {"id": scan.id, "target": target.name, "profile": scan.profile, "status": scan.status,
                 "trigger": scan.trigger, "incremental": scan.incremental, "started_at": iso(scan.started_at),
                 "finished_at": iso(scan.finished_at), "duration_seconds": scan.duration_seconds,
                 "prev_scan_id": scan.prev_scan_id, "modules_planned": scan.modules_planned,
                 "modules_completed": scan.modules_completed, "modules_failed": scan.modules_failed,
                 "modules_skipped": scan.modules_skipped, "tools_executed": scan.tools_executed,
                 "results_count": scan.results_count, "report_dir": scan.report_dir, "log_path": scan.log_path},
        "target": {"name": target.name, "root_domains": target.config.get("root_domains", []),
                   "ip_targets": target.config.get("ip_targets", []),
                   "scope": target.config.get("scope", {}), "authorization": target.config.get("authorization", {})},
        "overview": overview,
        "module_runs": [{"module": r.module, "tool": r.tool, "status": r.status, "started_at": iso(r.started_at),
                         "finished_at": iso(r.finished_at), "observations": r.observations, "command": r.command,
                         "reason": r.skip_reason or r.error, "skipped_inputs": len(r.skipped_inputs or [])} for r in runs],
        "hosts": host_rows,
        "ips": ip_rows,
        "asns": [_a(x) for x in by_type["asn"]],
        "providers": [_a(x) for x in by_type["provider"]],
        "services": services,
        "web_apps": app_rows,
        "technologies": dict(sorted(tech_groups.items())),
        "endpoints": ep_rows,
        "endpoint_summary": ep_summary or {"total": len(ep_rows), "historical": sum(1 for e in ep_rows if e["attributes"].get("historical")),
                                           "by_kind": dict(Counter(e["kind"] or "unknown" for e in ep_rows).most_common()),
                                           "api": sum(1 for e in ep_rows if e["kind"] in api_kinds)},
        "light": light,
        "api_hosts": api_hosts,
        "js_files": [{**_a(j), **{k: (j.attributes or {}).get(k) for k in ("size", "endpoints_found", "third_parties", "libraries", "sourcemap", "secret_patterns")}}
                     for j in by_type["js_file"]],
        "certificates": certs,
        "cloud": [_a(c) for c in by_type["cloud_resource"]],
        "third_parties": [{**_a(t), "referenced_by": [idx[r.src_id].key for r in in_edges[t.id] if r.src_id in idx]}
                          for t in by_type["third_party"]],
        "repositories": [_a(r) for r in by_type["repository"]],
        "findings": [_a(f) for f in sec_findings],
        "cve_findings": [_a(f) for f in cve_findings],
        "changes": [{"id": c.id, "category": c.category, "significance": c.significance, "summary": c.summary,
                     "asset_type": c.asset_type, "asset": c.asset_display, "asset_id": c.asset_id,
                     "previous": c.previous, "current": c.current, "first_observed": iso(c.first_observed),
                     "evidence": c.evidence_id} for c in sorted(changes, key=lambda c: ({"high": 0, "medium": 1, "low": 2}.get(c.significance, 3), c.category))],
        "priorities": priorities,
        "priority_disclaimer": DISCLAIMER,
        "coverage_gaps": gaps,
        "ai": ({"provider": ai.provider, "model": ai.model, "status": ai.status, "created_at": iso(ai.created_at),
                "result": ai.result, "rejected": ai.rejected, "error": ai.error} if ai else None),
        "evidence": evidence,
    }
    from .extended import extend

    return extend(data, by_type, scan)
