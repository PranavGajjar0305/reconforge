"""Reconnaissance coverage and quality engine.

Measures what a scan actually covered, phase by phase, and produces an explicit
coverage statement. A scan is never described as comprehensive when any planned
module failed/skipped or any intelligence source was unavailable.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from .core.module import PHASES, load_modules
from .db.models import Asset, ModuleRun

PASSIVE_MODULE_SOURCES = {"crtsh", "subfinder", "github_intel", "historical_urls", "domain_intel"}


def compute_coverage(s, scan, ctx) -> dict:
    registry = load_modules()
    runs = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == scan.id)).scalars())
    first_pass = [r for r in runs if "#" not in r.module]
    touched = ctx.engine.touched
    seen = set(touched) | set(ctx.engine.referenced)
    assets = {a.id: a for a in s.execute(select(Asset).where(Asset.id.in_(list(seen)))).scalars()} if seen else {}
    by_type = defaultdict(list)
    for a in assets.values():
        by_type[a.type].append(a)

    sources = dict(ctx.shared.get("sources", {}))
    for r in first_pass:
        if r.module in PASSIVE_MODULE_SOURCES:
            sources[r.module] = {"kind": "module", "status": {"completed": "ok", "failed": "error", "skipped": "unavailable"}[r.status]
                                 if r.status in ("completed", "failed", "skipped") else r.status,
                                 "results": r.observations, "error": r.error or r.skip_reason}
    ok = sorted(k for k, v in sources.items() if v.get("status") == "ok")
    unavailable = {k: v.get("error") for k, v in sources.items() if v.get("status") in ("unavailable", "disabled")}
    errored = {k: v.get("error") for k, v in sources.items() if v.get("status") == "error"}

    phases = {}
    for phase in sorted(PHASES, key=PHASES.get):
        mods = [r for r in first_pass if r.module in registry and registry[r.module].phase == phase]
        if not mods:
            phases[phase] = {"status": "not_run", "modules": {}}
            continue
        st = {r.module: r.status for r in mods}
        vals = set(st.values())
        status = "completed" if vals == {"completed"} else "failed" if vals == {"failed"} else \
            "skipped" if vals <= {"skipped"} else "partial"
        phases[phase] = {"status": status, "modules": st}

    hosts = [a for a in by_type["subdomain"] + by_type["domain"] if a.scope == "in_scope"]
    dns_records = sum(len(v) for a in hosts for v in ((a.attributes or {}).get("dns") or {}).values() if isinstance(v, list))
    port_run = next((r for r in first_pass if r.module == "port_scan" and r.status == "completed"), None)
    ports_cfg = ctx.target.get("ports") or ctx.config.get("ports.tcp", [])
    ips_assessed = len({(a.attributes or {}).get("ip") for a in by_type["service"]}) if port_run else 0
    metrics = {
        "passive_sources_queried": len(ok),
        "passive_sources_unavailable": len(unavailable),
        "passive_sources_failed": len(errored),
        "subdomains_discovered": len(hosts),
        "dns_records_collected": dns_records,
        "hosts_resolved": sum(1 for a in hosts if (a.attributes or {}).get("resolved")),
        "http_services_identified": len(by_type["web_app"]),
        "ports_assessed": (len(ports_cfg) * max(1, len({ip for h in hosts for ip in (h.attributes or {}).get("ips", [])
                                                        if ctx.scope.ip_allowed(ip)}))) if port_run else 0,
        "open_services": len(by_type["service"]),
        "urls_collected": len(by_type["endpoint"]),
        "javascript_analyzed": sum(1 for a in by_type["js_file"] if "js_analysis" in touched.get(a.id, set())),
        "technologies_identified": len(by_type["technology"]),
        "tls_certificates_inspected": len(by_type["certificate"]),
        "security_observations": len(by_type["finding"]),
        "modules_failed": sorted({r.module for r in first_pass if r.status == "failed"}),
        "modules_skipped": sorted({r.module for r in first_pass if r.status == "skipped"}),
        "tools_failed": sorted(k for k, v in errored.items() if v),
    }
    incomplete = []
    if metrics["modules_failed"]:
        incomplete.append(f"{len(metrics['modules_failed'])} module(s) failed ({', '.join(metrics['modules_failed'])})")
    if metrics["modules_skipped"]:
        incomplete.append(f"{len(metrics['modules_skipped'])} module(s) skipped ({', '.join(metrics['modules_skipped'])})")
    if unavailable:
        incomplete.append(f"{len(unavailable)} intelligence source(s) unavailable ({', '.join(sorted(unavailable))})")
    if errored:
        incomplete.append(f"{len(errored)} source(s) returned errors ({', '.join(sorted(errored))})")
    if scan.incremental:
        skipped_inputs = sum(len(r.skipped_inputs or []) for r in runs)
        if skipped_inputs:
            incomplete.append(f"incremental mode re-used {skipped_inputs} recent result(s) instead of re-checking")
    level = "partial" if incomplete else "complete_for_profile"
    statement = ("PARTIAL coverage: " + "; ".join(incomplete) + "." if incomplete else
                 f"All planned modules of profile '{scan.profile}' completed and every configured source answered.")
    statement += (" Coverage describes the modules and sources that ran; it is not a guarantee that every asset "
                  "of the target was discovered.")
    return {"level": level, "statement": statement, "metrics": metrics, "phases": phases,
            "sources": {k: {kk: vv for kk, vv in v.items() if kk != "detail"} for k, v in sorted(sources.items())},
            "unavailable_sources": unavailable, "errored_sources": errored,
            "tool_selection": ctx.shared.get("tool_selection", {})}
