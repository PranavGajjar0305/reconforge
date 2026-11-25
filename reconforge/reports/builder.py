"""Report generation: Markdown, HTML, JSON, CSV and PDF, with per-section toggles."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..db import Database
from ..db.models import Report, Scan
from ..graph.build import build_graph, stats, to_cytoscape, to_dot, to_graphml, to_svg
from ..util import iso, utcnow
from .data import build_report_data

TEMPLATES = Path(__file__).resolve().parent / "templates"
TOC = [("executive_summary", "Summary"), ("scope", "Scope"), ("methodology", "Methodology"), ("domains", "Subdomains"),
       ("dns", "DNS"), ("ip_asn", "IP/ASN"), ("ports", "Ports"), ("http", "HTTP"), ("technologies", "Technologies"),
       ("endpoints", "APIs & endpoints"), ("javascript", "JavaScript"), ("tls", "TLS"), ("cloud", "Cloud & 3rd party"),
       ("security", "Security"), ("cve", "CVE intel"), ("changes", "Changes"), ("graph", "Graph"),
       ("priorities", "Priorities"), ("ai_analysis", "AI analysis"), ("coverage", "Coverage gaps"), ("coverage_quality", "Coverage & quality"),
       ("source_comparison", "Source comparison"), ("subdomain_lists", "Host lists"), ("dns_infrastructure", "DNS & email"),
       ("http_profiles", "HTTP intelligence"), ("vhosts", "Virtual hosts"), ("identity", "Identity"),
       ("third_party_inventory", "Third parties"), ("parameters", "Parameters"), ("historical_urls", "Historical URLs"),
       ("documents", "Documents"), ("secrets", "Secret exposure"), ("screenshot_groups", "Visual groups"),
       ("limitations", "Limitations"), ("evidence", "Evidence")]


def _env(autoescape: bool) -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]) if autoescape else False,
                      trim_blocks=False, lstrip_blocks=False)
    env.policies["json.dumps_kwargs"] = {"sort_keys": True, "default": str}
    return env


def generate_reports(cfg, db: Database, scan_id: str, formats: list[str] | None = None,
                     sections: dict | None = None, out_dir: Path | None = None) -> dict[str, str]:
    formats = formats or cfg.get("reports.formats", ["markdown", "html", "json"])
    secs = {**cfg.get("reports.sections", {}), **(sections or {})}
    with db.session() as s:
        data = build_report_data(s, scan_id, light=None)  # huge scans: archive URLs stay in the output files
        scan = s.get(Scan, scan_id)
        g = build_graph(s, scan.target_id)
    out = out_dir or (cfg.dir("reports_dir") / data["scan"]["target"] / scan_id)
    out.mkdir(parents=True, exist_ok=True)
    gstats = stats(g)
    ctx = {"d": data, "sections": secs, "toc": TOC, "graph_stats": gstats, "generated_at": iso(utcnow())}
    written: dict[str, str] = {}
    if "markdown" in formats:
        p = out / "report.md"
        p.write_text(_env(False).get_template("report.md.j2").render(**ctx))
        written["markdown"] = str(p)
    if "html" in formats:
        p = out / "report.html"
        p.write_text(_env(True).get_template("report.html.j2").render(**ctx, graph_svg=to_svg(g) if secs.get("graph") else ""))
        written["html"] = str(p)
    if "json" in formats:
        p = out / "report.json"
        payload = {k: v for k, v in data.items() if _section_enabled_for_json(k, secs)}
        payload["sections_enabled"] = {k: bool(v) for k, v in secs.items()}
        p.write_text(json.dumps(payload, indent=2, default=str))
        written["json"] = str(p)
    if "csv" in formats:
        written.update(write_csvs(data, out))
    if "pdf" in formats:
        from .pdf import write_pdf

        p = out / "report.pdf"
        write_pdf(data, secs, gstats, p)
        written["pdf"] = str(p)
    if secs.get("graph"):
        (out / "graph.dot").write_text(to_dot(g))
        (out / "graph.graphml").write_text(to_graphml(g))
        (out / "graph.json").write_text(json.dumps(to_cytoscape(g), default=str))
    with db.session() as s:
        scan = s.get(Scan, scan_id)
        scan.report_dir = str(out)
        for fmt, path in written.items():
            s.add(Report(scan_id=scan_id, format=fmt.split(":")[0], path=path))
    return written


SECTION_KEYS = {"hosts": "domains", "ips": "ip_asn", "asns": "ip_asn", "providers": "ip_asn", "services": "ports",
                "web_apps": "http", "technologies": "technologies", "endpoints": "endpoints", "api_hosts": "endpoints",
                "js_files": "javascript", "certificates": "tls", "cloud": "cloud", "third_parties": "cloud",
                "findings": "security", "cve_findings": "cve", "changes": "changes", "priorities": "priorities",
                "ai": "ai_analysis", "coverage_gaps": "coverage", "evidence": "evidence", "module_runs": "methodology",
                "coverage": "coverage_quality", "source_comparison": "source_comparison", "resolved_hosts": "subdomain_lists",
                "unresolved_hosts": "subdomain_lists", "subdomain_clusters": "subdomain_lists", "dns_infrastructure": "dns_infrastructure",
                "email_findings": "dns_infrastructure", "cname_analysis": "dns_infrastructure", "http_profiles": "http_profiles",
                "http_vs_https": "http_profiles", "vhost_inventory": "vhosts", "identity": "identity",
                "third_party_inventory": "third_party_inventory", "parameter_inventory": "parameters",
                "endpoint_categories": "endpoints", "documents": "documents", "historical_urls": "historical_urls",
                "secret_exposures": "secrets", "screenshot_groups": "screenshot_groups", "limitations": "limitations"}


def _section_enabled_for_json(key: str, secs: dict) -> bool:
    sec = SECTION_KEYS.get(key)
    return sec is None or bool(secs.get(sec, True))


def write_csvs(data: dict, out: Path) -> dict[str, str]:
    tables = {
        "assets_hosts.csv": (["host", "type", "resolved", "ips", "cname", "discovered_via", "scope", "first_seen", "last_seen", "confidence"],
                             [[h["key"], h["type"], h["resolved"], ";".join(h["ips"]), ";".join(h["cname"]), ";".join(h["discovered_via"]),
                               h["scope"], h["first_seen"], h["last_seen"], h["confidence"]] for h in data["hosts"]]),
        "web_apps.csv": (["url", "status", "title", "server", "technologies", "cdn", "waf", "missing_headers", "ip", "last_seen"],
                         [[a["key"], a["status"], a["title"], a["server"], ";".join(f"{k} {v}".strip() for k, v in a["technologies"].items()),
                           a["cdn"], a["waf"], ";".join(a["missing_headers"]), a["ip"], a["last_seen"]] for a in data["web_apps"]]),
        "services.csv": (["ip", "port", "proto", "service", "product", "version", "hosts", "first_seen"],
                         [[x["ip"], x["port"], x["proto"], x["service"], x["product"], x["version"], ";".join(x["hosts"] or []), x["first_seen"]]
                          for x in data["services"]]),
        "endpoints.csv": (["url", "kind", "methods_documented", "methods_observed", "api_version", "sources", "first_seen"],
                          [[e["key"], e["kind"], ";".join(e["methods_documented"]), ";".join(e["methods_observed"]), e["api_version"],
                            ";".join(e["discovered_via"]), e["first_seen"]] for e in data["endpoints"]]),
        "findings.csv": (["severity", "category", "title", "subject", "confidence", "evidence", "description", "recommendation"],
                         [[f["attributes"].get("severity"), f["attributes"].get("category"), f["attributes"].get("title"),
                           f["attributes"].get("subject"), f["confidence"], f["evidence"], f["attributes"].get("description"),
                           f["attributes"].get("recommendation")] for f in data["findings"] + data["cve_findings"]]),
        "changes.csv": (["significance", "category", "summary", "asset", "previous", "current", "first_observed", "evidence"],
                        [[c["significance"], c["category"], c["summary"], c["asset"], json.dumps(c["previous"], default=str),
                          json.dumps(c["current"], default=str), c["first_observed"], c["evidence"]] for c in data["changes"]]),
        "priorities.csv": (["tier", "score", "asset", "reasons"],
                           [[p["tier"], p["score"], p["asset"]["key"], " | ".join(f["reason"] for f in p["factors"])] for p in data["priorities"]]),
    }
    written = {}
    for name, (header, rows) in tables.items():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        w.writerows(rows)
        (out / name).write_text(buf.getvalue())
        written[f"csv:{name}"] = str(out / name)
    return written
