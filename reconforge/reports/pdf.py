"""PDF rendering with ReportLab (no external binaries)."""
from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV_COLORS = {"critical": "#991b1b", "high": "#b91c1c", "medium": "#c2410c", "low": "#a16207", "info": "#0369a1"}


def _p(text, style):
    return Paragraph(escape(str(text if text is not None else "")), style)


def write_pdf(d: dict, sections: dict, gstats: dict, path: Path) -> None:
    styles = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=8.5, leading=11)
    cell = ParagraphStyle("c", parent=body, fontSize=7.2, leading=9)
    h1, h2 = styles["Title"], ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#312e81"))
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm, title=f"ReconForge — {d['target']['name']}")
    width = doc.width
    story = []

    def table(header, rows, widths=None, max_rows=400):
        if not rows:
            story.append(_p("None.", body))
            return
        cols = len(header)
        col_w = [width * w for w in widths] if widths else [width / cols] * cols
        # A cell taller than the page frame aborts the whole PDF (reportlab LayoutError), so cap each
        # cell to ~40 wrapped lines for its column width; the CSV/JSON exports keep the full text.
        caps = [max(80, int(w / (cell.fontSize * 0.55)) * 40) for w in col_w]

        def clip(text, cap):
            text = str(text if text is not None else "")
            return text if len(text) <= cap else text[:cap] + f" … (+{len(text) - cap} chars)"

        data = [[_p(h, cell) for h in header]] + [[_p(clip(c, caps[i]), cell) for i, c in enumerate(r)] for r in rows[:max_rows]]
        t = Table(data, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0e7ff")),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        if len(rows) > max_rows:
            story.append(_p(f"… {len(rows) - max_rows} more rows in CSV/JSON exports.", body))

    def h(title):
        story.append(Spacer(1, 6))
        story.append(_p(title, h2))

    s, o = d["scan"], d["overview"]
    story.append(_p(f"Attack Surface Report — {d['target']['name']}", h1))
    story.append(_p(f"Scan {s['id']} · profile {s['profile']} · {s['status']} · {s['started_at']} → {s['finished_at']} "
                    f"({s['duration_seconds']} s)", body))
    story.append(_p("Findings are evidence-backed observations. Exposure is not vulnerability; version-based CVE "
                    "correlations are unconfirmed until verified manually.", body))
    if sections.get("executive_summary"):
        h("Executive summary")
        table(["Metric", "Value"], [[k.replace("_", " "), json.dumps(v) if isinstance(v, dict) else v] for k, v in o.items()],
              [0.3, 0.7])
        if d["priorities"]:
            story.append(Spacer(1, 4))
            table(["Tier", "Score", "Asset", "Reasons"],
                  [[p["tier"], p["score"], p["asset"]["key"], "; ".join(f["reason"] for f in p["factors"] if f["points"] > 0)]
                   for p in d["priorities"][:10]], [0.05, 0.05, 0.25, 0.65])
    if sections.get("scope"):
        h("Scope and authorization")
        t = d["target"]
        table(["Item", "Value"], [["Targets", ", ".join(t["root_domains"] + t.get("ip_targets", []))],
                                  ["Include", ", ".join(t["scope"].get("include", []) or [])],
                                  ["Exclude", ", ".join(t["scope"].get("exclude", []) or [])],
                                  ["Active-check IP ranges", ", ".join(t["scope"].get("ip_allow", []) or [])],
                                  ["Authorization", t["authorization"].get("reference", "")]], [0.25, 0.75])
    if sections.get("methodology"):
        h("Methodology")
        table(["Module", "Status", "Tool", "Obs.", "Notes"],
              [[r["module"], r["status"], r["tool"], r["observations"], r["reason"] or ""] for r in d["module_runs"]],
              [0.18, 0.1, 0.12, 0.06, 0.54])
    if sections.get("domains"):
        h("Domains and subdomains")
        table(["Host", "Resolves", "IPs", "CNAME", "Sources", "First seen", "Conf."],
              [[x["key"], "yes" if x["resolved"] else "no", ", ".join(x["ips"]), ", ".join(x["cname"]),
                ", ".join(x["discovered_via"]), x["first_seen"], x["confidence"]] for x in d["hosts"]],
              [0.22, 0.06, 0.12, 0.2, 0.2, 0.14, 0.06])
    if sections.get("ip_asn"):
        h("IP and ASN")
        table(["IP", "ASN", "Organisation", "Provider", "CDN", "Hostnames"],
              [[i["key"], i["asn"], i["asn_name"], i["provider"], i["cdn"], ", ".join(i["hostnames"])] for i in d["ips"]])
    if sections.get("ports"):
        h("Open ports and services")
        table(["IP", "Port", "Service", "Product", "Version", "Banner"],
              [[x["ip"], x["port"], x["service"], x["product"], x["version"], (x["banner"] or "")[:80]] for x in d["services"]])
    if sections.get("http"):
        h("HTTP/HTTPS applications")
        table(["Application", "Status", "Title", "Server", "Technologies", "Missing headers"],
              [[a["key"], a["status"], a["title"], a["server"], ", ".join(f"{k} {v}".strip() for k, v in a["technologies"].items()),
                ", ".join(a["missing_headers"])] for a in d["web_apps"]], [0.2, 0.05, 0.17, 0.12, 0.26, 0.2])
    if sections.get("technologies"):
        h("Technology inventory")
        table(["Category", "Technologies"], [[g, ", ".join(f"{t['name']} {'/'.join(t['versions'])}".strip() for t in rows)]
                                             for g, rows in d["technologies"].items()], [0.2, 0.8])
    if sections.get("endpoints"):
        h("API and endpoint inventory")
        table(["Endpoint", "Kind", "Documented", "Observed", "Version", "Sources"],
              [[e["key"], e["kind"], ",".join(e["methods_documented"]), ",".join(e["methods_observed"]), e["api_version"],
                ", ".join(e["discovered_via"])] for e in d["endpoints"]], [0.4, 0.1, 0.12, 0.08, 0.08, 0.22])
    if sections.get("javascript"):
        h("JavaScript")
        table(["File", "Size", "API refs", "Third parties", "Secret-like patterns"],
              [[j["key"], j["size"], j["endpoints_found"], ", ".join(j["third_parties"] or []), j["secret_patterns"]] for j in d["js_files"]])
    if sections.get("tls"):
        h("TLS certificates")
        table(["Subject", "Issuer", "SANs", "Expires", "Days", "Trusted"],
              [[c["subject_cn"], c["issuer_cn"], ", ".join(c["sans"] or []), c["not_after"], c["days_remaining"], c["trusted"]]
               for c in d["certificates"]])
    if sections.get("cloud"):
        h("Cloud and third-party references")
        table(["Reference", "Provider", "Service", "Ownership"],
              [[c["attributes"].get("name"), c["attributes"].get("provider"), c["attributes"].get("service"),
                c["attributes"].get("ownership")] for c in d["cloud"]])
        table(["Third party", "Category", "Referenced by"],
              [[t["key"], t["attributes"].get("service") or t["attributes"].get("category"), ", ".join(t["referenced_by"])]
               for t in d["third_parties"]], [0.25, 0.2, 0.55])
    if sections.get("security"):
        story.append(PageBreak())
        h("Security configuration observations")
        table(["Severity", "Observation", "Subject", "Details", "Conf.", "Evidence"],
              [[f["attributes"].get("severity"), f["attributes"].get("title"), f["attributes"].get("subject"),
                f["attributes"].get("description"), f["confidence"], f["evidence"]] for f in d["findings"]],
              [0.06, 0.18, 0.2, 0.38, 0.05, 0.13])
    if sections.get("cve"):
        h("CVE intelligence (version correlation, unconfirmed)")
        table(["CVE", "Product", "Version", "Asset", "Evidence"],
              [[", ".join(f["attributes"].get("cves", [])), f["attributes"].get("product"), f["attributes"].get("version"),
                f["attributes"].get("subject"), f["evidence"]] for f in d["cve_findings"]])
    if sections.get("changes"):
        h("Historical changes")
        table(["Significance", "Category", "Change", "Previous", "Current"],
              [[c["significance"], c["category"], c["summary"], json.dumps(c["previous"], default=str)[:120],
                json.dumps(c["current"], default=str)[:120]] for c in d["changes"]], [0.08, 0.14, 0.38, 0.2, 0.2])
    if sections.get("graph"):
        h("Asset relationship graph")
        story.append(_p(f"{gstats['nodes']} nodes, {gstats['edges']} edges ({gstats['confirmed_edges']} confirmed, "
                        f"{gstats['inferred_edges']} inferred). Full graph: graph.graphml / graph.dot / report.html.", body))
        table(["Shared infrastructure", "Type", "Assets sharing it"],
              [[x["label"], x["type"], x["shared_by"]] for x in gstats["shared_infrastructure"]])
    if sections.get("priorities"):
        h("Asset prioritization")
        story.append(_p(d["priority_disclaimer"], body))
        table(["Tier", "Score", "Asset", "Factors"],
              [[p["tier"], p["score"], p["asset"]["key"], " | ".join(f"{f['points']:+} {f['reason']}" for f in p["factors"])]
               for p in d["priorities"][:40]], [0.05, 0.05, 0.25, 0.65])
    if sections.get("ai_analysis") and d.get("ai"):
        h(f"AI-assisted analysis ({d['ai']['provider']} / {d['ai']['model']})")
        rows = []
        for sec, items in (d["ai"]["result"] or {}).items():
            if isinstance(items, list):
                rows += [[sec, it.get("kind", "fact"), it.get("statement"), ", ".join(it.get("refs", []))] for it in items]
        table(["Section", "Kind", "Statement", "Evidence refs"], rows, [0.15, 0.08, 0.55, 0.22])
    if sections.get("coverage"):
        h("Coverage gaps")
        table(["Module", "Status", "Reason"], [[g["module"], g["status"], g["reason"]] for g in d["coverage_gaps"]], [0.15, 0.12, 0.73])
    cov = d.get("coverage") or {}
    if sections.get("coverage_quality") and cov:
        h("Coverage and quality")
        story.append(_p(cov.get("statement", ""), body))
        table(["Metric", "Value"], [[k.replace("_", " "), ", ".join(v) if isinstance(v, list) else v] for k, v in cov.get("metrics", {}).items()], [0.3, 0.7])
        table(["Phase", "Status", "Modules"], [[ph, p["status"], " ".join(f"{m}={st}" for m, st in p["modules"].items())]
                                               for ph, p in cov.get("phases", {}).items()], [0.15, 0.1, 0.75])
        table(["Source", "Kind", "Status", "Results", "Note"], [[n, s.get("kind"), s.get("status"), s.get("results", ""), s.get("error") or ""]
                                                                for n, s in cov.get("sources", {}).items()])
    if sections.get("source_comparison"):
        h("Discovery source comparison")
        table(["Source", "Hosts", "Unique", "Unique hosts"], [[c["source"], c["hosts"], c["unique"], ", ".join(c["unique_hosts"])]
                                                             for c in d["source_comparison"]], [0.15, 0.08, 0.08, 0.69])
    if sections.get("dns_infrastructure"):
        h("DNS and mail infrastructure")
        table(["Domain", "Nameservers", "DNSSEC", "CAA", "DMARC", "SPF lookups", "DKIM", "MTA-STS/TLS-RPT"],
              [[x["domain"], ", ".join(n["host"] for n in x["nameservers"]), x["dnssec"], ", ".join(x["caa"]), x["dmarc_policy"],
                x["spf_dns_lookups"], ", ".join(x["dkim_selectors_found"]), f"{x['mta_sts']}/{x['tls_rpt']}"] for x in d["dns_infrastructure"]])
    if sections.get("third_party_inventory"):
        h("Third-party dependency inventory")
        table(["Category", "Services"], [[c, ", ".join(t["domain"] for t in items)] for c, items in d["third_party_inventory"].items()], [0.2, 0.8])
    if sections.get("identity") and d["identity"]:
        h("Authentication and identity infrastructure (inventory only)")
        table(["Application", "Login", "Registration/reset", "Providers"],
              [[i["app"], ", ".join(i["login_pages"]), ", ".join(i["registration"] + i["password_reset"]), ", ".join(i["providers"])] for i in d["identity"]])
    if sections.get("secrets"):
        h("Potential secret exposure (redacted; never used or validated)")
        table(["Location", "Pattern", "Detail", "Evidence"], [[x["location"], x["pattern"], x["redacted"], x["evidence"]] for x in d["secret_exposures"]],
              [0.3, 0.15, 0.4, 0.15])
    if sections.get("limitations"):
        h("Assessment limitations")
        for l in d["limitations"]:
            story.append(_p("• " + l, body))
    if sections.get("evidence"):
        h("Evidence references")
        table(["Evidence", "Kind", "Module", "Summary", "SHA-256"],
              [[e["id"], e["kind"], e["module"], e["summary"], (e["sha256"] or "")[:16]] for e in d["evidence"].values()],
              [0.14, 0.1, 0.1, 0.52, 0.14])
    doc.build(story)
