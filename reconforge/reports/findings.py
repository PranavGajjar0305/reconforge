"""Focused "findings" report — security observations and version/CVE correlations only.

Rendered on demand (HTML or PDF) from the dashboard's Security page, so the operator has a
single, shareable document of what needs review. Every item keeps its evidence id,
confidence and the standard caveats: these are observations, not confirmed vulnerabilities.
"""
from __future__ import annotations

import io
from html import escape

from ..util import iso, utcnow

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_HEX = {"critical": "#991b1b", "high": "#b91c1c", "medium": "#c2410c", "low": "#a16207", "info": "#0369a1"}
DISCLAIMER = ("These are configuration observations and intelligence correlations, not confirmed vulnerabilities. "
              "Version-based CVE matches are unconfirmed until verified against the running service. "
              "Only GET/HEAD requests were sent to in-scope hosts; shared infrastructure is not assumed to be owned "
              "by the target.")


def _sev_sort(items):
    return sorted(items, key=lambda f: (SEV_ORDER.get((f.get("attributes") or {}).get("severity"), 5),
                                        (f.get("attributes") or {}).get("title", "")))


def _counts(findings):
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        sev = (f.get("attributes") or {}).get("severity", "info")
        c[sev] = c.get(sev, 0) + 1
    return c


def findings_html(d: dict) -> str:
    sec = _sev_sort(d.get("findings", []))
    cve = _sev_sort(d.get("cve_findings", []))
    t, s = d["target"], d["scan"]
    counts = _counts(sec + cve)
    chips = "".join(
        f'<span class="chip" style="--c:{SEV_HEX[k]}">{counts.get(k, 0)} {k}</span>'
        for k in SEV_ORDER if counts.get(k))

    def rows(items, cve_mode=False):
        if not items:
            return '<tr><td colspan="6" class="empty">None recorded.</td></tr>'
        out = []
        for f in items:
            a = f.get("attributes") or {}
            sev = a.get("severity", "info")
            cves = ", ".join(a.get("cves", [])) if cve_mode else ""
            title = escape(a.get("title") or f.get("display", ""))
            if cve_mode:
                title = f'{escape(a.get("product",""))} {escape(a.get("version",""))}'
            out.append(
                f'<tr><td><span class="sev" style="--c:{SEV_HEX.get(sev,"#555")}">{sev}</span></td>'
                f'<td class="cat">{escape(a.get("category",""))}</td>'
                f'<td><div class="ttl">{title}</div>'
                f'<div class="desc">{escape(a.get("description",""))}</div>'
                + (f'<div class="rec"><b>Recommendation:</b> {escape(a.get("recommendation",""))}</div>' if a.get("recommendation") else "")
                + (f'<div class="cve">CVE: {escape(cves)}</div>' if cves else "")
                + f'</td>'
                f'<td class="mono">{escape(a.get("subject",""))}</td>'
                f'<td>{f.get("confidence","")}</td>'
                f'<td class="mono ev">{escape(f.get("evidence") or "")}</td></tr>')
        return "".join(out)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ReconForge findings — {escape(t['name'])}</title>
<style>
 :root {{ color-scheme: light; }}
 * {{ box-sizing: border-box; }}
 body {{ font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; background: #f1f5f9; }}
 .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }}
 header {{ border-bottom: 3px solid #0f172a; padding-bottom: 14px; margin-bottom: 20px; }}
 h1 {{ font-size: 22px; margin: 0 0 4px; letter-spacing: .3px; }}
 .meta {{ color: #475569; font-size: 12.5px; }}
 .mono {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11.5px; }}
 .chips {{ margin: 14px 0; display: flex; flex-wrap: wrap; gap: 6px; }}
 .chip {{ font-size: 12px; font-weight: 600; color: #fff; background: var(--c); border-radius: 4px; padding: 2px 9px; }}
 .note {{ background: #fff7ed; border: 1px solid #fed7aa; color: #7c2d12; font-size: 12.5px; padding: 10px 12px; border-radius: 6px; margin: 10px 0 22px; }}
 h2 {{ font-size: 15px; margin: 26px 0 8px; padding-bottom: 5px; border-bottom: 1px solid #cbd5e1; }}
 table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.05); border-radius: 6px; overflow: hidden; }}
 th {{ text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; color: #475569; background: #f8fafc; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }}
 td {{ padding: 9px 10px; border-bottom: 1px solid #eef2f7; vertical-align: top; font-size: 12.5px; }}
 tr:last-child td {{ border-bottom: 0; }}
 .sev {{ display: inline-block; min-width: 54px; text-align: center; font-size: 11px; font-weight: 700; color: #fff; background: var(--c); border-radius: 3px; padding: 1px 6px; }}
 .cat {{ color: #64748b; font-size: 11.5px; }}
 .ttl {{ font-weight: 600; }}
 .desc {{ color: #475569; margin-top: 2px; }}
 .rec {{ color: #166534; margin-top: 3px; font-size: 11.5px; }}
 .cve {{ color: #9a3412; margin-top: 3px; font-size: 11.5px; }}
 .ev {{ color: #94a3b8; }}
 .empty {{ color: #94a3b8; text-align: center; padding: 16px; }}
 footer {{ margin-top: 30px; color: #94a3b8; font-size: 11px; }}
 @media print {{ body {{ background: #fff; }} .wrap {{ max-width: none; padding: 0; }} table {{ box-shadow: none; }} }}
</style></head><body><div class="wrap">
 <header>
  <h1>Attack surface findings — {escape(t['name'])}</h1>
  <div class="meta">Targets: <span class="mono">{escape(", ".join(t.get('root_domains', []) + t.get('ip_targets', [])))}</span> ·
   scan <span class="mono">{escape(s['id'])}</span> · {escape(str(s.get('profile','')))} profile ·
   {escape(str(s.get('started_at','')))} · generated {iso(utcnow())}</div>
  <div class="chips">{chips or '<span class="chip" style="--c:#0369a1">0 findings</span>'}</div>
 </header>
 <div class="note">{DISCLAIMER}</div>
 <h2>Security observations ({len(sec)})</h2>
 <table><thead><tr><th>Severity</th><th>Category</th><th>Observation</th><th>Subject</th><th>Conf.</th><th>Evidence</th></tr></thead>
  <tbody>{rows(sec)}</tbody></table>
 <h2>Version / CVE correlations ({len(cve)})</h2>
 <table><thead><tr><th>Severity</th><th>Category</th><th>Product &amp; CVEs</th><th>Subject</th><th>Conf.</th><th>Evidence</th></tr></thead>
  <tbody>{rows(cve, cve_mode=True)}</tbody></table>
 <footer>ReconForge · authorized assessment of {escape(t['name'])} · evidence ids reference the scan's evidence store.</footer>
</div></body></html>"""


def findings_pdf(d: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=8.5, leading=11)
    cell = ParagraphStyle("c", parent=body, fontSize=7.4, leading=9.2)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#0f172a"), fontSize=12)
    t, s = d["target"], d["scan"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm,
                            bottomMargin=12 * mm, title=f"ReconForge findings — {t['name']}")
    width = doc.width
    story = [Paragraph(f"Attack surface findings — {escape(t['name'])}", styles["Title"]),
             Paragraph(f"Targets: {escape(', '.join(t.get('root_domains', []) + t.get('ip_targets', [])))} · scan {escape(s['id'])} · "
                       f"{escape(str(s.get('profile','')))} profile · generated {iso(utcnow())}", body),
             Paragraph(DISCLAIMER, body), Spacer(1, 8)]

    def section(title, items, cve_mode=False):
        story.append(Paragraph(f"{title} ({len(items)})", h2))
        header = ["Sev", "Category", "Product & CVEs" if cve_mode else "Observation", "Subject", "Conf.", "Evidence"]
        rows = []
        for f in _sev_sort(items):
            a = f.get("attributes") or {}
            if cve_mode:
                what = f"{a.get('product','')} {a.get('version','')}\nCVE: {', '.join(a.get('cves', []))}"
            else:
                what = f"{a.get('title','')}\n{a.get('description','')}"
                if a.get("recommendation"):
                    what += f"\nRecommendation: {a['recommendation']}"
            rows.append([a.get("severity", "info"), a.get("category", ""), what, a.get("subject", ""),
                         f.get("confidence", ""), f.get("evidence", "")])
        if not rows:
            story.append(Paragraph("None recorded.", body))
        else:
            widths = (0.08, 0.1, 0.46, 0.18, 0.06, 0.12)
            caps = [max(80, int(width * w / (cell.fontSize * 0.55)) * 40) for w in widths]  # keep every cell within a page
            clip = lambda t, cap: t if len(t) <= cap else t[:cap] + f" … (+{len(t) - cap} chars)"
            data = [[Paragraph(escape(clip(str(c), caps[i])).replace("\n", "<br/>"), cell) for i, c in enumerate(r)] for r in rows]
            data.insert(0, [Paragraph(h, cell) for h in header])
            tbl = Table(data, colWidths=[width * w for w in widths], repeatRows=1)
            style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                     ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                     ("VALIGN", (0, 0), (-1, -1), "TOP")]
            for i, f in enumerate(_sev_sort(items), start=1):
                sev = (f.get("attributes") or {}).get("severity", "info")
                style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEV_HEX.get(sev, "#555"))))
            tbl.setStyle(TableStyle(style))
            story.append(tbl)
        story.append(Spacer(1, 10))

    section("Security observations", d.get("findings", []))
    section("Version / CVE correlations", d.get("cve_findings", []), cve_mode=True)
    doc.build(story)
    return buf.getvalue()
