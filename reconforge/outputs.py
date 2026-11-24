"""Per-scan output files with a predictable naming convention.

For every execution ReconForge writes plain-text / TSV files into
``<storage.output_dir>/<scan name>/<YYYY-MM-DD_HHMM>_<scan id>/``::

    00_INDEX.txt                          what every file contains, with line counts
    all/subdomains.txt                    every in-scope hostname (one per line)
    all/live_urls.txt, all/open_ports.txt, all/urls.txt, all/js_files.txt, ...
    findings/findings.tsv                 severity, title, subject, rule, evidence id
    findings/high.txt, findings/medium.txt, ...
    urls/gf/<class>.txt                   gf-style candidate lists (xss, sqli, ssrf, redirect, ...)
    modules/<module>/<module>_<type>.txt  what each module/tool found in this execution,
                                          e.g. modules/subfinder/subfinder_subdomains.txt
    raw/<module>/<nn>_<what>.<ext>        raw stdout of every external tool (nuclei, nmap, ffuf, ...)
    screenshots/<host>_<port>.png         every screenshot taken
    logs/execution.log                    the full execution log

The directory lives inside the git-ignored data directory. Nothing here contacts a target.
"""
from __future__ import annotations

import os
import re
import shutil
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select

from .db.models import Asset, Evidence, Observation, Scan, Target

PLURAL = {"subdomain": "subdomains", "domain": "domains", "ip": "ips", "service": "open_ports", "web_app": "web_apps",
          "endpoint": "urls", "js_file": "js_files", "technology": "technologies", "certificate": "certificates",
          "third_party": "third_parties", "finding": "findings", "asn": "asns", "cloud_resource": "cloud_resources",
          "provider": "providers", "repository": "repositories"}
SEVS = ["critical", "high", "medium", "low", "info"]
SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def slug(s: str, n: int = 60) -> str:
    return SAFE.sub("_", str(s)).strip("_")[:n] or "item"


def scan_output_dir(cfg, s, scan: Scan) -> Path:
    target = s.get(Target, scan.target_id)
    stamp = scan.started_at.strftime("%Y-%m-%d_%H%M") if scan.started_at else "scan"
    return cfg.dir("output_dir") / slug(target.name if target else "target") / f"{stamp}_{scan.id}"


def _line(a: Asset) -> str:
    at = a.attributes or {}
    if a.type == "service":
        return "\t".join(str(x) for x in (a.key, at.get("service") or "", at.get("product") or "", at.get("version") or ""))
    if a.type == "web_app":
        return "\t".join(str(x) for x in (a.key, at.get("status") or "", (at.get("title") or "").replace("\t", " "),
                                          at.get("server") or ""))
    if a.type == "finding":
        return "\t".join(str(x) for x in (at.get("severity") or "info", at.get("title") or "", at.get("subject") or a.key,
                                          at.get("rule") or "", at.get("_last_evidence") or ""))
    if a.type == "endpoint" and at.get("status"):
        return f"{at.get('status')}\t{a.key}"
    return a.display or a.key


def write_scan_outputs(cfg, db, scan_id: str) -> Path:
    from .modules.osint_intel import classify_url

    with db.session() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise KeyError(scan_id)
        out = scan_output_dir(cfg, s, scan)
        tmp = out.with_name(out.name + ".tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        index: list[tuple[str, int, str]] = []

        def write(rel: str, lines, desc: str):
            lines = [l for l in lines if l is not None and str(l) != ""]
            if not lines:
                return
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("\n".join(map(str, lines)) + "\n")
            index.append((rel, len(lines), desc))

        assets = list(s.execute(select(Asset).where(Asset.target_id == scan.target_id, Asset.status == "active",
                                                   Asset.false_positive.is_(False))).scalars())
        by = defaultdict(list)
        for a in assets:
            by[a.type].append(a)
        hosts = sorted([a for a in by["domain"] + by["subdomain"] if a.scope == "in_scope"], key=lambda a: a.key)
        # ------------------------------------------------------------- all/
        write("all/subdomains.txt", [a.key for a in hosts], "every in-scope hostname")
        write("all/subdomains_resolved.txt", [a.key for a in hosts if (a.attributes or {}).get("resolved")], "hostnames that resolve")
        write("all/subdomains_unresolved.txt", [a.key for a in hosts if not (a.attributes or {}).get("resolved")],
              "hostnames that do not resolve (takeover / history candidates)")
        write("all/ips.txt", sorted(a.key for a in by["ip"] if a.scope == "in_scope"), "in-scope IP addresses")
        write("all/ip_targets.txt", sorted(a.key for a in by["ip"] if (a.attributes or {}).get("target")), "IP addresses named as targets")
        write("all/open_ports.txt", sorted(_line(a) for a in by["service"]), "ip:port/proto  service  product  version")
        live = sorted(by["web_app"], key=lambda a: a.key)
        write("all/live_urls.txt", [a.key for a in live], "every web application origin")
        write("all/web_apps.tsv", ["url\tstatus\ttitle\tserver"] + [_line(a) for a in live], "web apps with status, title, server")
        eps = sorted(by["endpoint"], key=lambda a: a.key)
        write("all/urls.txt", [a.key for a in eps], "every URL/endpoint collected (crawl, archives, JS, docs, discovery)")
        write("all/api_endpoints.txt", [a.key for a in eps if (a.attributes or {}).get("kind") in ("api", "graphql", "openapi",
                                                                                                    "websocket", "api_documentation")],
              "API routes, GraphQL, WebSocket and API documentation")
        write("all/content_discovery.txt", [_line(a) for a in eps if "content_discovery" in ((a.attributes or {}).get("discovered_via") or [])],
              "status  URL found by directory/file discovery")
        write("all/parameters.txt", sorted({k for a in eps for k in re.findall(r"[?&]([^=&#]+)=", a.key)}), "unique query parameter names")
        write("all/js_files.txt", sorted(a.key for a in by["js_file"]), "JavaScript files")
        write("all/technologies.txt", sorted(f"{a.display}\t{', '.join((a.attributes or {}).get('versions_seen') or [])}"
                                             for a in by["technology"]), "technology  versions seen")
        write("all/certificates.tsv", ["sha256\tsubject\tissuer\tnot_after\tsans"] + sorted(
            "\t".join(str(x) for x in (a.key, (a.attributes or {}).get("subject_cn") or (a.attributes or {}).get("subject") or "",
                                       (a.attributes or {}).get("issuer") or "", (a.attributes or {}).get("not_after") or "",
                                       ",".join((a.attributes or {}).get("sans") or [])[:2000])) for a in by["certificate"]),
              "TLS certificates")
        write("all/third_parties.txt", sorted(f"{a.key}\t{(a.attributes or {}).get('category') or ''}\t{(a.attributes or {}).get('service') or ''}"
                                              for a in by["third_party"]), "third-party host  category  service")
        write("all/cloud_resources.txt", sorted(a.display or a.key for a in by["cloud_resource"]), "cloud resource references")
        doms = [a for a in by["domain"]]
        write("all/emails.txt", sorted({e for d in doms for e in ((d.attributes or {}).get("contacts") or {}).get("emails", [])}),
              "e-mail addresses published by the target")
        write("all/lookalike_domains.txt", sorted({x for d in doms for x in ((d.attributes or {}).get("lookalikes") or {}).get("domains", [])}),
              "registered look-alike domains")
        write("all/dorks.txt", [f"{x['engine']}\t{x['title']}\t{x['url']}" for d in doms for x in (d.attributes or {}).get("dorks") or []],
              "OSINT pivot links")
        write("all/asn_prefixes.txt", sorted({f"{p}\t{a.key}" for a in by["asn"] for p in (a.attributes or {}).get("announced_prefixes") or []}),
              "prefixes announced by organisation ASNs (candidate ranges)")
        # ------------------------------------------------------------- findings/
        fnd = sorted(by["finding"], key=lambda a: (SEVS.index((a.attributes or {}).get("severity") or "info")
                                                   if (a.attributes or {}).get("severity") in SEVS else 5, a.key))
        write("findings/findings.tsv", ["severity\ttitle\tsubject\trule\tevidence"] + [_line(a) for a in fnd],
              "every security observation (unconfirmed until verified)")
        for sev in SEVS:
            write(f"findings/{sev}.txt", [f"{(a.attributes or {}).get('title')}\t{(a.attributes or {}).get('subject') or a.key}"
                                          for a in fnd if (a.attributes or {}).get("severity") == sev], f"{sev} observations")
        # ------------------------------------------------------------- urls/gf/
        buckets = defaultdict(list)
        for a in eps:
            classes, _ = classify_url(a.key)
            for c in classes - {"secrets_in_url"}:
                buckets[c].append(a.key)
        for c, urls in sorted(buckets.items()):
            write(f"urls/gf/{c}.txt", sorted(set(urls)), f"gf-style {c} candidates")
        # ------------------------------------------------------------- modules/
        rows = s.execute(select(Observation.module, Observation.source, Asset).join(Asset, Asset.id == Observation.asset_id)
                         .where(Observation.scan_id == scan_id)).all()
        per = defaultdict(lambda: defaultdict(dict))
        for module, source, a in rows:
            name = module.split("#")[0] or "unknown"
            if name == "seed":
                continue
            per[name][a.type][a.key] = _line(a)
            if source and source not in (name, "seed") and name in ("passive_sources", "external_subdomains", "external_urls"):
                per[f"{name}/{slug(source)}"][a.type][a.key] = _line(a)  # e.g. passive_sources/otx
        for name, types in sorted(per.items()):
            base = name.split("/")[-1]
            for t, keys in sorted(types.items()):
                write(f"modules/{name}/{base}_{PLURAL.get(t, t + 's')}.txt", sorted(keys.values()),
                      f"{PLURAL.get(t, t)} recorded by {name} in this execution")
        # ------------------------------------------------------------- raw/ and screenshots/
        evs = list(s.execute(select(Evidence).where(Evidence.scan_id == scan_id, Evidence.kind.in_(["tool_output", "screenshot"]))
                             .order_by(Evidence.created_at)).scalars())
        counters = defaultdict(int)
        app_by_ev = {(a.attributes or {}).get("screenshot_evidence"): a for a in by["web_app"] if (a.attributes or {}).get("screenshot_evidence")}
        for e in evs:
            src = Path(e.path) if e.path else None
            if e.kind == "screenshot":
                app = app_by_ev.get(e.id)
                name = slug((app.key if app else e.summary).split("://", 1)[-1].replace(":", "_"), 90) + ".png"
                if src and src.exists():
                    dst = tmp / "screenshots" / name
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    _link_or_copy(src, dst)
                    index.append((f"screenshots/{name}", 1, f"screenshot of {app.key if app else e.summary}"))
                continue
            counters[e.module] += 1
            ext = src.suffix if src else ".txt"
            rel = f"raw/{slug(e.module)}/{counters[e.module]:02d}_{slug(e.summary, 50)}{ext}"
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src and src.exists():
                _link_or_copy(src, dst)
            elif e.content:
                dst.write_text(e.content)
            else:
                continue
            index.append((rel, sum(1 for _ in open(dst, errors="replace")), f"raw output: {e.summary}"))
        if scan.log_path and Path(scan.log_path).exists():
            (tmp / "logs").mkdir(exist_ok=True)
            shutil.copyfile(scan.log_path, tmp / "logs" / "execution.log")
            index.append(("logs/execution.log", sum(1 for _ in open(tmp / "logs" / "execution.log", errors="replace")),
                          "full execution log"))
        target = s.get(Target, scan.target_id)
        head = [f"ReconForge output files — {target.name if target else ''} — execution {scan.id}",
                f"profile: {scan.profile}   status: {scan.status}   started: {scan.started_at}", "",
                "Observations are unconfirmed until manually verified. Keep this folder private.", "",
                f"{'file':<64} {'lines':>7}  description", "-" * 110]
        (tmp / "00_INDEX.txt").write_text("\n".join(head + [f"{p:<64} {n:>7}  {d}" for p, n, d in sorted(index)]) + "\n")
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    return out


def _link_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


def list_files(root: Path) -> list[dict]:
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            out.append({"path": rel, "group": rel.split("/")[0] if "/" in rel else "", "size": p.stat().st_size,
                        "kind": "image" if p.suffix == ".png" else "text"})
    return out


def safe_file(root: Path, rel: str) -> Path:
    """Resolve `rel` inside `root`; refuses anything that escapes it."""
    p = (root / rel).resolve()
    if root.resolve() not in p.parents or not p.is_file():
        raise FileNotFoundError(rel)
    return p
