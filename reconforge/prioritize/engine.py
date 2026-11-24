"""Asset prioritization: where is manual review most likely to be worthwhile?

The score expresses *attention priority*, not vulnerability severity. An internet-facing
asset is not vulnerable just because it is exposed; exposure only raises the value of
looking at it. Every point is accompanied by a human-readable reason and the evidence
that produced it.
"""
from __future__ import annotations

import re
from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..db.models import Asset, AssetScore, Change, Relation, Target

ENV_LABELS = re.compile(r"(?:^|[.\-])(dev|develop|development|stage|staging|stg|test|testing|qa|uat|beta|sandbox|demo|"
                        r"preprod|pre-prod|old|legacy|backup|bak|internal|intranet|admin|jenkins|gitlab|git|ci|jira|"
                        r"vpn|debug|tmp|temp)(?:[.\-\d]|$)")
SENSITIVE_UI = re.compile(r"\b(log ?in|sign ?in|admin|dashboard|console|portal|manage|phpmyadmin|grafana|kibana|jenkins)\b", re.I)
SEV_POINTS = {"critical": 12, "high": 10, "medium": 6, "low": 2, "info": 0.5}
DISCLAIMER = ("Priority reflects where manual review is likely to be most valuable. It is not a vulnerability "
              "severity rating: exposure alone does not imply a weakness.")


def tier(score: float) -> str:
    return "P1" if score >= 60 else "P2" if score >= 35 else "P3" if score >= 15 else "P4"


def prioritize(s: Session, target_id: str, scan_id: str) -> list[AssetScore]:
    s.flush()
    assets = {a.id: a for a in s.execute(select(Asset).where(Asset.target_id == target_id, Asset.status == "active",
                                                             Asset.false_positive.is_(False))).scalars()}
    rels = list(s.execute(select(Relation).where(Relation.target_id == target_id)).scalars())
    changes = list(s.execute(select(Change).where(Change.scan_id == scan_id)).scalars())
    changed_ids = defaultdict(list)
    for c in changes:
        changed_ids[c.asset_id].append(c.category)
    out_edges = defaultdict(list)
    in_edges = defaultdict(list)
    for r in rels:
        out_edges[r.src_id].append(r)
        in_edges[r.dst_id].append(r)

    def findings_for(asset_ids: set[str]) -> list[Asset]:
        res = []
        for aid in asset_ids:
            for r in out_edges.get(aid, []):
                f = assets.get(r.dst_id)
                if f and f.type == "finding" and r.type == "has_observation":
                    res.append(f)
        return res

    target = s.get(Target, target_id)
    roots = sorted((target.config or {}).get("root_domains", []), key=len, reverse=True) if target else []

    def sub_labels(h: str) -> str:
        """Hostname labels left of the root domain (so the TLD/root never counts as an indicator)."""
        for r in roots:
            if h == r:
                return ""
            if h.endswith("." + r):
                return h[: -len(r) - 1]
        return h.rsplit(".", 2)[0] if h.count(".") >= 2 else ""

    s.execute(delete(AssetScore).where(AssetScore.scan_id == scan_id))
    scores = []
    for a in assets.values():
        if a.type not in ("web_app", "service", "subdomain", "domain") or a.scope != "in_scope":
            continue
        attrs = a.attributes or {}
        factors: list[dict] = []

        def add(points: float, factor: str, reason: str):
            factors.append({"factor": factor, "points": round(points, 1), "reason": reason})

        host = attrs.get("host") or (a.key if a.type in ("subdomain", "domain") else None)
        related = {a.id}
        if a.type in ("subdomain", "domain"):
            if not attrs.get("resolved"):
                continue
            apps = [assets.get(r.dst_id) for r in out_edges.get(a.id, []) if r.type == "serves"]
            if any(x for x in apps):
                continue  # scored via its web apps
            add(5, "internet_accessibility", "Hostname resolves publicly, but no HTTP service was observed.")
        elif a.type == "web_app":
            status = attrs.get("status")
            add(15, "internet_accessibility", f"Responds to HTTP(S) requests (status {status}).")
            if attrs.get("cdn") or attrs.get("waf"):
                add(-5, "mediated_exposure", f"Fronted by {attrs.get('cdn') or attrs.get('waf')}; exposure partly mediated.")
            if attrs.get("is_api"):
                add(10, "application_type", f"API surface detected ({', '.join(attrs.get('api_signals', []))}).")
            if "openapi" in (attrs.get("api_signals") or []):
                add(6, "application_type", "Machine-readable API documentation is publicly reachable.")
            title = attrs.get("title") or ""
            if SENSITIVE_UI.search(title):
                add(10, "application_type", f"Page title suggests an authentication or administrative interface: '{title[:60]}'.")
            if status and 300 <= int(status) < 400:
                add(-8, "application_type", "Only redirects elsewhere.")
            for r in in_edges.get(a.id, []):
                if r.type in ("serves",):
                    related.add(r.src_id)
        elif a.type == "service":
            svc = attrs.get("service") or "unknown"
            if svc in ("http", "https", "http-alt", "https-alt"):
                continue  # covered by web_app
            add(15, "exposed_service", f"Non-web service '{svc}' reachable on {attrs.get('ip')}:{attrs.get('port')}.")
            names = attrs.get("hosts") or []
            host = names[0] if len(names) == 1 else None  # shared IPs: don't attribute one name's label
        labels = sub_labels(host) if host else ""
        if labels and ENV_LABELS.search(labels):
            label = ENV_LABELS.search(labels).group(1)
            add(18, "environment_indicator", f"Hostname label '{label}' suggests a non-production or administrative system.")
        fnds = findings_for(related)
        cve_like = [f for f in fnds if (f.attributes or {}).get("category") in ("cve", "version", "nuclei")]
        other = [f for f in fnds if f not in cve_like]
        if cve_like:
            ids = sorted({c for f in cve_like for c in (f.attributes or {}).get("cves", [])} |
                         {(f.attributes or {}).get("title") for f in cve_like if (f.attributes or {}).get("category") == "version"})
            add(min(20, 6 * len(cve_like)), "public_advisories",
                f"{len(cve_like)} public advisory/EOL match(es) for advertised versions: {', '.join(i for i in ids if i)[:160]} "
                "(version-string correlation only).")
        if other:
            pts = min(20, sum(SEV_POINTS.get((f.attributes or {}).get("severity", "info"), 0.5) for f in other))
            sevs = defaultdict(int)
            for f in other:
                sevs[(f.attributes or {}).get("severity", "info")] += 1
            add(pts, "security_observations",
                "Security configuration observations: " + ", ".join(f"{n} {k}" for k, n in sorted(sevs.items())))
        if a.type == "web_app":
            ip = attrs.get("ip")
            for sa in assets.values():
                sat = sa.attributes or {}
                if sa.type == "service" and sat.get("ip") == ip and sat.get("service") not in ("http", "https", "http-alt", "https-alt", "unknown"):
                    if host in (sat.get("hosts") or []):
                        add(5, "exposed_service", f"Same host also exposes {sat.get('service')} on port {sat.get('port')}.")
        cats = changed_ids.get(a.id, [])
        if cats:
            if any(c.startswith("new_") for c in cats):
                add(10, "historical_change", "Newly observed in this scan.")
            else:
                add(5, "historical_change", f"Changed in this scan ({', '.join(sorted(set(cats)))}).")
        raw = sum(f["points"] for f in factors)
        conf = a.confidence or 0.5
        score = max(0.0, min(100.0, raw * (0.6 + 0.4 * conf)))
        factors.append({"factor": "evidence_confidence", "points": 0,
                        "reason": f"Score weighted by evidence confidence {conf:.2f} (×{0.6 + 0.4 * conf:.2f})."})
        sc = AssetScore(scan_id=scan_id, asset_id=a.id, score=round(score, 1), tier=tier(score), factors=factors)
        s.add(sc)
        scores.append(sc)
    return scores
