"""Asset state snapshots and change detection between scans.

Coverage-aware: an asset missing from the current scan is only reported as removed
when at least one module that previously observed it completed successfully in this
scan and did not skip the asset's host (incremental mode). Otherwise its previous
state is carried forward, so failed or skipped modules never produce false removals.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import Asset, AssetState, Change, ModuleRun, Relation, Scan
from ..util import new_id, stable_hash, utcnow

STATE_FIELDS: dict[str, list[str]] = {
    "domain": ["dns_public", "wildcard_dns", "dmarc"],
    "subdomain": ["resolved", "ips", "dns"],
    "ip": ["asn", "provider", "cdn"],
    "service": ["service", "product", "version"],
    "web_app": ["status", "server", "technologies", "security_headers", "tls.fingerprint_sha256", "cdn", "waf", "redirect",
                "screenshot_phash"],
    "certificate": ["not_after", "issuer", "expiring_soon", "expired"],
    "endpoint": ["status", "methods_documented", "kind"],
    "js_file": ["sha256"],
    "finding": ["severity", "status"],
    "cloud_resource": [],
    "third_party": [],
    "technology": [],
    "asn": ["name"],
    "provider": [],
    "repository": [],
}

NEW_CATEGORY = {
    "domain": "new_domain", "subdomain": "new_subdomain", "ip": "new_ip_address", "service": "new_open_port",
    "web_app": "new_web_application", "endpoint": "new_endpoint", "js_file": "new_javascript_file",
    "technology": "new_technology", "certificate": "new_certificate", "cloud_resource": "new_cloud_reference",
    "third_party": "new_third_party_integration", "finding": "new_security_observation", "asn": "new_asn",
    "provider": "new_hosting_provider", "repository": "new_repository_reference",
}
SIGNIFICANCE = {
    "new_subdomain": "high", "new_open_port": "high", "new_web_application": "high", "removed_subdomain": "medium",
    "new_ip_address": "medium", "dns_changed": "medium", "new_api_endpoint": "medium", "tech_version_changed": "medium",
    "new_technology": "medium", "new_certificate": "medium", "certificate_changed": "medium",
    "certificate_expiring": "high", "security_headers_changed": "medium", "new_cloud_reference": "medium",
    "new_security_observation": "medium", "service_changed": "medium", "subdomain_unresolved": "medium",
    "subdomain_now_resolves": "high", "infrastructure_changed": "medium", "http_status_changed": "low",
    "new_endpoint": "low", "new_javascript_file": "low", "new_third_party_integration": "medium",
    "removed_web_application": "medium", "closed_port": "medium", "resolved_security_observation": "low",
    "removed_endpoint": "low", "new_asn": "medium", "new_hosting_provider": "medium", "new_repository_reference": "medium",
    "new_domain": "high", "changed": "low", "visual_change": "medium",
}
REMOVED_CATEGORY = {"subdomain": "removed_subdomain", "web_app": "removed_web_application", "service": "closed_port",
                    "endpoint": "removed_endpoint", "finding": "resolved_security_observation",
                    "third_party": "removed_third_party_reference", "cloud_resource": "removed_cloud_reference",
                    "js_file": "removed_javascript_file"}


def _get(d: dict, dotted: str):
    node = d
    for p in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(p)
    return node


def asset_state(asset: Asset, cert_expiry_days: int = 30) -> dict:
    attrs = dict(asset.attributes or {})
    if asset.type == "certificate":
        attrs["expiring_soon"] = (attrs.get("days_remaining") is not None and attrs["days_remaining"] <= cert_expiry_days)
    return {f: _get(attrs, f) for f in STATE_FIELDS.get(asset.type, [])}


def latest_previous_scan(s: Session, target_id: str, before_scan_id: str) -> Scan | None:
    cur = s.get(Scan, before_scan_id)
    return s.execute(
        select(Scan).where(Scan.target_id == target_id, Scan.id != before_scan_id,
                           Scan.status.in_(["completed", "partial"]), Scan.started_at <= cur.started_at)
        .order_by(Scan.started_at.desc()).limit(1)
    ).scalar_one_or_none()


PARENT_RELATIONS = {"has_observation", "references", "has_endpoint", "loads", "exposes", "presents", "uses", "serves",
                    "references_endpoint", "documents"}


def snapshot_and_diff(s: Session, scan: Scan, touched: dict[str, set[str]], config,
                      referenced: dict[str, set[str]] | None = None) -> list[Change]:
    """Write AssetState rows for `scan`, mark removals, and create Change rows vs the previous scan."""
    expiry_days = int(config.get("change_detection.cert_expiry_days", 30))
    s.flush()
    runs = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == scan.id)).scalars())
    completed = {r.module.split("#")[0] for r in runs if r.status == "completed"}
    skipped_any: set[str] = {k for r in runs for k in (r.skipped_inputs or [])}
    referenced = referenced or {}

    prev = s.get(Scan, scan.prev_scan_id) if scan.prev_scan_id else None
    prev_states: dict[str, AssetState] = {}
    if prev:
        prev_states = {st.asset_id: st for st in s.execute(select(AssetState).where(AssetState.scan_id == prev.id)).scalars()}

    changes: list[Change] = []
    now = utcnow()
    current_ids = set(touched) | set(referenced)
    assets = {a.id: a for a in s.execute(select(Asset).where(Asset.target_id == scan.target_id)).scalars()}
    parents: dict[str, set[str]] = {}
    for r in s.execute(select(Relation).where(Relation.target_id == scan.target_id, Relation.type.in_(PARENT_RELATIONS))).scalars():
        parents.setdefault(r.dst_id, set()).add(r.src_id)

    for aid in current_ids:
        a = assets.get(aid)
        if a is None:
            continue
        state = asset_state(a, expiry_days)
        s.add(AssetState(scan_id=scan.id, asset_id=aid, state_hash=stable_hash(state), state=state,
                         modules=sorted(touched.get(aid) or referenced.get(aid) or []), carried=False))
        if not prev or a.false_positive:
            continue
        before = prev_states.get(aid)
        if before is None:
            if a.first_scan_id == scan.id or a.id not in prev_states:
                changes.append(_new_change(scan, prev, a, state, now))
                if a.type == "certificate" and state.get("expiring_soon"):
                    changes.append(_mk(scan, prev, a, "certificate_expiring",
                                       f"Certificate {a.display} expires {a.attributes.get('not_after')}",
                                       None, {"not_after": a.attributes.get("not_after"),
                                              "days_remaining": a.attributes.get("days_remaining")}, now))
            continue
        if before.state_hash != stable_hash(state):
            changes.extend(_field_changes(scan, prev, a, before.state or {}, state, now))

    # Assets present before but not observed now: carry forward or mark removed.
    # Iterate so that children of a removed parent (findings, endpoints, ...) are resolved too.
    missing = [aid for aid in prev_states if aid not in current_ids and aid in assets]
    removed_ids: set[str] = set()
    for _ in range(4):
        grew = False
        for aid in missing:
            if aid in removed_ids:
                continue
            a, before = assets[aid], prev_states[aid]
            observers = set(before.modules or [])
            host = _host_key(a)
            # Covered only if (1) a module that observed it before completed now, (2) its host was not
            # skipped by any module (incremental), and (3) a parent it derives from was re-examined
            # (or was itself removed in this scan).
            covered = bool(observers & completed)
            if covered and (host in skipped_any or a.key in skipped_any or (not host and skipped_any)):
                covered = False
            pids = parents.get(aid, set())
            if covered and pids and not (pids & (set(touched) | removed_ids)):
                covered = False
            if covered:
                removed_ids.add(aid)
                grew = True
        if not grew:
            break
    for aid in missing:
        a, before = assets[aid], prev_states[aid]
        if aid not in removed_ids:
            s.add(AssetState(scan_id=scan.id, asset_id=aid, state_hash=before.state_hash, state=before.state,
                             modules=before.modules, carried=True))
            continue
        a.status = "removed"
        cat = REMOVED_CATEGORY.get(a.type)
        if cat and not a.false_positive:
            changes.append(_mk(scan, prev, a, cat, f"{a.type.replace('_', ' ')} no longer observed: {a.display}",
                               before.state or {"present": True}, None, now))
    for c in changes:
        s.add(c)
    return changes


def _host_key(a: Asset) -> str:
    attrs = a.attributes or {}
    if a.type in ("domain", "subdomain"):
        return a.key
    if a.type == "service":
        return attrs.get("ip", "")
    return attrs.get("host") or attrs.get("subject", "") or ""


def _mk(scan, prev, a: Asset, category: str, summary: str, previous, current, now) -> Change:
    return Change(id=new_id("chg"), target_id=scan.target_id, scan_id=scan.id, prev_scan_id=prev.id if prev else None,
                  asset_id=a.id, asset_type=a.type, asset_display=a.display, category=category,
                  significance=SIGNIFICANCE.get(category, "low"), summary=summary, previous=previous, current=current,
                  first_observed=a.first_seen if current is not None else now,
                  evidence_id=_latest_evidence(a), fingerprint=stable_hash([category, a.type, a.key, current]))


def _latest_evidence(a: Asset) -> str | None:
    return (a.attributes or {}).get("_last_evidence")


def _new_change(scan, prev, a: Asset, state: dict, now) -> Change:
    cat = NEW_CATEGORY.get(a.type, "changed")
    attrs = a.attributes or {}
    if a.type == "endpoint" and attrs.get("kind") in ("api", "graphql", "openapi", "websocket", "api_documentation"):
        cat = "new_api_endpoint"
    summary = f"New {a.type.replace('_', ' ')}: {a.display}"
    if a.type == "finding":
        summary = f"New security observation: {attrs.get('title')} ({attrs.get('severity')}) on {attrs.get('subject')}"
    elif a.type == "service":
        summary = f"New open port {attrs.get('port')}/tcp on {attrs.get('ip')} ({attrs.get('service')})"
    current = {k: v for k, v in state.items() if v not in (None, [], {})} or {"key": a.key}
    if a.type == "finding" and attrs.get("severity") in ("medium", "high", "critical"):
        ch = _mk(scan, prev, a, cat, summary, None, current, now)
        ch.significance = "high"
        return ch
    if a.type == "finding" and attrs.get("severity") in ("info", "low"):
        ch = _mk(scan, prev, a, cat, summary, None, current, now)
        ch.significance = "low"
        return ch
    return _mk(scan, prev, a, cat, summary, None, current, now)


def _field_changes(scan, prev, a: Asset, before: dict, after: dict, now) -> list[Change]:
    out = []
    for field in sorted(set(before) | set(after)):
        old, new = before.get(field), after.get(field)
        if old == new:
            continue
        cat, summary = "changed", f"{a.display}: {field} changed"
        if a.type == "subdomain":
            if field == "resolved":
                cat = "subdomain_now_resolves" if new else "subdomain_unresolved"
                summary = f"{a.display} {'now resolves' if new else 'no longer resolves'}"
            else:
                cat, summary = "dns_changed", f"DNS records changed for {a.display} ({field})"
        elif a.type == "domain":
            cat, summary = "dns_changed", f"Public DNS records changed for {a.display} ({field})"
        elif a.type == "web_app" and field == "technologies":
            old, new = old or {}, new or {}
            for name in sorted(set(new) - set(old)):
                out.append(_mk(scan, prev, a, "new_technology", f"{name} {new[name]} now identified on {a.display}",
                               None, {name: new[name]}, now))
            for name in sorted(set(old) & set(new)):
                if old[name] != new[name]:
                    out.append(_mk(scan, prev, a, "tech_version_changed",
                                   f"{name} version changed on {a.display}: {old[name] or '?'} → {new[name] or '?'}",
                                   {name: old[name]}, {name: new[name]}, now))
            for name in sorted(set(old) - set(new)):
                out.append(_mk(scan, prev, a, "changed", f"{name} no longer identified on {a.display}",
                               {name: old[name]}, None, now))
            continue
        elif a.type == "web_app" and field == "security_headers":
            old, new = old or {}, new or {}
            diff_old = {k: old.get(k) for k in set(old) | set(new) if old.get(k) != new.get(k)}
            diff_new = {k: new.get(k) for k in diff_old}
            added = [k for k in diff_new if diff_new[k] is not None and diff_old.get(k) is None]
            removed = [k for k in diff_new if diff_new[k] is None and diff_old.get(k) is not None]
            summary = f"Security headers changed on {a.display}" + (f"; added {', '.join(added)}" if added else "") + \
                      (f"; removed {', '.join(removed)}" if removed else "")
            out.append(_mk(scan, prev, a, "security_headers_changed", summary, diff_old, diff_new, now))
            continue
        elif a.type == "web_app" and field == "screenshot_phash":
            from ..modules.screenshots import hamming

            if not old or not new or hamming(old, new) <= 10:
                continue  # rendering noise, or first/last screenshot missing
            cat, summary = "visual_change", f"{a.display} looks visually different (screenshot distance {hamming(old, new)}/64)"
        elif a.type == "web_app" and field == "tls.fingerprint_sha256":
            cat, summary = "certificate_changed", f"{a.display} now presents a different TLS certificate"
        elif a.type == "web_app" and field == "status":
            cat, summary = "http_status_changed", f"HTTP status on {a.display}: {old} → {new}"
        elif a.type == "web_app" and field == "server":
            cat, summary = "tech_version_changed", f"Server banner on {a.display}: {old} → {new}"
        elif a.type == "service":
            cat, summary = "service_changed", f"Service on {a.display} changed ({field}: {old} → {new})"
        elif a.type == "certificate" and field == "expiring_soon" and new:
            cat, summary = "certificate_expiring", f"Certificate {a.display} expires {a.attributes.get('not_after')}"
        elif a.type == "ip":
            cat, summary = "infrastructure_changed", f"{a.display}: {field} {old} → {new}"
        elif a.type == "finding":
            cat = "security_observation_changed"
        out.append(_mk(scan, prev, a, cat, summary, {field: old}, {field: new}, now))
    return out
