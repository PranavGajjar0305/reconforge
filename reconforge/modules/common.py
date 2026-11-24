"""Helpers shared by built-in modules."""
from __future__ import annotations

from ..core.observation import Obs, Rel
from ..util import normalize_host, valid_hostname

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def host_obs(ctx, host: str, source: str, evidence_id: str | None, extra: dict | None = None) -> Obs | None:
    h = normalize_host(host)
    if not valid_hostname(h) or not ctx.scope.host_in_scope(h):
        return None
    root = ctx.scope.root_for(h)
    rels = [Rel("has_subdomain", "domain", root, confirmed=True, reverse=True)] if root and root != h else []
    return Obs("subdomain", h, {"+discovered_via": [source], **(extra or {})}, source=source,
               evidence_id=evidence_id, relations=rels)


def finding(ctx, rule: str, subject: str, title: str, severity: str, description: str, evidence_id: str | None,
             recommendation: str, category: str, subject_type: str = "domain", extra: dict | None = None) -> None:
    from ..util import host_of

    if subject.startswith(("http://", "https://", "ws://", "wss://")):
        host = host_of(subject)
    elif subject_type == "service":
        host = subject.split(":")[0]
    else:
        host = normalize_host(subject.split("|")[0])
    attrs = {"host": host, "rule": rule, "title": title, "severity": severity, "description": description,
             "recommendation": recommendation, "category": category, "subject": subject, "status": "open",
             "manual_review": True, **(extra or {})}
    ctx.emit(Obs("finding", f"{rule}|{subject}", attrs, display=f"{title} — {subject}", evidence_id=evidence_id,
                 relations=[Rel("has_observation", subject_type, subject, reverse=True)]))


