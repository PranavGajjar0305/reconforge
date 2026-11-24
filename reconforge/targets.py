"""Target resolution: targets from the config file, or created from the dashboard (stored in the DB).

Config targets always win. Dashboard targets are stored in `targets.config` with
`source: dashboard`. Active modules still require `authorization.confirmed: true` and a
written authorization reference, whichever way the target was created.
"""
from __future__ import annotations

import re

from sqlalchemy import select

from .db import Database
from .db.models import Target
from .util import new_id, normalize_host, utcnow, valid_hostname

NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def resolve_target(cfg, db: Database, name: str) -> dict | None:
    t = cfg.target(name)
    if t:
        return t
    with db.session() as s:
        row = s.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
        if row and (row.config or {}).get("source") == "dashboard":
            return dict(row.config)
    return None


def list_targets(cfg, db: Database) -> list[dict]:
    out = {t["name"]: {**t, "source": "config"} for t in cfg.get("targets", []) or []}
    with db.session() as s:
        for row in s.execute(select(Target)).scalars():
            c = row.config or {}
            if row.name not in out and c.get("source") == "dashboard":
                out[row.name] = c
    return sorted(out.values(), key=lambda t: t["name"])


MAX_RANGE = 4096  # addresses per CIDR target (a /20 for IPv4)


def classify_entry(raw: str) -> tuple[str, str]:
    """('domain'|'ip'|'cidr', normalised value) for one target entry; raises ValueError if invalid.

    Accepts example.com, *.example.com, https://example.com/path, host:port, 203.0.113.7,
    [2001:db8::1], 203.0.113.0/24 and 2001:db8::/120.
    """
    import ipaddress

    v = raw.strip().strip(",;")
    if not v:
        raise ValueError("empty entry")
    if "/" in v and "://" not in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid CIDR range") from None
        if net.num_addresses > MAX_RANGE:
            raise ValueError(f"'{raw}' has {net.num_addresses} addresses; split it into ranges of at most {MAX_RANGE}")
        return ("ip", str(net.network_address)) if net.num_addresses == 1 else ("cidr", str(net))
    host = normalize_host(v)
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if valid_hostname(host) and "." in host:
        return "domain", host
    raise ValueError(f"'{raw}' is not a domain, IP address or CIDR range")


def split_targets(entries) -> tuple[list[str], list[str], list[str]]:
    """Split mixed entries into (domains, ip_targets, errors)."""
    if isinstance(entries, str):
        entries = re.split(r"[\s,;]+", entries)
    domains, ips, errors = set(), set(), []
    for e in entries or []:
        if not e or not str(e).strip():
            continue
        try:
            kind, val = classify_entry(str(e))
        except ValueError as exc:
            errors.append(str(exc))
            continue
        (domains if kind == "domain" else ips).add(val)
    # a host under another listed domain is already covered by that domain's *.domain scope
    domains = {d for d in domains if not any(d != o and d.endswith("." + o) for o in domains)}
    return sorted(domains), sorted(ips), errors


def validate_target(data: dict) -> dict:
    name = (data.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("name: letters, digits, dot, dash, underscore (max 64)")
    domains, ips, errors = split_targets(list(data.get("targets") or []) + list(data.get("root_domains") or [])
                                         + list(data.get("ip_targets") or []))
    if errors:
        raise ValueError("; ".join(errors[:5]))
    roots = domains
    confirmed = bool((data.get("authorization") or {}).get("confirmed"))
    if not roots and not ips:
        raise ValueError("targets: add at least one domain, IP address or CIDR range (e.g. example.com, 203.0.113.7, 203.0.113.0/28)")
    scope = data.get("scope") or {}
    include = [x.strip().lower() for x in scope.get("include") or [] if x.strip()] or [p for r in roots for p in (r, f"*.{r}")]
    import ipaddress

    for cidr in (scope.get("ip_allow") or []) + (scope.get("ip_exclude") or []):
        ipaddress.ip_network(cidr, strict=False)  # raises ValueError if invalid
    target = {
        "name": name, "root_domains": roots, "ip_targets": ips, "profile": data.get("profile") or "standard", "source": "dashboard",
        # the "I am authorized to test these targets" checkbox; active modules stay blocked without it
        "authorization": {"confirmed": confirmed, "reference": "self-attested in dashboard" if confirmed else "",
                          "contact": "", "confirmed_at": utcnow().isoformat() if confirmed else None},
        "scope": {"include": include, "exclude": [x.strip().lower() for x in scope.get("exclude") or [] if x.strip()],
                  "ip_allow": [x.strip() for x in scope.get("ip_allow") or [] if x.strip()],
                  "ip_exclude": [x.strip() for x in scope.get("ip_exclude") or [] if x.strip()]},
    }
    if data.get("ports"):
        target["ports"] = sorted({int(p) for p in data["ports"] if 0 < int(p) < 65536})
    if data.get("probe_ports"):
        target["probe_ports"] = {k: sorted({int(p) for p in v}) for k, v in data["probe_ports"].items() if k in ("http", "https")}
    return target


def save_target(cfg, db: Database, data: dict) -> dict:
    target = validate_target(data)
    if cfg.target(target["name"]):
        raise ValueError(f"'{target['name']}' is defined in the config file; edit it there")
    with db.session() as s:
        row = s.execute(select(Target).where(Target.name == target["name"])).scalar_one_or_none()
        if row is None:
            s.add(Target(id=new_id("tgt"), name=target["name"], config=target))
        else:
            row.config = target
    return target


def delete_target(cfg, db: Database, name: str) -> None:
    if cfg.target(name):
        raise ValueError("config-file targets cannot be deleted from the dashboard")
    with db.session() as s:
        row = s.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
        if row is None:
            raise KeyError(name)
        # keep scan history: only detach the dashboard definition
        row.config = {**(row.config or {}), "source": "deleted"}
