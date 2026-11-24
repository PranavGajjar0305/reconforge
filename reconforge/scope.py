"""Scope and authorization enforcement.

Every active module asks the Scope object before touching a host or IP. A host is
in scope only when it matches an include pattern and no exclude pattern. An IP may
only be contacted when it falls inside an allowed CIDR (when configured) and is not
excluded. Names that are referenced by in-scope assets but are not themselves in
scope are classified as third-party and are never actively probed.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field

from .util import is_ip, normalize_host

MAX_SEED_IPS = 4096


class ScopeError(RuntimeError):
    pass


@dataclass
class Scope:
    root_domains: list[str]
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ip_allow: list[str] = field(default_factory=list)
    ip_exclude: list[str] = field(default_factory=list)
    authorized: bool = False
    authorization_reference: str = ""
    ip_targets: list[str] = field(default_factory=list)  # IPs / CIDRs named as scan targets

    @classmethod
    def from_target(cls, target: dict) -> "Scope":
        roots = [normalize_host(d) for d in target.get("root_domains", [])]
        sc = target.get("scope", {}) or {}
        include = sc.get("include") or [p for d in roots for p in (d, f"*.{d}")]
        auth = target.get("authorization", {}) or {}
        return cls(
            root_domains=roots,
            include=[i.lower() for i in include],
            exclude=[e.lower() for e in sc.get("exclude", [])],
            ip_allow=list(sc.get("ip_allow", [])),
            ip_exclude=list(sc.get("ip_exclude", [])),
            authorized=bool(auth.get("confirmed", False)),
            authorization_reference=str(auth.get("reference", "")),
            ip_targets=[str(x).strip() for x in target.get("ip_targets", []) or [] if str(x).strip()],
        )

    @property
    def has_targets(self) -> bool:
        return bool(self.root_domains or self.ip_targets)

    def _ip_excluded(self, addr) -> bool:
        return any(addr in ipaddress.ip_network(net, strict=False) for net in self.ip_exclude)

    def ip_is_target(self, ip: str) -> bool:
        """True when the address was named as a scan target (directly or inside a target range)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self._ip_excluded(addr):
            return False
        return any(addr in ipaddress.ip_network(net, strict=False) for net in self.ip_targets)

    def seed_ips(self) -> list[str]:
        """Every address named by ip_targets (ranges expanded), capped at MAX_SEED_IPS."""
        out: list[str] = []
        for t in self.ip_targets:
            net = ipaddress.ip_network(t, strict=False)
            hosts = [net.network_address] if net.num_addresses == 1 else (net.hosts() if net.num_addresses > 2 else net)
            for a in hosts:
                if len(out) >= MAX_SEED_IPS:
                    return out
                if not self._ip_excluded(a):
                    out.append(str(a))
        return sorted(set(out), key=lambda x: ipaddress.ip_address(x))

    # -- hostnames -------------------------------------------------------
    def host_in_scope(self, host: str) -> bool:
        h = normalize_host(host)
        if not h:
            return False
        if is_ip(h):  # an IP is in scope only when it was named as a target
            return self.ip_is_target(h)
        if any(fnmatch.fnmatch(h, pat) for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(h, pat) for pat in self.include)

    def classify_host(self, host: str) -> str:
        """Return in_scope / out_of_scope / third_party."""
        h = normalize_host(host)
        if self.host_in_scope(h):
            return "in_scope"
        if any(h == r or h.endswith("." + r) for r in self.root_domains):
            return "out_of_scope"  # belongs to target namespace but excluded
        return "third_party"

    def root_for(self, host: str) -> str | None:
        h = normalize_host(host)
        for r in sorted(self.root_domains, key=len, reverse=True):
            if h == r or h.endswith("." + r):
                return r
        return None

    # -- IPs ---------------------------------------------------------------
    def ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self._ip_excluded(addr):
            return False
        if self.ip_is_target(ip):  # explicitly named targets are always contactable
            return True
        if not self.ip_allow:
            # No explicit allow-list: permit public addresses only. Private, loopback
            # and link-local addresses require an explicit allow entry (e.g. labs).
            return addr.is_global
        return any(addr in ipaddress.ip_network(net, strict=False) for net in self.ip_allow)

    def require_active_authorization(self) -> None:
        if not self.authorized:
            raise ScopeError(
                "Active modules need authorization: tick 'I am authorized to test these targets' when creating "
                "the scan, or set authorization.confirmed: true in the target config. Otherwise run a passive profile."
            )
