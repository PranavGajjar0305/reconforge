"""IP → ASN / hosting provider / CDN intelligence (static map, Team Cymru DNS, PTR)."""
from __future__ import annotations

import ipaddress
import json

import dns.exception
import dns.resolver
import dns.reversename

from ..core.module import Module, register
from ..core.net import make_resolver
from ..core.observation import Obs, Rel

CDN_HINTS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "incapsula": "Imperva",
    "imperva": "Imperva", "sucuri": "Sucuri", "stackpath": "StackPath", "edgecast": "Edgio", "cdn77": "CDN77",
}
CLOUD_HINTS = {
    "amazon": "Amazon Web Services", "aws": "Amazon Web Services", "google": "Google Cloud",
    "microsoft": "Microsoft Azure", "azure": "Microsoft Azure", "digitalocean": "DigitalOcean",
    "linode": "Akamai (Linode)", "ovh": "OVHcloud", "hetzner": "Hetzner", "oracle": "Oracle Cloud",
}


def classify_org(name: str) -> tuple[str | None, str | None]:
    low = (name or "").lower()
    cdn = next((v for k, v in CDN_HINTS.items() if k in low), None)
    cloud = next((v for k, v in CLOUD_HINTS.items() if k in low), None)
    return cdn, cloud


@register
class AsnIntel(Module):
    name = "asn_intel"
    description = "Maps IP addresses to ASNs, hosting providers and CDN indicators (passive)."
    phase = "network"
    requires_internet = False
    produces = ["asn", "provider"]

    def run(self, ctx) -> None:
        res = make_resolver(ctx.config)
        public_res = None
        static = ctx.option("asn", "static_map", {}) or {}
        use_cymru = bool(ctx.option("asn", "use_team_cymru", True)) and not ctx.offline
        for ip_asset in ctx.assets("ip", scope=None):
            ip = ip_asset.key
            addr = ipaddress.ip_address(ip)
            info: dict = {"private": not addr.is_global, "version": addr.version}
            for cidr, data in static.items():
                if addr in ipaddress.ip_network(cidr, strict=False):
                    info.update({"asn": f"AS{str(data.get('asn')).upper().lstrip('AS')}", "asn_name": data.get("name"),
                                 "country": data.get("country"), "asn_source": "static_map"})
                    break
            if "asn" not in info and addr.is_global and use_cymru:
                if public_res is None:
                    public_res = dns.resolver.Resolver()
                    public_res.lifetime = 5
                info.update(_cymru(public_res, addr))
            ptr = _ptr(res, ip)
            if ptr:
                info["ptr"] = ptr
            cdn, cloud = classify_org(f"{info.get('asn_name', '')} {ptr or ''}")
            info["cdn"] = cdn
            info["provider"] = cloud or info.get("asn_name") or ("Private / reserved range" if info["private"] else None)
            ev = ctx.evidence("asn_lookup", f"ASN data for {ip}", json.dumps(info, indent=2))
            rels = []
            if info.get("asn"):
                rels.append(Rel("announced_by", "asn", info["asn"], confirmed=True,
                                target_attrs={"name": info.get("asn_name"), "country": info.get("country")}))
            ctx.emit(Obs("ip", ip, info, evidence_id=ev, relations=rels))
            if info.get("asn") and info.get("provider"):
                ctx.emit(Obs("asn", info["asn"], {"name": info.get("asn_name")}, evidence_id=ev,
                             relations=[Rel("operated_by", "provider", info["provider"], confirmed=False,
                                            target_attrs={"name": info["provider"], "cdn": bool(cdn)})]))


def _cymru(res, addr) -> dict:
    try:
        if addr.version == 4:
            q = ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
        else:
            q = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        txt = b"".join(res.resolve(q, "TXT")[0].strings).decode()
        asn, prefix, country, *_ = [p.strip() for p in txt.split("|")]
        asn = asn.split()[0]
        desc = b"".join(res.resolve(f"AS{asn}.asn.cymru.com", "TXT")[0].strings).decode()
        name = desc.split("|")[-1].strip()
        return {"asn": f"AS{asn}", "asn_name": name, "bgp_prefix": prefix, "country": country, "asn_source": "team-cymru"}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError, IndexError):
        return {}


def _ptr(res, ip: str) -> str | None:
    try:
        return res.resolve(dns.reversename.from_address(ip), "PTR")[0].to_text().rstrip(".")
    except Exception:
        return None
