"""Passive intelligence providers (third-party datasets / APIs).

Each provider declares what it returns, whether an API key is required, and a parser.
Base URLs are configurable (`providers.<name>.base_url`), which lets the lab emulate
them. Providers never cause traffic to the target: they query the provider only.

Modules:
* passive_sources  – subdomains (and URLs) from OTX, HackerTarget, URLScan, SecurityTrails,
                     VirusTotal, Shodan DNS, Chaos, WhoisXML, Common Crawl, Brave Search
* ip_intelligence  – Shodan InternetDB (public exposure), RDAP (network ownership),
                     GreyNoise community, IPinfo — only for public IPs of in-scope hosts
* domain_ownership – RDAP registration data for root domains

Intelligence from these sources is recorded with its source and never used as
authorization to probe third-party infrastructure.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

import httpx

from ..core.module import Module, SkipModule, register
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_url
from .common import host_obs


@dataclass
class Provider:
    name: str
    kind: str                      # subdomains | urls | ip | domain
    base_url: str
    fetch: Callable                # (client, base, target, key) -> parsed
    api_env: str | None = None
    key_required: bool = False
    reliability: float = 0.6
    notes: str = ""
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------- parsers
def _otx(client, base, domain, key):
    h = {"X-OTX-API-KEY": key} if key else {}
    r = client.get(f"{base}/api/v1/indicators/domain/{domain}/passive_dns", headers=h)
    r.raise_for_status()
    data = r.json()
    return {"hosts": [x.get("hostname", "") for x in data.get("passive_dns", [])], "raw": data}


def _hackertarget(client, base, domain, key):
    r = client.get(f"{base}/hostsearch/", params={"q": domain, **({"apikey": key} if key else {})})
    r.raise_for_status()
    if "error" in r.text.lower()[:60] or "api count exceeded" in r.text.lower():
        raise RuntimeError(r.text.strip()[:120])
    return {"hosts": [l.split(",")[0] for l in r.text.splitlines() if "," in l], "raw": r.text}


def _urlscan(client, base, domain, key):
    r = client.get(f"{base}/api/v1/search/", params={"q": f"domain:{domain}", "size": 1000},
                   headers={"API-Key": key} if key else {})
    r.raise_for_status()
    data = r.json()
    hosts, urls = [], []
    for res in data.get("results", []):
        hosts.append((res.get("page") or {}).get("domain", ""))
        urls.append((res.get("task") or {}).get("url", ""))
    return {"hosts": hosts, "urls": urls, "raw": data}


def _securitytrails(client, base, domain, key):
    r = client.get(f"{base}/v1/domain/{domain}/subdomains", headers={"APIKEY": key})
    r.raise_for_status()
    return {"hosts": [f"{s}.{domain}" for s in r.json().get("subdomains", [])], "raw": r.json()}


def _virustotal(client, base, domain, key):
    r = client.get(f"{base}/api/v3/domains/{domain}/subdomains", params={"limit": 40}, headers={"x-apikey": key})
    r.raise_for_status()
    return {"hosts": [d.get("id", "") for d in r.json().get("data", [])], "raw": r.json()}


def _shodan_dns(client, base, domain, key):
    r = client.get(f"{base}/dns/domain/{domain}", params={"key": key})
    r.raise_for_status()
    data = r.json()
    return {"hosts": [f"{s}.{domain}" for s in data.get("subdomains", []) if s], "raw": data}


def _chaos(client, base, domain, key):
    r = client.get(f"{base}/dns/{domain}/subdomains", headers={"Authorization": key})
    r.raise_for_status()
    return {"hosts": [f"{s}.{domain}" for s in r.json().get("subdomains", [])], "raw": r.json()}


def _whoisxml(client, base, domain, key):
    r = client.get(f"{base}/api/v1", params={"apiKey": key, "domainName": domain})
    r.raise_for_status()
    data = r.json()
    return {"hosts": [x.get("domain", "") for x in (data.get("result") or {}).get("records", [])], "raw": data}


def _anubis(client, base, domain, key):
    r = client.get(f"{base}/anubis/subdomains/{domain}")
    r.raise_for_status()
    data = r.json() if r.text.strip() else []
    return {"hosts": [h for h in data if isinstance(h, str)], "raw": data}


def _certspotter(client, base, domain, key):
    r = client.get(f"{base}/v1/issuances", params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                   headers={"Authorization": f"Bearer {key}"} if key else {})
    r.raise_for_status()
    data = r.json()
    return {"hosts": sorted({n.lstrip("*.") for c in data if isinstance(c, dict) for n in c.get("dns_names") or []}), "raw": data}


def _fullhunt(client, base, domain, key):
    r = client.get(f"{base}/api/v1/domain/{domain}/subdomains", headers={"x-api-key": key})
    r.raise_for_status()
    data = r.json()
    return {"hosts": data.get("hosts") or [], "raw": data}


def _binaryedge(client, base, domain, key):
    hosts, page = [], 1
    while page <= 5:
        r = client.get(f"{base}/v2/query/domains/subdomain/{domain}", params={"page": page}, headers={"X-Key": key})
        r.raise_for_status()
        data = r.json()
        hosts += data.get("events") or []
        if page * int(data.get("pagesize") or 100) >= int(data.get("total") or 0):
            break
        page += 1
    return {"hosts": hosts, "raw": {"total": len(hosts)}}


def _leakix(client, base, domain, key):
    r = client.get(f"{base}/api/subdomains/{domain}", headers={"api-key": key, "Accept": "application/json"})
    r.raise_for_status()
    data = r.json() or []
    return {"hosts": [d.get("subdomain", "") for d in data if isinstance(d, dict)], "raw": data}


def _commoncrawl(client, base, domain, key):
    idx = client.get(f"{base}/collinfo.json")
    idx.raise_for_status()
    api = idx.json()[0]["cdx-api"]
    r = client.get(api, params={"url": f"*.{domain}", "output": "json", "limit": 2000})
    if r.status_code == 404:
        return {"urls": [], "hosts": []}
    r.raise_for_status()
    urls = [json.loads(l).get("url", "") for l in r.text.splitlines() if l.strip()]
    return {"urls": urls, "hosts": [host_of(u) for u in urls]}


def _brave(client, base, domain, key):
    r = client.get(f"{base}/res/v1/web/search", params={"q": f"site:{domain}", "count": 20},
                   headers={"X-Subscription-Token": key, "Accept": "application/json"})
    r.raise_for_status()
    urls = [x.get("url", "") for x in (r.json().get("web") or {}).get("results", [])]
    return {"urls": urls, "hosts": [host_of(u) for u in urls], "raw": r.json()}


def _internetdb(client, base, ip, key):
    r = client.get(f"{base}/{ip}")
    if r.status_code == 404:
        return {"ports": [], "hostnames": [], "cpes": [], "vulns": [], "tags": [], "indexed": False}
    r.raise_for_status()
    return {**r.json(), "indexed": True}


def _rdap_ip(client, base, ip, key):
    r = client.get(f"{base}/ip/{ip}")
    r.raise_for_status()
    d = r.json()
    ents = [e.get("handle") for e in d.get("entities", []) if e.get("handle")]
    return {"network_name": d.get("name"), "handle": d.get("handle"), "start": d.get("startAddress"),
            "end": d.get("endAddress"), "country": d.get("country"), "entities": ents[:10], "type": d.get("type")}


def _rdap_domain(client, base, domain, key):
    r = client.get(f"{base}/domain/{domain}")
    r.raise_for_status()
    d = r.json()
    registrar = None
    for e in d.get("entities", []):
        if "registrar" in (e.get("roles") or []):
            vcard = (e.get("vcardArray") or [None, []])[1]
            registrar = next((v[3] for v in vcard if v[0] == "fn"), e.get("handle"))
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    return {"registrar": registrar, "status": d.get("status", []), "events": events,
            "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])],
            "dnssec_signed": (d.get("secureDNS") or {}).get("delegationSigned")}


def _greynoise(client, base, ip, key):
    r = client.get(f"{base}/v3/community/{ip}", headers={"key": key} if key else {})
    if r.status_code == 404:
        return {"noise": False, "riot": False, "classification": "not observed"}
    r.raise_for_status()
    d = r.json()
    return {"noise": d.get("noise"), "riot": d.get("riot"), "classification": d.get("classification"), "name": d.get("name")}


def _ipinfo(client, base, ip, key):
    r = client.get(f"{base}/{ip}/json", params={"token": key} if key else {})
    r.raise_for_status()
    d = r.json()
    return {"org": d.get("org"), "hostname": d.get("hostname"), "country": d.get("country"), "anycast": d.get("anycast")}


PROVIDERS: dict[str, Provider] = {p.name: p for p in [
    Provider("otx", "subdomains", "https://otx.alienvault.com", _otx, "OTX_API_KEY", False, 0.6, "AlienVault OTX passive DNS"),
    Provider("hackertarget", "subdomains", "https://api.hackertarget.com", _hackertarget, "HACKERTARGET_API_KEY", False, 0.6),
    Provider("urlscan", "subdomains", "https://urlscan.io", _urlscan, "URLSCAN_API_KEY", False, 0.65),
    Provider("securitytrails", "subdomains", "https://api.securitytrails.com", _securitytrails, "SECURITYTRAILS_API_KEY", True, 0.75),
    Provider("virustotal", "subdomains", "https://www.virustotal.com", _virustotal, "VIRUSTOTAL_API_KEY", True, 0.65),
    Provider("shodan_dns", "subdomains", "https://api.shodan.io", _shodan_dns, "SHODAN_API_KEY", True, 0.65),
    Provider("chaos", "subdomains", "https://dns.projectdiscovery.io", _chaos, "PDCP_API_KEY", True, 0.7),
    Provider("whoisxml", "subdomains", "https://subdomains.whoisxmlapi.com", _whoisxml, "WHOISXML_API_KEY", True, 0.65),
    Provider("anubis", "subdomains", "https://jldc.me", _anubis, None, False, 0.55, "AnubisDB (no key)"),
    Provider("certspotter", "subdomains", "https://api.certspotter.com", _certspotter, "CERTSPOTTER_API_KEY", False, 0.8,
             "Cert Spotter certificate transparency"),
    Provider("fullhunt", "subdomains", "https://fullhunt.io", _fullhunt, "FULLHUNT_API_KEY", True, 0.65),
    Provider("binaryedge", "subdomains", "https://api.binaryedge.io", _binaryedge, "BINARYEDGE_API_KEY", True, 0.65),
    Provider("leakix", "subdomains", "https://leakix.net", _leakix, "LEAKIX_API_KEY", True, 0.6),
    Provider("commoncrawl", "urls", "https://index.commoncrawl.org", _commoncrawl, None, False, 0.5),
    Provider("brave_search", "urls", "https://api.search.brave.com", _brave, "BRAVE_SEARCH_API_KEY", True, 0.5, "search engine indexing"),
    Provider("internetdb", "ip", "https://internetdb.shodan.io", _internetdb, None, False, 0.6, "Shodan InternetDB public exposure"),
    Provider("rdap_ip", "ip", "https://rdap.org", _rdap_ip, None, False, 0.9, "network ownership"),
    Provider("greynoise", "ip", "https://api.greynoise.io", _greynoise, "GREYNOISE_API_KEY", False, 0.6),
    Provider("ipinfo", "ip", "https://ipinfo.io", _ipinfo, "IPINFO_TOKEN", False, 0.7),
    Provider("rdap_domain", "domain", "https://rdap.org", _rdap_domain, None, False, 0.9, "registration data"),
]}


def provider_plan(ctx, kind: str) -> list[tuple[Provider, str, str | None]]:
    """[(provider, base_url, key)] for enabled, usable providers; records skips in ctx.shared['sources']."""
    sources = ctx.shared.setdefault("sources", {})
    cfg_all = ctx.config.get("providers", {}) or {}
    plan = []
    for p in PROVIDERS.values():
        if p.kind != kind:
            continue
        pc = cfg_all.get(p.name, {}) or {}
        base = (pc.get("base_url") or p.base_url).rstrip("/")
        local = base.startswith(("http://127.", "http://localhost"))
        key = os.environ.get(pc.get("api_env") or p.api_env or "", "") or pc.get("api_key") or None
        if pc.get("enabled") is False:
            sources[p.name] = {"kind": "provider", "status": "disabled"}
        elif ctx.offline and not local:
            sources[p.name] = {"kind": "provider", "status": "unavailable", "error": "network.offline"}
        elif p.key_required and not key and not local:
            sources[p.name] = {"kind": "provider", "status": "unavailable", "error": f"no API key ({p.api_env})"}
        else:
            plan.append((p, base, key))
    return plan


def _client(ctx) -> httpx.Client:
    return httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": ctx.config.get("network.user_agent")})


@register
class PassiveSources(Module):
    name = "passive_sources"
    needs_domains = True
    description = "Queries passive DNS / dataset / search providers (OTX, URLScan, SecurityTrails, VirusTotal, Shodan, Chaos, ...)."
    phase = "passive"
    requires_internet = True
    handles_offline = True  # per-provider decision (local emulators allowed)
    produces = ["subdomain", "endpoint"]

    def run(self, ctx) -> None:
        plan = provider_plan(ctx, "subdomains") + provider_plan(ctx, "urls")
        if not plan:
            raise SkipModule("no passive providers usable (offline or missing API keys)")
        sources = ctx.shared["sources"]
        from .crawler import classify_endpoint

        with _client(ctx) as client:
            for p, base, key in plan:
                start, hosts, urls = time.monotonic(), set(), set()
                try:
                    for root in ctx.scope.root_domains:
                        ctx.action("provider %s query %s (%s)", p.name, root, base)
                        res = p.fetch(client, base, root, key)
                        ev = ctx.evidence("provider_response", f"{p.name} results for {root}",
                                          json.dumps({k: v for k, v in res.items() if k != "raw"}, default=str)[:200000], ".json")
                        for h in res.get("hosts", []):
                            o = host_obs(ctx, h, p.name, ev)
                            if o:
                                ctx.emit(o)
                                hosts.add(o.key)
                        for u in res.get("urls", []):
                            if u and ctx.scope.host_in_scope(host_of(u)):
                                nu = normalize_url(u)
                                urls.add(nu)
                                ctx.emit(Obs("endpoint", nu, {"url": nu, "host": host_of(nu), "kind": classify_endpoint(nu),
                                                              "historical": True, "+discovered_via": [p.name]},
                                             source=p.name, evidence_id=ev, confidence=0.9,
                                             relations=[Rel("historical_url", "subdomain", host_of(nu), confirmed=False, reverse=True)]))
                    sources[p.name] = {"kind": "provider", "status": "ok", "results": len(hosts) + len(urls),
                                       "hosts": len(hosts), "urls": len(urls), "seconds": round(time.monotonic() - start, 1)}
                except Exception as exc:
                    sources[p.name] = {"kind": "provider", "status": "error", "error": f"{type(exc).__name__}: {exc}"[:300]}
                    ctx.log.warning("[%s] provider %s failed: %s", self.name, p.name, exc)


@register
class IpIntelligence(Module):
    name = "ip_intelligence"
    description = "Public exposure (Shodan InternetDB), ownership (RDAP), noise (GreyNoise), org (IPinfo) for public IPs."
    phase = "network"
    requires_internet = True
    handles_offline = True  # per-provider decision (local emulators allowed)
    produces = ["ip", "finding"]

    def run(self, ctx) -> None:
        ips = [a for a in ctx.live("ip") if ctx.config.get("providers.include_private_ips") or ipaddress.ip_address(a.key).is_global]
        if not ips:
            raise SkipModule("no public IP addresses observed in this scan")
        plan = provider_plan(ctx, "ip")
        if not plan:
            raise SkipModule("no IP intelligence providers usable")
        sources = ctx.shared["sources"]
        with _client(ctx) as client:
            for p, base, key in plan:
                ok = 0
                try:
                    for ip in ips:
                        ctx.action("provider %s lookup %s", p.name, ip.key)
                        data = p.fetch(client, base, ip.key, key)
                        ev = ctx.evidence("provider_response", f"{p.name} for {ip.key}", json.dumps(data, default=str))
                        ctx.emit(Obs("ip", ip.key, {f"intel_{p.name}": data}, source=p.name, evidence_id=ev))
                        ok += 1
                        if p.name == "internetdb" and data.get("indexed"):
                            seen = set(data.get("ports") or [])
                            scanned = {(s.attributes or {}).get("port") for s in ctx.live("service") if (s.attributes or {}).get("ip") == ip.key}
                            extra = sorted(seen - scanned)
                            if extra:
                                from .common import finding

                                finding(ctx, "exposure.indexed_ports", ip.key, "Ports publicly indexed by Shodan not covered by this scan",
                                        "info", f"InternetDB lists ports {extra} for {ip.key}; they were not assessed in this scan "
                                        "(not in the configured port list or not open now). Indexed data may be stale.",
                                        ev, "Review whether these ports should be added to the authorized port list.",
                                        category="coverage", subject_type="ip", extra={"ports": extra, "source": "internetdb"})
                    sources[p.name] = {"kind": "provider", "status": "ok", "results": ok}
                except Exception as exc:
                    sources[p.name] = {"kind": "provider", "status": "error", "error": f"{type(exc).__name__}: {exc}"[:300]}


@register
class DomainOwnership(Module):
    name = "domain_ownership"
    needs_domains = True
    description = "RDAP registration data (registrar, dates, nameservers, DNSSEC delegation) for root domains."
    phase = "passive"
    requires_internet = True
    handles_offline = True  # per-provider decision (local emulators allowed)
    produces = ["domain"]

    def run(self, ctx) -> None:
        plan = provider_plan(ctx, "domain")
        if not plan:
            raise SkipModule("RDAP unavailable")
        with _client(ctx) as client:
            for p, base, key in plan:
                try:
                    for root in ctx.scope.root_domains:
                        data = p.fetch(client, base, root, key)
                        ev = ctx.evidence("provider_response", f"RDAP for {root}", json.dumps(data, default=str))
                        ctx.emit(Obs("domain", root, {"registration": data}, source=p.name, evidence_id=ev))
                    ctx.shared["sources"][p.name] = {"kind": "provider", "status": "ok", "results": len(ctx.scope.root_domains)}
                except Exception as exc:
                    ctx.shared["sources"][p.name] = {"kind": "provider", "status": "error", "error": str(exc)[:300]}
