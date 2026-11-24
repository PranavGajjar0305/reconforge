"""Passive intelligence modules: no traffic is sent to target-operated web hosts.

* domain_intel     – public DNS records of root domains (NS/MX/TXT/SOA/CAA/DMARC)
* crtsh            – Certificate Transparency search (crt.sh JSON API)
* subfinder        – ProjectDiscovery subfinder adapter (passive sources)
* historical_urls  – Wayback Machine CDX API and/or `gau`
* github_intel     – public code search references to the target domains
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote

import dns.exception
import dns.resolver
import httpx

from ..core.module import Module, SkipModule, register
from ..core.net import make_resolver
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_host, normalize_url, valid_hostname
from .common import finding as _finding, host_obs as _in_scope_host_obs

TXT_INTEGRATIONS = {
    "google-site-verification": ("google.com", "Google Workspace / Search Console"),
    "ms=": ("microsoft.com", "Microsoft 365"),
    "atlassian-domain-verification": ("atlassian.com", "Atlassian"),
    "facebook-domain-verification": ("facebook.com", "Meta Business"),
    "apple-domain-verification": ("apple.com", "Apple"),
    "docusign": ("docusign.com", "DocuSign"),
    "stripe-verification": ("stripe.com", "Stripe"),
    "zoom-verification": ("zoom.us", "Zoom"),
    "slack-domain-verification": ("slack.com", "Slack"),
    "adobe-idp-site-verification": ("adobe.com", "Adobe"),
    "hubspot-developer-verification": ("hubspot.com", "HubSpot"),
}

MX_PROVIDERS = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast", "zoho.com": "Zoho Mail",
}


def _http(ctx) -> httpx.Client:
    return httpx.Client(timeout=30, headers={"User-Agent": ctx.config.get("network.user_agent")}, follow_redirects=True)


@register
class DomainIntel(Module):
    name = "domain_intel"
    needs_domains = True
    description = "Public DNS records for root domains (NS, MX, TXT/SPF, DMARC, CAA, SOA) and integrations they reveal."
    phase = "passive"
    produces = ["domain", "third_party", "finding"]

    def run(self, ctx) -> None:
        res = make_resolver(ctx.config)
        for root in ctx.scope.root_domains:
            records: dict[str, list[str]] = {}
            for rtype in ("NS", "MX", "TXT", "SOA", "CAA"):
                records[rtype] = _query(res, root, rtype)
            dmarc = _query(res, f"_dmarc.{root}", "TXT")
            ev = ctx.evidence("dns_answer", f"DNS records for {root}",
                              json.dumps({"records": records, "_dmarc": dmarc}, indent=2))
            ctx.emit(Obs("domain", root, {"dns_public": records, "dmarc": dmarc}, evidence_id=ev))
            spf = [t for t in records["TXT"] if t.lower().startswith("v=spf1")]
            for txt in records["TXT"]:
                low = txt.lower()
                for prefix, (domain, label) in TXT_INTEGRATIONS.items():
                    if low.startswith(prefix):
                        ctx.emit(Obs("third_party", domain, {"service": label, "category": "saas-integration",
                                                            "+evidence": [f"TXT {txt[:80]}"]}, evidence_id=ev,
                                     relations=[Rel("integrates_with", "domain", root, confirmed=True, reverse=True,
                                                    attrs={"via": "TXT verification record"})]))
            for s in spf:
                for inc in re.findall(r"include:([^\s]+)", s):
                    ctx.emit(Obs("third_party", inc, {"service": "SPF authorised sender", "category": "email"},
                                 evidence_id=ev, relations=[Rel("authorizes_sender", "domain", root, reverse=True,
                                                                attrs={"via": "SPF include"})]))
                if re.search(r"[?+]all\b", s):
                    _finding(ctx, "dns.spf_permissive", root, "Permissive SPF policy", "low",
                             f"SPF record ends with a permissive qualifier: {s}", ev,
                             "Review whether '~all'/'-all' is appropriate for this domain.", category="email")
            for mx in records["MX"]:
                host = normalize_host(mx.split()[-1])
                if ctx.scope.host_in_scope(host):
                    o = _in_scope_host_obs(ctx, host, self.name, ev, {"role": "mail"})
                    if o:
                        ctx.emit(o)
                else:
                    provider = next((v for k, v in MX_PROVIDERS.items() if host.endswith(k)), "Mail provider")
                    ctx.emit(Obs("third_party", host, {"service": provider, "category": "email"}, evidence_id=ev,
                                 relations=[Rel("mail_handled_by", "domain", root, reverse=True)]))
            if not dmarc:
                _finding(ctx, "dns.dmarc_missing", root, "No DMARC record published", "low",
                         f"No TXT record found at _dmarc.{root}.", ev,
                         "Publish a DMARC policy to reduce spoofing of this domain.", category="email")
            elif any("p=none" in d.lower() for d in dmarc):
                _finding(ctx, "dns.dmarc_monitor_only", root, "DMARC policy is monitor-only (p=none)", "info",
                         f"DMARC: {dmarc[0]}", ev, "Consider quarantine/reject once reporting is reviewed.", category="email")


def _query(res, name: str, rtype: str) -> list[str]:
    try:
        return sorted(r.to_text().strip('"') if rtype != "TXT" else b"".join(r.strings).decode("utf-8", "replace")
                      for r in res.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


@register
class CrtSh(Module):
    name = "crtsh"
    needs_domains = True
    description = "Certificate Transparency log search via the crt.sh JSON API."
    phase = "passive"
    requires_internet = True
    produces = ["subdomain"]

    def run(self, ctx) -> None:
        base = ctx.option(self.name, "base_url", "https://crt.sh").rstrip("/")
        if ctx.offline and not base.startswith(("http://127.", "http://localhost")):
            raise SkipModule("network.offline is true")
        with _http(ctx) as client:
            for root in ctx.scope.root_domains:
                url = f"{base}/?q={quote('%.' + root)}&output=json"
                ctx.action("GET %s", url)
                r = client.get(url)
                r.raise_for_status()
                rows = r.json() if r.text.strip() else []
                ev = ctx.evidence("tool_output", f"crt.sh results for {root} ({len(rows)} rows)", r.text, ".json")
                names: dict[str, dict] = {}
                for row in rows:
                    for name in str(row.get("name_value", "")).splitlines():
                        h = normalize_host(name)
                        info = names.setdefault(h, {"ct_first": row.get("not_before"), "ct_issuers": set()})
                        info["ct_issuers"].add(row.get("issuer_name", ""))
                for h, info in names.items():
                    o = _in_scope_host_obs(ctx, h, self.name, ev, {"ct_issuers": sorted(i for i in info["ct_issuers"] if i)[:5]})
                    if o:
                        ctx.emit(o)


@register
class Subfinder(Module):
    name = "subfinder"
    needs_domains = True
    description = "ProjectDiscovery subfinder adapter (passive sources, JSON output)."
    phase = "passive"
    requires_internet = True
    tools = ["subfinder"]
    produces = ["subdomain"]

    def run(self, ctx) -> None:
        if ctx.offline:
            raise SkipModule("network.offline is true")
        if not ctx.tool("subfinder").available:
            raise SkipModule(ctx.tool("subfinder").reason)
        args = ["-silent", "-json", "-all", "-dL", "/dev/stdin"]
        pc = subfinder_provider_config(ctx.work_dir)
        if pc:
            args += ["-pc", str(pc)]
        try:
            proc = ctx.run_tool("subfinder", args, input_text="\n".join(ctx.scope.root_domains))
        finally:
            if pc:
                pc.unlink(missing_ok=True)
        ev = ctx.evidence("tool_output", "subfinder JSONL output", proc.stdout, ".jsonl")
        for obs in parse_subfinder(proc.stdout, ev):
            if ctx.scope.host_in_scope(obs.key):
                root = ctx.scope.root_for(obs.key)
                if root and root != obs.key:
                    obs.relations.append(Rel("has_subdomain", "domain", root, reverse=True))
                ctx.emit(obs)


# API key env var -> subfinder provider name
SUBFINDER_KEYS = {"SECURITYTRAILS_API_KEY": "securitytrails", "VIRUSTOTAL_API_KEY": "virustotal", "SHODAN_API_KEY": "shodan",
                  "PDCP_API_KEY": "chaos", "BINARYEDGE_API_KEY": "binaryedge", "FULLHUNT_API_KEY": "fullhunt",
                  "GITHUB_TOKEN": "github", "LEAKIX_API_KEY": "leakix", "CERTSPOTTER_API_KEY": "certspotter",
                  "WHOISXML_API_KEY": "whoisxmlapi", "OTX_API_KEY": "alienvault", "URLSCAN_API_KEY": "urlscan"}


def subfinder_provider_config(work_dir):
    """Write a temporary subfinder provider-config (mode 600) merging the user's own file with the
    API keys configured in ReconForge. Returns its path, or None when no keys are configured."""
    import os
    from pathlib import Path

    import yaml

    keys = {prov: os.environ[env] for env, prov in SUBFINDER_KEYS.items() if os.environ.get(env)}
    if not keys:
        return None
    user_cfg = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
    data = {}
    if user_cfg.exists():
        try:
            data = yaml.safe_load(user_cfg.read_text()) or {}
        except Exception:
            data = {}
    for prov, key in keys.items():
        cur = [k for k in (data.get(prov) or []) if k]
        if key not in cur:
            data[prov] = [key, *cur]
    path = Path(work_dir) / "subfinder-providers.yaml"
    path.touch(mode=0o600)
    path.write_text(yaml.safe_dump(data))
    os.chmod(path, 0o600)
    return path


def parse_subfinder(output: str, evidence_id: str | None = None) -> list[Obs]:
    out = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            host, src = row.get("host"), row.get("source") or row.get("sources")
        except ValueError:
            host, src = line, None
        h = normalize_host(host)
        if valid_hostname(h):
            srcs = src if isinstance(src, list) else ([src] if src else [])
            out.append(Obs("subdomain", h, {"+discovered_via": ["subfinder"], "+passive_sources": srcs},
                           source="subfinder", evidence_id=evidence_id))
    return out


@register
class HistoricalUrls(Module):
    name = "historical_urls"
    needs_domains = True
    description = "Historical URLs from the Wayback Machine CDX API (and gau when installed)."
    phase = "passive"
    requires_internet = True
    tools = ["gau"]
    produces = ["endpoint", "subdomain"]

    def run(self, ctx) -> None:
        base = ctx.option(self.name, "base_url", "https://web.archive.org").rstrip("/")
        local = base.startswith(("http://127.", "http://localhost"))
        if ctx.offline and not local:
            raise SkipModule("network.offline is true")
        limit = int(ctx.option(self.name, "limit", 2000))
        urls: dict[str, dict] = {}
        with _http(ctx) as client:
            for root in ctx.scope.root_domains:
                q = f"{base}/cdx/search/cdx?url=*.{root}/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
                ctx.action("GET %s", q)
                r = client.get(q)
                r.raise_for_status()
                rows = r.json() if r.text.strip() else []
                ev = ctx.evidence("tool_output", f"Wayback CDX for {root} ({max(len(rows) - 1, 0)} rows)", r.text, ".json")
                for row in rows[1:]:
                    urls[row[0]] = {"archived_at": row[1], "archived_status": row[2], "mime": row[3], "ev": ev}
        if ctx.tool("gau").available and not ctx.offline:
            proc = ctx.run_tool("gau", ["--subs"], input_text="\n".join(ctx.scope.root_domains))
            ev = ctx.evidence("tool_output", "gau output", proc.stdout)
            for line in proc.stdout.splitlines():
                urls.setdefault(line.strip(), {"ev": ev})
        for raw, meta in urls.items():
            host = host_of(raw)
            if not ctx.scope.host_in_scope(host):
                continue
            o = _in_scope_host_obs(ctx, host, self.name, meta["ev"])
            if o:
                ctx.emit(o)
            nurl = normalize_url(raw)
            kind = "api" if re.search(r"/(api|v\d+|graphql|rest)(/|$)", nurl) else "page"
            attrs = {"url": nurl, "host": host, "kind": kind, "historical": True,
                     "archived_at": meta.get("archived_at"), "archived_status": meta.get("archived_status"),
                     "+discovered_via": [self.name]}
            ctx.emit(Obs("endpoint", nurl, attrs, evidence_id=meta["ev"], confidence=0.9,
                         relations=[Rel("historical_url", "subdomain", host, confirmed=False, reverse=True)]))


@register
class GithubIntel(Module):
    name = "github_intel"
    needs_domains = True
    description = "Public code search for references to target domains (records references only, never secrets)."
    phase = "passive"
    requires_internet = True
    produces = ["repository", "subdomain"]

    def run(self, ctx) -> None:
        import os

        api = ctx.option("github", "api_base", "https://api.github.com").rstrip("/")
        local = api.startswith(("http://127.", "http://localhost"))
        if ctx.offline and not local:
            raise SkipModule("network.offline is true")
        token = os.environ.get(ctx.option("github", "token_env", "GITHUB_TOKEN") or "")
        if not token and not local:
            raise SkipModule("GitHub code search requires a token (set GITHUB_TOKEN)")
        headers = {"Accept": "application/vnd.github.text-match+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        max_results = int(ctx.option("github", "max_results", 50))
        with _http(ctx) as client:
            for root in ctx.scope.root_domains:
                r = client.get(f"{api}/search/code", params={"q": f'"{root}"', "per_page": min(max_results, 100)}, headers=headers)
                r.raise_for_status()
                data = r.json()
                ev = ctx.evidence("tool_output", f"code search for {root}: {data.get('total_count', 0)} results",
                                  json.dumps(_redact(data), indent=1)[:200000], ".json")
                for item in data.get("items", [])[:max_results]:
                    repo = item.get("repository", {}).get("full_name", "unknown")
                    ctx.emit(Obs("repository", f"github:{repo}", {
                        "platform": "github", "repo": repo, "+paths": [item.get("path")],
                        "+urls": [item.get("html_url")], "public": True},
                        display=f"github.com/{repo}", evidence_id=ev,
                        relations=[Rel("mentions", "domain", root, confirmed=False)]))
                    for tm in item.get("text_matches", []) or []:
                        for h in re.findall(r"[a-z0-9][a-z0-9.-]*\." + re.escape(root), tm.get("fragment", "").lower()):
                            o = _in_scope_host_obs(ctx, h, self.name, ev)
                            if o:
                                o.confidence = 0.8
                                ctx.emit(o)


_SECRETISH = re.compile(r"(AKIA[0-9A-Z]{16}|(?i:secret|token|password|passwd|api[_-]?key)\s*[:=]\s*\S+)")


def _redact(obj):
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        return _SECRETISH.sub("[REDACTED]", obj)
    return obj
