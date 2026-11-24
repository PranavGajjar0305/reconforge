"""Advanced DNS reconnaissance.

* dns_bruteforce – controlled wordlist brute force + permutations + bounded recursion,
                   wildcard-filtered (built-in, or puredns when selected)
* dns_security   – nameserver infrastructure, DNSSEC, CAA, SPF depth, DMARC policy, DKIM
                   selector presence, MTA-STS, TLS-RPT, BIMI, optional zone-transfer check
"""
from __future__ import annotations

import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from ..core.module import Module, SkipModule, register
from ..core.net import make_resolver
from ..core.observation import Obs, Rel
from ..util import normalize_host
from .common import finding, host_obs

WORDLIST = Path(__file__).resolve().parent.parent / "data" / "subdomains-small.txt"
AFFIXES = ["dev", "staging", "stage", "test", "qa", "uat", "prod", "api", "admin", "internal", "beta", "old", "new", "v2"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mx",
                  "everlytickey1", "mandrill", "sendgrid", "amazonses", "zoho", "protonmail", "fm1", "pm"]
NS_PROVIDERS = {"awsdns": "Amazon Route 53", "cloudflare": "Cloudflare", "azure-dns": "Azure DNS", "googledomains": "Google",
                "google.com": "Google Cloud DNS", "nsone": "NS1", "ultradns": "UltraDNS", "dnsimple": "DNSimple",
                "akam": "Akamai", "dynect": "Oracle Dyn", "godaddy": "GoDaddy", "domaincontrol": "GoDaddy",
                "registrar-servers": "Namecheap", "digitalocean": "DigitalOcean", "linode": "Linode", "hetzner": "Hetzner"}


def _a(res, name):
    try:
        ans = res.resolve(name, "A", raise_on_no_answer=False)
        return sorted(r.address for r in (ans.rrset or []))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def _txt(res, name) -> list[str]:
    try:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in res.resolve(name, "TXT")]
    except Exception:
        return []


def _records(res, name, rtype) -> list[str]:
    try:
        return sorted(r.to_text() for r in res.resolve(name, rtype))
    except Exception:
        return []


def permutations(labels: set[str], affixes: list[str], limit: int) -> list[str]:
    out: list[str] = []
    for lab in sorted(labels):
        for w in affixes:
            if w == lab:
                continue
            for cand in (f"{w}-{lab}", f"{lab}-{w}", f"{w}{lab}", f"{lab}{w}"):
                out.append(cand)
        for n in (1, 2):
            out.append(f"{lab}{n}")
    seen, uniq = set(), []
    for c in out:
        if c not in seen and c not in labels:
            seen.add(c)
            uniq.append(c)
    return uniq[:limit]


@register
class DnsBruteforce(Module):
    name = "dns_bruteforce"
    needs_domains = True
    description = "Controlled wordlist + permutation + recursive DNS brute force with wildcard filtering."
    phase = "resolve"
    active = True  # generates many queries toward the target's authoritative DNS
    tools = ["puredns"]
    produces = ["subdomain"]

    def run(self, ctx) -> None:
        opt = lambda k, d: ctx.option(self.name, k, d)
        path = Path(opt("wordlist", str(WORDLIST)))
        words = [w.strip().lower() for w in path.read_text().splitlines() if w.strip() and not w.startswith("#")]
        words = words[: int(opt("max_words", 5000))]
        res = make_resolver(ctx.config)
        workers = int(opt("concurrency", 10))
        found_total = 0
        stats = {}
        for root in ctx.scope.root_domains:
            wildcard = set(_a(res, f"rf-{uuid.uuid4().hex[:10]}.{root}"))
            existing = {a.key for a in ctx.assets(["subdomain"]) if a.key.endswith("." + root)}
            labels = {k[: -len(root) - 1].split(".")[0] for k in existing}
            candidates = [f"{w}.{root}" for w in words]
            perms = []
            if opt("permutations", True):
                perms = [f"{p}.{root}" for p in permutations(labels, AFFIXES, int(opt("max_permutations", 400)))]
            ctx.action("dns brute force %s: %d wordlist + %d permutation candidates (wildcard=%s)", root,
                       len(candidates), len(perms), bool(wildcard))
            hits = self._resolve_many(ctx, res, [c for c in candidates + perms if c not in existing], wildcard, workers)
            for h, ips in hits.items():
                ctx.action("dns brute force hit %s -> %s", h, ",".join(ips))
            recursive_hits = {}
            depth = int(opt("recursion_depth", 1))
            frontier = {h for h in hits} | {e for e in existing if ctx.engine.get("subdomain", e) and (ctx.engine.get("subdomain", e).attributes or {}).get("resolved")}
            top = words[: int(opt("recursive_words", 15))]
            for _ in range(depth):
                cand = [f"{w}.{h}" for h in sorted(frontier) for w in top if ctx.scope.host_in_scope(f"{w}.{h}")]
                new = self._resolve_many(ctx, res, [c for c in cand if c not in existing and c not in hits], wildcard, workers)
                recursive_hits.update(new)
                frontier = set(new)
                if not frontier:
                    break
            ev = ctx.evidence("dns_bruteforce", f"brute force for {root}: {len(candidates)} words, {len(perms)} permutations",
                              json.dumps({"wordlist": str(path), "words": len(candidates), "permutations": len(perms),
                                          "wildcard_ips": sorted(wildcard), "hits": hits, "recursive_hits": recursive_hits}, indent=1))
            for host, ips in {**hits, **recursive_hits}.items():
                via = "dns_permutation" if host in {p for p in perms} else "dns_bruteforce"
                o = host_obs(ctx, host, via, ev, {"bruteforce_ips": ips})
                if o:
                    ctx.emit(o)
                    found_total += 1
            stats[root] = {"queries": len(candidates) + len(perms), "found": len(hits) + len(recursive_hits),
                           "wildcard": bool(wildcard)}
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": found_total,
                                                           "detail": stats}

    def _resolve_many(self, ctx, res, names, wildcard, workers) -> dict[str, list[str]]:
        def one(n):
            ctx.limiter.wait()
            ips = _a(res, n)
            if ips and not (wildcard and set(ips) <= wildcard):
                return n, ips
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            return dict(r for r in pool.map(one, names) if r)


def spf_lookups(record: str) -> int:
    """Count SPF terms that trigger DNS lookups (RFC 7208 §4.6.4), term by term."""
    n = 0
    for term in record.split()[1:]:
        mech = term.lstrip("+-~?").lower()
        name = re.split(r"[:/=]", mech, maxsplit=1)[0]
        if name in ("include", "a", "mx", "ptr", "exists") or mech.startswith("redirect="):
            n += 1
    return n


@register
class DnsSecurity(Module):
    name = "dns_security"
    needs_domains = True
    description = "Nameserver mapping, DNSSEC, CAA, SPF/DMARC depth, DKIM/MTA-STS/TLS-RPT/BIMI presence, optional AXFR check."
    phase = "resolve"
    active = False  # resolver queries only (AXFR attempt and MTA-STS policy fetch are opt-in/active-gated)
    produces = ["domain", "finding", "third_party"]

    def run(self, ctx) -> None:
        res = make_resolver(ctx.config)
        for root in ctx.scope.root_domains:
            info: dict = {}
            ns = [normalize_host(n) for n in _records(res, root, "NS")]
            info["nameservers"] = [{"host": n, "ips": _a(res, n),
                                    "provider": next((v for k, v in NS_PROVIDERS.items() if k in n), None)} for n in ns]
            info["dnskey"] = len(_records(res, root, "DNSKEY"))
            info["ds"] = len(_records(res, root, "DS"))
            info["dnssec"] = "signed+delegated" if info["dnskey"] and info["ds"] else "signed (no DS at parent)" if info["dnskey"] else "unsigned"
            info["caa"] = _records(res, root, "CAA")
            spf = [t for t in _txt(res, root) if t.lower().startswith("v=spf1")]
            dmarc = [t for t in _txt(res, f"_dmarc.{root}") if t.lower().startswith("v=dmarc1")]
            info["spf"] = spf
            info["spf_dns_lookups"] = spf_lookups(spf[0]) if spf else 0
            info["dmarc"] = dmarc
            info["dmarc_policy"] = _tag(dmarc[0], "p") if dmarc else None
            info["dkim_selectors_found"] = [s for s in ctx.option(self.name, "dkim_selectors", DKIM_SELECTORS)
                                            if any("p=" in t for t in _txt(res, f"{s}._domainkey.{root}"))]
            info["mta_sts"] = _txt(res, f"_mta-sts.{root}")
            info["tls_rpt"] = _txt(res, f"_smtp._tls.{root}")
            info["bimi"] = _txt(res, f"default._bimi.{root}")
            info["mx"] = _records(res, root, "MX")
            ev = ctx.evidence("dns_answer", f"DNS security posture for {root}", json.dumps(info, indent=2))
            rels = []
            for n in info["nameservers"]:
                if ctx.scope.host_in_scope(n["host"]):
                    rels.append(Rel("delegated_to", "subdomain", n["host"], target_attrs={"+discovered_via": ["dns_security"], "role": "nameserver"}))
                else:
                    rels.append(Rel("delegated_to", "third_party", n["host"], target_attrs={"category": "dns-provider", "service": n["provider"] or "DNS hosting"}))
            ctx.emit(Obs("domain", root, {"dns_security": info}, evidence_id=ev, relations=rels))
            self._findings(ctx, root, info, ev)
            if ctx.option(self.name, "try_axfr", False):
                self._axfr(ctx, root, info["nameservers"])

    def _findings(self, ctx, root, info, ev):
        f = lambda rule, title, sev, desc, rec, cat="dns": finding(ctx, rule, root, title, sev, desc, ev, rec, category=cat)
        if info["dnssec"] == "unsigned":
            f("dns.dnssec_unsigned", "DNSSEC not enabled", "info", f"No DNSKEY records published for {root}.",
              "Consider DNSSEC signing if your DNS provider supports it.")
        elif info["dnssec"].startswith("signed (no DS"):
            f("dns.dnssec_no_ds", "DNSSEC keys present but no DS at parent", "low",
              "DNSKEY records exist but no DS record was found, so the chain of trust is incomplete.", "Publish the DS record at the registrar.")
        if not info["caa"]:
            f("dns.caa_missing", "No CAA records", "info", f"{root} publishes no CAA records; any CA may issue certificates.",
              "Publish CAA records naming the CAs you use.")
        if len(info["spf"]) > 1:
            f("email.spf_multiple", "Multiple SPF records", "low", "More than one v=spf1 TXT record (invalid per RFC 7208).",
              "Merge into a single SPF record.", "email")
        if info["spf_dns_lookups"] > 10:
            f("email.spf_lookup_limit", "SPF exceeds 10 DNS lookups", "low",
              f"SPF has {info['spf_dns_lookups']} lookup mechanisms (limit 10); receivers may return permerror.", "Flatten or reduce includes.", "email")
        if info["mx"] and not info["mta_sts"]:
            f("email.mta_sts_missing", "MTA-STS not published", "info", "No _mta-sts TXT record.", "Consider MTA-STS for SMTP TLS enforcement.", "email")
        if info["mx"] and not info["tls_rpt"]:
            f("email.tls_rpt_missing", "SMTP TLS reporting not published", "info", "No _smtp._tls TXT record.", "Consider TLS-RPT.", "email")
        if info["mx"] and not info["dkim_selectors_found"]:
            f("email.dkim_not_found", "No DKIM key found for common selectors", "info",
              "None of the probed common selectors returned a DKIM key. Selectors are arbitrary, so DKIM may still be in use.",
              "Confirm DKIM signing with the mail provider.", "email")

    def _axfr(self, ctx, root, nameservers):
        """Opt-in (dns_security.try_axfr: true): ask each authoritative server for a zone transfer."""
        for n in nameservers:
            for ip in n["ips"][:1]:
                try:
                    ctx.limiter.wait()
                    z = dns.zone.from_xfr(dns.query.xfr(ip, root, timeout=10, lifetime=20))
                except Exception:
                    continue
                names = sorted({f"{k}.{root}".replace("@.", "") for k in z.nodes.keys()})
                ev = ctx.evidence("zone_transfer", f"AXFR {root} from {n['host']} ({len(names)} names)", "\n".join(names))
                finding(ctx, "dns.axfr_allowed", f"{root}@{n['host']}", "Zone transfer permitted", "medium",
                        f"{n['host']} answered a full zone transfer for {root} ({len(names)} names).", ev,
                        "Restrict AXFR to secondary nameservers.", category="dns", subject_type="domain")
                for h in names:
                    o = host_obs(ctx, h.lstrip("@."), "zone_transfer", ev)
                    if o:
                        ctx.emit(o)


def _tag(record: str, tag: str) -> str | None:
    m = re.search(rf"\b{tag}=([^;\s]+)", record, re.I)
    return m.group(1).lower() if m else None
