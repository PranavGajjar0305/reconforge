"""DNS resolution of discovered hostnames (built-in dnspython engine or dnsx)."""
from __future__ import annotations

import json
import uuid

import dns.exception
import dns.resolver

from ..core.module import Module, register
from ..core.net import make_resolver
from ..core.observation import Obs, Rel
from ..util import normalize_host
from .common import finding

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")


def _resolve(res, name: str, rtype: str):
    try:
        return res.resolve(name, rtype, raise_on_no_answer=False), None
    except dns.resolver.NXDOMAIN:
        return None, "NXDOMAIN"
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        return None, type(exc).__name__
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


@register
class DnsResolve(Module):
    name = "dns_resolve"
    description = "Resolves in-scope hostnames (A/AAAA/CNAME/MX/TXT/NS), detects wildcards and dangling CNAMEs."
    phase = "resolve"
    active = False  # queries resolvers, not target web hosts
    tools = ["dnsx"]
    produces = ["ip", "subdomain"]

    def run(self, ctx) -> None:
        res = make_resolver(ctx.config)
        wildcard = self._wildcards(ctx, res)
        hosts = sorted({a.key for a in ctx.assets(["domain", "subdomain"]) if ctx.in_filter(a.key)})
        engine = ctx.option(self.name, "engine", "builtin")
        if engine == "dnsx" and ctx.tool("dnsx").available:
            return self._run_dnsx(ctx, hosts, wildcard)
        for host in hosts:
            self._resolve_host(ctx, res, host, wildcard)

    def _wildcards(self, ctx, res) -> dict[str, set[str]]:
        out = {}
        for root in ctx.scope.root_domains:
            ips: set[str] = set()
            for _ in range(2):
                ans, _err = _resolve(res, f"rf-{uuid.uuid4().hex[:10]}.{root}", "A")
                if ans is not None and ans.rrset:
                    ips |= {r.address for r in ans.rrset}
            if ips:
                out[root] = ips
                ctx.log.warning("wildcard DNS detected for *.%s -> %s", root, sorted(ips))
                ctx.emit(Obs("domain", root, {"wildcard_dns": sorted(ips)}))
        return out

    def _resolve_host(self, ctx, res, host: str, wildcard: dict[str, set[str]]) -> None:
        records: dict[str, list[str]] = {}
        chain: list[str] = []
        status = "NOERROR"
        a_ans, err = _resolve(res, host, "A")
        if err == "NXDOMAIN":
            status = "NXDOMAIN"
        if a_ans is not None:
            try:
                chain = [normalize_host(rr.name.to_text()) for rr in a_ans.chaining_result.cnames]
            except Exception:
                chain = []
            records["A"] = sorted(r.address for r in (a_ans.rrset or []))
            cname_targets = []
            for rrset in a_ans.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    cname_targets += [normalize_host(r.target.to_text()) for r in rrset]
            if cname_targets:
                records["CNAME"] = cname_targets
        for rtype in ("AAAA", "MX", "TXT", "NS"):
            ans, _ = _resolve(res, host, rtype)
            if ans is not None and ans.rrset:
                if rtype == "AAAA":
                    records[rtype] = sorted(r.address for r in ans.rrset)
                elif rtype == "TXT":
                    records[rtype] = sorted(b"".join(r.strings).decode("utf-8", "replace") for r in ans.rrset)
                else:
                    records[rtype] = sorted(r.to_text() for r in ans.rrset)
        if "CNAME" not in records:
            cn, _ = _resolve(res, host, "CNAME")
            if cn is not None and cn.rrset:
                records["CNAME"] = [normalize_host(r.target.to_text()) for r in cn.rrset]
        ips = records.get("A", []) + records.get("AAAA", [])
        root = ctx.scope.root_for(host)
        wc_ips = wildcard.get(root or "", set())
        wildcard_only = bool(ips) and bool(wc_ips) and set(ips) <= wc_ips and host != root
        ctx.action("dns %s -> %s %s%s", host, status, ",".join(ips) or "-",
                   f" CNAME {','.join(records['CNAME'])}" if records.get("CNAME") else "")
        ev = ctx.evidence("dns_answer", f"DNS resolution for {host}: {status}",
                          json.dumps({"host": host, "status": status, "records": records, "cname_chain": chain}, indent=2))
        rels: list[Rel] = []
        for ip in ips:
            rels.append(Rel("resolves_to", "ip", ip, confirmed=True,
                            target_attrs={"version": 6 if ":" in ip else 4}))
        for target in records.get("CNAME", []):
            if ctx.scope.host_in_scope(target):
                rels.append(Rel("cname_to", "subdomain", target, confirmed=True,
                                target_attrs={"+discovered_via": ["cname"]}))
            else:
                rels.append(Rel("cname_to", "third_party", target, confirmed=True,
                                target_attrs={"category": "cname-target"}))
        attrs = {"resolved": bool(ips), "dns_status": status, "ips": ips, "dns": records, "cname_chain": chain,
                 "wildcard_match": wildcard_only}
        ctx.emit(Obs("subdomain", host, attrs, evidence_id=ev, relations=rels,
                     confidence=0.5 if wildcard_only else None))
        # Dangling CNAME: alias exists but its target does not resolve.
        for target in records.get("CNAME", []):
            if not ips:
                tans, terr = _resolve(res, target, "A")
                if terr == "NXDOMAIN" or (tans is not None and not tans.rrset):
                    finding(ctx, "dns.dangling_cname", host, "Potential dangling CNAME (candidate; manual verification required)", "medium",
                            f"{host} is an alias for {target}, which returned {terr or 'no A records'}. Dangling "
                            "aliases to deprovisioned cloud resources can sometimes be claimed by third parties. This is an "
                            "indicator only, not a confirmed takeover.",
                            ev, "Manually verify ownership of the CNAME target; remove the record if unused.",
                            category="dns", subject_type="subdomain", extra={"cname_target": target})

    def _run_dnsx(self, ctx, hosts: list[str], wildcard) -> None:
        args = ["-silent", "-json", "-a", "-aaaa", "-cname", "-resp"]
        resolvers = ctx.config.get("dns.resolvers") or []
        if resolvers:
            args += ["-r", ",".join(resolvers)]
        proc = ctx.run_tool("dnsx", args, input_text="\n".join(hosts))
        ev = ctx.evidence("tool_output", "dnsx JSONL output", proc.stdout, ".jsonl")
        for obs in parse_dnsx(proc.stdout, ev):
            if ctx.scope.host_in_scope(obs.key):
                ctx.emit(obs)


def parse_dnsx(output: str, evidence_id: str | None = None) -> list[Obs]:
    out = []
    for line in output.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        host = normalize_host(row.get("host"))
        ips = list(row.get("a") or []) + list(row.get("aaaa") or [])
        records = {k.upper(): v for k, v in row.items() if k in ("a", "aaaa", "cname", "mx", "ns", "txt") and v}
        rels = [Rel("resolves_to", "ip", ip, confirmed=True) for ip in ips]
        out.append(Obs("subdomain", host, {"resolved": bool(ips), "ips": ips, "dns": records,
                                           "dns_status": row.get("status_code", "NOERROR")},
                       source="dnsx", evidence_id=evidence_id, relations=rels))
    return out
