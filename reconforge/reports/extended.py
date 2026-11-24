"""Derived intelligence views added to report data (and therefore JSON, API, dashboard)."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

VALIDATION_SOURCES = {"dns_resolve", "dnsx", "http_probe", "httpx", "asn_intel", "http_intel", "tech_detect", "whatweb",
                      "security_config", "cloud_intel", "cve_intel", "screenshots", "seed", "port_scan", "tls_inspect",
                      "api_discovery", "identity_intel", "web_metadata", "dns_security", "ip_intelligence"}
ENV_WORDS = re.compile(r"^(dev|develop|staging|stage|stg|test|qa|uat|beta|sandbox|demo|preprod|prod|old|new|internal)$")

LIMITATIONS = [
    "Findings are observations from externally visible evidence; none were exploited or confirmed.",
    "CVE and end-of-life matches compare advertised version strings only; backported fixes or misleading banners cause false positives.",
    "Potentially dangling DNS records are candidates requiring manual verification, not confirmed takeovers.",
    "Secret-like patterns are reported with redacted values and were never used or validated against any service.",
    "Third-party, CDN and shared-hosting infrastructure referenced by the target is not assumed to be owned by the target.",
    "Passive datasets can be stale or incomplete; absence of an asset in this report does not prove it does not exist.",
    "Only GET/HEAD requests were sent to in-scope hosts; authenticated areas and state-changing functionality were not assessed.",
]


def _stem(label: str) -> str:
    parts = [p for p in re.split(r"[-_.]", label) if p and not ENV_WORDS.match(p)]
    return re.sub(r"\d+$", "", parts[0]) if parts else label


def extend(d: dict, assets_by_type: dict, scan) -> dict:
    roots = d["target"]["root_domains"]
    hosts = [h for h in d["hosts"] if h["scope"] == "in_scope"]

    # --- source comparison: which providers produce unique assets
    per_source, found_by = defaultdict(set), defaultdict(set)
    for h in hosts:
        disc = {s for s in h["sources"] if s not in VALIDATION_SOURCES} | set(h.get("discovered_via") or [])
        disc -= VALIDATION_SOURCES
        for s in disc:
            per_source[s].add(h["key"])
            found_by[h["key"]].add(s)
    comparison = []
    for src, keys in sorted(per_source.items(), key=lambda kv: -len(kv[1])):
        unique = sorted(k for k in keys if found_by[k] == {src})
        comparison.append({"source": src, "hosts": len(keys), "unique": len(unique), "unique_hosts": unique[:50]})
    d["source_comparison"] = comparison

    # --- resolved / unresolved lists and naming clusters
    d["resolved_hosts"] = sorted(h["key"] for h in hosts if h["resolved"])
    d["unresolved_hosts"] = sorted(h["key"] for h in hosts if not h["resolved"])
    clusters = defaultdict(list)
    for h in hosts:
        root = next((r for r in roots if h["key"].endswith("." + r)), None)
        if root:
            clusters[_stem(h["key"][: -len(root) - 1].split(".")[0])].append(h["key"])
    by_ip = defaultdict(list)
    for h in hosts:
        for ip in h["ips"]:
            by_ip[ip].append(h["key"])
    d["subdomain_clusters"] = {
        "by_name_pattern": {k: sorted(v) for k, v in clusters.items() if len(v) > 1},
        "by_ip": {k: sorted(v) for k, v in by_ip.items() if len(v) > 1},
        "by_environment": {env: sorted(h["key"] for h in hosts if re.search(rf"(^|[.-]){env}([.-]|$)", h["key"].split(".")[0]))
                           for env in ("dev", "staging", "test", "qa", "uat", "beta", "internal", "admin", "old")
                           if any(re.search(rf"(^|[.-]){env}([.-]|$)", h["key"].split(".")[0]) for h in hosts)},
    }

    # --- DNS & email infrastructure
    dns_infra = []
    for dom in assets_by_type.get("domain", []):
        a = dom.attributes or {}
        sec = a.get("dns_security") or {}
        dns_infra.append({"domain": dom.key, "nameservers": sec.get("nameservers", []), "dnssec": sec.get("dnssec"),
                          "caa": sec.get("caa", []), "mx": sec.get("mx") or (a.get("dns_public") or {}).get("MX", []),
                          "spf": sec.get("spf", []), "spf_dns_lookups": sec.get("spf_dns_lookups"),
                          "dmarc": sec.get("dmarc", []), "dmarc_policy": sec.get("dmarc_policy"),
                          "dkim_selectors_found": sec.get("dkim_selectors_found", []), "mta_sts": bool(sec.get("mta_sts")),
                          "tls_rpt": bool(sec.get("tls_rpt")), "bimi": bool(sec.get("bimi")),
                          "registration": a.get("registration"), "wildcard_dns": a.get("wildcard_dns")})
    d["dns_infrastructure"] = dns_infra
    d["email_findings"] = [f for f in d["findings"] if f["attributes"].get("category") == "email"]
    cname_chains = [{"host": h["key"], "chain": h["attributes"].get("cname_chain") or h["cname"]} for h in hosts if h["cname"]]
    d["cname_analysis"] = cname_chains

    # --- HTTP intelligence & vhost/application grouping
    d["http_profiles"] = [{"app": a["key"], **(a["attributes"].get("http_profile") or {})} for a in d["web_apps"]
                          if a["attributes"].get("http_profile")]
    d["http_vs_https"] = [{"host": h["key"], **(h["attributes"].get("http_summary") or {}).get("http_vs_https", {})}
                          for h in hosts if (h["attributes"].get("http_summary") or {}).get("http_vs_https")]
    by_cert = defaultdict(list)
    for c in d["certificates"]:
        if len(c["presented_by"]) > 1:
            by_cert[f"{c['subject_cn']} ({c['key'][:12]})"] = c["presented_by"]
    apps_by_ip = defaultdict(list)
    for a in d["web_apps"]:
        apps_by_ip[a["ip"]].append(a["key"])
    d["vhost_inventory"] = {
        "applications_by_ip": {k: sorted(v) for k, v in apps_by_ip.items() if k},
        "shared_certificates": dict(by_cert),
        "default_vhost_only_hosts": sorted(h["key"] for h in hosts if h["attributes"].get("default_vhost_only") and not h["web_apps"]),
        "default_vhost_origins": sorted({o for h in hosts for o in (h["attributes"].get("default_vhost_only") or [])}),
        "redirects": [{"from": a["key"], "to": a["attributes"].get("redirect")} for a in d["web_apps"] if a["attributes"].get("redirect")],
    }

    # --- identity, third parties, parameters, documents, secrets, historical URLs
    d["identity"] = [{"app": a["key"], **a["attributes"]["identity"]} for a in d["web_apps"] if a["attributes"].get("identity")]
    tp = defaultdict(list)
    for t in d["third_parties"]:
        tp[t["attributes"].get("category") or "external"].append({"domain": t["key"], "service": t["attributes"].get("service"),
                                                                    "referenced_by": t["referenced_by"]})
    d["third_party_inventory"] = dict(sorted(tp.items()))
    params = defaultdict(set)
    for e in d["endpoints"]:
        for p in (e["attributes"].get("params") or []):
            params[p].add(e["key"])
    d["parameter_inventory"] = [{"name": k, "endpoints": len(v), "examples": sorted(v)[:5]} for k, v in
                                sorted(params.items(), key=lambda kv: -len(kv[1]))]
    cats = Counter(c for e in d["endpoints"] for c in (e["attributes"].get("url_categories") or ["other"]))
    d["endpoint_categories"] = dict(cats.most_common())
    d["documents"] = [e for e in d["endpoints"] if e["kind"] == "document"]
    d["historical_urls"] = [e for e in d["endpoints"] if e["attributes"].get("historical")]
    d["secret_exposures"] = [{"location": f["attributes"].get("js_file") or f["attributes"].get("subject"),
                              "pattern": f["attributes"].get("pattern"), "redacted": f["attributes"].get("description"),
                              "evidence": f["evidence"], "confidence": f["confidence"]}
                             for f in d["findings"] if f["attributes"].get("rule", "").startswith("exposure.secret")]
    d["ip_intelligence"] = [{"ip": i["key"], **{k: v for k, v in i["attributes"].items() if k.startswith("intel_")}}
                            for i in d["ips"] if any(k.startswith("intel_") for k in i["attributes"])]

    # --- screenshots grouped by visual similarity
    try:
        from ..modules.screenshots import group_by_similarity

        items = [(a["key"], a["attributes"]["screenshot_phash"]) for a in d["web_apps"] if a["attributes"].get("screenshot_phash")]
        # near-blank renders (almost no gradients) all hash alike; list them separately instead of "similar"
        blank = [k for k, h in items if bin(int(h, 16)).count("1") <= 3]
        d["screenshot_near_blank"] = sorted(blank)
        d["screenshot_groups"] = [g for g in group_by_similarity([i for i in items if i[0] not in blank]) if len(g) > 1]
    except Exception:
        d["screenshot_groups"], d["screenshot_near_blank"] = [], []

    # --- coverage & limitations
    d["coverage"] = (scan.summary or {}).get("coverage") or {}
    d["limitations"] = LIMITATIONS
    return d
