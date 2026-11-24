"""OSINT and analysis modules (no traffic to target web hosts).

* url_patterns      – gf-style classification of every collected URL with parameters into
                      vulnerability-class candidate lists (xss, sqli, ssrf, redirect, lfi, rce, idor, ...),
                      plus credentials/tokens leaked in URLs (values redacted)
* lookalike_domains – dnstwist-style typosquat/look-alike candidates checked with DNS only
* broken_links      – external link domains that no longer exist (broken-link hijacking candidates; DNS only)
* asn_prefixes      – prefixes announced by the target's ASNs (RIPEstat) as candidate IP ranges
* dork_builder      – ready-to-open search-engine / code-search / internet-scan pivots (no requests)
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, quote_plus, urlsplit

import dns.resolver

from ..core.module import Module, SkipModule, register
from ..core.net import make_resolver
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_host
from .common import finding

# ----------------------------------------------------------------------------- url_patterns

GF = {
    "xss": {"q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p",
            "month", "image", "list_type", "url", "terms", "categoryid", "key", "l", "begindate", "enddate", "callback", "message",
            "msg", "text", "title", "comment"},
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name", "sort", "where", "search", "params", "process",
             "row", "view", "table", "from", "sel", "results", "sleep", "fetch", "order", "keyword", "column", "field", "delete",
             "string", "number", "filter", "category", "item", "pid", "uid", "cat"},
    "ssrf": {"dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val",
             "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show",
             "navigation", "open", "file", "document", "folder", "pg", "php_path", "style", "doc", "img", "filename", "proxy",
             "target", "endpoint", "webhook", "src", "source", "link"},
    "redirect": {"next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect",
                 "return", "returnto", "return_to", "checkout_url", "continue", "return_path", "success", "login", "logout",
                 "goto", "image_url", "go", "out", "to", "forward", "returnurl", "back", "callback_url", "service"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "php_path", "doc", "page", "name",
            "cat", "dir", "action", "board", "date", "detail", "download", "prefix", "include", "inc", "locate", "show", "site",
            "type", "view", "content", "layout", "mod", "conf", "filename", "filepath", "lang"},
    "rce": {"cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load",
            "process", "step", "read", "function", "req", "feature", "exe", "module", "payload", "run", "print", "shell"},
    "idor": {"id", "user", "user_id", "userid", "account", "account_id", "number", "order", "order_id", "no", "doc", "key",
             "email", "group", "profile", "edit", "report", "invoice", "uid", "pid", "customer", "customer_id", "ticket"},
    "debug": {"debug", "test", "dbg", "admin", "cfg", "config", "env", "verbose", "trace", "dev", "internal"},
}
SECRET_PARAMS = re.compile(r"^(pass(word|wd)?|pwd|token|access_token|refresh_token|id_token|api[_-]?key|apikey|secret|client_secret|"
                           r"auth|authorization|session(id)?|sid|jwt|key|private_key|signature|sig|x-amz-signature|code)$", re.I)
JUICY_EXT = re.compile(r"\.(bak|old|orig|sql|sqlite|db|zip|tar|tgz|gz|rar|7z|env|log|conf|config|ini|ya?ml|xml|json|csv|xlsx?|docx?|"
                       r"pdf|key|pem|p12|pfx|swp|git|svn|DS_Store|backup|dump)$", re.I)


def classify_url(url: str) -> tuple[set[str], list[str]]:
    """(candidate classes, names of parameters that look like secrets)."""
    parts = urlsplit(url)
    names = {k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)}
    classes = {cls for cls, keys in GF.items() if names & keys}
    if JUICY_EXT.search(parts.path):
        classes.add("interesting_files")
    if names:
        classes.add("parameters")
    secrets = sorted({k for k, v in parse_qsl(parts.query, keep_blank_values=True) if SECRET_PARAMS.match(k) and len(v) >= 6})
    if secrets:
        classes.add("secrets_in_url")
    return classes, secrets


def redact_query(url: str) -> str:
    parts = urlsplit(url)
    q = "&".join(f"{k}=<redacted>" if SECRET_PARAMS.match(k) else f"{k}={v[:40]}" for k, v in parse_qsl(parts.query, keep_blank_values=True))
    return f"{parts.scheme}://{parts.netloc}{parts.path}" + (f"?{q}" if q else "")


@register
class UrlPatterns(Module):
    name = "url_patterns"
    description = "gf-style classification of collected URLs into xss/sqli/ssrf/redirect/lfi/rce/idor candidate lists; tokens in URLs (redacted)."
    phase = "assessment"
    active = False
    produces = ["finding"]

    def run(self, ctx) -> None:
        eps = [e for e in ctx.live("endpoint") if e.key.startswith("http")]
        if not eps:
            raise SkipModule("no URLs collected")
        buckets: dict[str, list[str]] = defaultdict(list)
        secret_hits: dict[str, list[str]] = defaultdict(list)
        params: dict[str, int] = defaultdict(int)
        for e in eps:
            classes, secrets = classify_url(e.key)
            for k, _ in parse_qsl(urlsplit(e.key).query, keep_blank_values=True):
                params[k] += 1
            if not classes:
                continue
            for c in classes:
                buckets[c].append(e.key if c != "secrets_in_url" else redact_query(e.key))
            if secrets:
                secret_hits[host_of(e.key)].append(redact_query(e.key))
            if classes - {"parameters"}:
                ctx.emit(Obs("endpoint", e.key, {"+candidate_classes": sorted(classes - {"parameters"})}))
        summary = {c: len(v) for c, v in sorted(buckets.items())}
        ctx.action("url patterns over %d URL(s): %s", len(eps), ", ".join(f"{k}={v}" for k, v in summary.items()) or "none")
        ev = ctx.evidence("url_patterns", f"gf-style URL classification ({len(eps)} URLs)",
                          json.dumps({"summary": summary, "top_parameters": sorted(params.items(), key=lambda x: -x[1])[:200],
                                      "buckets": {c: sorted(set(v))[:3000] for c, v in buckets.items()}}, indent=1))
        ctx.shared["url_patterns"] = {c: sorted(set(v)) for c, v in buckets.items()}
        for root in ctx.scope.root_domains or [None]:
            if root:
                ctx.emit(Obs("domain", root, {"url_patterns": summary,
                                              "top_parameters": [k for k, _ in sorted(params.items(), key=lambda x: -x[1])[:50]]},
                             evidence_id=ev))
        for host, urls in secret_hits.items():
            finding(ctx, "disclosure.secret_in_url", host, "Credentials or tokens in URLs", "low",
                    f"{len(urls)} collected URL(s) on {host} carry credential-like parameters (values redacted), e.g. {urls[0]}. "
                    "URLs end up in logs, archives and referrer headers.", ev,
                    "Move secrets out of query strings; rotate any that were exposed.", category="disclosure",
                    extra={"examples": urls[:10]})
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": sum(summary.values())}


# ----------------------------------------------------------------------------- lookalike_domains

KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "o",
            "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn", "k": "jilm", "l": "kop",
            "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"}
HOMOGLYPH = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"],
             "g": ["q"], "b": ["d"], "d": ["b"], "rn": ["m"], "vv": ["w"], "cl": ["d"]}
ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "app", "online", "site", "xyz", "us", "ca", "uk", "co.uk", "de", "in",
            "cc", "me", "store", "shop", "support", "live"]
AFFIX = ["login", "secure", "account", "support", "help", "my", "online", "portal", "auth", "verify", "pay", "mail", "web"]


def lookalikes(domain: str, limit: int = 400) -> dict[str, str]:
    """{candidate: technique} for a registrable domain such as example.com or example.co.uk."""
    label, _, suffix = domain.partition(".")
    out: dict[str, str] = {}

    def add(lab: str, tech: str, suf: str | None = None):
        lab = lab.strip("-")
        cand = f"{lab}.{suf or suffix}"
        if lab and cand != domain and re.fullmatch(r"[a-z0-9-]{1,63}", lab) and cand not in out:
            out[cand] = tech

    for i in range(len(label)):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] + label[i:], "repetition")
        if i < len(label) - 1:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
            add(label[:i + 1] + "-" + label[i + 1:], "hyphenation")
        for k in KEYBOARD.get(label[i], ""):
            add(label[:i] + k + label[i + 1:], "replacement")
        for c in range(8):  # bitsquatting
            ch = chr(ord(label[i]) ^ (1 << c))
            if re.fullmatch(r"[a-z0-9-]", ch):
                add(label[:i] + ch + label[i + 1:], "bitsquatting")
    for src, dsts in HOMOGLYPH.items():
        start = label.find(src)
        while start != -1:
            for d in dsts:
                add(label[:start] + d + label[start + len(src):], "homoglyph")
            start = label.find(src, start + 1)
    for w in AFFIX:
        add(f"{label}-{w}", "affix")
        add(f"{w}-{label}", "affix")
        add(f"{label}{w}", "affix")
    for t in ALT_TLDS:
        if t != suffix:
            add(label, "tld-swap", t)
    ordered = sorted(out.items(), key=lambda kv: ["tld-swap", "homoglyph", "affix", "omission", "transposition", "repetition",
                                                   "replacement", "hyphenation", "bitsquatting"].index(kv[1]))
    return dict(ordered[:limit])


def _lookup(res, name: str) -> dict | None:
    rec = {}
    for rtype in ("A", "MX", "NS"):
        try:
            ans = res.resolve(name, rtype, raise_on_no_answer=False)
            if ans.rrset:
                rec[rtype] = sorted(r.to_text().rstrip(".") for r in ans.rrset)[:5]
        except dns.resolver.NXDOMAIN:
            return None
        except Exception:
            continue
    return rec or None


@register
class LookalikeDomains(Module):
    name = "lookalike_domains"
    needs_domains = True
    description = "dnstwist-style typosquat / look-alike domains (omission, homoglyph, bitsquat, TLD swap, affixes) checked with DNS only."
    phase = "passive"
    active = False
    produces = ["third_party", "finding"]

    def run(self, ctx) -> None:
        res = make_resolver(ctx.config)
        limit = int(ctx.option(self.name, "max_candidates", 400))
        workers = int(ctx.option(self.name, "concurrency", 16))
        total = 0
        for root in ctx.scope.root_domains:
            cands = lookalikes(root, limit)
            ctx.action("look-alike check for %s: %d candidate(s) via DNS", root, len(cands))

            def one(name):
                ctx.limiter.wait()
                return name, _lookup(res, name)

            with ThreadPoolExecutor(max_workers=workers) as pool:
                registered = {n: r for n, r in pool.map(one, cands) if r}
            total += len(registered)
            rows = [{"domain": n, "technique": cands[n], **r} for n, r in sorted(registered.items())]
            ev = ctx.evidence("lookalike", f"{len(registered)} registered look-alike(s) of {root}",
                              json.dumps({"checked": len(cands), "registered": rows}, indent=1))
            for row in rows:
                ctx.action("look-alike %s (%s) -> A=%s MX=%s", row["domain"], row["technique"], ",".join(row.get("A", [])) or "-",
                           ",".join(row.get("MX", [])) or "-")
                ctx.emit(Obs("third_party", row["domain"], {"category": "lookalike-domain", "service": f"look-alike of {root}",
                                                            "technique": row["technique"], "dns": {k: row.get(k) for k in ("A", "MX", "NS")}},
                             evidence_id=ev, relations=[Rel("lookalike_of", "domain", root, confirmed=False, reverse=True)]))
                if row.get("MX"):
                    finding(ctx, "brand.lookalike_with_mail", row["domain"], "Look-alike domain can receive e-mail", "low",
                            f"{row['domain']} ({row['technique']} of {root}) is registered and publishes MX records "
                            f"({', '.join(row['MX'][:3])}). It may be a defensive registration or a phishing domain.", ev,
                            "Check ownership (WHOIS/RDAP); consider takedown or defensive registration.", category="brand",
                            subject_type="third_party", extra={"lookalike_of": root, "technique": row["technique"]})
            ctx.emit(Obs("domain", root, {"lookalikes": {"checked": len(cands), "registered": len(registered),
                                                         "domains": [r["domain"] for r in rows][:200]}}, evidence_id=ev))
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": total}


# ----------------------------------------------------------------------------- broken_links

MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in", "com.br", "com.mx",
                "co.za", "com.cn", "com.tr", "co.kr", "com.sg", "com.hk", "gc.ca", "qc.ca", "on.ca"}


def registrable(host: str) -> str:
    parts = normalize_host(host).split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@register
class BrokenLinks(Module):
    name = "broken_links"
    description = "External domains referenced by the target that are no longer registered (broken-link hijacking candidates; DNS only)."
    phase = "assessment"
    active = False
    produces = ["finding"]

    def run(self, ctx) -> None:
        tps = [t for t in ctx.live("third_party") if "." in t.key and (t.attributes or {}).get("category") != "lookalike-domain"]
        if not tps:
            raise SkipModule("no third-party references collected in this scan")
        domains: dict[str, list[str]] = defaultdict(list)
        for t in tps:
            domains[registrable(t.key)].append(t.key)
        res = make_resolver(ctx.config)

        def check(dom):
            ctx.limiter.wait()
            try:
                res.resolve(dom, "NS", raise_on_no_answer=False)
                return dom, False
            except dns.resolver.NXDOMAIN:
                return dom, True
            except Exception:
                return dom, False

        doms = sorted(domains)[: int(ctx.option(self.name, "max_domains", 600))]
        ctx.action("broken-link check: %d external registrable domain(s)", len(doms))
        with ThreadPoolExecutor(max_workers=12) as pool:
            dead = [d for d, nx in pool.map(check, doms) if nx]
        for d in dead:
            refs = sorted(domains[d])
            ctx.action("unregistered external domain %s (referenced as %s)", d, ", ".join(refs[:3]))
            ev = ctx.evidence("dns_answer", f"{d} returned NXDOMAIN", json.dumps({"domain": d, "referenced_hosts": refs}, indent=2))
            finding(ctx, "web.broken_link_hijack", d, "Reference to an unregistered domain (broken-link hijacking candidate)", "low",
                    f"The target references {', '.join(refs[:5])}, but {d} does not exist in DNS. Anyone could register it and "
                    "serve content (scripts, links, redirects) the target points to.", ev,
                    "Remove or update the reference, or register the domain defensively.", category="third_party",
                    subject_type="third_party", extra={"referenced_hosts": refs[:20]})
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": len(dead)}


# ----------------------------------------------------------------------------- asn_prefixes

SHARED_ASN = re.compile(r"cloudflare|amazon|aws|google|microsoft|azure|akamai|fastly|incapsula|imperva|digitalocean|ovh|"
                        r"hetzner|linode|oracle|alibaba|tencent|edgecast|stackpath|cdn77|leaseweb|github|vercel|netlify", re.I)


@register
class AsnPrefixes(Module):
    name = "asn_prefixes"
    description = "Prefixes announced by the target's own ASNs (RIPEstat) — candidate IP ranges to review (never auto-scanned)."
    phase = "network"
    active = False
    requires_internet = True
    produces = ["asn"]

    def run(self, ctx) -> None:
        import httpx

        asns = [a for a in ctx.live("asn") if not SHARED_ASN.search(str((a.attributes or {}).get("name") or ""))]
        if not asns:
            raise SkipModule("no organisation-owned ASNs observed (shared cloud/CDN networks are skipped)")
        base = ctx.option(self.name, "base_url", "https://stat.ripe.net").rstrip("/")
        cap = int(ctx.option(self.name, "max_prefixes", 500))
        with httpx.Client(timeout=30, headers={"User-Agent": ctx.config.get("network.user_agent")}) as client:
            for a in asns[: int(ctx.option(self.name, "max_asns", 10))]:
                ctx.action("provider ripestat announced-prefixes %s", a.key)
                try:
                    r = client.get(f"{base}/data/announced-prefixes/data.json", params={"resource": a.key})
                    r.raise_for_status()
                    pref = [p.get("prefix") for p in ((r.json().get("data") or {}).get("prefixes") or []) if p.get("prefix")]
                except Exception as exc:
                    ctx.log.warning("[%s] %s: %s", self.name, a.key, exc)
                    continue
                v4 = sorted(p for p in pref if ":" not in p)
                v6 = sorted(p for p in pref if ":" in p)
                ev = ctx.evidence("provider_response", f"announced prefixes of {a.key}", json.dumps({"ipv4": v4, "ipv6": v6}, indent=1))
                ctx.emit(Obs("asn", a.key, {"announced_prefixes": (v4 + v6)[:cap], "prefix_count": len(pref),
                                            "prefix_note": "Candidate ranges: confirm ownership before adding them as IP targets."},
                             evidence_id=ev))


# ----------------------------------------------------------------------------- dork_builder

def dorks_for(root: str) -> list[dict]:
    g = lambda q: f"https://www.google.com/search?q={quote_plus(q)}"
    items = [
        ("Google", "Subdomains (excluding www)", f"site:*.{root} -www.{root}"),
        ("Google", "Exposed documents", f"site:{root} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt OR ext:csv"),
        ("Google", "Config / backup / log files", f"site:{root} ext:env OR ext:log OR ext:sql OR ext:bak OR ext:old OR ext:conf OR ext:ini"),
        ("Google", "Directory listings", f"site:{root} intitle:\"index of\""),
        ("Google", "Login and admin pages", f"site:{root} inurl:login OR inurl:admin OR inurl:signin OR inurl:portal"),
        ("Google", "API endpoints and docs", f"site:{root} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:api-docs"),
        ("Google", "Error and debug pages", f"site:{root} \"stack trace\" OR \"Traceback\" OR \"Warning: mysql\" OR \"PHP Parse error\""),
        ("Google", "Open redirect parameters", f"site:{root} inurl:redirect= OR inurl:url= OR inurl:next= OR inurl:return="),
        ("Google", "Pastebin / code-sharing mentions", f"site:pastebin.com OR site:ghostbin.com OR site:justpaste.it \"{root}\""),
        ("Google", "Trello / Notion / Atlassian boards", f"site:trello.com OR site:notion.site OR site:atlassian.net \"{root}\""),
        ("Google", "Cloud storage references", f"site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com \"{root}\""),
    ]
    out = [{"engine": e, "title": t, "query": q, "url": g(q)} for e, t, q in items]
    out += [
        {"engine": "GitHub", "title": "Code mentioning the domain", "query": f"\"{root}\"",
         "url": f"https://github.com/search?q={quote_plus(chr(34) + root + chr(34))}&type=code"},
        {"engine": "GitHub", "title": "Possible secrets near the domain", "query": f"\"{root}\" password OR secret OR token OR apikey",
         "url": f"https://github.com/search?q={quote_plus(chr(34) + root + chr(34) + ' password OR secret OR token OR apikey')}&type=code"},
        {"engine": "Shodan", "title": "Hosts with certificates for the domain", "query": f"ssl.cert.subject.cn:\"{root}\"",
         "url": f"https://www.shodan.io/search?query={quote_plus('ssl.cert.subject.cn:' + chr(34) + root + chr(34))}"},
        {"engine": "Shodan", "title": "Hostname search", "query": f"hostname:\"{root}\"",
         "url": f"https://www.shodan.io/search?query={quote_plus('hostname:' + chr(34) + root + chr(34))}"},
        {"engine": "Censys", "title": "Hosts and certificates", "query": root,
         "url": f"https://search.censys.io/search?resource=hosts&q={quote_plus(root)}"},
        {"engine": "crt.sh", "title": "Certificate transparency", "query": f"%.{root}", "url": f"https://crt.sh/?q=%25.{root}"},
        {"engine": "Wayback", "title": "Archived URLs", "query": f"*.{root}/*", "url": f"https://web.archive.org/cdx/search/cdx?url=*.{root}/*&output=txt&fl=original&collapse=urlkey"},
        {"engine": "urlscan", "title": "Scans of the domain", "query": f"domain:{root}", "url": f"https://urlscan.io/search/#domain:{root}"},
        {"engine": "VirusTotal", "title": "Domain relations", "query": root, "url": f"https://www.virustotal.com/gui/domain/{root}/relations"},
        {"engine": "SecurityTrails", "title": "DNS history", "query": root, "url": f"https://securitytrails.com/domain/{root}/history/a"},
        {"engine": "DNSDumpster", "title": "DNS map", "query": root, "url": "https://dnsdumpster.com/"},
        {"engine": "BuiltWith", "title": "Technology profile", "query": root, "url": f"https://builtwith.com/{root}"},
    ]
    return out


@register
class DorkBuilder(Module):
    name = "dork_builder"
    needs_domains = True
    description = "Builds ready-to-open Google/GitHub/Shodan/Censys/CT/Wayback pivots for manual OSINT (sends no requests)."
    phase = "passive"
    active = False
    produces = ["domain"]

    def run(self, ctx) -> None:
        n = 0
        for root in ctx.scope.root_domains:
            d = dorks_for(root)
            n += len(d)
            ctx.emit(Obs("domain", root, {"dorks": d}))
        ctx.action("built %d OSINT pivot link(s)", n)
