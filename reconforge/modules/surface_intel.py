"""Extended attack-surface intelligence modules.

* favicon_hash    – GET /favicon.ico; Shodan-style MurmurHash3, MD5, product match, clusters of hosts
                    that share a favicon (pivot: ``http.favicon.hash:<n>``)
* waf_detect      – WAF / CDN / edge / load-balancer / API-gateway identification from responses
                    already collected (no new requests, no attack payloads)
* exposed_files   – GET a curated list of commonly exposed files (VCS metadata, env files, status
                    pages, backups). Soft-404 aware. Secret-bearing content is redacted in evidence
* well_known      – mobile app links, change-password, host-meta, nodeinfo, JWKS, web manifest,
                    ads.txt and humans.txt (GET only)
* source_maps     – detects publicly served JavaScript source maps and lists the original sources
* contact_intel   – e-mail addresses and social profiles published on collected pages (no requests)
* cors_check      – GET with a foreign / ``null`` Origin header to see whether it is reflected
* panel_detect    – identifies exposed administrative, DevOps, monitoring, VPN and mail interfaces
                    from collected responses (no requests, no login attempts)
* takeover_check  – matches CNAMEs to third-party services with known "unclaimed" response
                    fingerprints (candidates only; nothing is ever claimed)

All traffic is GET/HEAD through the scope-checked ``HttpFetcher``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections import defaultdict
from urllib.parse import urljoin, urlsplit

from ..core.module import Module, SkipModule, register
from ..core.net import HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_url, origin_of
from .common import finding


def _apps(ctx, skip_redirects: bool = True):
    out = []
    for a in ctx.live("web_app"):
        attrs = a.attributes or {}
        if not ctx.in_filter(attrs.get("host")):
            continue
        st = int(attrs.get("status") or 0)
        if skip_redirects and 300 <= st < 400:
            continue
        out.append(a)
    return out


def _tech(name: str, category: str) -> Rel:
    return Rel("uses", "technology", name, confirmed=True, attrs={"version": "", "confidence": 0.8, "matched": [category]},
               target_attrs={"name": name, "categories": [category]})


def _collected(ctx) -> dict[str, str]:
    """url -> html for every page collected in this scan (crawler pages + root responses)."""
    pages = dict(ctx.shared.get("pages", {}))
    for origin, res in ctx.shared.get("http_root", {}).items():
        pages.setdefault(normalize_url(origin + "/"), res.text)
    return pages


# --------------------------------------------------------------------------- favicon_hash

def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed — identical to ``mmh3.hash`` (used by Shodan favicon hashes)."""
    c1, c2, m = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h, n = seed & m, len(data)
    rot = lambda x, r: ((x << r) | (x >> (32 - r))) & m
    for i in range(0, n - n % 4, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = rot((k * c1) & m, 15) * c2 & m
        h = (rot(h ^ k, 13) * 5 + 0xE6546B64) & m
    tail, k = data[n - n % 4:], 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        h ^= rot((k * c1) & m, 15) * c2 & m
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & m
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & m
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def favicon_hash(body: bytes) -> int:
    return mmh3_32(base64.encodebytes(body))


KNOWN_FAVICONS = {81586312: "Jenkins", 116323821: "Spring Boot"}
ICON_LINK = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


@register
class FaviconHash(Module):
    name = "favicon_hash"
    description = "Favicon MurmurHash3 (Shodan-compatible) + MD5, product match and clusters of hosts sharing an icon."
    phase = "fingerprint"
    active = True
    produces = ["web_app"]

    def run(self, ctx) -> None:
        apps = _apps(ctx)
        if not apps:
            raise SkipModule("no web applications")
        known = {**KNOWN_FAVICONS, **{int(k): v for k, v in (ctx.option(self.name, "known", {}) or {}).items()}}
        cache = ctx.shared.get("http_root", {})
        fetcher = HttpFetcher(ctx)
        clusters: dict[int, list[str]] = defaultdict(list)
        try:
            for app in apps:
                url = app.key + "/favicon.ico"
                root = cache.get(app.key)
                if root is not None:
                    m = ICON_LINK.search(root.text[:100000])
                    href = HREF.search(m.group(0)) if m else None
                    if href and not href.group(1).startswith("data:"):
                        cand = urljoin(app.key + "/", href.group(1))
                        if ctx.scope.host_in_scope(host_of(cand)):
                            url = cand
                ctx.action("GET %s", url)
                r = fetcher.get(url)
                ctype = (r.header("content-type") or "").lower()
                if r.status != 200 or not r.body or "html" in ctype or len(r.body) < 32:
                    continue
                h = favicon_hash(r.body)
                info = {"url": url, "mmh3": h, "md5": hashlib.md5(r.body).hexdigest(), "size": len(r.body),
                        "content_type": ctype or None, "product": known.get(h), "shodan_query": f"http.favicon.hash:{h}"}
                clusters[h].append(app.key)
                ev = ctx.evidence("favicon", f"favicon {url} mmh3={h}", json.dumps(info, indent=2))
                ctx.emit(Obs("web_app", app.key, {"favicon": info}, evidence_id=ev))
                if info["product"]:
                    ctx.emit(Obs("web_app", app.key, {}, relations=[_tech(info["product"], "favicon")]))
            shared = {str(h): apps_ for h, apps_ in clusters.items() if len(apps_) > 1}
            for h, members in shared.items():
                for origin in members:
                    ctx.emit(Obs("web_app", origin, {"favicon_cluster": {"mmh3": int(h), "size": len(members),
                                                                        "peers": [m for m in members if m != origin][:20]}}))
            ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok",
                                                              "results": sum(len(v) for v in clusters.values()),
                                                              "detail": {"unique_icons": len(clusters), "shared_icons": len(shared)}}
        finally:
            fetcher.close()


# --------------------------------------------------------------------------- waf_detect

# (vendor, kind, header-name regex -> value regex | None, cookie-name regex, server regex)
EDGE_RULES = [
    ("Cloudflare", "waf/cdn", {"cf-ray": None, "cf-cache-status": None}, r"^(__cf_bm|cf_clearance|__cfruid)$", r"cloudflare"),
    ("Akamai", "waf/cdn", {"akamai-grn": None, "x-akamai-transformed": None, "akamai-cache-status": None},
     r"^(ak_bmsc|bm_sz|bm_sv|_abck)$", r"akamaighost|akamainetstorage"),
    ("Imperva Incapsula", "waf/cdn", {"x-iinfo": None, "x-cdn": r"incapsula|imperva"}, r"^(incap_ses_|visid_incap_|nlbi_)", None),
    ("AWS CloudFront", "cdn", {"x-amz-cf-id": None, "x-amz-cf-pop": None, "via": r"cloudfront"}, None, r"^cloudfront$"),
    ("AWS WAF", "waf", {"x-amzn-waf-action": None}, r"^aws-waf-token$", None),
    ("AWS Elastic Load Balancing", "load_balancer", {}, r"^(AWSALB|AWSALBCORS|AWSELB)$", r"awselb"),
    ("AWS API Gateway", "api_gateway", {"x-amzn-requestid": None, "x-amz-apigw-id": None}, None, None),
    ("Fastly", "cdn", {"x-fastly-request-id": None, "fastly-debug-digest": None, "x-served-by": r"cache-[a-z]{3}"}, None, None),
    ("Sucuri", "waf/cdn", {"x-sucuri-id": None, "x-sucuri-cache": None}, r"^sucuri", r"sucuri"),
    ("F5 BIG-IP", "load_balancer", {"x-wa-info": None}, r"^(BIGipServer|F5_|MRHSession|LastMRH_Session)", r"big-?ip"),
    ("F5 Advanced WAF (ASM)", "waf", {}, r"^TS[0-9a-f]{6,8}$", None),
    ("Azure Front Door", "waf/cdn", {"x-azure-ref": None, "x-fd-healthprobe": None}, None, None),
    ("Azure Application Gateway", "load_balancer", {}, r"^(ApplicationGatewayAffinity|ApplicationGatewayAffinityCORS)$",
     r"microsoft-azure-application-gateway"),
    ("Barracuda WAF", "waf", {}, r"^barra_counter_session", r"barracuda"),
    ("FortiWeb", "waf", {}, r"^(FORTIWAFSID|cookiesession1)$", r"fortiweb"),
    ("Citrix NetScaler ADC", "load_balancer", {"via": r"ns-cache", "cneonction": None}, r"^(citrix_ns_id|NSC_)", r"netscaler"),
    ("Google Cloud Load Balancing", "load_balancer", {"via": r"1\.1 google"}, r"^GCLB$", r"google frontend|^gws$"),
    ("Vercel", "edge", {"x-vercel-id": None, "x-vercel-cache": None}, None, r"^vercel$"),
    ("Netlify", "edge", {"x-nf-request-id": None}, None, r"^netlify$"),
    ("DDoS-Guard", "waf/cdn", {}, r"^__ddg", r"ddos-guard"),
    ("StackPath", "waf/cdn", {"x-sp-url": None, "x-hw": None}, None, None),
    ("Varnish", "cache", {"x-varnish": None, "via": r"varnish"}, None, None),
    ("Kong Gateway", "api_gateway", {"x-kong-upstream-latency": None, "x-kong-proxy-latency": None, "via": r"kong"}, None, r"^kong"),
    ("Envoy", "proxy", {"x-envoy-upstream-service-time": None}, None, r"^envoy$"),
    ("Apigee", "api_gateway", {"x-apigee-message-id": None}, None, None),
    ("ModSecurity", "waf", {}, None, r"mod_security|modsecurity"),
    ("Wordfence", "waf", {}, r"^wfvt_", None),
]


def detect_edge(headers: dict[str, str], cookies: list[str]) -> list[dict]:
    h = {k.lower(): v for k, v in headers.items()}
    names = [c.split("=", 1)[0].strip() for c in cookies]
    server = h.get("server", "")
    out = []
    for vendor, kind, hdrs, cookie_rx, server_rx in EDGE_RULES:
        ev = []
        for name, val_rx in hdrs.items():
            if name in h and (val_rx is None or re.search(val_rx, h[name], re.I)):
                ev.append(f"header {name}")
        if cookie_rx:
            ev += [f"cookie {n}" for n in names if re.search(cookie_rx, n, re.I)]
        if server_rx and server and re.search(server_rx, server, re.I):
            ev.append(f"server: {server}")
        if ev:
            out.append({"vendor": vendor, "kind": kind, "evidence": sorted(set(ev))[:6],
                        "confidence": round(min(0.5 + 0.2 * len(ev), 0.95), 2)})
    return out


@register
class WafDetect(Module):
    name = "waf_detect"
    description = "Identifies WAF / CDN / load balancer / API gateway in front of each web app (passive; no payloads)."
    phase = "fingerprint"
    active = False
    produces = ["web_app"]

    def run(self, ctx) -> None:
        cache = ctx.shared.get("http_root", {})
        if not cache:
            raise SkipModule("no HTTP responses collected in this scan")
        protected = 0
        for origin, res in cache.items():
            if not res.status:
                continue
            edges = detect_edge(res.headers, res.set_cookies())
            ctx.action("edge analysis %s -> %s", origin, ", ".join(e["vendor"] for e in edges) or "none")
            if not edges:
                ctx.emit(Obs("web_app", origin, {"edge": [], "waf": None}))
                continue
            waf = next((e["vendor"] for e in edges if "waf" in e["kind"]), None)
            protected += bool(waf)
            ev = ctx.evidence("edge_detection", f"edge stack for {origin}", json.dumps(edges, indent=2))
            ctx.emit(Obs("web_app", origin, {"edge": edges, "waf": waf}, evidence_id=ev,
                         relations=[_tech(e["vendor"], e["kind"]) for e in edges]))
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": protected,
                                                          "detail": {"apps": len(cache), "behind_waf": protected}}


# --------------------------------------------------------------------------- exposed_files

# path, body regex (bytes-safe text), severity, title, redaction ("keys" | "all" | None), head_only
EXPOSURES = [
    ("/.git/HEAD", r"^ref:\s*refs/", "medium", "Git repository metadata exposed", None, False),
    ("/.git/config", r"^\s*\[core\]", "medium", "Git config exposed", "all", False),
    ("/.svn/wc.db", r"^SQLite format 3", "medium", "Subversion working copy database exposed", "all", False),
    ("/.hg/requires", r"^(revlogv1|store|fncache|dotencode)", "medium", "Mercurial repository metadata exposed", None, False),
    ("/.env", r"^(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file exposed", "keys", False),
    ("/.env.production", r"^(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file exposed", "keys", False),
    ("/.aws/credentials", r"aws_access_key_id", "high", "Cloud credentials file exposed", "keys", False),
    ("/.htpasswd", r"^[^:\s<]{1,64}:\S{8,}$", "medium", "Password file exposed", "all", False),
    ("/wp-config.php.bak", r"DB_(NAME|USER|PASSWORD)", "high", "Configuration backup exposed", "all", False),
    ("/config.php.bak", r"<\?php", "high", "Configuration backup exposed", "all", False),
    ("/.vscode/sftp.json", r"\"(host|username)\"\s*:", "medium", "Editor deployment config exposed", "keys", False),
    ("/.DS_Store", r"^\x00\x00\x00\x01Bud1", "low", "macOS .DS_Store file exposed", None, False),
    ("/.idea/workspace.xml", r"<project version=", "low", "IDE workspace file exposed", None, False),
    ("/server-status", r"Apache Server Status", "low", "Apache server-status exposed", None, False),
    ("/server-info", r"Apache Server Information", "low", "Apache server-info exposed", None, False),
    ("/phpinfo.php", r"<title>phpinfo\(\)", "low", "phpinfo() page exposed", None, False),
    ("/info.php", r"<title>phpinfo\(\)", "low", "phpinfo() page exposed", None, False),
    ("/actuator/env", r"\"(propertySources|activeProfiles)\"", "medium", "Spring Boot actuator /env exposed", "all", False),
    ("/actuator/heapdump", None, "high", "Spring Boot heap dump exposed", None, True),
    ("/actuator", r"\"_links\"\s*:", "low", "Spring Boot actuator index exposed", None, False),
    ("/debug/pprof/", r"Types of profiles available", "low", "Go pprof debug endpoint exposed", None, False),
    ("/elmah.axd", r"Error Log for", "medium", "ELMAH error log exposed", None, False),
    ("/trace.axd", r"Application Trace", "medium", "ASP.NET trace exposed", None, False),
    ("/crossdomain.xml", r"allow-access-from\s+domain=\"\*\"", "low", "Permissive crossdomain.xml", None, False),
    ("/clientaccesspolicy.xml", r"<domain\s+uri=\"\*\"", "low", "Permissive clientaccesspolicy.xml", None, False),
    ("/docker-compose.yml", r"^(services|version)\s*:", "low", "docker-compose file exposed", "keys", False),
    ("/Dockerfile", r"^FROM\s+\S+", "info", "Dockerfile exposed", None, False),
    ("/package.json", r"\"(dependencies|devDependencies)\"\s*:", "info", "package.json exposed", None, False),
    ("/composer.json", r"\"require\"\s*:", "info", "composer.json exposed", None, False),
    ("/backup.zip", None, "medium", "Backup archive exposed", None, True),
    ("/backup.tar.gz", None, "medium", "Backup archive exposed", None, True),
    ("/site.zip", None, "medium", "Backup archive exposed", None, True),
    ("/database.sql", r"^(--|CREATE TABLE|INSERT INTO|/\*!)", "high", "Database dump exposed", "all", False),
]
ARCHIVE_TYPES = ("application/zip", "application/x-zip", "application/gzip", "application/x-gzip", "application/x-tar",
                 "application/octet-stream", "application/x-compressed")


def redact(text: str, mode: str | None, limit: int = 2000) -> str:
    """Never keep secret values: 'keys' keeps variable/field names only, 'all' keeps nothing."""
    if mode == "all":
        return f"<{len(text)} characters redacted — content intentionally not stored>"
    if mode == "keys":
        out = []
        for line in text.splitlines()[:200]:
            m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-\"]*)\s*[=:]", line)
            if m:
                out.append(f"{m.group(1).strip(chr(34))}=<redacted>")
        return "\n".join(out) or "<redacted>"
    return text[:limit]


@register
class ExposedFiles(Module):
    name = "exposed_files"
    description = "Checks a curated list of commonly exposed files (VCS metadata, env/config, status pages, backups). Soft-404 aware; secrets redacted."
    phase = "content"
    active = True
    produces = ["endpoint", "finding"]

    def run(self, ctx) -> None:
        apps = _apps(ctx)
        if not apps:
            raise SkipModule("no web applications")
        extra = [(p, None, "low", "Custom path reachable", None, False) for p in ctx.option(self.name, "extra_paths", []) or []]
        rules = EXPOSURES + extra
        fetcher = HttpFetcher(ctx)
        hits = 0
        try:
            for app in apps:
                if ctx.incremental and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host"))
                    continue
                base = fetcher.get(f"{app.key}/rf-{uuid.uuid4().hex[:12]}.txt")
                soft = (base.status == 200, len(base.body), hashlib.sha256(base.body).hexdigest() if base.body else None)
                for path, rx, sev, title, mode, head_only in rules:
                    url = app.key + path
                    r = fetcher.get(url, method="HEAD" if head_only else "GET")
                    ctx.action("%s %s -> %s", "HEAD" if head_only else "GET", url, r.status)
                    if r.status != 200:
                        continue
                    ctype = (r.header("content-type") or "").lower()
                    if head_only:
                        size = int(r.header("content-length") or 0)
                        if not size or "html" in ctype or (soft[0] and abs(size - soft[1]) < 64):
                            continue
                        if path.endswith((".zip", ".gz")) and not any(t in ctype for t in ARCHIVE_TYPES):
                            continue
                        body_note = f"HEAD only — {size} bytes, {ctype or 'no content-type'}; content not downloaded"
                    else:
                        if soft[2] and hashlib.sha256(r.body).hexdigest() == soft[2]:
                            continue
                        text = r.body.decode("latin-1") if path.endswith((".DS_Store", ".db")) else r.text
                        if rx and not re.search(rx, text[:20000], re.M):
                            continue
                        if not rx and "html" in ctype:
                            continue
                        body_note = redact(text, mode)
                    hits += 1
                    evidence = format_http_evidence(r, "HEAD" if head_only else "GET", body_limit=0) + "\n\n" + body_note
                    ev = ctx.evidence("http_response", f"{title}: {url}", evidence)
                    nurl = normalize_url(url)
                    ctx.emit(Obs("endpoint", nurl, {"url": nurl, "host": host_of(nurl), "path": path, "kind": "exposed_file",
                                                    "status": 200, "content_type": ctype or None, "exposure": title,
                                                    "+discovered_via": [self.name]}, evidence_id=ev,
                                 relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
                    finding(ctx, f"exposure.{re.sub(r'[^a-z0-9]+', '_', path.lower()).strip('_') or 'root'}", nurl, title, sev,
                            f"{nurl} is publicly reachable and matches the expected signature for this file type."
                            + (" Content was redacted and not stored." if mode else ""), ev,
                            "Remove the file from the web root or block it at the server; rotate any credentials it may have contained.",
                            category="exposure", subject_type="endpoint", extra={"path": path})
            ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": hits,
                                                              "detail": {"apps": len(apps), "paths": len(rules)}}
        finally:
            fetcher.close()


# --------------------------------------------------------------------------- well_known

WELL_KNOWN = ["/.well-known/assetlinks.json", "/.well-known/apple-app-site-association", "/apple-app-site-association",
              "/.well-known/change-password", "/.well-known/host-meta", "/.well-known/nodeinfo", "/.well-known/jwks.json",
              "/.well-known/gpc.json", "/manifest.json", "/site.webmanifest", "/ads.txt", "/app-ads.txt", "/humans.txt"]


def parse_well_known(path: str, text: str) -> dict | None:
    """Return structured metadata for a well-known document, or None if it does not look like one."""
    try:
        doc = json.loads(text) if text.lstrip()[:1] in ("{", "[") else None
    except ValueError:
        doc = None
    if path.endswith("assetlinks.json") and isinstance(doc, list):
        apps = sorted({(s.get("target") or {}).get("package_name") for s in doc if isinstance(s, dict)} - {None})
        return {"kind": "android_app_links", "mobile_apps": [f"android:{p}" for p in apps]} if apps else None
    if "apple-app-site-association" in path and isinstance(doc, dict):
        ids = set()
        for d in ((doc.get("applinks") or {}).get("details") or []):
            ids.update([d["appID"]] if d.get("appID") else d.get("appIDs") or [])
        ids.update(((doc.get("webcredentials") or {}).get("apps")) or [])
        return {"kind": "ios_app_links", "mobile_apps": sorted(f"ios:{i}" for i in ids)} if ids else None
    if path.endswith("nodeinfo") and isinstance(doc, dict) and "links" in doc:
        return {"kind": "nodeinfo", "links": [l.get("href") for l in doc["links"] if isinstance(l, dict)][:5]}
    if path.endswith("jwks.json") and isinstance(doc, dict) and isinstance(doc.get("keys"), list):
        return {"kind": "jwks", "keys": len(doc["keys"]), "algorithms": sorted({k.get("alg") or k.get("kty") for k in doc["keys"]
                                                                               if isinstance(k, dict)} - {None})}
    if path.endswith("gpc.json") and isinstance(doc, dict) and "gpc" in doc:
        return {"kind": "global_privacy_control", "gpc": doc.get("gpc")}
    if path.endswith(("manifest.json", ".webmanifest")) and isinstance(doc, dict) and ("name" in doc or "short_name" in doc):
        return {"kind": "web_manifest", "app_name": doc.get("name") or doc.get("short_name"), "start_url": doc.get("start_url"),
                "related_applications": [f"{a.get('platform')}:{a.get('id') or a.get('url')}"
                                         for a in doc.get("related_applications") or [] if isinstance(a, dict)]}
    if path.endswith("host-meta") and "<XRD" in text[:2000]:
        return {"kind": "host_meta", "templates": re.findall(r'template="([^"]+)"', text)[:5]}
    if path.endswith("ads.txt"):
        lines = [l.split("#")[0].strip() for l in text.splitlines()]
        sellers = [l.split(",") for l in lines if l.count(",") >= 2]
        if not sellers:
            return None
        return {"kind": "ads_txt", "entries": len(sellers),
                "ad_systems": sorted({s[0].strip().lower() for s in sellers})[:40]}
    if path.endswith("humans.txt") and "<html" not in text[:500].lower() and len(text.strip()) > 10:
        return {"kind": "humans_txt", "preview": text.strip()[:400]}
    return None


@register
class WellKnown(Module):
    name = "well_known"
    description = "Mobile app links (Android/iOS), change-password, host-meta, nodeinfo, JWKS, web manifest, ads.txt, humans.txt (GET only)."
    phase = "content"
    active = True
    produces = ["endpoint", "third_party"]

    def run(self, ctx) -> None:
        apps = _apps(ctx)
        if not apps:
            raise SkipModule("no web applications")
        fetcher = HttpFetcher(ctx)
        found = 0
        try:
            for app in apps:
                if ctx.incremental and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host"))
                    continue
                mobile: set[str] = set()
                for path in WELL_KNOWN:
                    url = app.key + path
                    r = fetcher.get(url)
                    ctx.action("GET %s -> %s", url, r.status)
                    if path.endswith("change-password") and r.status and 300 <= r.status < 400:
                        meta = {"kind": "change_password", "location": r.header("location")}
                    elif r.status == 200:
                        meta = parse_well_known(path, r.text)
                    else:
                        meta = None
                    if not meta:
                        continue
                    found += 1
                    mobile.update(meta.get("mobile_apps", []))
                    ev = ctx.evidence("http_response", f"{meta['kind']} at {url}", format_http_evidence(r, body_limit=6000))
                    nurl = normalize_url(url)
                    ctx.emit(Obs("endpoint", nurl, {"url": nurl, "host": host_of(nurl), "path": path, "kind": "well_known",
                                                    "status": r.status, "well_known": meta, "+discovered_via": [self.name]},
                                 evidence_id=ev, relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
                    for system in meta.get("ad_systems", [])[:40]:
                        if "." in system:
                            ctx.emit(Obs("third_party", system, {"category": "advertising", "service": "ads.txt seller"},
                                         relations=[Rel("authorises_seller", "web_app", app.key, confirmed=True, reverse=True)]))
                if mobile:
                    ctx.emit(Obs("web_app", app.key, {"+mobile_apps": sorted(mobile)}))
            ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": found}
        finally:
            fetcher.close()


# --------------------------------------------------------------------------- source_maps

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


@register
class SourceMaps(Module):
    name = "source_maps"
    description = "Detects publicly served JavaScript source maps and lists the original source files they reveal."
    phase = "content"
    active = True
    produces = ["endpoint", "finding"]

    def run(self, ctx) -> None:
        files = [a for a in ctx.live("js_file") if ctx.in_filter((a.attributes or {}).get("host"))]
        if not files:
            raise SkipModule("no in-scope JavaScript files discovered")
        bodies = ctx.shared.get("js_bodies", {})
        limit = int(ctx.option(self.name, "max_files", 200))
        fetcher = HttpFetcher(ctx)
        exposed = 0
        try:
            for js in files[:limit]:
                body = bodies.get(js.key)
                m = SOURCEMAP_RE.search(body[-4000:]) if body else None
                if m and m.group(1).startswith("data:"):
                    continue  # inline map – already public in the bundle
                url = urljoin(js.key, m.group(1)) if m else js.key.split("?")[0] + ".map"
                if not ctx.scope.host_in_scope(host_of(url)):
                    continue
                r = fetcher.get(url)
                ctx.action("GET %s -> %s", url, r.status)
                if r.status != 200 or not r.text.lstrip().startswith("{"):
                    continue
                try:
                    doc = json.loads(r.text)
                except ValueError:
                    continue
                sources = [s for s in doc.get("sources") or [] if isinstance(s, str)]
                if not sources:
                    continue
                exposed += 1
                info = {"map": url, "for": js.key, "version": doc.get("version"), "sources": len(sources),
                        "embeds_source_content": bool(doc.get("sourcesContent")),
                        "sample_sources": sorted({re.sub(r"^webpack:/+", "", s) for s in sources})[:60]}
                ev = ctx.evidence("source_map", f"source map {url} ({len(sources)} sources)", json.dumps(info, indent=2))
                nurl = normalize_url(url)
                ctx.emit(Obs("endpoint", nurl, {"url": nurl, "host": host_of(nurl), "kind": "source_map", "status": 200,
                                                "source_map": {k: v for k, v in info.items() if k != "sample_sources"},
                                                "+discovered_via": [self.name]}, evidence_id=ev,
                             relations=[Rel("has_source_map", "js_file", js.key, confirmed=True, reverse=True)]))
                finding(ctx, "exposure.source_map", nurl, "JavaScript source map publicly accessible", "low",
                        f"{nurl} exposes {len(sources)} original source paths"
                        + (" including full source content." if info["embeds_source_content"] else "."), ev,
                        "Do not deploy .map files to production, or restrict access to them.",
                        category="exposure", subject_type="endpoint", extra={"sources": len(sources)})
            ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": exposed}
        finally:
            fetcher.close()


# --------------------------------------------------------------------------- contact_intel

EMAIL_RE = re.compile(r"(?<![\w.%+-])([a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9.-]+\.[a-z]{2,24})(?![\w-])", re.I)
NOT_EMAIL_TLD = ("png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff", "woff2")
SOCIAL = [("twitter.com", "X / Twitter"), ("x.com", "X / Twitter"), ("linkedin.com", "LinkedIn"), ("github.com", "GitHub"),
          ("facebook.com", "Facebook"), ("instagram.com", "Instagram"), ("youtube.com", "YouTube"), ("t.me", "Telegram"),
          ("tiktok.com", "TikTok"), ("mastodon.social", "Mastodon"), ("discord.gg", "Discord"), ("reddit.com", "Reddit")]
SOCIAL_RE = re.compile(r"https?://(?:www\.)?(" + "|".join(re.escape(d) for d, _ in SOCIAL) + r")/([A-Za-z0-9_.\-/@]{2,80})", re.I)


def extract_contacts(text: str) -> tuple[set[str], set[tuple[str, str]]]:
    emails = {e.lower() for e in EMAIL_RE.findall(text) if not e.lower().rsplit(".", 1)[-1] in NOT_EMAIL_TLD}
    social = set()
    for dom, path in SOCIAL_RE.findall(text):
        path = path.rstrip("/").split("?")[0]
        low = path.lower()
        if low in ("share", "sharer", "intent/tweet", "sharer.php", "home", "watch", "sharearticle", "share-offsite") \
                or "/sharer" in low or low.startswith(("sharing/", "intent/", "share?")):
            continue
        social.add((dom.lower(), path))
    return emails, social


@register
class ContactIntel(Module):
    name = "contact_intel"
    description = "E-mail addresses and social profiles published on collected pages and scripts (no new requests)."
    phase = "assessment"
    active = False
    produces = ["third_party"]

    def run(self, ctx) -> None:
        texts = {**_collected(ctx), **ctx.shared.get("js_bodies", {})}
        if not texts:
            raise SkipModule("no pages collected in this scan")
        per_root: dict[str, dict] = defaultdict(lambda: {"emails": defaultdict(set), "social": defaultdict(set)})
        for url, text in texts.items():
            root = ctx.scope.root_for(host_of(url)) or (ctx.scope.root_domains or [None])[0]
            if not root:
                continue
            emails, social = extract_contacts(text[:400000])
            for e in emails:
                per_root[root]["emails"][e].add(url)
            for dom, path in social:
                per_root[root]["social"][f"https://{dom}/{path}"].add(url)
        total = 0
        for root, data in per_root.items():
            emails = {e: sorted(src)[:5] for e, src in data["emails"].items()}
            social = {s: sorted(src)[:5] for s, src in data["social"].items()}
            if not emails and not social:
                continue
            in_scope = sorted(e for e in emails if ctx.scope.host_in_scope(e.split("@", 1)[1]))
            info = {"emails": sorted(emails), "emails_in_scope": in_scope, "social_profiles": sorted(social),
                    "role_accounts": sorted(e for e in in_scope if re.match(r"^(security|abuse|admin|support|info|contact|"
                                                                            r"privacy|press|hr|careers|sales|noc|webmaster)@", e))}
            total += len(emails) + len(social)
            ctx.action("contacts for %s: %d e-mail(s), %d social profile(s)", root, len(emails), len(social))
            ev = ctx.evidence("contacts", f"contacts published for {root}", json.dumps({"emails": emails, "social": social}, indent=2))
            rels = [Rel("has_social_profile", "third_party", urlsplit(s).hostname.removeprefix("www."), confirmed=True,
                        target_attrs={"category": "social", "service": dict(SOCIAL).get(urlsplit(s).hostname.removeprefix("www."))})
                    for s in sorted(social)[:30]]
            ctx.emit(Obs("domain", root, {"contacts": info}, evidence_id=ev, relations=rels))
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": total}


# --------------------------------------------------------------------------- cors_check

PROBE_ORIGIN = "https://reconforge-cors-probe.example"


def classify_cors(sent: str, acao: str | None, acac: str | None) -> str | None:
    if not acao:
        return None
    creds = (acac or "").lower() == "true"
    if acao == sent:
        return "reflects_with_credentials" if creds else "reflects"
    if acao == "null" and sent == "null":
        return "null_with_credentials" if creds else "null"
    return None


@register
class CorsCheck(Module):
    name = "cors_check"
    description = "GET with a foreign, a look-alike and a null Origin to see whether CORS reflects it (no credentials sent)."
    phase = "assessment"
    active = True
    produces = ["finding"]

    def run(self, ctx) -> None:
        apps = _apps(ctx)[: int(ctx.option(self.name, "max_apps", 300))]
        if not apps:
            raise SkipModule("no web applications")
        fetcher = HttpFetcher(ctx)
        issues = 0
        try:
            for app in apps:
                host = (app.attributes or {}).get("host") or host_of(app.key)
                scheme = "https" if app.key.startswith("https") else "http"
                results = {}
                for label, origin in (("foreign", PROBE_ORIGIN), ("suffix", f"{scheme}://{host}.reconforge-cors-probe.example"),
                                      ("null", "null")):
                    r = fetcher.get(app.key + "/", extra_headers={"Origin": origin})
                    acao, acac = r.header("access-control-allow-origin"), r.header("access-control-allow-credentials")
                    verdict = classify_cors(origin, acao, acac)
                    ctx.action("GET %s/ Origin: %s -> ACAO=%s ACAC=%s", app.key, origin, acao or "-", acac or "-")
                    if verdict:
                        results[label] = {"origin": origin, "acao": acao, "acac": acac, "verdict": verdict}
                ctx.emit(Obs("web_app", app.key, {"cors": results or {"reflects": False}}))
                if not results:
                    continue
                issues += 1
                ev = ctx.evidence("cors", f"CORS behaviour of {app.key}", json.dumps(results, indent=2))
                creds = any(v["verdict"].endswith("with_credentials") for v in results.values())
                kinds = ", ".join(f"{k} origin" for k in results)
                finding(ctx, "cors.reflected_origin", app.key,
                        "CORS reflects untrusted origin" + (" with credentials" if creds else ""), "medium" if creds else "low",
                        f"{app.key} echoes the request Origin in Access-Control-Allow-Origin for: {kinds}."
                        + (" Access-Control-Allow-Credentials is true, so a hostile site could read authenticated responses."
                           if creds else ""), ev,
                        "Allow-list trusted origins explicitly; never reflect arbitrary or 'null' origins.",
                        category="cors", subject_type="web_app", extra={"cases": sorted(results)})
            ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": issues}
        finally:
            fetcher.close()


# --------------------------------------------------------------------------- panel_detect

# product, category, severity, regex over "<headers>\n<title>\n<body>"
PANELS = [
    ("Jenkins", "devops", "low", r"x-jenkins:|<title>[^<]*jenkins"),
    ("GitLab", "devops", "info", r"<title>[^<]*gitlab|content=\"gitlab\""),
    ("Gitea", "devops", "info", r"<title>[^<]*gitea|powered by gitea"),
    ("Argo CD", "devops", "low", r"<title>argo cd"),
    ("SonarQube", "devops", "low", r"<title>sonarqube"),
    ("Nexus Repository", "devops", "low", r"nexus repository manager"),
    ("Harbor", "devops", "low", r"<title>harbor</title>"),
    ("Portainer", "devops", "low", r"<title>portainer"),
    ("Rancher", "devops", "low", r"<title>rancher"),
    ("Kubernetes Dashboard", "devops", "medium", r"<title>kubernetes dashboard"),
    ("Traefik dashboard", "devops", "low", r"<title>traefik"),
    ("HashiCorp Consul", "devops", "low", r"<title>consul by hashicorp"),
    ("Apache Airflow", "devops", "low", r"<title>[^<]*airflow"),
    ("Jupyter", "devops", "medium", r"<title>(?:home - )?jupyter|jupyter-config-data"),
    ("MinIO Console", "storage", "low", r"minio console|<title>minio"),
    ("Grafana", "monitoring", "low", r"<title>grafana|grafana-app"),
    ("Kibana", "monitoring", "low", r"kbn-name:|<title>kibana"),
    ("Prometheus", "monitoring", "low", r"<title>prometheus time series"),
    ("Zabbix", "monitoring", "low", r"<title>[^<]*zabbix"),
    ("Nagios", "monitoring", "low", r"<title>nagios"),
    ("Splunk", "monitoring", "low", r"<title>[^<]*splunk"),
    ("Elasticsearch API", "database", "medium", r"you know, for search"),
    ("phpMyAdmin", "database", "medium", r"<title>[^<]*phpmyadmin"),
    ("Adminer", "database", "medium", r"<title>[^<]*adminer"),
    ("RabbitMQ Management", "database", "low", r"<title>rabbitmq management"),
    ("Apache Tomcat", "admin", "low", r"<title>apache tomcat/\d"),
    ("Webmin", "admin", "low", r"<title>login to webmin"),
    ("cPanel", "admin", "low", r"<title>[^<]*cpanel"),
    ("Plesk", "admin", "low", r"<title>[^<]*plesk"),
    ("WordPress login", "admin", "info", r"wp-login\.php"),
    ("Atlassian Jira", "collaboration", "info", r"com\.atlassian\.jira|<title>[^<]*jira"),
    ("Atlassian Confluence", "collaboration", "info", r"confluence-base-url|<title>[^<]*confluence"),
    ("Citrix Gateway", "vpn", "info", r"citrix gateway|netscaler gateway|/vpn/index\.html"),
    ("Ivanti / Pulse Connect Secure", "vpn", "info", r"dana-na|pulse connect secure|ivanti connect secure"),
    ("Fortinet SSL VPN", "vpn", "info", r"/remote/login|fgt_lang"),
    ("Palo Alto GlobalProtect", "vpn", "info", r"globalprotect portal|global-protect"),
    ("Cisco ASA / AnyConnect", "vpn", "info", r"/\+cscoe\+/|webvpn"),
    ("Outlook Web App", "mail", "info", r"/owa/auth|<title>outlook"),
    ("Microsoft RD Web Access", "remote_access", "low", r"rd web access|/rdweb/"),
    ("VMware vSphere / Horizon", "remote_access", "low", r"id_vc_welcome|vmware horizon|<title>[^<]*vsphere"),
]


def detect_panels(headers: dict[str, str], body: str) -> list[dict]:
    hay = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items()).lower() + "\n" + body[:150000].lower()
    return [{"product": p, "category": c, "severity": s} for p, c, s, rx in PANELS if re.search(rx, hay)]


@register
class PanelDetect(Module):
    name = "panel_detect"
    description = "Flags exposed administrative, DevOps, monitoring, database, VPN and mail interfaces (no login attempts)."
    phase = "assessment"
    active = False
    produces = ["finding"]

    def run(self, ctx) -> None:
        cache = ctx.shared.get("http_root", {})
        if not cache:
            raise SkipModule("no HTTP responses collected in this scan")
        n = 0
        for origin, res in cache.items():
            if not res.status:
                continue
            panels = detect_panels(res.headers, res.text)
            if not panels:
                continue
            n += 1
            ctx.action("panel %s -> %s", origin, ", ".join(p["product"] for p in panels))
            ev = ctx.evidence("http_response", f"interface fingerprint for {origin}", format_http_evidence(res, body_limit=3000))
            ctx.emit(Obs("web_app", origin, {"panels": panels}, evidence_id=ev,
                         relations=[_tech(p["product"], p["category"]) for p in panels]))
            for p in panels:
                finding(ctx, f"panel.{re.sub(r'[^a-z0-9]+', '_', p['product'].lower()).strip('_')}", origin,
                        f"{p['product']} interface exposed", p["severity"],
                        f"{origin} serves a {p['product']} {p['category'].replace('_', ' ')} interface to the internet.", ev,
                        "Confirm the interface must be public; otherwise restrict it by network (VPN/IP allow-list) and enforce MFA.",
                        category="exposure", subject_type="web_app", extra={"product": p["product"], "panel_category": p["category"]})
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": n}


# --------------------------------------------------------------------------- takeover_check

# service, CNAME suffixes, body fingerprint
TAKEOVER = [
    ("GitHub Pages", ("github.io",), r"there isn't a github pages site here"),
    ("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"), r"no such app|herokucdn\.com/error-pages/no-such-app"),
    ("AWS S3", ("amazonaws.com",), r"nosuchbucket|the specified bucket does not exist"),
    ("Shopify", ("myshopify.com",), r"sorry, this shop is currently unavailable"),
    ("Fastly", ("fastly.net",), r"fastly error: unknown domain"),
    ("Pantheon", ("pantheonsite.io",), r"the gods are wise, but do not know of the site which you seek"),
    ("Tumblr", ("domains.tumblr.com",), r"whatever you were looking for doesn't currently exist at this address"),
    ("Ghost", ("ghost.io",), r"the thing you were looking for is no longer here"),
    ("Surge.sh", ("surge.sh",), r"project not found"),
    ("Bitbucket", ("bitbucket.io",), r"repository not found"),
    ("Zendesk", ("zendesk.com",), r"help center closed"),
    ("ReadMe", ("readme.io",), r"project doesnt exist\.\.\. yet!"),
    ("Azure App Service", ("azurewebsites.net",), r"404 web site not found|error 404 - web app not found"),
    ("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"), r"the page you are looking for doesn't exist or has been moved"),
    ("Strikingly", ("s.strikinglydns.com",), r"page not found.*strikingly"),
    ("Agile CRM", ("agilecrm.com",), r"sorry, this page is no longer available"),
]


def takeover_match(cnames: list[str], body: str) -> dict | None:
    low = body[:60000].lower()
    for service, suffixes, rx in TAKEOVER:
        target = next((c for c in cnames if any(c == s or c.endswith("." + s) for s in suffixes)), None)
        if target and re.search(rx, low):
            return {"service": service, "cname": target, "fingerprint": rx}
    return None


@register
class TakeoverCheck(Module):
    name = "takeover_check"
    description = "Matches CNAMEs to third-party services with their 'unclaimed resource' fingerprints (candidates only; nothing is claimed)."
    phase = "assessment"
    active = False
    produces = ["finding"]

    def run(self, ctx) -> None:
        cache = ctx.shared.get("http_root", {})
        subs = {s.key: s for s in ctx.live("subdomain") if (s.attributes or {}).get("dns", {}).get("CNAME")}
        if not subs:
            raise SkipModule("no CNAME records observed in this scan")
        bodies: dict[str, str] = defaultdict(str)
        for origin, res in cache.items():
            bodies[host_of(origin)] += res.text[:60000]
        n = 0
        for host, sub in subs.items():
            cnames = [c.lower().rstrip(".") for c in (sub.attributes or {}).get("dns", {}).get("CNAME", [])]
            hit = takeover_match(cnames, bodies.get(host, ""))
            ctx.action("takeover fingerprint %s CNAME %s -> %s", host, ",".join(cnames), hit["service"] if hit else "no match")
            if not hit:
                continue
            n += 1
            ev = ctx.evidence("takeover", f"takeover fingerprint for {host}", json.dumps({**hit, "host": host}, indent=2))
            finding(ctx, "dns.takeover_candidate", host,
                    f"Potential subdomain takeover via {hit['service']} (candidate; manual verification required)", "medium",
                    f"{host} is a CNAME to {hit['cname']} and the response matches {hit['service']}'s 'unclaimed resource' page. "
                    "Confirm ownership manually; ReconForge never attempts to claim resources.", ev,
                    "Remove the DNS record or re-claim the resource at the provider.", category="dns", subject_type="subdomain",
                    extra={"service": hit["service"], "cname": hit["cname"]})
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": n}
