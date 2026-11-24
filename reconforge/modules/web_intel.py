"""HTTP intelligence, web metadata and identity infrastructure fingerprinting.

* http_intel     – per-host HTTP/HTTPS profile: redirect chains, HTTP/2 (ALPN), HTTP/3 (Alt-Svc),
                   compression, caching, HSTS/CSP/CORS details, HTTP-vs-HTTPS behaviour, default pages
* web_metadata   – security.txt, sitemap.xml, HTML/Open Graph/canonical metadata, public document
                   inventory (HEAD only — documents are not downloaded)
* identity_intel – login/registration/password-reset pages, SSO/IdP providers, OIDC/SAML metadata,
                   from data already collected (no authentication attempts of any kind)
"""
from __future__ import annotations

import json
import re
import socket
import ssl
from collections import defaultdict
from urllib.parse import urljoin, urlsplit

from ..core.module import Module, SkipModule, register
from ..core.net import HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_url, origin_of
from .common import finding

DEFAULT_PAGES = [("Welcome to nginx!", "nginx"), ("Apache2 Ubuntu Default Page", "Apache"), ("Apache2 Debian Default Page", "Apache"),
                 ("Test Page for the Apache", "Apache"), ("IIS Windows Server", "IIS"), ("Welcome to CentOS", "CentOS"),
                 ("It works!", "Apache"), ("Default Web Site Page", "generic"), ("Welcome to Caddy", "Caddy")]
DOC_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|odt|ods|csv|txt|rtf|zip)$", re.I)
META_RE = re.compile(r"<meta\s+[^>]*(?:name|property)=[\"']([^\"']+)[\"'][^>]*content=[\"']([^\"']*)[\"']", re.I)
CANON_RE = re.compile(r"<link[^>]+rel=[\"']canonical[\"'][^>]*href=[\"']([^\"']+)[\"']", re.I)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
PASSWORD_INPUT = re.compile(r"<input[^>]+type=[\"']?password", re.I)
IDP_HINTS = [("okta.com", "Okta"), ("oktacdn.com", "Okta"), ("auth0.com", "Auth0"), ("login.microsoftonline.com", "Microsoft Entra ID"),
             ("accounts.google.com", "Google Identity"), ("amazoncognito.com", "Amazon Cognito"), ("onelogin.com", "OneLogin"),
             ("pingidentity.com", "Ping Identity"), ("duosecurity.com", "Duo"), ("/realms/", "Keycloak"), ("/auth/realms/", "Keycloak"),
             ("clerk.", "Clerk"), ("firebaseapp.com/__/auth", "Firebase Auth"), ("SAMLRequest", "SAML SP-initiated flow")]


def alpn(ip: str, port: int, sni: str, timeout: float = 5.0) -> str | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=sni) as t:
            return t.selected_alpn_protocol()
    except OSError:
        return None


def hsts_details(v: str | None) -> dict | None:
    if not v:
        return None
    m = re.search(r"max-age=(\d+)", v)
    return {"max_age": int(m.group(1)) if m else None, "include_subdomains": "includesubdomains" in v.lower(),
            "preload": "preload" in v.lower()}


def csp_details(v: str | None) -> dict | None:
    if not v:
        return None
    directives = {d.strip().split(" ")[0]: d.strip() for d in v.split(";") if d.strip()}
    return {"directives": sorted(directives), "unsafe_inline": "'unsafe-inline'" in v, "unsafe_eval": "'unsafe-eval'" in v,
            "frame_ancestors": "frame-ancestors" in directives, "report_only": False}


@register
class HttpIntel(Module):
    name = "http_intel"
    description = "Per-host HTTP/HTTPS intelligence profile (redirect chains, HTTP/2/3, compression, caching, HSTS/CSP/CORS, default pages)."
    phase = "fingerprint"
    active = True
    produces = ["web_app", "subdomain"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))]
        if not apps:
            raise SkipModule("no web applications")
        cache = ctx.shared.get("http_root", {})
        fetcher = HttpFetcher(ctx)
        per_host: dict[str, dict] = defaultdict(dict)
        try:
            for app in apps:
                a = app.attributes or {}
                host = a.get("host")
                if ctx.incremental and app.key not in cache and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input(host)
                    continue
                prof: dict = {"scheme": a.get("scheme"), "status": a.get("status")}
                chain, url = [], app.key + "/"
                for _ in range(5):
                    r = fetcher.get(url)
                    chain.append({"url": url, "status": r.status})
                    loc = r.header("location") if r.status and 300 <= r.status < 400 else None
                    if not loc:
                        break
                    nxt = urljoin(url, loc)
                    if not ctx.scope.host_in_scope(host_of(nxt)):
                        chain.append({"url": nxt, "status": None, "note": "leaves scope (not followed)"})
                        break
                    url = nxt
                prof["redirect_chain"] = chain
                prof["final_url"] = chain[-1]["url"]
                comp = fetcher.get(app.key + "/", extra_headers={"Accept-Encoding": "gzip, deflate, br"}) if a.get("status") else None
                hdr = (comp.headers if comp and comp.status else {}) or {}
                prof["compression"] = hdr.get("content-encoding")
                prof["cache_control"] = hdr.get("cache-control")
                prof["http3_advertised"] = "h3" in (hdr.get("alt-svc") or "")
                prof["hsts"] = hsts_details(hdr.get("strict-transport-security"))
                prof["csp"] = csp_details(hdr.get("content-security-policy"))
                prof["cors"] = {k: v for k, v in hdr.items() if k.startswith("access-control-")}
                prof["http_version"] = a.get("http_version")
                if a.get("scheme") == "https" and a.get("ip"):
                    prof["alpn"] = alpn(a["ip"], int(a.get("port") or 443), host)
                    prof["http2"] = prof["alpn"] == "h2"
                title = a.get("title") or ""
                default = next((srv for t, srv in DEFAULT_PAGES if t.lower() in title.lower()), None)
                prof["default_page"] = default
                ev = ctx.evidence("http_profile", f"HTTP profile for {app.key}", json.dumps(prof, indent=2, default=str))
                ctx.emit(Obs("web_app", app.key, {"http_profile": prof}, evidence_id=ev))
                per_host[host][a.get("scheme")] = {"origin": app.key, "status": a.get("status"), "title": title,
                                                   "server": a.get("server"), "final": prof["final_url"]}
                if default:
                    finding(ctx, "web.default_page", app.key, f"Default {default} page served", "info",
                            f"{app.key} serves a default server page ('{title}').", ev,
                            "Confirm whether this host is intended to be public.", category="disclosure", subject_type="web_app")
                if prof["csp"] and (prof["csp"]["unsafe_inline"] or prof["csp"]["unsafe_eval"]):
                    finding(ctx, "headers.csp_unsafe", app.key, "CSP allows unsafe-inline/unsafe-eval", "info",
                            "The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval', reducing its protection.", ev,
                            "Tighten the CSP with nonces/hashes.", category="headers", subject_type="web_app")
                if prof["hsts"] and (prof["hsts"]["max_age"] or 0) < 15552000:
                    finding(ctx, "headers.hsts_short", app.key, "Short HSTS max-age", "info",
                            f"HSTS max-age is {prof['hsts']['max_age']} seconds (< 180 days).", ev,
                            "Use max-age of at least 6 months.", category="headers", subject_type="web_app")
            for host, schemes in per_host.items():
                diff = {}
                if "http" in schemes and "https" in schemes:
                    h, s = schemes["http"], schemes["https"]
                    diff = {"http_redirects_to_https": str(h["final"]).startswith("https://"),
                            "same_title": h["title"] == s["title"], "same_server": h["server"] == s["server"]}
                ctx.emit(Obs("subdomain", host, {"http_summary": {"schemes": schemes, "http_vs_https": diff}}))
        finally:
            fetcher.close()


@register
class WebMetadata(Module):
    name = "web_metadata"
    description = "security.txt, sitemap.xml, HTML/OpenGraph/canonical metadata and a public document inventory (HEAD only)."
    phase = "content"
    active = True
    produces = ["endpoint"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))
                and (a.attributes or {}).get("status") and not 300 <= int((a.attributes or {}).get("status")) < 400]
        if not apps:
            raise SkipModule("no web applications")
        fetcher = HttpFetcher(ctx)
        pages = dict(ctx.shared.get("pages", {}))
        for origin, res in ctx.shared.get("http_root", {}).items():
            pages.setdefault(normalize_url(origin + "/"), res.text)
        max_docs = int(ctx.option(self.name, "max_documents", 50))
        try:
            for app in apps:
                if ctx.incremental and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host"))
                    continue
                self._security_txt(ctx, fetcher, app)
                self._sitemap(ctx, fetcher, app)
            docs_seen = 0
            for url, html in pages.items():
                origin = origin_of(url)
                metas = {k.lower(): v for k, v in META_RE.findall(html[:200000])}
                canon = CANON_RE.search(html[:200000])
                meta = {k: v for k, v in metas.items() if k in ("description", "generator", "author", "robots", "keywords")
                        or k.startswith("og:") or k.startswith("twitter:")}
                if meta or canon:
                    ctx.emit(Obs("endpoint", url, {"url": url, "host": host_of(url), "html_meta": meta,
                                                   "canonical": canon.group(1) if canon else None}))
                for link in HREF_RE.findall(html):
                    absolute = urljoin(url, link)
                    if not DOC_EXT.search(urlsplit(absolute).path) or not ctx.scope.host_in_scope(host_of(absolute)):
                        continue
                    if docs_seen >= max_docs:
                        break
                    docs_seen += 1
                    r = fetcher.get(absolute, method="HEAD")
                    ev = ctx.evidence("http_response", f"HEAD {absolute}", format_http_evidence(r, "HEAD"))
                    ext = urlsplit(absolute).path.rsplit(".", 1)[-1].lower()
                    ctx.emit(Obs("endpoint", normalize_url(absolute), {
                        "url": normalize_url(absolute), "host": host_of(absolute), "kind": "document", "document_type": ext,
                        "status": r.status, "content_type": r.header("content-type"), "size": r.header("content-length"),
                        "last_modified": r.header("last-modified"), "+discovered_via": [self.name],
                        "note": "metadata via HEAD only; content not downloaded"}, evidence_id=ev,
                        relations=[Rel("has_endpoint", "web_app", origin, confirmed=True, reverse=True)]))
        finally:
            fetcher.close()

    def _security_txt(self, ctx, fetcher, app):
        for path in ("/.well-known/security.txt", "/security.txt"):
            r = fetcher.get(app.key + path)
            if r.status == 200 and "contact:" in r.text.lower()[:5000]:
                fields = defaultdict(list)
                for line in r.text.splitlines():
                    if ":" in line and not line.lstrip().startswith("#"):
                        k, v = line.split(":", 1)
                        fields[k.strip().lower()].append(v.strip())
                ev = ctx.evidence("http_response", f"security.txt on {app.key}", format_http_evidence(r))
                ctx.emit(Obs("endpoint", app.key + path, {"url": app.key + path, "host": host_of(app.key), "kind": "security_txt",
                                                          "contacts": fields.get("contact", []), "expires": (fields.get("expires") or [None])[0],
                                                          "policy": (fields.get("policy") or [None])[0], "+discovered_via": [self.name]},
                             evidence_id=ev, relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
                ctx.emit(Obs("web_app", app.key, {"security_txt": True}))
                return

    def _sitemap(self, ctx, fetcher, app):
        r = fetcher.get(app.key + "/sitemap.xml")
        if r.status != 200 or "<urlset" not in r.text[:2000] and "<sitemapindex" not in r.text[:2000]:
            return
        ev = ctx.evidence("http_response", f"sitemap.xml on {app.key}", format_http_evidence(r, body_limit=20000))
        locs = LOC_RE.findall(r.text)[: int(ctx.option(self.name, "max_sitemap_urls", 500))]
        ctx.emit(Obs("endpoint", app.key + "/sitemap.xml", {"url": app.key + "/sitemap.xml", "host": host_of(app.key),
                                                             "kind": "sitemap", "sitemap_urls": len(locs), "+discovered_via": [self.name]},
                     evidence_id=ev, relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
        from .crawler import classify_endpoint

        for loc in locs:
            if ctx.scope.host_in_scope(host_of(loc)):
                u = normalize_url(loc)
                ctx.emit(Obs("endpoint", u, {"url": u, "host": host_of(u), "kind": classify_endpoint(u),
                                             "+discovered_via": ["sitemap"]}, evidence_id=ev,
                             relations=[Rel("has_endpoint", "web_app", origin_of(u), confirmed=False, reverse=True)]))


@register
class IdentityIntel(Module):
    name = "identity_intel"
    description = "Login/registration/reset pages, SSO/IdP providers, OIDC/SAML metadata (analysis only; no auth attempts)."
    phase = "assessment"
    active = False
    produces = ["third_party"]

    def run(self, ctx) -> None:
        pages = dict(ctx.shared.get("pages", {}))
        for origin, res in ctx.shared.get("http_root", {}).items():
            pages.setdefault(normalize_url(origin + "/"), res.text)
        endpoints = ctx.live("endpoint")
        if not pages and not endpoints:
            raise SkipModule("no pages or endpoints collected in this scan")
        per_app: dict[str, dict] = defaultdict(lambda: {"login_pages": set(), "registration": set(), "password_reset": set(),
                                                        "providers": set(), "oidc": [], "saml": []})
        for url, html in pages.items():
            app = per_app[origin_of(url)]
            if PASSWORD_INPUT.search(html):
                app["login_pages"].add(url)
            for link in HREF_RE.findall(html):
                absolute = urljoin(url, link).lower()
                if re.search(r"/(register|sign-?up|create-account)", absolute):
                    app["registration"].add(absolute)
                if re.search(r"/(forgot|reset)[-_]?password|/password/(reset|forgot)", absolute):
                    app["password_reset"].add(absolute)
                for needle, name in IDP_HINTS:
                    if needle.lower() in absolute:
                        app["providers"].add(name)
                        h = host_of(absolute)
                        if h and not ctx.scope.host_in_scope(h):
                            ctx.emit(Obs("third_party", h, {"category": "identity", "service": name},
                                         relations=[Rel("authenticates_with", "web_app", origin_of(url), confirmed=False, reverse=True)]))
            for needle, name in IDP_HINTS:
                if needle in html and name.startswith("SAML"):
                    app["providers"].add(name)
        for e in endpoints:
            a = e.attributes or {}
            origin = origin_of(e.key) if e.key.startswith("http") else None
            if not origin:
                continue
            cats = a.get("url_categories") or []
            if "authentication" in cats and a.get("kind") not in ("api",):
                per_app[origin]["login_pages"].add(e.key)
            if a.get("kind") == "oidc_metadata":
                per_app[origin]["oidc"].append({"url": e.key, "issuer": a.get("issuer")})
            if a.get("kind") == "saml_metadata":
                per_app[origin]["saml"].append({"url": e.key, "entity_id": a.get("entity_id")})
        analysed = {origin_of(u) for u in pages}
        for origin, info in per_app.items():
            # Only publish a profile for apps whose pages were analysed in this scan; endpoint-only
            # evidence (e.g. incremental scans without crawling) must not overwrite a fuller profile.
            if origin not in analysed or not any(info.values()):
                continue
            data = {k: sorted(v) if isinstance(v, set) else v for k, v in info.items()}
            if ctx.engine.get("web_app", origin) is None:
                continue
            ev = ctx.evidence("identity", f"identity infrastructure for {origin}", json.dumps(data, indent=2))
            ctx.emit(Obs("web_app", origin, {"identity": data}, evidence_id=ev))
