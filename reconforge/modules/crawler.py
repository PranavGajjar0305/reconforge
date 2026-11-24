"""Public web crawling (GET only, same-origin, bounded) and endpoint inventory."""
from __future__ import annotations

import json
import re
from collections import deque
from urllib.parse import urljoin, urlsplit

from ..core.module import Module, SkipModule, register
from ..core.net import HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_host, normalize_url, origin_of

HREF_RE = re.compile(r"""(?:href|src|action|data-src)\s*=\s*["']([^"'#][^"']*)["']""", re.I)
FORM_RE = re.compile(r"<form[^>]*>", re.I)
FORM_ATTR_RE = re.compile(r"""(action|method)\s*=\s*["']([^"']*)["']""", re.I)
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
STATIC_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|otf|mp4|mp3|pdf|zip|gz|map)$", re.I)
API_PATH = re.compile(r"(?:^|/)(?:api|rest|v\d+|graphql|gql|rpc|services?)(?:/|$)|\.json$", re.I)


def classify_endpoint(url: str, content_type: str | None = None) -> str:
    path = urlsplit(url).path.lower()
    if url.startswith(("ws://", "wss://")):
        return "websocket"
    if "graphql" in path or path.endswith("/gql"):
        return "graphql"
    if re.search(r"swagger|openapi|api-docs|redoc", path):
        return "api_documentation"
    if path.endswith("/robots.txt"):
        return "robots"
    if "sitemap" in path and path.endswith(".xml"):
        return "sitemap"
    if API_PATH.search(path) or (content_type or "").endswith("json"):
        return "api"
    return "page"


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    disallow, sitemaps, applies = [], [], False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "user-agent":
            applies = v == "*"
        elif k == "disallow" and applies and v:
            disallow.append(v)
        elif k == "sitemap":
            sitemaps.append(v)
    return disallow, sitemaps


@register
class Crawler(Module):
    name = "crawler"
    description = "Bounded same-origin crawl of discovered web apps; inventories pages, forms, scripts and references."
    phase = "content"
    active = True
    tools = ["katana"]
    produces = ["endpoint", "js_file", "third_party"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))
                and (a.attributes or {}).get("status") and not 300 <= int((a.attributes or {}).get("status")) < 400]
        if not apps:
            raise SkipModule("no crawlable web applications")
        if ctx.option(self.name, "engine", "builtin") == "katana" and ctx.tool("katana").available:
            return self._katana(ctx, apps)
        fetcher = HttpFetcher(ctx)
        try:
            for app in apps:
                if ctx.incremental and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host", app.key))
                    continue
                self._crawl(ctx, fetcher, app.key)
        finally:
            fetcher.close()

    def _crawl(self, ctx, fetcher: HttpFetcher, origin: str) -> None:
        max_pages = int(ctx.option(self.name, "max_pages", 60))
        max_depth = int(ctx.option(self.name, "max_depth", 2))
        respect_robots = bool(ctx.option(self.name, "respect_robots", True))
        pages = ctx.shared.setdefault("pages", {})
        js_seen: dict[str, str] = ctx.shared.setdefault("js_files", {})
        third: dict[str, set[str]] = {}
        disallow: list[str] = []
        robots = fetcher.get(origin + "/robots.txt")
        if robots.status == 200 and "text" in (robots.header("content-type") or "text"):
            disallow, sitemaps = parse_robots(robots.text)
            ev = ctx.evidence("http_response", f"robots.txt for {origin}", format_http_evidence(robots))
            self._endpoint(ctx, origin, origin + "/robots.txt", 200, "text/plain", ev,
                           {"robots_disallow": disallow[:50], "sitemaps": sitemaps[:10]})
        queue = deque([(origin + "/", 0)])
        seen = set()
        while queue and len(seen) < max_pages:
            url, depth = queue.popleft()
            nurl = normalize_url(url, keep_query=True)
            if nurl in seen:
                continue
            path = urlsplit(nurl).path
            if respect_robots and any(path.startswith(d) for d in disallow if d != "/"):
                continue
            seen.add(nurl)
            res = ctx.shared.get("http_root", {}).get(origin) if path == "/" else None
            if res is None:
                res = fetcher.get(url)
            if res.status is None:
                continue
            ctype = (res.header("content-type") or "").split(";")[0]
            ev = ctx.evidence("http_response", f"GET {nurl} -> {res.status}", format_http_evidence(res, body_limit=1500))
            if path != "/":
                self._endpoint(ctx, origin, nurl, res.status, ctype, ev, {})
            if "html" not in ctype and "xml" not in ctype:
                continue
            body = res.text
            pages[nurl] = body[:200000]
            for form in FORM_RE.findall(body):
                attrs = {k.lower(): v for k, v in FORM_ATTR_RE.findall(form)}
                action = normalize_url(urljoin(url, attrs.get("action") or url))
                if host_of(action) == host_of(origin):
                    self._endpoint(ctx, origin, action, None, None, ev,
                                   {"+methods_documented": [(attrs.get("method") or "GET").upper()],
                                    "form": True, "requested": False})
            for src in SCRIPT_SRC_RE.findall(body):
                js = urljoin(url, src)
                self._script(ctx, origin, js, ev, js_seen, third)
            for link in HREF_RE.findall(body):
                absolute = urljoin(url, link.strip())
                if absolute.startswith(("mailto:", "javascript:", "tel:", "data:")):
                    continue
                host = host_of(absolute)
                if not host:
                    continue
                if origin_of(absolute) == origin:
                    if STATIC_EXT.search(urlsplit(absolute).path):
                        continue
                    if absolute.endswith(".js"):
                        self._script(ctx, origin, absolute, ev, js_seen, third)
                    elif depth + 1 <= max_depth:
                        queue.append((absolute, depth + 1))
                elif ctx.scope.host_in_scope(host):
                    ctx.emit(Obs("subdomain", host, {"+discovered_via": ["crawler"]}, evidence_id=ev,
                                 relations=[Rel("links_to", "web_app", origin, confirmed=True, reverse=True)]))
                else:
                    third.setdefault(host, set()).add("link")
        for host, kinds in third.items():
            ctx.emit(Obs("third_party", host, {"+reference_kinds": sorted(kinds), "category": _third_category(host)},
                         relations=[Rel("references", "web_app", origin, confirmed=True, reverse=True,
                                        attrs={"kinds": sorted(kinds)})]))

    def _endpoint(self, ctx, origin, url, status, ctype, ev, extra) -> None:
        kind = classify_endpoint(url, ctype)
        attrs = {"url": url, "host": host_of(url), "path": urlsplit(url).path, "kind": kind,
                 "+discovered_via": ["crawler"], **extra}
        if status is not None:
            attrs.update({"status": status, "content_type": ctype, "+methods_observed": ["GET"]})
        ctx.emit(Obs("endpoint", url, attrs, evidence_id=ev,
                     relations=[Rel("has_endpoint", "web_app", origin, confirmed=True, reverse=True)]))

    def _script(self, ctx, origin, js_url, ev, js_seen, third) -> None:
        host = host_of(js_url)
        if not host:
            return
        if ctx.scope.host_in_scope(host):
            key = normalize_url(js_url, keep_query=False)
            if key not in js_seen:
                js_seen[key] = origin
                ctx.emit(Obs("js_file", key, {"url": key, "host": host, "+loaded_by": [origin]}, evidence_id=ev,
                             relations=[Rel("loads", "web_app", origin, confirmed=True, reverse=True)]))
        else:
            third.setdefault(normalize_host(host), set()).add("script")

    def _katana(self, ctx, apps) -> None:
        depth = str(ctx.option(self.name, "max_depth", 2))
        proc = ctx.run_tool("katana", ["-silent", "-jsonl", "-d", depth, "-jc", "-fs", "fqdn"],
                            input_text="\n".join(a.key for a in apps))
        ev = ctx.evidence("tool_output", "katana JSONL output", proc.stdout, ".jsonl")
        for row in parse_katana(proc.stdout):
            url = row["url"]
            if not ctx.scope.host_in_scope(host_of(url)):
                continue
            origin = origin_of(url)
            if url.endswith(".js"):
                ctx.emit(Obs("js_file", normalize_url(url, False), {"url": url, "host": host_of(url)}, source="katana",
                             evidence_id=ev, relations=[Rel("loads", "web_app", origin, reverse=True)]))
            else:
                self._endpoint(ctx, origin, normalize_url(url), row.get("status"), row.get("content_type"), ev,
                               {"+methods_observed": [row.get("method", "GET")]})


def parse_katana(output: str) -> list[dict]:
    out = []
    for line in output.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        req = row.get("request", {}) or {}
        resp = row.get("response", {}) or {}
        out.append({"url": req.get("endpoint") or row.get("endpoint"), "method": req.get("method", "GET"),
                    "status": resp.get("status_code"), "content_type": (resp.get("headers") or {}).get("content_type")})
    return [r for r in out if r["url"]]


def _third_category(host: str) -> str:
    from ..correlation.classify import classify_third_party

    return classify_third_party(host)[0]
