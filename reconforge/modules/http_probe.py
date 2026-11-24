"""HTTP/HTTPS service probing of in-scope hosts (built-in or ProjectDiscovery httpx)."""
from __future__ import annotations

import html
import json
import re
from urllib.parse import urljoin

from ..core.module import Module, SkipModule, register
from ..core.net import FetchResult, HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, is_ip, normalize_url, origin_of, sha256

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
]
INTERESTING_HEADERS = ["server", "x-powered-by", "via", "x-aspnet-version", "x-generator", "x-runtime",
                       "x-amz-cf-id", "cf-ray", "x-cache", "x-served-by", "x-akamai-transformed", "x-sucuri-id",
                       "x-cdn", "content-type", "location", "access-control-allow-origin", "www-authenticate"]
CDN_HEADER_HINTS = [
    ("cf-ray", None, "Cloudflare"), ("server", "cloudflare", "Cloudflare"), ("x-amz-cf-id", None, "Amazon CloudFront"),
    ("via", "cloudfront", "Amazon CloudFront"), ("x-served-by", "cache-", "Fastly"), ("x-akamai-transformed", None, "Akamai"),
    ("server", "akamaighost", "Akamai"), ("x-sucuri-id", None, "Sucuri"), ("x-cdn", "incapsula", "Imperva"),
]
WAF_HEADER_HINTS = [("x-sucuri-id", None, "Sucuri WAF"), ("x-cdn", "incapsula", "Imperva WAF"),
                    ("server", "cloudflare", "Cloudflare (WAF capable)"), ("x-waf", None, "Generic WAF header")]
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def cdn_waf(headers: dict[str, str]) -> tuple[str | None, str | None]:
    def match(rules):
        for h, needle, name in rules:
            v = headers.get(h)
            if v is not None and (needle is None or needle in v.lower()):
                return name
        return None

    return match(CDN_HEADER_HINTS), match(WAF_HEADER_HINTS)


def summarize_response(res: FetchResult) -> dict:
    title = TITLE_RE.search(res.text[:200000])
    sec = {h: res.headers.get(h) for h in SECURITY_HEADERS}
    cdn, waf = cdn_waf(res.headers)
    return {
        "status": res.status,
        "title": html.unescape(title.group(1).strip())[:200] if title else None,
        "server": res.headers.get("server"),
        "content_type": (res.headers.get("content-type") or "").split(";")[0] or None,
        "content_length": len(res.body),
        "body_sha256": sha256(res.body)[:32] if res.body else None,
        "headers": {h: res.headers[h] for h in INTERESTING_HEADERS if h in res.headers},
        "security_headers": sec,
        "missing_security_headers": sorted(h for h, v in sec.items() if v is None),
        "redirect": res.headers.get("location"),
        "cdn": cdn,
        "waf": waf,
        "http_version": res.http_version,
        "response_ms": res.elapsed_ms,
    }


@register
class HttpProbe(Module):
    name = "http_probe"
    description = "Probes in-scope hosts on configured HTTP/HTTPS ports with a single GET / request."
    phase = "http"
    active = True
    tools = ["httpx"]
    produces = ["web_app"]

    def run(self, ctx) -> None:
        if ctx.option(self.name, "engine", "builtin") == "httpx" and ctx.tool("httpx").available:
            return self._run_pd_httpx(ctx)
        probe_ports = ctx.target.get("probe_ports") or ctx.option("http", "probe_ports", {"http": [80], "https": [443]})
        hosts = ctx.hosts()
        if not hosts:
            raise SkipModule("no resolved in-scope hosts")
        fetcher = HttpFetcher(ctx)
        cache = ctx.shared.setdefault("http_root", {})
        queue: list[str] = []
        for h in hosts:
            if ctx.incremental and not ctx.needs_refresh(h, self.name):
                ctx.mark_skipped_input(h.key)
                continue
            extra_ports = self._service_ports(ctx, h)
            for scheme, ports in probe_ports.items():
                for port in sorted(set(ports) | extra_ports.get(scheme, set())):
                    queue.append(origin_of(f"{scheme}://{h.key}:{port}/"))
        seen: set[str] = set()
        baselines: dict[tuple, tuple | None] = {}
        try:
            while queue:
                origin = queue.pop(0)
                if origin in seen:
                    continue
                seen.add(origin)
                res = fetcher.get(origin + "/")
                if res.status is None:
                    continue
                if self._is_default_vhost(ctx, fetcher, origin, res, baselines):
                    ctx.emit(Obs("subdomain", host_of(origin), {"+default_vhost_only": [origin]}))
                    continue
                cache[origin] = res
                summary = summarize_response(res)
                ev = ctx.evidence("http_response", f"GET {origin}/ -> {res.status}", format_http_evidence(res))
                host = host_of(origin)
                attrs = {"url": origin, "host": host, "scheme": origin.split(":")[0], "ip": res.ip,
                         "port": int(origin.rsplit(":", 1)[1]) if origin.count(":") == 2 else (443 if origin.startswith("https") else 80),
                         **summary}
                ctx.emit(Obs("web_app", origin, attrs, evidence_id=ev, relations=[
                    Rel("serves", "subdomain", host, confirmed=True, reverse=True),
                    Rel("hosted_on", "ip", res.ip, confirmed=True),
                ]))
                loc = summary.get("redirect")
                if loc and res.status and 300 <= res.status < 400:
                    target = normalize_url(urljoin(origin + "/", loc))
                    t_origin = origin_of(target)
                    if ctx.scope.host_in_scope(host_of(target)):
                        if t_origin not in seen and fetcher.ip_for(host_of(target)):
                            queue.append(t_origin)
                        if t_origin != origin:
                            ctx.emit(Obs("web_app", origin, {}, relations=[Rel("redirects_to", "web_app", t_origin, confirmed=True)]))
                    else:
                        ctx.emit(Obs("web_app", origin, {}, relations=[
                            Rel("redirects_to", "third_party", host_of(target), confirmed=True,
                                target_attrs={"category": "redirect-target"})]))
        finally:
            fetcher.close()

    @staticmethod
    def _is_default_vhost(ctx, fetcher, origin: str, res: FetchResult, baselines: dict) -> bool:
        """True when the host only receives the shared server's catch-all response.

        A request with a random, non-existent name under the same root domain is sent to the
        same IP:port; if the host's answer is identical (status + body) it carries no
        host-specific application and is not recorded as a web application.
        """
        import uuid

        if res.status is None or 200 <= res.status < 400:
            return False
        host = host_of(origin)
        if is_ip(host):
            return False  # an IP target has no name-based virtual hosting to compare against
        root = ctx.scope.root_for(host) or host
        scheme, rest = origin.split("://", 1)
        port = rest.rsplit(":", 1)[1] if ":" in rest else ("443" if scheme == "https" else "80")
        key = (res.ip, scheme, port, root)
        if key not in baselines:
            probe = fetcher.get(f"{scheme}://rf-baseline-{uuid.uuid4().hex[:8]}.{root}:{port}/", ip=res.ip)
            baselines[key] = (probe.status, sha256(probe.body)) if probe.status is not None else None
        return baselines[key] == (res.status, sha256(res.body))

    @staticmethod
    def _service_ports(ctx, host_asset) -> dict[str, set[int]]:
        out: dict[str, set[int]] = {"http": set(), "https": set()}
        for svc in ctx.live("service"):
            a = svc.attributes or {}
            if a.get("ip") in (host_asset.attributes or {}).get("ips", []):
                name = (a.get("service") or "")
                if name in ("https", "https-alt"):
                    out["https"].add(a["port"])
                elif name in ("http", "http-alt"):
                    out["http"].add(a["port"])
        return out

    def _run_pd_httpx(self, ctx) -> None:
        targets = [h.key for h in ctx.hosts()]
        proc = ctx.run_tool("httpx", ["-silent", "-json", "-title", "-status-code", "-web-server", "-tech-detect",
                                      "-ip", "-cdn", "-follow-redirects=false", "-no-color"], input_text="\n".join(targets))
        ev = ctx.evidence("tool_output", "httpx JSONL output", proc.stdout, ".jsonl")
        for obs in parse_pd_httpx(proc.stdout, ev):
            if ctx.scope.host_in_scope(obs.attrs["host"]):
                ctx.emit(obs)


def parse_pd_httpx(output: str, evidence_id: str | None = None) -> list[Obs]:
    out = []
    for line in output.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        url = row.get("url")
        origin = origin_of(url)
        host = host_of(url)
        ip = row.get("host") if row.get("host") and row.get("host") != host else (row.get("a") or [None])[0]
        tech = {t.split(":")[0]: (t.split(":")[1] if ":" in t else "") for t in row.get("tech", []) or []}
        attrs = {"url": origin, "host": host, "status": row.get("status_code") or row.get("status-code"),
                 "title": row.get("title"), "server": row.get("webserver"), "ip": ip,
                 "cdn": row.get("cdn_name") if row.get("cdn") else None, "technologies_httpx": tech}
        rels = [Rel("serves", "subdomain", host, confirmed=True, reverse=True)]
        if ip:
            rels.append(Rel("hosted_on", "ip", ip, confirmed=True))
        out.append(Obs("web_app", origin, attrs, source="httpx", evidence_id=evidence_id, relations=rels))
    return out
