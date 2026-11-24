"""Network helpers used by built-in modules.

HTTP requests are always sent to an IP address that DNS resolution produced and that
the scope allows, with the original hostname in the Host header and TLS SNI. This
guarantees active traffic only reaches addresses that passed the scope check, and it
works the same in labs with private resolvers.

Only GET/HEAD requests are ever issued by ReconForge.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import dns.resolver
import httpx

from ..util import DEFAULT_PORTS, is_ip, normalize_host


def make_resolver(config) -> dns.resolver.Resolver:
    servers = config.get("dns.resolvers") or []
    res = dns.resolver.Resolver(configure=not servers)
    if servers:
        res.nameservers = []
        port = 53
        for s in servers:
            host, _, p = s.rpartition(":") if s.count(":") == 1 else (s, "", "")
            res.nameservers.append(host or s)
            if p:
                port = int(p)
        res.port = port
    t = float(config.get("dns.timeout", 3.0))
    res.timeout = t
    res.lifetime = t * 2
    return res


@dataclass
class FetchResult:
    url: str
    ip: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = ""
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def set_cookies(self) -> list[str]:
        return [v for k, v in self.raw_headers if k.lower() == "set-cookie"]


class HttpFetcher:
    def __init__(self, ctx):
        self.ctx = ctx
        cfg = ctx.config
        self.timeout = float(cfg.get("http.timeout", 8.0))
        self.max_body = int(cfg.get("http.max_body_bytes", 512000))
        self.ua = cfg.get("network.user_agent")
        self.client = httpx.Client(verify=bool(cfg.get("http.verify_tls", False)), timeout=self.timeout,
                                   follow_redirects=False, http2=False)
        self._ip_cache: dict[str, str | None] = {}

    def close(self) -> None:
        self.client.close()

    def ip_for(self, host: str) -> str | None:
        host = normalize_host(host)
        if host in self._ip_cache:
            return self._ip_cache[host]
        if is_ip(host):  # IP target: connect to the address itself when the scope allows it
            self._ip_cache[host] = host if self.ctx.scope.ip_allowed(host) else None
            return self._ip_cache[host]
        ip = None
        asset = self.ctx.engine.get("subdomain", host)
        if asset:
            for candidate in (asset.attributes or {}).get("ips", []):
                if self.ctx.scope.ip_allowed(candidate):
                    ip = candidate
                    break
        self._ip_cache[host] = ip
        return ip

    def get(self, url: str, method: str = "GET", ip: str | None = None, extra_headers: dict | None = None) -> FetchResult:
        if method not in ("GET", "HEAD"):
            raise ValueError("ReconForge only issues GET/HEAD requests")
        parts = urlsplit(url)
        host = normalize_host(parts.hostname or "")
        if not self.ctx.scope.host_in_scope(host):
            return FetchResult(url, "", None, error="host out of scope")
        ip = ip or self.ip_for(host)
        if not ip:
            return FetchResult(url, "", None, error="no in-scope resolved IP")
        port = parts.port or DEFAULT_PORTS.get(parts.scheme, 80)
        ip_netloc = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
        target = urlunsplit((parts.scheme, f"{ip_netloc}:{port}", parts.path or "/", parts.query, ""))
        host_header = host if port == DEFAULT_PORTS.get(parts.scheme) else f"{host}:{port}"
        headers = {"Host": host_header, "User-Agent": self.ua, "Accept": "*/*"}
        headers.update(extra_headers or {})
        self.ctx.limiter.wait()
        try:
            req = self.client.build_request(method, target, headers=headers,
                                            extensions={"sni_hostname": host} if parts.scheme == "https" else {})
            resp = self.client.send(req, stream=True)
            body = b""
            try:
                if method == "GET":
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) >= self.max_body:
                            break
            finally:
                resp.close()
            self.ctx.action("%s %s (via %s) -> %s %dB", method, url, ip, resp.status_code, len(body))
            return FetchResult(
                url=url, ip=ip, status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                raw_headers=[(k, v) for k, v in resp.headers.multi_items()],
                body=body[: self.max_body], http_version=resp.http_version,
                elapsed_ms=int(resp.elapsed.total_seconds() * 1000) if resp.elapsed else 0,
            )
        except httpx.HTTPError as exc:
            self.ctx.action("%s %s (via %s) -> error %s", method, url, ip, type(exc).__name__)
            return FetchResult(url, ip, None, error=f"{type(exc).__name__}: {exc}")


def format_http_evidence(res: FetchResult, method: str = "GET", body_limit: int = 4000) -> str:
    lines = [f"> {method} {res.url}  (connected to {res.ip})"]
    if res.error:
        lines.append(f"! error: {res.error}")
        return "\n".join(lines)
    lines.append(f"< {res.http_version} {res.status}")
    lines += [f"< {k}: {v}" for k, v in res.raw_headers]
    if res.body:
        lines.append("")
        lines.append(res.text[:body_limit])
    return "\n".join(lines)
