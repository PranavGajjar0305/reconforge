"""Configured TCP port and service discovery (built-in connect scan, nmap, or naabu).

Only ports listed in the target/config are checked, only on IPs that in-scope hosts
resolve to *and* that the scope's IP allow-list permits. The built-in engine performs a
TCP connect and passively reads any banner the service volunteers; it sends no payload.
"""
from __future__ import annotations

import json
import re
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from ..core.module import Module, SkipModule, register
from ..core.observation import Obs, Rel
from .common import finding

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5601: "kibana", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 9300: "elasticsearch-transport", 11211: "memcached", 27017: "mongodb",
}
SENSITIVE = {"telnet", "smb", "mssql", "oracle", "nfs", "docker", "mysql", "rdp", "postgresql", "redis", "vnc",
             "elasticsearch", "elasticsearch-transport", "memcached", "mongodb", "kibana"}

BANNER_RULES = [
    (re.compile(r"^SSH-[\d.]+-OpenSSH_([\w.]+)"), "ssh", "OpenSSH"),
    (re.compile(r"^SSH-[\d.]+-([\w.-]+)"), "ssh", None),
    (re.compile(r"^220.*ESMTP\s+Postfix"), "smtp", "Postfix"),
    (re.compile(r"^220.*Microsoft ESMTP"), "smtp", "Microsoft Exchange"),
    (re.compile(r"^220.*(E?SMTP)"), "smtp", None),
    (re.compile(r"^220.*FTP"), "ftp", None),
    (re.compile(r"^\+OK"), "pop3", None),
    (re.compile(r"^\* OK.*IMAP"), "imap", None),
    (re.compile(r"^HTTP/\d"), "http", None),
    (re.compile(r"mysql_native_password|^.\x00\x00\x00\x0a([\d.]+)", re.S), "mysql", "MySQL"),
]


def identify(port: int, banner: str) -> tuple[str, str | None, str | None]:
    for rx, svc, product in BANNER_RULES:
        m = rx.search(banner)
        if m:
            version = m.group(1) if m.groups() and product else None
            if svc == "ssh" and product is None and m.groups():
                product = m.group(1)
            return svc, product, version
    return WELL_KNOWN.get(port, "unknown"), None, None


@register
class PortScan(Module):
    name = "port_scan"
    description = "Checks configured TCP ports on in-scope IPs and records services and banners."
    phase = "network"
    active = True
    tools = ["nmap", "naabu"]
    produces = ["service"]

    def run(self, ctx) -> None:
        ports = [int(p) for p in (ctx.target.get("ports") or ctx.option("ports", "tcp", []))]
        if not ports:
            raise SkipModule("no ports configured")
        ip_hosts: dict[str, list[str]] = {}
        for h in ctx.hosts():
            for ip in (h.attributes or {}).get("ips", []):
                if ctx.scope.ip_allowed(ip):
                    ip_hosts.setdefault(ip, []).append(h.key)
        if not ip_hosts:
            raise SkipModule("no in-scope IP addresses to check")
        targets = sorted(ip_hosts)
        if ctx.incremental:
            fresh = []
            for ip in targets:
                a = ctx.engine.get("ip", ip)
                if a is None or ctx.needs_refresh(a, self.name):
                    fresh.append(ip)
                else:
                    ctx.mark_skipped_input(ip)
            targets = fresh
        engine = ctx.option(self.name, "engine", "builtin")
        if engine == "nmap" and ctx.tool("nmap").available:
            results = self._nmap(ctx, targets, ports)
        elif engine == "naabu" and ctx.tool("naabu").available:
            results = self._naabu(ctx, targets, ports)
        else:
            results = self._builtin(ctx, targets, ports)
        for r in results:
            ip, port = r["ip"], r["port"]
            ev = ctx.evidence("banner", f"tcp/{port} open on {ip}", json.dumps(r, indent=2))
            key = f"{ip}:{port}/tcp"
            attrs = {"ip": ip, "port": port, "proto": "tcp", "state": "open", "service": r.get("service"),
                     "product": r.get("product"), "version": r.get("version"), "banner": r.get("banner", "")[:256],
                     "hosts": sorted(ip_hosts.get(ip, [])), "engine": r.get("engine", "builtin")}
            ctx.emit(Obs("service", key, attrs, source=r.get("engine", self.name), evidence_id=ev,
                         display=f"{ip}:{port}/tcp ({r.get('service')})",
                         relations=[Rel("exposes", "ip", ip, confirmed=True, reverse=True)]))
            if r.get("service") in SENSITIVE:
                finding(ctx, "exposure.sensitive_service", key, f"{r.get('service')} service reachable", "medium",
                        f"A {r.get('service')} service answered on {ip}:{port}. Exposure is not a vulnerability by "
                        "itself; confirm whether internet reachability is intended.", ev,
                        "Restrict access with network controls if not intended to be public.", category="exposure",
                        subject_type="service")

    def _builtin(self, ctx, ips: list[str], ports: list[int]) -> list[dict]:
        timeout = float(ctx.option("ports", "timeout", 1.5))
        nbytes = int(ctx.option("ports", "banner_bytes", 256))

        def probe(pair):
            ip, port = pair
            ctx.limiter.wait()
            try:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    try:
                        banner = sock.recv(nbytes).decode("latin-1", "replace").strip()
                    except (socket.timeout, OSError):
                        banner = ""
            except (socket.timeout, OSError):
                return None
            svc, product, version = identify(port, banner)
            ctx.action("tcp connect %s:%s -> open %s %s", ip, port, svc, banner[:60])
            return {"ip": ip, "port": port, "banner": banner, "service": svc, "product": product, "version": version,
                    "engine": "port_scan"}

        pairs = [(ip, p) for ip in ips for p in ports]
        ctx.action("tcp connect scan: %d IP(s) x %d port(s) = %d probes", len(ips), len(ports), len(pairs))
        with ThreadPoolExecutor(max_workers=int(ctx.config.get("network.max_concurrency", 10))) as pool:
            return [r for r in pool.map(probe, pairs) if r]

    def _nmap(self, ctx, ips, ports) -> list[dict]:
        proc = ctx.run_tool("nmap", ["-sT", "-sV", "--version-light", "-Pn", "-n", "-p", ",".join(map(str, ports)),
                                     "-oX", "-", *ips])
        ctx.evidence("tool_output", "nmap XML output", proc.stdout, ".xml")
        return parse_nmap_xml(proc.stdout)

    def _naabu(self, ctx, ips, ports) -> list[dict]:
        proc = ctx.run_tool("naabu", ["-silent", "-json", "-p", ",".join(map(str, ports))], input_text="\n".join(ips))
        ctx.evidence("tool_output", "naabu JSONL output", proc.stdout, ".jsonl")
        return parse_naabu(proc.stdout)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    out = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        for port in host.findall("./ports/port"):
            if port.find("state").get("state") != "open":
                continue
            svc = port.find("service")
            out.append({"ip": addr, "port": int(port.get("portid")), "engine": "nmap",
                        "service": svc.get("name") if svc is not None else WELL_KNOWN.get(int(port.get("portid"))),
                        "product": svc.get("product") if svc is not None else None,
                        "version": svc.get("version") if svc is not None else None, "banner": ""})
    return out


def parse_naabu(output: str) -> list[dict]:
    out = []
    for line in output.splitlines():
        if line.strip():
            row = json.loads(line)
            port = int(row["port"]) if not isinstance(row["port"], dict) else int(row["port"]["Port"])
            out.append({"ip": row.get("ip") or row.get("host"), "port": port, "engine": "naabu",
                        "service": WELL_KNOWN.get(port, "unknown"), "banner": ""})
    return out
