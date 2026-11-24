"""Generic adapters that run registry tools (data/tools.yaml) without per-tool code.

* external_subdomains – every selected `subdomain_enum` tool with a command template
* external_urls       – every selected `url_collection` tool with a command template

Tools are selected by the registry's selection engine (installed, correct binary,
credentials, profile). Output is parsed generically: hostnames under the root domains,
or URLs on in-scope hosts, so format differences between tool versions are tolerated.
"""
from __future__ import annotations

import re
import time

from ..core.module import Module, SkipModule, register
from ..core.registry import render_command, select_tools
from ..util import host_of, normalize_url
from .common import host_obs

URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def extract_hostnames(text: str, roots: list[str]) -> set[str]:
    out = set()
    for root in roots:
        rx = re.compile(r"(?<![a-z0-9_-])(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*" + re.escape(root) + r"(?![a-z0-9-])", re.I)
        out |= {m.group(0).lower().lstrip("*.") for m in rx.finditer(text)}
    return out


def record_selection(ctx, module: str, statuses) -> None:
    ctx.shared.setdefault("tool_selection", {})[module] = [st.as_dict() for _, st in statuses]


def _run_selected(ctx, module_name: str, category: str):
    statuses = select_tools(ctx.config, category, active_allowed=bool(ctx.profile.get("active", True)), offline=ctx.offline)
    record_selection(ctx, module_name, statuses)
    only = ctx.shared.get("only_tools")
    chosen = [(e, st) for e, st in statuses if st.selected and (not only or e["name"] in only)]
    if not chosen:
        reasons = "; ".join(f"{st.name}: {st.reason}" for _, st in statuses) or "no tools registered"
        raise SkipModule(f"no {category} tools selected ({reasons})")
    return chosen


@register
class ExternalSubdomains(Module):
    name = "external_subdomains"
    needs_domains = True
    description = "Runs installed registry subdomain tools (amass, assetfinder, findomain, chaos, github-subdomains, ...)."
    phase = "passive"
    requires_internet = True
    handles_offline = True  # the registry selection engine records the offline reason
    produces = ["subdomain"]

    def run(self, ctx) -> None:
        sources = ctx.shared.setdefault("sources", {})
        for entry, st in _run_selected(ctx, self.name, "subdomain_enum"):
            found: set[str] = set()
            start = time.monotonic()
            try:
                for root in ctx.scope.root_domains:
                    cmd = render_command(entry, domain=root)
                    proc = ctx.run_tool(entry["name"], cmd, timeout=int(entry.get("timeout", 900)))
                    ev = ctx.evidence("tool_output", f"{entry['name']} output for {root}", proc.stdout)
                    for h in extract_hostnames(proc.stdout, [root]):
                        o = host_obs(ctx, h, entry["name"], ev)
                        if o:
                            ctx.emit(o)
                            found.add(h)
                sources[entry["name"]] = {"kind": "tool", "status": "ok", "results": len(found),
                                          "seconds": round(time.monotonic() - start, 1)}
            except Exception as exc:  # one tool failing must not stop the others
                sources[entry["name"]] = {"kind": "tool", "status": "error", "error": str(exc)[:300]}
                ctx.log.error("[%s] %s failed: %s", self.name, entry["name"], exc)


@register
class ExternalUrls(Module):
    name = "external_urls"
    needs_domains = True
    description = "Runs installed registry URL collectors (waybackurls, waymore, ...) and records in-scope URLs."
    phase = "passive"
    requires_internet = True
    handles_offline = True  # the registry selection engine records the offline reason
    produces = ["endpoint"]

    def run(self, ctx) -> None:
        from ..core.observation import Obs, Rel
        from .crawler import classify_endpoint

        sources = ctx.shared.setdefault("sources", {})
        for entry, st in _run_selected(ctx, self.name, "url_collection"):
            n = 0
            try:
                for root in ctx.scope.root_domains:
                    proc = ctx.run_tool(entry["name"], render_command(entry, domain=root),
                                        input_text=root + "\n", timeout=int(entry.get("timeout", 900)))
                    ev = ctx.evidence("tool_output", f"{entry['name']} URLs for {root}", proc.stdout)
                    for raw in {m.group(0) for m in URL_RE.finditer(proc.stdout)}:
                        host = host_of(raw)
                        if not ctx.scope.host_in_scope(host):
                            continue
                        url = normalize_url(raw)
                        n += 1
                        ctx.emit(Obs("endpoint", url, {"url": url, "host": host, "kind": classify_endpoint(url),
                                                       "historical": True, "+discovered_via": [entry["name"]]},
                                     source=entry["name"], evidence_id=ev, confidence=0.9,
                                     relations=[Rel("historical_url", "subdomain", host, confirmed=False, reverse=True)]))
                sources[entry["name"]] = {"kind": "tool", "status": "ok", "results": n}
            except Exception as exc:
                sources[entry["name"]] = {"kind": "tool", "status": "error", "error": str(exc)[:300]}
                ctx.log.error("[%s] %s failed: %s", self.name, entry["name"], exc)
