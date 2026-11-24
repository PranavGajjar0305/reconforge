"""Technology identification (built-in fingerprint engine, optional WhatWeb)."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import yaml

from ..core.module import Module, SkipModule, register
from ..core.net import FetchResult, HttpFetcher
from ..core.observation import Obs, Rel

DATA = Path(__file__).resolve().parent.parent / "data" / "fingerprints.yaml"
META_RE = re.compile(r"<meta\s+[^>]*name=[\"']([^\"']+)[\"'][^>]*content=[\"']([^\"']*)[\"']", re.I)
SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
LINK_RE = re.compile(r"<link[^>]+href=[\"']([^\"']+)[\"']", re.I)


@lru_cache
def load_fingerprints() -> list[dict]:
    rules = yaml.safe_load(DATA.read_text())
    for r in rules:
        r["_compiled"] = {}
        for kind in ("header", "meta"):
            if kind in r:
                r["_compiled"][kind] = {k.lower(): re.compile(v, re.I) for k, v in r[kind].items()}
        for kind in ("body", "script", "cookie"):
            if kind in r:
                r["_compiled"][kind] = re.compile(r[kind], re.I)
    return rules


def fingerprint(headers: dict[str, str], body: str, cookies: list[str]) -> list[dict]:
    """Return [{name, version, categories, confidence, evidence}] for a response."""
    metas = {k.lower(): v for k, v in META_RE.findall(body[:300000])}
    scripts = SCRIPT_RE.findall(body[:300000]) + LINK_RE.findall(body[:300000])
    cookie_names = [c.split("=", 1)[0].strip() for c in cookies]
    found: dict[str, dict] = {}
    for rule in load_fingerprints():
        comp = rule["_compiled"]
        hits: list[tuple[str, str | None]] = []
        for h, rx in comp.get("header", {}).items():
            v = headers.get(h)
            if v is not None and (m := rx.search(v)):
                hits.append((f"header {h}: {v[:80]}", m.groupdict().get("version")))
        for n, rx in comp.get("meta", {}).items():
            v = metas.get(n)
            if v is not None and (m := rx.search(v)):
                hits.append((f"meta {n}={v[:80]}", m.groupdict().get("version")))
        if "body" in comp and (m := comp["body"].search(body[:300000])):
            hits.append((f"body matches /{comp['body'].pattern[:60]}/", m.groupdict().get("version")))
        if "script" in comp:
            for s in scripts:
                if m := comp["script"].search(s):
                    hits.append((f"resource {s[:120]}", m.groupdict().get("version")))
                    break
        if "cookie" in comp:
            for c in cookie_names:
                if comp["cookie"].search(c):
                    hits.append((f"cookie {c}", None))
                    break
        if hits:
            version = next((v for _, v in hits if v), None)
            base = float(rule.get("confidence", 0.8))
            conf = min(0.99, base + 0.1 * (len(hits) - 1))
            found[rule["name"]] = {"name": rule["name"], "version": version or "", "categories": rule["categories"],
                                   "confidence": round(conf, 2), "evidence": [h for h, _ in hits][:4]}
    return list(found.values())


@register
class TechDetect(Module):
    name = "tech_detect"
    description = "Identifies web servers, frameworks, CMS, CDN/WAF, cloud and libraries from responses."
    phase = "fingerprint"
    active = True  # may re-fetch root pages when not cached
    tools = ["whatweb"]
    produces = ["technology"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))]
        if not apps:
            raise SkipModule("no web applications discovered")
        use_whatweb = ctx.option(self.name, "engine", "builtin") == "whatweb" and ctx.tool("whatweb").available
        cache: dict[str, FetchResult] = ctx.shared.get("http_root", {})
        fetcher = None
        try:
            for app in apps:
                if ctx.incremental and app.key not in cache and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host", app.key))
                    continue
                res = cache.get(app.key)
                if res is None:
                    fetcher = fetcher or HttpFetcher(ctx)
                    res = fetcher.get(app.key + "/")
                    if res.status is None:
                        continue
                techs = fingerprint(res.headers, res.text, res.set_cookies())
                # Fold in JS-library hits from crawled scripts discovered earlier this scan.
                for extra in ctx.shared.get("tech_hints", {}).get(app.key, []):
                    techs.append(extra)
                if use_whatweb:
                    techs += self._whatweb(ctx, app.key)
                self._emit(ctx, app, techs)
        finally:
            if fetcher:
                fetcher.close()

    def _emit(self, ctx, app, techs: list[dict]) -> None:
        merged: dict[str, dict] = {}
        for t in techs:
            cur = merged.get(t["name"])
            if not cur or (t.get("version") and not cur.get("version")):
                merged[t["name"]] = t
        if not merged:
            return
        ev = ctx.evidence("fingerprint", f"technology matches for {app.key}", json.dumps(list(merged.values()), indent=2))
        categories: dict[str, list[str]] = {}
        for t in merged.values():
            for c in t["categories"]:
                categories.setdefault(c, []).append(t["name"])
        rels = [Rel("uses", "technology", t["name"], confirmed=t["confidence"] >= 0.7,
                    attrs={"version": t.get("version") or "", "confidence": t["confidence"], "matched": t["evidence"]},
                    target_attrs={"name": t["name"], "categories": t["categories"],
                                  "+versions_seen": [t["version"]] if t.get("version") else []})
                for t in merged.values()]
        ctx.emit(Obs("web_app", app.key, {
            "technologies": {n: t.get("version") or "" for n, t in sorted(merged.items())},
            "tech_categories": {k: sorted(set(v)) for k, v in categories.items()},
        }, evidence_id=ev, relations=rels))

    def _whatweb(self, ctx, url: str) -> list[dict]:
        proc = ctx.run_tool("whatweb", ["--color=never", "-a", "1", "--log-json=-", url], timeout=120)
        ctx.evidence("tool_output", f"whatweb {url}", proc.stdout, ".json")
        return parse_whatweb(proc.stdout)


def parse_whatweb(output: str) -> list[dict]:
    out = []
    text = output.strip()
    if not text:
        return out
    try:
        rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
    except ValueError:
        return out
    skip = {"IP", "Country", "Title", "HTTPServer", "UncommonHeaders", "RedirectLocation", "Cookies", "HttpOnly",
            "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "Script", "Email", "Meta-Author"}
    for row in rows:
        for name, data in (row.get("plugins") or {}).items():
            if name in skip:
                continue
            version = (data.get("version") or [""])[0] if isinstance(data, dict) else ""
            out.append({"name": name, "version": version, "categories": ["whatweb"], "confidence": 0.75,
                        "evidence": [f"whatweb plugin {name}"]})
    return out
