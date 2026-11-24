"""Active web discovery (GET/HEAD only, scope-pinned, rate limited, authorization required).

* content_discovery – dirb-style directory and file discovery with soft-404 calibration.
                      Engines: built-in (default), ffuf, feroxbuster, gobuster, dirsearch, dirb.
* vhost_discovery   – finds virtual hosts served by known web IPs by varying only the Host header
                      (candidates are in-scope names; nothing else is sent)
* cms_intel         – WordPress / Drupal / Joomla deep fingerprint: core version, plugins and themes
                      with versions, REST-API user listing, XML-RPC, exposed debug logs
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..core.module import Module, SkipModule, register
from ..core.net import HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, is_ip, normalize_url, origin_of
from .common import finding, host_obs

WORDLIST = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "content.txt"
SECLISTS = ["/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt", "~/SecLists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt", "/usr/share/dirb/wordlists/common.txt"]
DEFAULT_CODES = [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
TITLE = re.compile(r"<title[^>]*>([^<]{0,200})</title>", re.I)
SENSITIVE = [
    (re.compile(r"(^|/)\.(git|svn|hg|bzr)(/|$)"), "low", "Version-control metadata path reachable"),
    (re.compile(r"(^|/)\.env(\.|$)|credentials|secrets?\.(json|ya?ml)|id_rsa|\.htpasswd|\.aws"), "medium", "Credential-bearing file path reachable"),
    (re.compile(r"\.(sql|sqlite|db|bak|old|backup|tar|tgz|gz|zip|rar|7z|swp)$|backup|dump"), "medium", "Backup or database file reachable"),
    (re.compile(r"(^|/)(actuator|jolokia|_profiler|telescope|debug|console|elmah\.axd|trace\.axd|server-status|server-info|phpinfo|info\.php)"),
     "low", "Debug or management endpoint reachable"),
    (re.compile(r"(^|/)(phpmyadmin|pma|adminer|pgadmin|myadmin|dbadmin)"), "low", "Database administration interface reachable"),
    (re.compile(r"(^|/)(admin|administrator|wp-admin|manager|backoffice|cpanel|panel|dashboard)(/|$)"), "info", "Administrative path discovered"),
    (re.compile(r"\.(log)$|(^|/)logs?(/|$)"), "low", "Log file or directory reachable"),
    (re.compile(r"(swagger|api-docs|openapi|graphiql|playground|altair|voyager)"), "info", "API documentation / console reachable"),
]


def load_wordlist(spec: str | None, limit: int) -> tuple[list[str], str]:
    """'builtin' (default), 'auto' (SecLists/dirb common.txt if present, else built-in) or a file path."""
    path = WORDLIST
    if spec and spec not in ("builtin", "auto"):
        path = Path(spec).expanduser()
    elif spec == "auto":
        path = next((Path(p).expanduser() for p in SECLISTS if Path(p).expanduser().exists()), WORDLIST)
    words, seen = [], set()
    for line in path.read_text(errors="replace").splitlines():
        w = line.strip().lstrip("/")
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            words.append(w)
        if len(words) >= limit:
            break
    return words, str(path)


def body_fingerprint(body: bytes, probe: str) -> str:
    """Hash of a response with the requested word removed (soft-404 pages often echo the path)."""
    return hashlib.sha256(body.replace(probe.encode(), b"")).hexdigest()[:20]


class Calibration:
    """Learns what 'not found' looks like for one origin from a few random paths."""

    def __init__(self):
        self.sigs: list[tuple[int | None, int, str]] = []

    def add(self, status, body: bytes, probe: str):
        self.sigs.append((status, len(body), body_fingerprint(body, probe)))

    def is_soft404(self, status, body: bytes, probe: str) -> bool:
        fp = body_fingerprint(body, probe)
        for s, length, sig in self.sigs:
            if fp == sig:
                return True
            if status == s and abs(len(body) - length) <= max(24, int(length * 0.04)):
                return True
        return False


def classify_hit(path: str, status: int) -> tuple[str, str] | None:
    if status not in (200, 204) and not (status in (401, 403) and "admin" in path):
        return None
    for rx, sev, title in SENSITIVE:
        if rx.search(path.lower()):
            return sev if status in (200, 204) else "info", title
    return None


def parse_ffuf(text: str) -> list[dict]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    return [{"url": r.get("url"), "status": r.get("status"), "length": r.get("length"),
             "redirect": r.get("redirectlocation") or None, "content_type": r.get("content-type")}
            for r in doc.get("results", []) if r.get("url")]


GOBUSTER_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?(?:\s*\[-->\s*(\S+)\])?")
DIRB_RE = re.compile(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")


def parse_gobuster(text: str, base: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = GOBUSTER_RE.match(line.strip().replace("\x1b[2K", ""))
        if m:
            out.append({"url": urljoin(base + "/", m.group(1).lstrip("/")), "status": int(m.group(2)),
                        "length": int(m.group(3) or 0), "redirect": m.group(4)})
    return out


def parse_dirb(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = DIRB_RE.match(line.strip())
        if m:
            out.append({"url": m.group(1), "status": int(m.group(2)), "length": int(m.group(3))})
        elif line.startswith("==> DIRECTORY:"):
            out.append({"url": line.split(":", 1)[1].strip(), "status": 301, "length": 0})
    return out


def parse_feroxbuster(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("type") == "response" and r.get("url"):
            out.append({"url": r["url"], "status": r.get("status"), "length": r.get("content_length"),
                        "redirect": (r.get("headers") or {}).get("location")})
    return out


def parse_dirsearch(text: str) -> list[dict]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    rows = doc.get("results") if isinstance(doc, dict) and "results" in doc else \
        [r for v in (doc.values() if isinstance(doc, dict) else []) if isinstance(v, list) for r in v]
    out = []
    for r in rows or []:
        url = r.get("url") or r.get("path")
        if url:
            out.append({"url": url, "status": r.get("status"), "length": r.get("content-length") or r.get("contentLength"),
                        "redirect": r.get("redirect")})
    return out


@register
class ContentDiscovery(Module):
    name = "content_discovery"
    description = "dirb-style directory/file discovery with soft-404 calibration (built-in, ffuf, feroxbuster, gobuster, dirsearch, dirb)."
    phase = "content"
    active = True
    tools = ["ffuf", "feroxbuster", "gobuster", "dirsearch", "dirb"]
    produces = ["endpoint", "finding"]

    def run(self, ctx) -> None:
        opt = lambda k, d: ctx.option(self.name, k, d)
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))
                and not 300 <= int((a.attributes or {}).get("status") or 0) < 400]
        if not apps:
            raise SkipModule("no web applications")
        apps.sort(key=lambda a: (int((a.attributes or {}).get("status") or 999) != 200, a.key))
        apps = apps[: int(opt("max_apps", 40))]
        spec = opt("wordlist", "builtin")
        if spec not in ("builtin", "auto") and not Path(spec).expanduser().is_absolute():
            spec = str(ctx.config.resolve_path(spec))  # relative to the config file's project
        words, source = load_wordlist(spec, int(opt("max_words", 2000)))
        exts = [e if e.startswith(".") else "." + e for e in (opt("extensions", []) or [])]
        codes = [int(c) for c in opt("match_codes", DEFAULT_CODES)]
        engine = opt("engine", "builtin")
        external = engine != "builtin" and ctx.tool(engine).available
        if engine != "builtin" and not external:
            ctx.log.warning("[%s] engine %s unavailable (%s); using the built-in engine", self.name, engine,
                            ctx.tool(engine).reason)
        ctx.action("content discovery: %d app(s), %d words%s from %s, engine=%s", len(apps), len(words),
                   f" x {len(exts)} extension(s)" if exts else "", source, engine if external else "builtin")
        total = 0
        for app in apps:
            if ctx.cancel is not None and ctx.cancel.is_set():
                break
            if ctx.incremental and not ctx.needs_refresh(app, self.name):
                ctx.mark_skipped_input((app.attributes or {}).get("host"))
                continue
            hits = self._external(ctx, engine, app.key, words, exts, codes) if external else \
                self._builtin(ctx, app.key, words, exts, codes)
            total += len(hits)
            self._emit(ctx, app, hits, engine if external else "builtin")
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": total,
                                                          "detail": {"apps": len(apps), "words": len(words), "wordlist": source}}

    # ------------------------------------------------------------ built-in engine
    def _builtin(self, ctx, origin: str, words: list[str], exts: list[str], codes: list[int]) -> list[dict]:
        local = threading.local()
        fetchers: list[HttpFetcher] = []

        def fetcher() -> HttpFetcher:
            if not hasattr(local, "f"):
                local.f = HttpFetcher(ctx)
                fetchers.append(local.f)
            return local.f

        cal = Calibration()
        for probe in (f"rf-{uuid.uuid4().hex[:12]}", f"rf-{uuid.uuid4().hex[:12]}.php", f"rf-{uuid.uuid4().hex[:12]}/",
                      f".rf-{uuid.uuid4().hex[:8]}"):
            r = fetcher().get(f"{origin}/{probe}")
            if r.status is None:
                return []
            cal.add(r.status, r.body, probe.rstrip("/"))
        paths = [w + e for w in words for e in ([""] + [x for x in exts if "." not in w.rsplit("/", 1)[-1]])]
        max_depth = int(ctx.option(self.name, "recursion_depth", 1))
        rec_words = words[: int(ctx.option(self.name, "recursive_words", 120))]
        hits: list[dict] = []
        seen: set[str] = set()
        lock = threading.Lock()
        counter = {"n": 0, "stop": False}

        def probe(path: str):
            if counter["stop"] or (ctx.cancel is not None and ctx.cancel.is_set()):
                return None
            url = f"{origin}/{path}"
            r = fetcher().get(url)
            with lock:
                counter["n"] += 1
                if counter["n"] % 300 == 0:
                    ctx.action("content discovery %s: %d requests, %d hit(s)", origin, counter["n"], len(hits))
            if r.status is None or r.status not in codes or cal.is_soft404(r.status, r.body, path.rsplit("/", 1)[-1]):
                return None
            title = TITLE.search(r.text[:20000]) if "html" in (r.header("content-type") or "") else None
            hit = {"url": normalize_url(url), "path": "/" + path, "status": r.status, "length": len(r.body),
                   "content_type": (r.header("content-type") or "").split(";")[0] or None,
                   "redirect": r.header("location"), "title": title.group(1).strip() if title else None,
                   "listing": bool(re.search(r"<title>\s*Index of /", r.text[:3000], re.I)), "_res": r}
            return hit

        def sweep(batch: list[str], depth: int):
            with ThreadPoolExecutor(max_workers=int(ctx.option(self.name, "threads", 10))) as pool:
                for hit in pool.map(probe, batch):
                    if not hit or hit["url"] in seen:
                        continue
                    seen.add(hit["url"])
                    hits.append(hit)
                    ctx.action("content hit %s -> %s %s", hit["url"], hit["status"], hit["length"])
                    if not counter["stop"] and len(hits) > 60 and len(hits) > counter["n"] * 0.5:
                        counter["stop"] = True  # remaining queued probes return immediately
                        ctx.log.warning("[%s] %s answers most paths; stopping (wildcard responses)", self.name, origin)
            if counter["stop"]:
                return
            if depth < max_depth:
                dirs = [h["path"].strip("/") for h in hits if h.get("depth", 0) == depth and (
                    (h["status"] in (301, 302, 307, 308) and (h.get("redirect") or "").rstrip().endswith(h["path"].rstrip("/") + "/"))
                    or (h["status"] in (200, 403) and h["listing"]))]
                for d in dirs[:10]:
                    before = len(hits)
                    sweep([f"{d}/{w}" for w in rec_words], depth + 1)
                    for h in hits[before:]:
                        h["depth"] = depth + 1

        try:
            sweep(paths, 0)
        finally:
            for f in fetchers:
                f.close()
        ctx.action("content discovery %s: %d requests, %d hit(s)", origin, counter["n"], len(hits))
        return hits

    # ------------------------------------------------------------ external engines
    def _external(self, ctx, engine: str, origin: str, words: list[str], exts: list[str], codes: list[int]) -> list[dict]:
        wl = ctx.work_dir / "content-wordlist.txt"
        wl.write_text("\n".join(words) + "\n")
        out = ctx.work_dir / f"{engine}-{uuid.uuid4().hex[:6]}.out"
        threads = str(ctx.option(self.name, "threads", 10))
        rate = str(int(float(ctx.config.get("network.rate_limit_per_second", 5)) or 5))
        mc = ",".join(map(str, codes))
        ext_csv = ",".join(e.lstrip(".") for e in exts)
        depth = str(int(ctx.option(self.name, "recursion_depth", 1)))
        if engine == "ffuf":
            args = ["-u", f"{origin}/FUZZ", "-w", str(wl), "-mc", mc, "-ac", "-t", threads, "-rate", rate, "-s",
                    "-noninteractive", "-of", "json", "-o", str(out), *(["-e", ",".join(exts)] if exts else [])]
        elif engine == "feroxbuster":
            args = ["-u", origin, "-w", str(wl), "-s", mc, "-t", threads, "--rate-limit", rate, "--json", "-o", str(out),
                    "--silent", "--depth", depth, "--no-state", "--insecure", *(["-x", ext_csv] if ext_csv else [])]
        elif engine == "gobuster":
            args = ["dir", "-u", origin, "-w", str(wl), "-s", mc, "-b", "", "-t", threads, "-q", "-k", "--no-color",
                    *(["-x", ext_csv] if ext_csv else [])]
        elif engine == "dirsearch":
            args = ["-u", origin, "-w", str(wl), "-i", mc, "-t", threads, "--max-rate", rate, "--format", "json",
                    "-o", str(out), "-q", *(["-e", ext_csv] if ext_csv else [])]
        elif engine == "dirb":
            args = [origin + "/", str(wl), "-S", "-w", *(["-r"] if depth == "0" else []), *(["-X", ",".join(exts)] if exts else [])]
        else:
            return []
        proc = ctx.run_tool(engine, args, timeout=int(ctx.option(self.name, "timeout", 1800)), keep_partial=True,
                            echo=lambda s, l: l if s == "stdout" and l.strip() and len(l) < 400 else None)
        text = out.read_text(errors="replace") if out.exists() else ""
        raw = text or proc.stdout
        ctx.evidence("tool_output", f"{engine} output for {origin}", raw[:2_000_000], ".json" if text.lstrip()[:1] in "{[" else ".txt")
        parser = {"ffuf": lambda: parse_ffuf(text), "feroxbuster": lambda: parse_feroxbuster(text or proc.stdout),
                  "gobuster": lambda: parse_gobuster(proc.stdout, origin), "dirsearch": lambda: parse_dirsearch(text),
                  "dirb": lambda: parse_dirb(proc.stdout)}[engine]
        out.unlink(missing_ok=True)
        hits = []
        for h in parser():
            if not h.get("url") or not ctx.scope.host_in_scope(host_of(h["url"])) or (h.get("status") or 0) not in codes:
                continue
            u = normalize_url(h["url"])
            hits.append({**h, "url": u, "path": urlsplit(u).path or "/", "listing": False})
        return hits

    # ------------------------------------------------------------ results
    def _emit(self, ctx, app, hits: list[dict], engine: str) -> None:
        if not hits:
            return
        from .crawler import classify_endpoint

        summary = [{k: v for k, v in h.items() if not k.startswith("_")} for h in hits]
        ev = ctx.evidence("content_discovery", f"{len(hits)} path(s) discovered on {app.key} ({engine})",
                          json.dumps(summary, indent=1, default=str))
        for h in hits:
            res = h.get("_res")
            hev = ctx.evidence("http_response", f"GET {h['url']} -> {h['status']}", format_http_evidence(res, body_limit=1500)) \
                if res is not None and h["status"] in (200, 204) and classify_hit(h["path"], h["status"]) else ev
            kind = "directory_listing" if h.get("listing") else classify_endpoint(h["url"], h.get("content_type"))
            ctx.emit(Obs("endpoint", h["url"], {"url": h["url"], "host": host_of(h["url"]), "path": h["path"], "kind": kind,
                                               "status": h["status"], "content_length": h.get("length"),
                                               "content_type": h.get("content_type"), "redirect": h.get("redirect"),
                                               "title": h.get("title"), "+discovered_via": ["content_discovery"],
                                               "discovery_engine": engine},
                         evidence_id=hev, relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
            cls = classify_hit(h["path"], h["status"])
            if h.get("listing"):
                finding(ctx, "disclosure.directory_listing", h["url"], "Directory listing enabled", "low",
                        f"{h['url']} returns an auto-generated directory index.", hev, "Disable auto-indexing.",
                        category="disclosure", subject_type="endpoint")
            elif cls:
                sev, title = cls
                finding(ctx, f"content.{re.sub(r'[^a-z0-9]+', '_', title.lower()).strip('_')}", h["url"], title, sev,
                        f"{h['url']} answered {h['status']} ({h.get('length') or 0} bytes) during content discovery.", hev,
                        "Confirm the path must be public; otherwise remove it or restrict access.",
                        category="exposure", subject_type="endpoint", extra={"path": h["path"], "status": h["status"]})


# --------------------------------------------------------------------------- vhost discovery

VHOST_WORDS = ["admin", "internal", "intranet", "dev", "development", "staging", "stage", "test", "qa", "uat", "preprod", "beta",
               "api", "portal", "vpn", "mail", "webmail", "git", "gitlab", "jenkins", "ci", "grafana", "kibana", "monitor",
               "old", "legacy", "backup", "corp", "secure", "private", "cms", "app", "dashboard", "console", "manage", "www2",
               "demo", "sandbox", "shop", "store", "static", "cdn", "assets", "auth", "sso", "login", "help", "support"]


@register
class VhostDiscovery(Module):
    name = "vhost_discovery"
    description = "Finds virtual hosts on known web IPs by varying only the Host header (in-scope names; GET only)."
    phase = "fingerprint"
    active = True
    produces = ["web_app", "subdomain"]

    def run(self, ctx) -> None:
        roots = ctx.scope.root_domains
        if not roots:
            raise SkipModule("virtual-host names must be in scope; this scan has no domain targets")
        apps = [a for a in ctx.live("web_app") if (a.attributes or {}).get("ip")]
        if not apps:
            raise SkipModule("no web applications with a known IP")
        groups: dict[tuple, set[str]] = {}
        for a in apps:
            at = a.attributes or {}
            key = (at["ip"], at.get("scheme") or a.key.split(":")[0], int(at.get("port") or (443 if a.key.startswith("https") else 80)))
            groups.setdefault(key, set()).add(at.get("host") or host_of(a.key))
        known = {s.key for s in ctx.assets(["subdomain", "domain"])}
        words = VHOST_WORDS + list(ctx.option(self.name, "extra_words", []) or [])
        generated = {f"{w}.{r}" for r in roots for w in words}
        max_c = int(ctx.option(self.name, "max_candidates", 250))
        fetcher = HttpFetcher(ctx)
        cache = ctx.shared.setdefault("http_root", {})
        found = 0
        try:
            for (ip, scheme, port), served in list(groups.items())[: int(ctx.option(self.name, "max_ips", 40))]:
                if not ctx.scope.ip_allowed(ip):
                    continue
                root = next(iter(roots))
                rnd = f"rf-vhost-{uuid.uuid4().hex[:8]}.{root}"
                base = fetcher.get(f"{scheme}://{rnd}:{port}/", ip=ip)
                if base.status is None:
                    continue
                cal = Calibration()
                cal.add(base.status, base.body, rnd)
                candidates = sorted((known | generated) - served)
                candidates = [c for c in candidates if ctx.scope.host_in_scope(c) and not is_ip(c)][:max_c]
                ctx.action("vhost discovery %s:%s (%s): %d candidate Host header(s)", ip, port, scheme, len(candidates))
                for name in candidates:
                    if ctx.cancel is not None and ctx.cancel.is_set():
                        return
                    r = fetcher.get(f"{scheme}://{name}:{port}/", ip=ip)
                    if r.status is None or cal.is_soft404(r.status, r.body, name):
                        continue
                    origin = origin_of(f"{scheme}://{name}:{port}/")
                    found += 1
                    ctx.action("vhost hit %s on %s:%s -> %s", name, ip, port, r.status)
                    cache.setdefault(origin, r)
                    ev = ctx.evidence("http_response", f"Host: {name} on {ip}:{port} -> {r.status}", format_http_evidence(r))
                    title = TITLE.search(r.text[:20000])
                    ctx.emit(Obs("web_app", origin, {"url": origin, "host": name, "scheme": scheme, "ip": ip, "port": port,
                                                     "status": r.status, "title": title.group(1).strip() if title else None,
                                                     "server": r.header("server"), "vhost_on": ip,
                                                     "+discovered_via": ["vhost_discovery"]}, evidence_id=ev,
                                 relations=[Rel("serves", "subdomain", name, confirmed=True, reverse=True),
                                            Rel("hosted_on", "ip", ip, confirmed=True)]))
                    sub = ctx.engine.get("subdomain", name)
                    resolves = bool(sub and (sub.attributes or {}).get("resolved"))
                    o = host_obs(ctx, name, "vhost_discovery", ev, {"+vhost_ips": [ip]})
                    if o:
                        ctx.emit(o)
                    if not resolves:
                        finding(ctx, "web.hidden_vhost", origin, "Virtual host reachable only via Host header", "low",
                                f"{ip}:{port} serves {name} (status {r.status}) although the name does not resolve publicly. "
                                "Hidden virtual hosts often expose staging or internal applications.", ev,
                                "Confirm the virtual host should be reachable from the internet.", category="exposure",
                                subject_type="web_app")
        finally:
            fetcher.close()
        ctx.shared.setdefault("sources", {})[self.name] = {"kind": "technique", "status": "ok", "results": found}


# --------------------------------------------------------------------------- CMS intelligence

WP_PLUGIN = re.compile(r"/wp-content/plugins/([a-z0-9_\-]+)/[^\"'\s>]*?(?:\?ver=([0-9.]+))?[\"'\s>]", re.I)
WP_THEME = re.compile(r"/wp-content/themes/([a-z0-9_\-]+)/", re.I)
STABLE_TAG = re.compile(r"^\s*Stable tag:\s*([0-9][0-9a-z.\-]*)", re.I | re.M)
GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)


def detect_cms(headers: dict, body: str) -> str | None:
    low = body[:300000].lower()
    m = GENERATOR.search(body[:300000])
    gen = m.group(1).lower() if m else ""
    if "wp-content/" in low or "wp-includes/" in low or "wordpress" in gen:
        return "WordPress"
    if "drupal" in gen or "drupal.settings" in low or "/sites/default/files" in low or "drupal" in (headers.get("x-generator") or "").lower():
        return "Drupal"
    if "joomla" in gen or "/media/jui/" in low or "/media/system/js/" in low:
        return "Joomla"
    return None


@register
class CmsIntel(Module):
    name = "cms_intel"
    description = "WordPress/Drupal/Joomla deep fingerprint: versions, plugins/themes, REST user listing, XML-RPC, debug logs (GET only)."
    phase = "assessment"
    active = True
    produces = ["finding"]

    def run(self, ctx) -> None:
        cache = ctx.shared.get("http_root", {})
        targets = [(o, detect_cms(r.headers, r.text)) for o, r in cache.items() if r.status and r.status < 400]
        targets = [(o, c) for o, c in targets if c and ctx.in_filter(host_of(o))]
        if not targets:
            raise SkipModule("no WordPress, Drupal or Joomla sites identified in this scan")
        fetcher = HttpFetcher(ctx)
        try:
            for origin, cms in targets[: int(ctx.option(self.name, "max_sites", 40))]:
                ctx.action("cms %s -> %s", origin, cms)
                info = {"name": cms}
                if cms == "WordPress":
                    self._wordpress(ctx, fetcher, origin, cache[origin].text, info)
                elif cms == "Drupal":
                    self._drupal(ctx, fetcher, origin, info)
                else:
                    self._joomla(ctx, fetcher, origin, info)
                ev = ctx.evidence("cms", f"{cms} fingerprint for {origin}", json.dumps(info, indent=2))
                rels = [Rel("uses", "technology", cms, confirmed=True, attrs={"version": info.get("version") or "", "confidence": 0.9,
                                                                               "matched": ["cms_intel"]},
                            target_attrs={"name": cms, "categories": ["CMS"],
                                          "+versions_seen": [info["version"]] if info.get("version") else []})]
                for p in info.get("plugins", [])[:60]:
                    rels.append(Rel("uses", "technology", f"{cms} plugin: {p['name']}", confirmed=True,
                                    attrs={"version": p.get("version") or "", "confidence": 0.8, "matched": ["cms_intel"]},
                                    target_attrs={"name": f"{cms} plugin: {p['name']}", "categories": ["CMS plugin"]}))
                ctx.emit(Obs("web_app", origin, {"cms": info}, evidence_id=ev, relations=rels))
        finally:
            fetcher.close()

    def _wordpress(self, ctx, fetcher, origin, html, info):
        plugins = {}
        for name, ver in WP_PLUGIN.findall(html[:500000]):
            plugins.setdefault(name.lower(), ver or None)
        info["themes"] = sorted({t.lower() for t in WP_THEME.findall(html[:500000])})
        gen = GENERATOR.search(html[:300000])
        if gen and "wordpress" in gen.group(1).lower():
            info["version"] = gen.group(1).split()[-1]
        if not info.get("version"):
            r = fetcher.get(origin + "/feed/")
            m = re.search(r"<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>", r.text[:5000]) if r.status == 200 else None
            if m:
                info["version"] = m.group(1)
        out = []
        for name, ver in list(plugins.items())[: int(ctx.option(self.name, "max_plugins", 30))]:
            r = fetcher.get(f"{origin}/wp-content/plugins/{name}/readme.txt")
            m = STABLE_TAG.search(r.text[:6000]) if r.status == 200 else None
            out.append({"name": name, "version": (m.group(1) if m else None) or ver, "readme": r.status == 200})
        info["plugins"] = out
        r = fetcher.get(origin + "/wp-json/wp/v2/users?per_page=100")
        users = []
        if r.status == 200 and r.text.lstrip().startswith("["):
            try:
                users = [{"id": u.get("id"), "slug": u.get("slug"), "name": u.get("name")} for u in json.loads(r.text) if isinstance(u, dict)]
            except ValueError:
                users = []
        info["rest_users"] = users
        if users:
            ev = ctx.evidence("http_response", f"WordPress REST users on {origin}", format_http_evidence(r, body_limit=4000))
            finding(ctx, "cms.wp_user_enumeration", origin, "WordPress users listed by the REST API", "low",
                    f"{origin}/wp-json/wp/v2/users returns {len(users)} account(s) ({', '.join(u['slug'] or '' for u in users[:8])}).",
                    ev, "Restrict the users endpoint to authenticated requests if usernames should not be public.",
                    category="disclosure", subject_type="web_app", extra={"users": [u["slug"] for u in users]})
        r = fetcher.get(origin + "/xmlrpc.php")
        info["xmlrpc"] = r.status in (200, 405) and "XML-RPC server accepts POST requests only" in r.text[:2000]
        if info["xmlrpc"]:
            ev = ctx.evidence("http_response", f"XML-RPC on {origin}", format_http_evidence(r, body_limit=500))
            finding(ctx, "cms.wp_xmlrpc", origin, "WordPress XML-RPC endpoint enabled", "info",
                    f"{origin}/xmlrpc.php is enabled. It is commonly abused for credential stuffing and pingback reflection.",
                    ev, "Disable XML-RPC if it is not needed.", category="exposure", subject_type="web_app")
        r = fetcher.get(origin + "/wp-content/debug.log")
        if r.status == 200 and re.search(r"PHP (Notice|Warning|Fatal|Deprecated)", r.text[:20000]):
            ev = ctx.evidence("http_response", f"debug.log on {origin}",
                              format_http_evidence(r, body_limit=0) + f"\n\n<{len(r.body)} bytes; content not stored>")
            finding(ctx, "cms.wp_debug_log", origin + "/wp-content/debug.log", "WordPress debug log exposed", "medium",
                    "The PHP debug log is publicly readable and may disclose paths, queries and secrets.", ev,
                    "Disable WP_DEBUG_LOG on production and delete the file.", category="exposure", subject_type="endpoint")

    def _drupal(self, ctx, fetcher, origin, info):
        for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
            r = fetcher.get(origin + path)
            m = re.search(r"Drupal ([0-9][0-9.]+)", r.text[:2000]) if r.status == 200 else None
            if m:
                info["version"] = m.group(1)
                info["changelog"] = path
                break
        r = fetcher.get(origin + "/user/login")
        info["login"] = r.status == 200

    def _joomla(self, ctx, fetcher, origin, info):
        r = fetcher.get(origin + "/administrator/manifests/files/joomla.xml")
        m = re.search(r"<version>([0-9.]+)</version>", r.text[:5000]) if r.status == 200 else None
        if m:
            info["version"] = m.group(1)
        r = fetcher.get(origin + "/administrator/")
        info["admin_login"] = r.status == 200 and "joomla" in r.text[:20000].lower()
