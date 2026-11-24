"""Content analysis: JavaScript analysis and API documentation discovery."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..core.module import Module, SkipModule, register
from ..core.net import HttpFetcher, format_http_evidence
from ..core.observation import Obs, Rel
from ..util import host_of, normalize_url, origin_of, sha256
from .common import finding
from .crawler import classify_endpoint

STRING_RE = re.compile(r"""["'`]((?:https?|wss?)://[^"'`\s<>]{4,300}|/[A-Za-z0-9_\-./{}:$]{2,200})["'`]""")
CALL_RE = re.compile(
    r"""(?:axios|http|api|client|\$)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]"""
    r"""|fetch\(\s*["'`]([^"'`]+)["'`]\s*(?:,\s*\{[^}]*?method\s*:\s*["'`](\w+)["'`])?""", re.I)
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("Generic bearer token assignment", re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{24,}[\"']")),
]
LIB_VERSION_RE = re.compile(r"/\*!?\s*([A-Za-z][\w.\- ]{1,40}?)\s+v?(\d+\.\d+\.\d+)")
DOC_PATHS = ["/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/openapi.json",
             "/api/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui/", "/swagger-ui.html", "/docs", "/redoc",
             "/graphql", "/api/graphql", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
             "/saml/metadata", "/saml2/metadata", "/FederationMetadata/2007-06/FederationMetadata.xml"]


def redact(value: str) -> str:
    return f"{value[:4]}…[redacted, sha256:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"


def extract_js(text: str, base_url: str) -> dict:
    """Pure function: extract references from JavaScript source."""
    urls, methods = set(), {}
    for m in STRING_RE.finditer(text):
        val = m.group(1)
        if val.startswith("/") and (val.startswith("//") or re.search(r"\.(?:png|jpe?g|svg|css|gif|woff2?)$", val)):
            continue
        urls.add(val)
    for m in CALL_RE.finditer(text):
        method, path = (m.group(1), m.group(2)) if m.group(2) else ((m.group(4) or "GET"), m.group(3))
        methods.setdefault(path, set()).add(method.upper())
        urls.add(path)
    secrets = []
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            secrets.append({"type": label, "redacted": redact(m.group(0)), "offset": m.start()})
    libs = [{"name": n.strip(), "version": v} for n, v in LIB_VERSION_RE.findall(text[:5000])]
    sm = SOURCEMAP_RE.search(text)
    resolved = {}
    for u in urls:
        absolute = urljoin(base_url, u) if u.startswith("/") else u
        resolved[absolute] = sorted(methods.get(u, set()))
    return {"urls": resolved, "secrets": secrets, "libraries": libs,
            "sourcemap": urljoin(base_url, sm.group(1)) if sm else None}


@register
class JsAnalysis(Module):
    name = "js_analysis"
    description = "Analyses in-scope JavaScript for endpoints, API calls, WebSockets, third parties and exposed data patterns."
    phase = "content"
    active = True
    tools = ["retire"]
    produces = ["endpoint", "third_party", "finding"]

    def run(self, ctx) -> None:
        files = [a for a in ctx.live("js_file") if ctx.in_filter((a.attributes or {}).get("host"))]
        if not files:
            raise SkipModule("no in-scope JavaScript files discovered")
        fetcher = HttpFetcher(ctx)
        bodies = ctx.shared.setdefault("js_bodies", {})
        try:
            for js in files:
                if ctx.incremental and not ctx.needs_refresh(js, self.name):
                    ctx.mark_skipped_input(js.key)
                    continue
                res = fetcher.get(js.key)
                if res.status != 200:
                    continue
                text = res.text
                bodies[js.key] = text
                ev = ctx.evidence("file", f"JavaScript {js.key} ({len(res.body)} bytes)", text, ".js")
                info = extract_js(text, js.key)
                origin = (js.attributes or {}).get("loaded_by", [origin_of(js.key)])[0]
                n_endpoints, thirds = 0, set()
                for url, methods in info["urls"].items():
                    host = host_of(url)
                    if not host:
                        continue
                    if ctx.scope.host_in_scope(host):
                        kind = classify_endpoint(url)
                        if kind == "page" and not methods:
                            continue  # only keep API-like references from JS
                        nurl = normalize_url(url)
                        n_endpoints += 1
                        ctx.emit(Obs("endpoint", nurl, {"url": nurl, "host": host, "path": urlsplit(nurl).path,
                                                        "kind": kind, "+discovered_via": ["js_analysis"],
                                                        "+methods_documented": methods, "+referenced_in": [js.key]},
                                     evidence_id=ev, confidence=0.8,
                                     relations=[Rel("references_endpoint", "js_file", js.key, confirmed=False, reverse=True),
                                                Rel("has_endpoint", "web_app", origin_of(nurl.replace("wss://", "https://").replace("ws://", "http://")),
                                                    confirmed=False, reverse=True)]))
                        if host != (js.attributes or {}).get("host"):
                            ctx.emit(Obs("subdomain", host, {"+discovered_via": ["js_analysis"]}, evidence_id=ev))
                    else:
                        thirds.add(host)
                for host in thirds:
                    ctx.emit(Obs("third_party", host, {"+reference_kinds": ["javascript"]}, evidence_id=ev,
                                 relations=[Rel("references", "js_file", js.key, confirmed=True, reverse=True)]))
                for s in info["secrets"]:
                    finding(ctx, "exposure.secret_pattern_in_js", f"{js.key}#{s['redacted'][-13:-1]}",
                            f"Possible {s['type']} pattern in JavaScript", "medium",
                            f"A string matching the {s['type']} pattern was found in {js.key} (value redacted: "
                            f"{s['redacted']}). Pattern matches are frequently test/example values.", ev,
                            "Manually verify whether the value is a real credential; rotate it if so.",
                            category="exposure", subject_type="js_file", extra={"pattern": s["type"], "js_file": js.key})
                if info["sourcemap"] and ctx.scope.host_in_scope(host_of(info["sourcemap"])):
                    ctx.emit(Obs("endpoint", normalize_url(info["sourcemap"]), {"url": info["sourcemap"], "kind": "sourcemap",
                                                                                 "host": host_of(info["sourcemap"]),
                                                                                 "+discovered_via": ["js_analysis"]},
                                 evidence_id=ev, relations=[Rel("references_endpoint", "js_file", js.key, confirmed=False, reverse=True)]))
                ctx.emit(Obs("js_file", js.key, {"size": len(res.body), "sha256": sha256(res.body),
                                                 "endpoints_found": n_endpoints, "third_parties": sorted(thirds),
                                                 "libraries": info["libraries"], "sourcemap": info["sourcemap"],
                                                 "secret_patterns": len(info["secrets"])}, evidence_id=ev))
                hints = ctx.shared.setdefault("tech_hints", {}).setdefault(origin, [])
                for lib in info["libraries"]:
                    hints.append({"name": lib["name"], "version": lib["version"], "categories": ["js_library"],
                                  "confidence": 0.6, "evidence": [f"banner in {js.key}"]})
        finally:
            fetcher.close()
        if ctx.option(self.name, "engine", "builtin") == "retire" and ctx.tool("retire").available:
            self._retire(ctx, bodies)

    def _retire(self, ctx, bodies: dict) -> None:
        """Run Retire.js over the JavaScript collected this scan to flag known-vulnerable libraries."""
        import tempfile

        files = {k: v for k, v in bodies.items() if ctx.in_filter(host_of(k))}
        if not files:
            return
        with tempfile.TemporaryDirectory(prefix="retire-", dir=ctx.work_dir) as tmp:  # stays inside data/work
            index = {}
            for i, (url, text) in enumerate(files.items()):
                p = f"{i}.js"
                (Path(tmp) / p).write_text(text, errors="replace")
                index[p] = url
            ctx.action("retire.js: scanning %d collected JavaScript file(s) for vulnerable libraries", len(files))
            try:
                proc = ctx.run_tool("retire", ["--path", tmp, "--outputformat", "json", "--exitwith", "0"],
                                    timeout=180, keep_partial=True,
                                    echo=lambda s, l: None)
            except Exception as exc:  # pragma: no cover - environment specific
                ctx.log.info("retire.js run failed: %s", exc)
                return
            ev = ctx.evidence("tool_output", "retire.js JSON output", proc.stdout or proc.stderr, ".json")
            for rec in _parse_retire(proc.stdout):
                url = index.get(Path(rec["file"]).name, rec["file"])
                host = host_of(url)
                for comp in rec["results"]:
                    for vuln in comp.get("vulnerabilities", []) or []:
                        ids = vuln.get("identifiers", {}) or {}
                        cves = ids.get("CVE") or []
                        sev = (vuln.get("severity") or "medium").lower()
                        sev = sev if sev in ("critical", "high", "medium", "low", "info") else "medium"
                        title = f"Vulnerable {comp['component']} {comp.get('version', '')}".strip()
                        summary = ids.get("summary") or (cves[0] if cves else title)
                        finding(ctx, f"dependency.retire.{comp['component']}.{comp.get('version', '')}",
                                url, title, sev,
                                f"Retire.js flagged {comp['component']} {comp.get('version', '')} loaded from {url}: {summary}",
                                ev, "Confirm the library version in use and upgrade to a fixed release.",
                                category="cve" if cves else "dependency", subject_type="js_file",
                                extra={"component": comp["component"], "version": comp.get("version"),
                                       "cves": cves, "references": (vuln.get("info") or [])[:5]})


@register
class ApiDiscovery(Module):
    name = "api_discovery"
    description = "Looks for OpenAPI/Swagger documents, GraphQL and OIDC metadata at well-known paths (GET only)."
    phase = "content"
    active = True
    produces = ["endpoint"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))
                and not 300 <= int((a.attributes or {}).get("status") or 0) < 400]
        if not apps:
            raise SkipModule("no web applications discovered")
        fetcher = HttpFetcher(ctx)
        try:
            for app in apps:
                if ctx.incremental and not ctx.needs_refresh(app, self.name):
                    ctx.mark_skipped_input((app.attributes or {}).get("host", app.key))
                    continue
                self._probe(ctx, fetcher, app)
        finally:
            fetcher.close()

    def _probe(self, ctx, fetcher, app) -> None:
        origin = app.key
        root_hash = (app.attributes or {}).get("body_sha256")
        api_signals = []
        for path in DOC_PATHS:
            res = fetcher.get(origin + path)
            if res.status is None or res.status in (404, 405, 410) or res.status >= 500:
                continue
            if res.body and sha256(res.body)[:32] == root_hash:
                continue  # catch-all route returning the home page
            ctype = (res.header("content-type") or "").split(";")[0]
            text = res.text
            ev = ctx.evidence("http_response", f"GET {origin}{path} -> {res.status}", format_http_evidence(res, body_limit=8000))
            if path.endswith("graphql"):
                if re.search(r"graphql|must provide query|query string|\"errors\"\s*:", text, re.I):
                    api_signals.append("graphql")
                    self._ep(ctx, origin, origin + path, "graphql", ev, {"status": res.status, "graphql_detected": True,
                                                                         "note": "Detected via GET only; no queries or introspection sent."})
                continue
            if res.status != 200:
                continue
            if "json" in ctype or text.lstrip().startswith("{"):
                try:
                    doc = json.loads(text)
                except ValueError:
                    continue
                if "openapi" in doc or "swagger" in doc:
                    api_signals.append("openapi")
                    self._openapi(ctx, origin, origin + path, doc, ev)
                elif "issuer" in doc and "authorization_endpoint" in doc:
                    api_signals.append("oidc")
                    self._ep(ctx, origin, origin + path, "oidc_metadata", ev,
                             {"issuer": doc.get("issuer"), "status": 200})
            elif "EntityDescriptor" in text[:5000] and ("saml" in path.lower() or "Federation" in path):
                api_signals.append("saml")
                ent = re.search(r'entityID="([^"]+)"', text)
                self._ep(ctx, origin, origin + path, "saml_metadata", ev, {"status": 200, "entity_id": ent.group(1) if ent else None})
            elif "html" in ctype and re.search(r"swagger-ui|redoc|api documentation", text, re.I):
                api_signals.append("docs_ui")
                self._ep(ctx, origin, origin + path, "api_documentation", ev, {"status": 200, "ui": True})
        if api_signals:
            ctx.emit(Obs("web_app", origin, {"is_api": True, "api_signals": sorted(set(api_signals))}))

    def _ep(self, ctx, origin, url, kind, ev, extra) -> None:
        nurl = normalize_url(url)
        ctx.emit(Obs("endpoint", nurl, {"url": nurl, "host": host_of(nurl), "path": urlsplit(nurl).path, "kind": kind,
                                        "+discovered_via": ["api_discovery"], **extra}, evidence_id=ev,
                     relations=[Rel("has_endpoint", "web_app", origin, confirmed=True, reverse=True)]))

    def _openapi(self, ctx, origin, doc_url, doc: dict, ev) -> None:
        version = doc.get("openapi") or doc.get("swagger")
        info = doc.get("info", {}) or {}
        servers = [s.get("url") for s in doc.get("servers", []) or [] if isinstance(s, dict)]
        base = doc.get("basePath", "") if "swagger" in doc else ""
        self._ep(ctx, origin, doc_url, "openapi", ev, {"spec_version": version, "api_title": info.get("title"),
                                                       "api_version": info.get("version"), "servers": servers,
                                                       "paths_documented": len(doc.get("paths", {}) or {}), "status": 200})
        server_origin = origin
        for s in servers:
            full = urljoin(origin + "/", s or "/")
            if ctx.scope.host_in_scope(host_of(full)):
                server_origin = full.rstrip("/")
                break
        schemes = (doc.get("components", {}) or {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
        auth = sorted({f"{n}:{(s or {}).get('type')}{'/' + s.get('scheme') if (s or {}).get('scheme') else ''}" for n, s in schemes.items()})
        if auth:
            ctx.emit(Obs("web_app", origin, {"api_auth_documented": auth}))
        for path, ops in (doc.get("paths", {}) or {}).items():
            methods = sorted(m.upper() for m in (ops or {}) if m.lower() in
                             ("get", "post", "put", "patch", "delete", "head", "options"))
            params = sorted({p.get("name") for op in (ops or {}).values() if isinstance(op, dict)
                             for p in op.get("parameters", []) or [] if isinstance(p, dict) and p.get("name")})
            body_fields = sorted({k for op in (ops or {}).values() if isinstance(op, dict)
                                  for c in ((op.get("requestBody") or {}).get("content") or {}).values()
                                  for k in ((c.get("schema") or {}).get("properties") or {})})
            url = normalize_url(server_origin + base + re.sub(r"\{[^}]+\}", "{param}", path))
            if not ctx.scope.host_in_scope(host_of(url)):
                continue
            vm = re.search(r"/v(\d+)(?:/|$)", url)
            ctx.emit(Obs("endpoint", url, {"url": url, "host": host_of(url), "path": urlsplit(url).path, "kind": "api",
                                           "+methods_documented": methods, "documented": True,
                                           "api_version": f"v{vm.group(1)}" if vm else info.get("version"),
                                           "+discovered_via": ["openapi"], "spec": doc_url, "requested": False,
                                           "params": params, "body_fields": body_fields,
                                           "summaries": sorted({(op or {}).get("summary") for op in (ops or {}).values()
                                                                if isinstance(op, dict) and op.get("summary")})},
                         evidence_id=ev,
                         relations=[Rel("has_endpoint", "web_app", origin_of(url), confirmed=False, reverse=True),
                                    Rel("documents", "endpoint", normalize_url(doc_url), confirmed=True, reverse=True)]))


def _parse_retire(output: str) -> list[dict]:
    """Normalise Retire.js JSON (its shape varies by version) to [{file, results:[component...]}]."""
    try:
        doc = json.loads(output or "[]")
    except ValueError:
        return []
    data = doc.get("data", doc) if isinstance(doc, dict) else doc
    out = []
    for entry in data if isinstance(data, list) else []:
        results = entry.get("results") or []
        vuln = [c for c in results if c.get("vulnerabilities")]
        if vuln:
            out.append({"file": entry.get("file", ""), "results": vuln})
    return out
