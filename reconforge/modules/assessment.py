"""Non-intrusive assessment modules.

* security_config – security headers, cookie flags, version disclosure, CORS, listings
* cloud_intel     – cloud resource references in DNS, headers, HTML and JavaScript
* nuclei          – the Nuclei template library (or an explicit allow-list via nuclei.reviewed_templates)
* cve_intel       – version-based CVE / end-of-life correlation (local curated DB, optional NVD)

None of these send exploit payloads or state-changing requests.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import yaml

from ..core.module import Module, SkipModule, register
from ..core.observation import Obs, Rel
from ..util import host_of
from .common import finding

HEADER_ADVICE = {
    "strict-transport-security": "Enable HSTS on HTTPS responses.",
    "content-security-policy": "Define a Content-Security-Policy.",
    "x-frame-options": "Set X-Frame-Options or CSP frame-ancestors to prevent framing.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set a Referrer-Policy.",
}


def cookie_issues(set_cookie: str, https: bool) -> tuple[str, list[str]]:
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0]
    flags = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
    issues = []
    if https and "secure" not in flags:
        issues.append("missing Secure")
    if "httponly" not in flags:
        issues.append("missing HttpOnly")
    if "samesite" not in flags:
        issues.append("missing SameSite")
    elif str(flags.get("samesite")).lower() == "none" and "secure" not in flags:
        issues.append("SameSite=None without Secure")
    return name, issues


@register
class SecurityConfig(Module):
    name = "security_config"
    description = "Evaluates HTTP security headers, cookies, CORS, banners and directory listings from collected responses."
    phase = "assessment"
    active = False  # analyses responses already collected; sends no new traffic
    produces = ["finding"]

    def run(self, ctx) -> None:
        cache = ctx.shared.get("http_root", {})
        apps = [a for a in ctx.assets("web_app") if a.key in cache]
        if not apps:
            raise SkipModule("no HTTP responses collected in this scan")
        for app in apps:
            res = cache[app.key]
            a = app.attributes or {}
            https = app.key.startswith("https://")
            redirect = res.status and 300 <= res.status < 400
            ev = ctx.evidence("http_response", f"headers evaluated for {app.key}",
                              "\n".join(f"{k}: {v}" for k, v in res.raw_headers))
            if not redirect:
                missing = [h for h in HEADER_ADVICE if res.header(h) is None and (https or h != "strict-transport-security")]
                if "x-frame-options" in missing and "frame-ancestors" in (res.header("content-security-policy") or ""):
                    missing.remove("x-frame-options")
                if missing:
                    sev = "low" if "content-security-policy" in missing and https else "info"
                    finding(ctx, "headers.missing", app.key, "Missing HTTP security headers", sev,
                            f"{app.key} does not send: {', '.join(missing)}.", ev,
                            " ".join(HEADER_ADVICE[m] for m in missing), category="headers", subject_type="web_app",
                            extra={"missing": missing})
            for cookie in res.set_cookies():
                name, issues = cookie_issues(cookie, https)
                if issues:
                    finding(ctx, "cookies.flags", f"{app.key}#{name}", f"Cookie '{name}' configuration", "low",
                            f"Cookie {name} set by {app.key}: {', '.join(issues)}.", ev,
                            "Set Secure, HttpOnly and SameSite where compatible with the application.",
                            category="cookies", subject_type="web_app", extra={"cookie": name, "issues": issues, "app": app.key})
            disclosed = {h: res.header(h) for h in ("server", "x-powered-by", "x-aspnet-version") if res.header(h)}
            versions = {h: v for h, v in disclosed.items() if re.search(r"\d+\.\d+", v)}
            if versions:
                finding(ctx, "disclosure.version_banner", app.key, "Software versions disclosed in headers", "info",
                        "; ".join(f"{h}: {v}" for h, v in versions.items()), ev,
                        "Consider suppressing version numbers in response headers.", category="disclosure",
                        subject_type="web_app", extra={"headers": versions})
            acao, acac = res.header("access-control-allow-origin"), res.header("access-control-allow-credentials")
            if acao == "*" and (acac or "").lower() == "true":
                finding(ctx, "cors.wildcard_credentials", app.key, "CORS wildcard with credentials", "low",
                        "Access-Control-Allow-Origin: * combined with Allow-Credentials: true.", ev,
                        "Review the CORS policy.", category="cors", subject_type="web_app")
            if re.search(r"<title>\s*Index of /", res.text[:5000], re.I):
                finding(ctx, "disclosure.directory_listing", app.key, "Directory listing enabled", "low",
                        f"{app.key}/ returns an auto-generated index.", ev, "Disable auto-indexing.",
                        category="disclosure", subject_type="web_app")
            if not https and not redirect and a.get("host"):
                twin = app.key.replace("http://", "https://").rsplit(":", 1)[0]
                if any(o.startswith(twin) for o in cache if o.startswith("https://")):
                    finding(ctx, "transport.http_no_redirect", app.key, "HTTP served without redirect to HTTPS", "info",
                            f"{app.key} serves content over plain HTTP although HTTPS is available.", ev,
                            "Redirect HTTP to HTTPS.", category="transport", subject_type="web_app")
            dev_markers = [m for m in ("debug", "stack trace", "traceback", "staging build", "phpinfo()", "laravel debug")
                           if m in res.text[:50000].lower()]
            if dev_markers:
                finding(ctx, "disclosure.debug_markers", app.key, "Development/debug markers in response", "low",
                        f"Response body contains: {', '.join(dev_markers)}.", ev,
                        "Confirm this is not a debug build exposed to the internet.", category="disclosure",
                        subject_type="web_app", extra={"markers": dev_markers})


CLOUD_PATTERNS = [
    ("aws", "s3", re.compile(r"\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com\b")),
    ("aws", "s3", re.compile(r"\bs3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\b")),
    ("aws", "cloudfront", re.compile(r"\b([a-z0-9]+)\.cloudfront\.net\b")),
    ("aws", "api-gateway", re.compile(r"\b([a-z0-9]{10})\.execute-api\.[a-z0-9\-]+\.amazonaws\.com\b")),
    ("aws", "elastic-beanstalk", re.compile(r"\b([a-z0-9\-]+)\.[a-z0-9\-]+\.elasticbeanstalk\.com\b")),
    ("azure", "blob-storage", re.compile(r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b")),
    ("azure", "app-service", re.compile(r"\b([a-z0-9\-]+)\.azurewebsites\.net\b")),
    ("azure", "api-management", re.compile(r"\b([a-z0-9\-]+)\.azure-api\.net\b")),
    ("gcp", "cloud-storage", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\b")),
    ("gcp", "cloud-storage", re.compile(r"\b([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b")),
    ("gcp", "app-engine", re.compile(r"\b([a-z0-9\-]+)\.appspot\.com\b")),
    ("gcp", "firebase", re.compile(r"\b([a-z0-9\-]+)\.firebaseio\.com\b")),
    ("gcp", "firebase-hosting", re.compile(r"\b([a-z0-9\-]+)\.(?:web\.app|firebaseapp\.com)\b")),
    ("heroku", "app", re.compile(r"\b([a-z0-9\-]+)\.herokuapp\.com\b")),
    ("digitalocean", "spaces", re.compile(r"\b([a-z0-9\-]+)\.[a-z0-9]+\.digitaloceanspaces\.com\b")),
]


def find_cloud_refs(text: str) -> list[tuple[str, str, str, str]]:
    out = set()
    for provider, service, rx in CLOUD_PATTERNS:
        for m in rx.finditer(text.lower()):
            out.add((provider, service, m.group(1), m.group(0)))
    return sorted(out)


@register
class CloudIntel(Module):
    name = "cloud_intel"
    description = "Finds references to cloud resources (S3, Azure Blob, GCS, Firebase, ...) in collected data."
    phase = "assessment"
    active = False
    produces = ["cloud_resource"]

    def run(self, ctx) -> None:
        sources: list[tuple[str, str, str]] = []  # (asset_type, asset_key, text)
        for h in ctx.live(["domain", "subdomain"]):
            dns_data = (h.attributes or {}).get("dns", {}) or {}
            sources.append((h.type, h.key, " ".join(dns_data.get("CNAME", []) + dns_data.get("TXT", []))))
        for origin, res in ctx.shared.get("http_root", {}).items():
            sources.append(("web_app", origin, " ".join(f"{k}: {v}" for k, v in res.raw_headers) + "\n" + res.text))
        for url, body in ctx.shared.get("js_bodies", {}).items():
            sources.append(("js_file", url, body))
        for url, body in ctx.shared.get("pages", {}).items():
            sources.append(("web_app", _origin(url), body))
        if not sources:
            raise SkipModule("no collected data to analyse")
        for a_type, a_key, text in sources:
            if not text:
                continue
            for provider, service, name, ref in find_cloud_refs(text):
                key = f"{provider}:{service}:{name}"
                ev = ctx.evidence("reference", f"{a_type} {a_key} references {ref}", _context(text, ref))
                ctx.emit(Obs("cloud_resource", key, {"provider": provider, "service": service, "name": name,
                                                     "+references": [ref], "ownership": "unverified"},
                             display=f"{provider.upper()} {service}: {name}", evidence_id=ev,
                             relations=[Rel("references", a_type, a_key, confirmed=False, reverse=True,
                                            attrs={"ownership": "unverified"})]))


def _origin(url: str) -> str:
    from ..util import origin_of

    return origin_of(url)


def _context(text: str, needle: str, width: int = 160) -> str:
    idx = text.lower().find(needle)
    if idx < 0:
        return needle
    return text[max(0, idx - width): idx + len(needle) + width]


@register
class Nuclei(Module):
    name = "nuclei"
    description = ("Runs the installed Nuclei template library (kept up to date by Nuclei) against in-scope web apps, "
                   "hostnames and services. nuclei.reviewed_templates turns it into an allow-list instead.")
    phase = "assessment"
    active = True
    tools = ["nuclei"]
    produces = ["finding"]

    def run(self, ctx) -> None:
        if not ctx.tool("nuclei").available:
            raise SkipModule(ctx.tool("nuclei").reason)
        inputs = nuclei_inputs(ctx)
        if not inputs:
            raise SkipModule("no in-scope web applications, hostnames or services to test")
        opt = lambda k, d=None: ctx.option("nuclei", k, d)  # noqa: E731
        args = ["-jsonl", "-nc", "-stats", "-si", str(int(opt("stats_interval", 30))),
                "-rl", str(opt("rate_limit", 100)), "-c", str(opt("concurrency", 25)),
                "-timeout", str(opt("request_timeout", 10)), "-retries", "1"]
        templates = opt("reviewed_templates", []) or []
        if templates:  # allow-list mode
            for t in templates:
                args += (["-t", t] if ("/" in t or t.endswith(".yaml")) else ["-id", t])
            mode = f"{len(templates)} reviewed template(s)"
        else:
            mode = "the full template library"
            if opt("template_dir"):
                args += ["-t", str(opt("template_dir"))]
        if opt("exclude_tags"):
            args += ["-etags", ",".join(opt("exclude_tags"))]
        if opt("severities"):
            args += ["-severity", ",".join(opt("severities"))]
        if ctx.offline or not opt("update_templates", True):
            args.append("-disable-update-check")  # never reach out for template updates in offline mode
        if opt("headless", False):
            args.append("-headless")
        args += [str(a) for a in (opt("extra_args", []) or [])]
        ctx.action("nuclei: %s against %d input(s); excluded tags: %s; severities: %s", mode, len(inputs),
                   ",".join(opt("exclude_tags") or []) or "none", ",".join(opt("severities") or []) or "all")

        def echo(stream, line):
            text = line.strip()
            if not text:
                return None
            if text.startswith("{"):
                try:
                    r = json.loads(text)
                except ValueError:
                    return text
                if r.get("template-id") or r.get("templateID"):
                    sev = ((r.get("info") or {}).get("severity") or "info").upper()
                    return f"match [{sev}] {r.get('template-id') or r.get('templateID')} {r.get('matched-at') or r.get('host')}"
                if "percent" in r or "requests" in r:
                    return (f"progress {r.get('percent', '?')}% requests {r.get('requests')}/{r.get('total')} "
                            f"matched {r.get('matched')} errors {r.get('errors')} templates {r.get('templates')} "
                            f"hosts {r.get('hosts')} elapsed {r.get('duration')}")
                return None
            return text if stream == "stderr" else None

        timeout = float(opt("timeout_minutes", 360)) * 60
        proc = ctx.run_tool("nuclei", args + ["-sj"], input_text="\n".join(inputs), timeout=timeout,
                            echo=echo, keep_partial=True)
        ev = ctx.evidence("tool_output", f"nuclei JSONL output ({mode})", proc.stdout, ".jsonl")
        for f in parse_nuclei(proc.stdout):
            host = host_of(f["matched_at"]) or host_of("//" + (f["host"] or "")) or f["host"]
            if not ctx.scope.host_in_scope(host) and not ctx.scope.ip_allowed(host):
                continue
            subject = f.get("matched_at") or f["host"]
            finding(ctx, f"nuclei.{f['template_id']}", subject, f["name"], f["severity"],
                    f.get("description") or f["name"], ev,
                    "Validate manually; Nuclei matches are detections, not confirmed vulnerabilities.",
                    category="nuclei", subject_type="web_app" if subject.startswith("http") else "subdomain",
                    extra={"template_id": f["template_id"], "cves": f.get("cves", []), "references": f.get("references", []),
                           "matcher": f.get("matcher_name"), "extracted": f.get("extracted", [])[:5],
                           "tags": f.get("tags", [])})


def nuclei_inputs(ctx) -> list[str]:
    """Web app URLs, resolved in-scope hostnames (DNS/SSL templates) and host:port for non-HTTP services."""
    out: list[str] = []
    seen: set[str] = set()

    def add(x):
        if x and x not in seen:
            seen.add(x)
            out.append(x)

    for a in ctx.live("web_app"):
        if ctx.in_filter((a.attributes or {}).get("host")):
            add(a.key)
    for h in ctx.hosts():
        add(h.key)
    for sv in ctx.live("service"):
        at = sv.attributes or {}
        if str(at.get("service", "")).startswith("http"):
            continue  # covered by the web app URL
        hosts = [h for h in at.get("hosts") or [] if ctx.scope.host_in_scope(h) and ctx.in_filter(h)]
        if hosts:
            add(f"{hosts[0]}:{at.get('port')}")
        elif at.get("ip") and ctx.host_filter is None and ctx.scope.ip_allowed(at["ip"]):
            add(f"{at['ip']}:{at.get('port')}")
    return out


def parse_nuclei(output: str) -> list[dict]:
    out = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not (r.get("template-id") or r.get("templateID")):
            continue  # statistics lines share the stream
        info = r.get("info", {}) or {}
        cls = info.get("classification", {}) or {}
        out.append({
            "template_id": r.get("template-id") or r.get("templateID"),
            "name": info.get("name", r.get("template-id")),
            "severity": (info.get("severity") or "info").lower(),
            "description": (info.get("description") or "").strip(),
            "references": info.get("reference") or [],
            "cves": cls.get("cve-id") or [],
            "host": r.get("host"),
            "matched_at": r.get("matched-at") or r.get("matched") or r.get("host"),
            "matcher_name": r.get("matcher-name"),
            "extracted": r.get("extracted-results") or [],
            "tags": info.get("tags") or [],
        })
    return out


# ------------------------------------------------------------------ CVE intel
CVE_DB = Path(__file__).resolve().parent.parent / "data" / "cve_intel.yaml"


@lru_cache
def load_cve_db(path: str | None = None) -> dict:
    return yaml.safe_load(Path(path or CVE_DB).read_text())


def parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))[:4]


def in_range(version: str, rng: dict) -> bool:
    v = parse_version(version)
    if not v:
        return False
    if "versions" in rng:
        return any(parse_version(x) == v for x in rng["versions"])
    if "from" in rng and v < parse_version(rng["from"]):
        return False
    if "before" in rng and v >= parse_version(rng["before"]):
        return False
    if "through" in rng and v > parse_version(rng["through"]):
        return False
    return True


def match_cves(product: str, version: str, db: dict) -> tuple[list[dict], dict | None]:
    entry = None
    for name, data in db.get("products", {}).items():
        if name.lower() == product.lower() or product.lower() in [a.lower() for a in data.get("aliases", [])]:
            entry = data
            break
    if not entry or not version:
        return [], None
    cves = [c for c in entry.get("cves", []) if any(in_range(version, r) for r in c["affected"])]
    eol = entry.get("eol")
    eol_hit = eol if eol and in_range(version, {"before": eol["before"]}) else None
    return cves, eol_hit


@register
class CveIntel(Module):
    name = "cve_intel"
    description = "Correlates identified product versions with publicly documented CVEs and end-of-life data."
    phase = "assessment"
    active = False
    produces = ["finding"]

    def run(self, ctx) -> None:
        db = load_cve_db(ctx.option("cve_intel", "local_db") if ctx.option("cve_intel", "local_db") not in (None, "builtin") else None)
        subjects: list[tuple[str, str, str, str]] = []  # (asset_type, key, product, version)
        for app in ctx.live("web_app"):
            for name, ver in ((app.attributes or {}).get("technologies") or {}).items():
                if ver:
                    subjects.append(("web_app", app.key, name, ver))
        for svc in ctx.live("service"):
            a = svc.attributes or {}
            if a.get("product") and a.get("version"):
                subjects.append(("service", svc.key, a["product"], a["version"]))
        if not subjects:
            raise SkipModule("no product versions identified")
        for a_type, key, product, version in subjects:
            cves, eol = match_cves(product, version, db)
            if not cves and not eol:
                continue
            ev = ctx.evidence("cve_correlation", f"{product} {version} on {key}",
                              json.dumps({"product": product, "version": version, "cves": cves, "eol": eol,
                                          "database": db.get("meta", {})}, indent=2))
            for c in cves:
                finding(ctx, f"cve.{c['id']}", key, f"{product} {version} is in the affected range of {c['id']}", "info",
                        f"{c['summary']} Correlation is based only on the advertised version string; backported fixes, "
                        "configuration, or a misleading banner can make this a false positive.", ev,
                        "Verify the actual patch level and whether the affected component/feature is in use.",
                        category="cve", subject_type=a_type,
                        extra={"cves": [c["id"]], "product": product, "version": version,
                               "references": c.get("references", []), "advisory_severity": c.get("severity"),
                               "confidence_note": "version-match only"})
            if eol:
                finding(ctx, f"eol.{product}", key, f"{product} {version} is past end of life", "low",
                        f"{product} releases before {eol['before']} are no longer supported ({eol.get('note', '')}).", ev,
                        "Plan an upgrade to a supported release.", category="version", subject_type=a_type,
                        extra={"product": product, "version": version})
