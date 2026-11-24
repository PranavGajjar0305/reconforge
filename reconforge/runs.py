"""Background scan execution for the dashboard.

`RunManager.start()` validates a request synchronously (target exists, modules known,
authorization present for active modules), assigns the scan id, and runs the pipeline in
a worker thread. The scan's log file (one line per action and command) feeds the live
console. Runs can be cancelled between modules.
"""
from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field

from .core.module import load_modules
from .core.pipeline import ScanOptions, plan_modules, run_scan
from .core.registry import load_registry, render_command, tool_status
from .scope import Scope, ScopeError
from .targets import resolve_target
from .util import iso, new_id, utcnow

# registry tools that are engines of a built-in module: tool -> (module, option, value)
ENGINE_TOOLS = {
    "nmap": ("port_scan", "engine", "nmap"), "naabu": ("port_scan", "engine", "naabu"),
    "dnsx": ("dns_resolve", "engine", "dnsx"), "httpx": ("http_probe", "engine", "httpx"),
    "whatweb": ("tech_detect", "engine", "whatweb"), "katana": ("crawler", "engine", "katana"),
    "puredns": ("dns_bruteforce", "engine", "puredns"),
    "sslscan": ("tls_inspect", "engine", "sslscan"), "retire": ("js_analysis", "engine", "retire"),
    "ffuf": ("content_discovery", "engine", "ffuf"), "feroxbuster": ("content_discovery", "engine", "feroxbuster"),
    "gobuster": ("content_discovery", "engine", "gobuster"), "dirsearch": ("content_discovery", "engine", "dirsearch"),
    "dirb": ("content_discovery", "engine", "dirb"),
    "subfinder": ("subfinder", None, None),
    "gau": ("historical_urls", None, None), "nuclei": ("nuclei", None, None), "chrome": ("screenshots", None, None),
}
CATEGORY_MODULE = {"subdomain_enum": "external_subdomains", "url_collection": "external_urls"}

MODULE_ACTIONS = {
    "domain_intel": "DNS queries: NS, MX, TXT, SOA, CAA, _dmarc for {root}",
    "crtsh": "GET {crtsh}/?q=%.{root}&output=json",
    "subfinder": "subfinder -silent -json -all -dL <roots>",
    "github_intel": "GET {github}/search/code?q=\"{root}\"",
    "historical_urls": "GET {wayback}/cdx/search/cdx?url=*.{root}/*&output=json",
    "passive_sources": "Query passive providers (OTX, HackerTarget, URLScan, SecurityTrails, VirusTotal, Shodan, Chaos, ...) for {root}",
    "external_subdomains": "Run installed registry subdomain tools for {root}",
    "external_urls": "Run installed registry URL collectors for {root}",
    "domain_ownership": "GET {rdap}/domain/{root}",
    "dns_resolve": "DNS A/AAAA/CNAME/MX/TXT/NS for every in-scope host (+ wildcard probe)",
    "dns_bruteforce": "Resolve <wordlist>.{root} + permutations + recursion (wildcard-filtered)",
    "dns_security": "DNSKEY/DS/CAA/SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI queries for {root}",
    "asn_intel": "Team Cymru / static map ASN lookup + PTR for each IP",
    "ip_intelligence": "InternetDB / RDAP / GreyNoise / IPinfo lookups for public IPs",
    "port_scan": "TCP connect + banner on ports {ports} of in-scope IPs",
    "http_probe": "GET / on every in-scope host on {probe_ports}",
    "http_intel": "Follow redirects, ALPN, compression and header analysis per web app",
    "tls_inspect": "TLS handshake + certificate parsing for every HTTPS app",
    "tech_detect": "Fingerprint technologies from collected responses",
    "crawler": "Same-origin GET crawl (max {max_pages} pages, depth {max_depth}) of each web app",
    "web_metadata": "GET security.txt, sitemap.xml; HEAD public documents",
    "js_analysis": "GET in-scope JavaScript; extract endpoints, third parties, secret patterns (redacted)",
    "api_discovery": "GET well-known API doc paths (openapi.json, swagger, graphql, OIDC, SAML) per web app",
    "security_config": "Evaluate headers/cookies/CORS of collected responses (no new requests)",
    "cloud_intel": "Search collected data for cloud resource references (no requests)",
    "identity_intel": "Identify login/SSO/IdP from collected pages (no requests)",
    "nuclei": "nuclei -jsonl against in-scope web apps/hosts/services, using the full template library (or nuclei.reviewed_templates)",
    "cve_intel": "Correlate identified versions with the CVE/EOL database (no requests)",
    "favicon_hash": "GET /favicon.ico (or <link rel=icon>) per web app; mmh3 + MD5 hash, cluster shared icons",
    "waf_detect": "Identify WAF/CDN/load balancer from collected headers and cookies (no requests)",
    "exposed_files": "GET ~33 commonly exposed paths (/.git/HEAD, /.env, /server-status, backups...) per web app; soft-404 aware, secrets redacted",
    "well_known": "GET assetlinks.json, apple-app-site-association, change-password, nodeinfo, jwks, manifest, ads.txt, humans.txt",
    "source_maps": "GET sourceMappingURL / <script>.map for each in-scope JavaScript file",
    "contact_intel": "Extract e-mail addresses and social profiles from collected pages (no requests)",
    "cors_check": "GET / with Origin: https://reconforge-cors-probe.example, a look-alike and null; read ACAO/ACAC",
    "panel_detect": "Fingerprint admin/DevOps/monitoring/VPN/mail interfaces from collected responses (no requests)",
    "takeover_check": "Match CNAME targets + responses against unclaimed-service fingerprints (no requests)",
    "content_discovery": "GET <web app>/<word> for each wordlist entry per web app (soft-404 calibrated, rate limited, recursion 1)",
    "vhost_discovery": "GET / on each web IP with Host: <in-scope candidate name>; compare with a random-host baseline",
    "cms_intel": "GET /feed/, /wp-json/wp/v2/users, /xmlrpc.php, plugin readme.txt, CHANGELOG.txt, joomla.xml on CMS sites",
    "url_patterns": "Classify collected URLs into gf-style candidate lists (xss/sqli/ssrf/redirect/lfi/rce/idor); no requests",
    "lookalike_domains": "DNS A/MX/NS for ~400 typosquat permutations of {root} (no HTTP)",
    "broken_links": "DNS NS lookups for external domains the target links to (unregistered = hijack candidate)",
    "asn_prefixes": "GET https://stat.ripe.net/data/announced-prefixes/data.json?resource=<ASN>",
    "dork_builder": "Build Google/GitHub/Shodan/Censys/crt.sh/Wayback pivot links for {root} (no requests)",
    "screenshots": "Chrome --headless --host-resolver-rules=MAP host ip --screenshot <web app>",
}


@dataclass
class RunInfo:
    scan_id: str
    target: str
    label: str
    kind: str
    cancel: threading.Event = field(default_factory=threading.Event)
    status: str = "starting"
    error: str | None = None
    started_at: str = field(default_factory=lambda: iso(utcnow()))
    finished_at: str | None = None
    log_path: str = ""


class RunManager:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.runs: dict[str, RunInfo] = {}
        self._lock = threading.Lock()

    def active(self) -> list[RunInfo]:
        return [r for r in self.runs.values() if r.status in ("starting", "running")]

    def preflight(self, opts: ScanOptions) -> dict:
        target = resolve_target(self.cfg, self.db, opts.target)
        if not target:
            raise ValueError(f"unknown target '{opts.target}'")
        profile = self.cfg.profile(opts.profile or target.get("profile") or "standard")
        modules = plan_modules(self.cfg, profile, opts)
        if not modules:
            raise ValueError("no modules selected")
        scope = Scope.from_target(target)
        if any(m.active for m in modules) and not scope.authorized:
            active = [m.name for m in modules if m.active]
            raise ScopeError(f"active modules ({', '.join(active)}) need authorization for '{opts.target}'. Edit the scan and tick "
                             "'I am authorized to test these targets' (config-file scans: authorization.confirmed: true), "
                             "or run the passive profile.")
        return {"target": target, "modules": [m.name for m in modules]}

    def start(self, opts: ScanOptions, label: str, kind: str = "scan") -> RunInfo:
        with self._lock:
            if any(r.target == opts.target for r in self.active()):
                raise RuntimeError(f"a run for '{opts.target}' is already in progress")
            self.preflight(opts)
            opts.scan_id = new_id("scn")
            info = RunInfo(scan_id=opts.scan_id, target=opts.target, label=label, kind=kind,
                           log_path=str(self.cfg.dir("logs_dir") / f"{opts.scan_id}.log"))
            opts.cancel = info.cancel
            self.runs[info.scan_id] = info

        def work():
            info.status = "running"
            try:
                run_scan(self.cfg, opts, self.db)
                info.status = "cancelled" if info.cancel.is_set() else "finished"
            except Exception as exc:
                info.status, info.error = "failed", f"{type(exc).__name__}: {exc}"
                with open(info.log_path, "a") as fh:
                    fh.write(f"{iso(utcnow())} ERROR run failed: {info.error}\n{traceback.format_exc()}\n")
            finally:
                info.finished_at = iso(utcnow())

        threading.Thread(target=work, daemon=True, name=f"scan-{info.scan_id}").start()
        return info

    def cancel(self, scan_id: str) -> bool:
        r = self.runs.get(scan_id)
        if not r or r.status not in ("starting", "running"):
            return False
        r.cancel.set()
        return True


class _Keep(dict):
    def __missing__(self, key):  # leave unknown {placeholders} as written instead of failing
        return "{" + key + "}"


def _fmt(text: str, values: dict) -> str:
    try:
        return text.format_map(_Keep(values))
    except (ValueError, IndexError):
        return text


def action_catalog(cfg, target: dict | None) -> list[dict]:
    """Every executable action: built-in modules and registry tools, with the command they would run."""
    roots = (target or {}).get("root_domains") or ["<target>"]
    root = roots[0]
    fmt = {"root": root, "crtsh": cfg.get("crtsh.base_url"), "github": cfg.get("github.api_base"),
           "wayback": cfg.get("historical_urls.base_url"), "rdap": "https://rdap.org",
           "ports": ",".join(map(str, (target or {}).get("ports") or cfg.get("ports.tcp", []))),
           "probe_ports": (target or {}).get("probe_ports") or cfg.get("http.probe_ports"),
           "max_pages": cfg.get("crawler.max_pages"), "max_depth": cfg.get("crawler.max_depth")}
    scope = Scope.from_target(target) if target else None
    out = []
    for name, cls in sorted(load_modules(cfg.get("plugins", [])).items(), key=lambda kv: (kv[1].order(), kv[0])):
        needs_auth = cls.active and not (scope and scope.authorized)
        out.append({"id": f"module:{name}", "kind": "module", "name": name, "phase": cls.phase, "active": cls.active,
                    "description": cls.description, "command": _fmt(MODULE_ACTIONS.get(name, cls.description), fmt),
                    "runnable": not needs_auth, "reason": "needs confirmed authorization" if needs_auth else "",
                    "module": name})
    offline = bool(cfg.get("network.offline"))
    from .installer import installable_names
    can_install = installable_names()
    for e in load_registry(cfg):
        st = tool_status(e, cfg, offline=offline)
        module, opt, val = ENGINE_TOOLS.get(e["name"], (CATEGORY_MODULE.get(e.get("category")), None, None))
        if e.get("command"):
            cmd = " ".join([e["name"], *render_command(e, domain=root, wordlist="<wordlist>", resolvers="<resolvers>")])
        else:
            cmd = f"via module {module}" if module else "reference only"
        if e.get("command"):
            runnable = bool(module) and st.selected
        elif e["name"] == "chrome":
            from .modules.screenshots import find_chrome

            st.installed = bool(find_chrome(cfg.get("screenshots.chrome_path", "auto")))
            runnable = st.installed
        else:
            runnable = bool(module) and st.installed and e.get("profile") != "reference"
        # Keep the registry's specific reason (safety rationale, missing creds, offline, etc.);
        # only override the two cases that otherwise read like a bug.
        ALT = {"tlsx": "tls_inspect", "shuffledns": "dns_bruteforce", "massdns": "dns_bruteforce"}
        SECRETS = {"gitleaks", "trufflehog"}
        if runnable:
            reason = ""
        elif module and st.installed and st.selected:
            reason = f"available as the {module} engine; run the {module} module to use it"
        elif e["name"] in ALT and st.installed:
            reason = f"alternative engine for {ALT[e['name']]}; the built-in is used by default"
        elif e["name"] in SECRETS and st.installed:
            reason = "scans source repositories, not live targets; not run during surface recon"
        else:
            reason = st.reason
        mod_cls = load_modules().get(module) if module else None
        if runnable and mod_cls and mod_cls.active and not (scope and scope.authorized):
            runnable, reason = False, "needs confirmed authorization"
        install_name = e["name"] if e["name"] in can_install else None
        out.append({"id": f"tool:{e['name']}", "kind": "tool", "name": e["name"], "phase": e.get("phase"),
                    "category": e.get("category"), "description": e.get("purpose", ""), "command": cmd,
                    "installed": st.installed, "version": st.version, "install": e.get("install"),
                    "installable": bool(install_name) and not st.installed, "install_name": install_name,
                    "profile": e.get("profile"), "maintenance": e.get("maintenance"), "api_env": e.get("api_env") or [],
                    "runnable": runnable, "reason": reason, "module": module,
                    "module_options": {module: {opt: val}} if opt else {}})
    return out


def options_for_action(cfg, target_name: str, action: dict) -> ScanOptions:
    opts = ScanOptions(target=target_name, modules=[action["module"]], standalone=True, notify=False,
                       trigger="dashboard-action", reports=True)
    if action["kind"] == "tool" and action["module"] in CATEGORY_MODULE.values():
        opts.only_tools = [action["name"]]
    opts.module_options = action.get("module_options") or {}
    return opts
