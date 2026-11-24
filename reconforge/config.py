"""Configuration loading.

Configuration is a YAML document deep-merged over DEFAULTS. Every section is
optional; see config/reconforge.example.yaml for a fully documented example.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "passive": {
        "description": "Passive intelligence only. No packets are sent to target hosts.",
        "active": False,
        "modules": [
            "domain_intel",
            "crtsh",
            "subfinder",
            "github_intel",
            "historical_urls",
            "passive_sources",
            "external_subdomains",
            "external_urls",
            "domain_ownership",
            "dns_resolve",  # queries DNS resolvers only; no traffic to target web hosts
            "dns_security",
            "asn_intel",
            "asn_prefixes",
            "ip_intelligence",
            "lookalike_domains",
            "dork_builder",
        ],
    },
    "standard": {
        "description": "Passive plus controlled discovery of authorized hosts.",
        "active": True,
        "modules": [
            "domain_intel",
            "crtsh",
            "subfinder",
            "github_intel",
            "historical_urls",
            "passive_sources",
            "external_subdomains",
            "external_urls",
            "domain_ownership",
            "dns_resolve",
            "dns_security",
            "asn_intel",
            "ip_intelligence",
            "http_probe",
            "http_intel",
            "tls_inspect",
            "tech_detect",
            "favicon_hash",
            "waf_detect",
            "crawler",
            "web_metadata",
            "well_known",
            "screenshots",
            "security_config",
            "cloud_intel",
            "identity_intel",
            "contact_intel",
            "panel_detect",
            "takeover_check",
            "url_patterns",
            "broken_links",
            "lookalike_domains",
            "dork_builder",
        ],
    },
    "comprehensive": {
        "description": "Standard plus explicitly authorized port discovery, JS/API analysis and reviewed Nuclei templates.",
        "active": True,
        "modules": [
            "domain_intel",
            "crtsh",
            "subfinder",
            "github_intel",
            "historical_urls",
            "passive_sources",
            "external_subdomains",
            "external_urls",
            "domain_ownership",
            "dns_resolve",
            "dns_bruteforce",
            "dns_security",
            "asn_intel",
            "ip_intelligence",
            "asn_prefixes",
            "port_scan",
            "http_probe",
            "vhost_discovery",
            "http_intel",
            "tls_inspect",
            "tech_detect",
            "favicon_hash",
            "waf_detect",
            "crawler",
            "web_metadata",
            "well_known",
            "content_discovery",
            "js_analysis",
            "source_maps",
            "api_discovery",
            "exposed_files",
            "screenshots",
            "security_config",
            "cloud_intel",
            "identity_intel",
            "contact_intel",
            "cors_check",
            "panel_detect",
            "takeover_check",
            "cms_intel",
            "url_patterns",
            "broken_links",
            "lookalike_domains",
            "dork_builder",
            "nuclei",
            "cve_intel",
        ],
        "overrides": {"crawler": {"max_pages": 150, "max_depth": 3}},
    },
    "continuous": {
        "description": "Scheduled discovery with historical comparison, change detection and notifications.",
        "active": True,
        "incremental": True,
        "notify": True,
        "modules": [
            "domain_intel",
            "crtsh",
            "subfinder",
            "historical_urls",
            "passive_sources",
            "dns_resolve",
            "dns_security",
            "asn_intel",
            "http_probe",
            "http_intel",
            "tls_inspect",
            "tech_detect",
            "favicon_hash",
            "waf_detect",
            "security_config",
            "cloud_intel",
            "identity_intel",
            "panel_detect",
            "takeover_check",
            "url_patterns",
            "cve_intel",
        ],
    },
}

# storage sub-directories derived from storage.data_dir when not configured
DERIVED_DIRS = {"output_dir": "output", "work_dir": "work", "screenshots_dir": "screenshots"}

DEFAULTS: dict[str, Any] = {
    "database": {"url": "sqlite:///data/reconforge.db"},
    "storage": {
        "data_dir": "data",
        "evidence_dir": "data/evidence",
        "reports_dir": "data/reports",
        "backups_dir": "data/backups",
        "logs_dir": "data/logs",
        "retention_days": 365,
        "keep_min_scans": 5,
    },
    "network": {
        # When offline, modules that query public internet services skip themselves.
        "offline": False,
        "user_agent": "ReconForge/1.0 (authorized security assessment)",
        "rate_limit_per_second": 5.0,
        "max_concurrency": 10,
    },
    "dns": {"resolvers": [], "timeout": 3.0, "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]},
    "http": {
        "timeout": 8.0,
        "verify_tls": False,
        "probe_ports": {"http": [80], "https": [443]},
        "max_body_bytes": 512000,
    },
    "tls": {"timeout": 6.0, "expiry_warning_days": 30},
    "ports": {"tcp": [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200], "timeout": 1.5, "banner_bytes": 256},
    "crawler": {"max_pages": 60, "max_depth": 2, "same_origin_only": True, "respect_robots": True},
    "screenshots": {"chrome_path": "auto", "timeout": 25, "window_size": "1280,800"},
    "asn": {"static_map": {}, "use_team_cymru": True},
    "crtsh": {"base_url": "https://crt.sh"},
    "historical_urls": {"base_url": "https://web.archive.org", "limit": 2000},
    "github": {"api_base": "https://api.github.com", "token_env": "GITHUB_TOKEN", "max_results": 50},
    "nuclei": {
        # Default: the whole installed template library, auto-updated by Nuclei before each run.
        # List template IDs/paths in reviewed_templates to run only those instead.
        "reviewed_templates": [],
        "template_dir": None,              # optional custom template directory
        # Safe-by-default: run the whole library EXCEPT aggressive / state-changing templates.
        # Set exclude_tags: [] to run literally every template (only on explicit authorization).
        "exclude_tags": ["dos", "intrusive", "fuzz", "fuzzing", "brute-force", "bruteforce",
                         "sqli", "xss", "rce", "ssrf", "lfi"],
        "severities": [],                  # [] = all severities
        "rate_limit": 100,                 # requests per second
        "concurrency": 25,
        "request_timeout": 10,
        "timeout_minutes": 360,
        "stats_interval": 30,
        "update_templates": True,
        "headless": False,                 # true also runs templates that need a headless browser
        "extra_args": [],
    },
    "cve_intel": {"local_db": "builtin"},
    "tools": {
        # Each external tool: enabled (true/false/auto), path. "auto" = use if found on PATH.
        "subfinder": {"enabled": "auto", "path": "subfinder"},
        "dnsx": {"enabled": "auto", "path": "dnsx"},
        "httpx": {"enabled": "auto", "path": "httpx"},
        "tlsx": {"enabled": "auto", "path": "tlsx"},
        "katana": {"enabled": "auto", "path": "katana"},
        "whatweb": {"enabled": "auto", "path": "whatweb"},
        "nuclei": {"enabled": "auto", "path": "nuclei"},
        "nmap": {"enabled": "auto", "path": "nmap"},
        "naabu": {"enabled": "auto", "path": "naabu"},
        "gau": {"enabled": "auto", "path": "gau"},
    },
    "source_reliability": {
        "dns_resolve": 0.95,
        "dnsx": 0.95,
        "tls_inspect": 0.95,
        "tlsx": 0.95,
        "http_probe": 0.95,
        "httpx": 0.95,
        "port_scan": 0.9,
        "nmap": 0.9,
        "naabu": 0.85,
        "crtsh": 0.75,
        "subfinder": 0.7,
        
        "tls_san": 0.8,
        "historical_urls": 0.5,
        "gau": 0.5,
        "github_intel": 0.5,
        "tech_detect": 0.7,
        "whatweb": 0.75,
        "crawler": 0.9,
        "katana": 0.85,
        "js_analysis": 0.6,
        "api_discovery": 0.85,
        "security_config": 0.9,
        "cloud_intel": 0.7,
        "nuclei": 0.8,
        "cve_intel": 0.5,
        "domain_intel": 0.9,
        "asn_intel": 0.85,
        "screenshots": 0.95,
        "otx": 0.6, "hackertarget": 0.6, "urlscan": 0.65, "securitytrails": 0.75, "virustotal": 0.65,
        "shodan_dns": 0.65, "chaos": 0.7, "whoisxml": 0.65, "commoncrawl": 0.5, "brave_search": 0.5,
        "internetdb": 0.6, "rdap_ip": 0.9, "rdap_domain": 0.9, "greynoise": 0.6, "ipinfo": 0.7,
        "amass": 0.75, "assetfinder": 0.6, "findomain": 0.7, "github-subdomains": 0.6, "waybackurls": 0.5,
        "waymore": 0.5, "dns_bruteforce": 0.9, "dns_permutation": 0.9, "zone_transfer": 0.95,
        "default": 0.6,
    },
    "profiles": copy.deepcopy(DEFAULT_PROFILES),
    "incremental": {"max_age_hours": 24},
    "change_detection": {"significant_categories": "all", "cert_expiry_days": 30},
    "notifications": {
        "enabled": False,
        "dedup_hours": 168,
        "report_base_url": "http://127.0.0.1:8765",
        "categories": "all",
        "email": {
            "enabled": False,
            "smtp_host": "localhost",
            "smtp_port": 587,
            "starttls": True,
            "username": "",
            "password_env": "RECONFORGE_SMTP_PASSWORD",
            "from": "reconforge@localhost",
            "to": [],
        },
        "telegram": {"enabled": False, "bot_token_env": "RECONFORGE_TELEGRAM_TOKEN", "chat_id": "", "api_base": "https://api.telegram.org"},
        "discord": {"enabled": False, "webhook_url": "", "webhook_url_env": "RECONFORGE_DISCORD_WEBHOOK"},
        "slack": {"enabled": False, "webhook_url": "", "webhook_url_env": "RECONFORGE_SLACK_WEBHOOK"},
    },
    "reports": {
        "auto_generate": True,
        "formats": ["markdown", "html", "json", "csv", "pdf"],
        "sections": {
            "executive_summary": True,
            "scope": True,
            "methodology": True,
            "domains": True,
            "dns": True,
            "ip_asn": True,
            "ports": True,
            "http": True,
            "technologies": True,
            "endpoints": True,
            "javascript": True,
            "tls": True,
            "cloud": True,
            "security": True,
            "cve": True,
            "changes": True,
            "graph": True,
            "priorities": True,
            "ai_analysis": True,
            "coverage": True,
            "evidence": True,
            "coverage_quality": True,
            "source_comparison": True,
            "subdomain_lists": True,
            "dns_infrastructure": True,
            "http_profiles": True,
            "vhosts": True,
            "identity": True,
            "third_party_inventory": True,
            "parameters": True,
            "historical_urls": True,
            "documents": True,
            "secrets": True,
            "screenshot_groups": True,
            "limitations": True,
        },
    },
    "ai": {
        "enabled": False,
        "provider": "anthropic",
        "model": "claude-opus-5-5",
        "effort": "high",
        "max_assets": 400,
    },
    "api": {"host": "127.0.0.1", "port": 8765, "token_env": "RECONFORGE_API_TOKEN"},
    "targets": [],
    "schedules": [],
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config:
    """Thin wrapper around the merged configuration dictionary."""

    def __init__(self, data: dict[str, Any], path: Path | None = None):
        self.data = data
        self.path = path
        self.base_dir = path.parent.parent if path and path.parent.name == "config" else (path.parent if path else Path.cwd())

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def resolve_path(self, value: str) -> Path:
        p = Path(os.path.expanduser(value))
        return p if p.is_absolute() else (self.base_dir / p)

    @property
    def database_url(self) -> str:
        url = os.environ.get("RECONFORGE_DATABASE_URL") or self.get("database.url")
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            rel = url[len("sqlite:///"):]
            if rel != ":memory:":
                path = self.resolve_path(rel)
                path.parent.mkdir(parents=True, exist_ok=True)
                url = f"sqlite:///{path}"
        elif url.startswith("sqlite:////"):
            Path(url[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)
        return url

    def dir(self, name: str) -> Path:
        value = self.get(f"storage.{name}")
        if not value and name in DERIVED_DIRS:  # live next to the data dir unless configured explicitly
            p = self.dir("data_dir") / DERIVED_DIRS[name]
            p.mkdir(parents=True, exist_ok=True)
            return p
        p = self.resolve_path(value)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def target(self, name: str) -> dict | None:
        for t in self.get("targets", []):
            if t.get("name") == name:
                return t
        return None

    def profile(self, name: str) -> dict:
        profiles = self.get("profiles", {})
        if name not in profiles:
            raise KeyError(f"Unknown profile '{name}'. Available: {', '.join(sorted(profiles))}")
        return profiles[name]

    def reliability(self, source: str) -> float:
        table = self.get("source_reliability", {})
        return float(table.get(source, table.get("default", 0.6)))


def _apply_tool_paths(merged: dict, user_data: dict) -> None:
    """Use verified absolute tool paths written by the installer / `reconforge tools --detect`.
    Paths set explicitly in the config file always win."""
    from .core.tools import augment_path, tool_paths_file

    augment_path()
    p = tool_paths_file()
    if not p.exists():
        return
    try:
        found = (yaml.safe_load(p.read_text()) or {}).get("tools", {}) or {}
    except Exception:
        return
    explicit = (user_data.get("tools") or {})
    for name, info in found.items():
        user_path = str((explicit.get(name) or {}).get("path") or "")
        # only a real path (with a directory) counts as an explicit override; "path: httpx" does not
        if info.get("path") and "/" not in user_path:
            merged.setdefault("tools", {}).setdefault(name, {"enabled": "auto"})
            merged["tools"][name]["path"] = info["path"]


def load_config(path: str | os.PathLike | None = None, overrides: dict | None = None) -> Config:
    """Load configuration from `path` (or $RECONFORGE_CONFIG, or ./config/reconforge.yaml)."""
    candidates = [path, os.environ.get("RECONFORGE_CONFIG"), "config/reconforge.yaml"]
    data: dict[str, Any] = {}
    chosen: Path | None = None
    for c in candidates:
        if c and Path(c).exists():
            chosen = Path(c).resolve()
            with open(chosen) as fh:
                data = yaml.safe_load(fh) or {}
            break
    merged = deep_merge(DEFAULTS, data)
    if chosen is None and not (overrides or {}).get("storage"):
        # No config file: keep data in ~/.reconforge so `reconforge` works from any directory.
        home = Path(os.environ.get("RECONFORGE_HOME", Path.home() / ".reconforge"))
        merged["storage"] = {k: (str(home / Path(v).relative_to("data")) if str(v).startswith("data") else v)
                             for k, v in merged["storage"].items()}
        merged["database"]["url"] = f"sqlite:///{home / 'reconforge.db'}"
    # Profiles: user-defined profiles merge over defaults per profile name.
    merged["profiles"] = deep_merge(DEFAULT_PROFILES, data.get("profiles", {}) or {})
    _apply_tool_paths(merged, data)
    if overrides:
        merged = deep_merge(merged, overrides)
    return Config(merged, chosen)
