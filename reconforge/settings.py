"""Dashboard-editable settings (stored in <data_dir>/settings.json, file mode 0600).

Currently: the AI provider. API keys may be given here or (preferred) via environment
variables; keys are never returned by the API, only whether one is set.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# Environment as it was when ReconForge started: a key set there is reported as coming from the
# environment, and is restored if a dashboard-stored override is removed.
_ORIGINAL_ENV = dict(os.environ)
_APPLIED: set[str] = set()
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
# Custom names must look like credentials; never allow variables that change how programs load or run.
CREDENTIAL_NAME = re.compile(r"(_API_KEY|_KEY|_TOKEN|_SECRET|_API_ID|_API_SECRET|_PASSWORD|_ACCESS_ID)$")
FORBIDDEN_PREFIX = ("LD_", "DYLD_", "PYTHON", "PATH", "RECONFORGE_", "SHELL", "HOME", "NODE_", "GO", "SSL_", "REQUESTS_",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "BASH_", "IFS", "PERL", "RUBY")

# Every credential ReconForge or a registered tool can use. Values are stored in settings.json (0600)
# and exported to the process environment, so providers, modules and external tools pick them up.
KEY_CATALOG = [
    {"env": "SHODAN_API_KEY", "service": "Shodan", "used_by": "passive_sources (Shodan DNS), subfinder, uncover", "url": "https://account.shodan.io/"},
    {"env": "SECURITYTRAILS_API_KEY", "service": "SecurityTrails", "used_by": "passive_sources, subfinder", "url": "https://securitytrails.com/app/account/credentials"},
    {"env": "VIRUSTOTAL_API_KEY", "service": "VirusTotal", "used_by": "passive_sources, subfinder", "url": "https://www.virustotal.com/gui/my-apikey"},
    {"env": "PDCP_API_KEY", "service": "ProjectDiscovery Chaos / Cloud", "used_by": "passive_sources (Chaos), chaos, subfinder, nuclei", "url": "https://cloud.projectdiscovery.io/"},
    {"env": "GITHUB_TOKEN", "service": "GitHub", "used_by": "github_intel, github-subdomains, subfinder", "url": "https://github.com/settings/tokens"},
    {"env": "CERTSPOTTER_API_KEY", "service": "Cert Spotter", "used_by": "passive_sources (optional; raises rate limits)", "url": "https://sslmate.com/account/api_credentials"},
    {"env": "FULLHUNT_API_KEY", "service": "FullHunt", "used_by": "passive_sources, subfinder", "url": "https://fullhunt.io/user/settings/"},
    {"env": "BINARYEDGE_API_KEY", "service": "BinaryEdge", "used_by": "passive_sources, subfinder", "url": "https://app.binaryedge.io/account/api"},
    {"env": "LEAKIX_API_KEY", "service": "LeakIX", "used_by": "passive_sources, subfinder", "url": "https://leakix.net/settings/api"},
    {"env": "WHOISXML_API_KEY", "service": "WhoisXML API", "used_by": "passive_sources, subfinder", "url": "https://user.whoisxmlapi.com/products"},
    {"env": "OTX_API_KEY", "service": "AlienVault OTX", "used_by": "passive_sources (optional), subfinder", "url": "https://otx.alienvault.com/api"},
    {"env": "URLSCAN_API_KEY", "service": "urlscan.io", "used_by": "passive_sources (optional), subfinder", "url": "https://urlscan.io/user/profile/"},
    {"env": "HACKERTARGET_API_KEY", "service": "HackerTarget", "used_by": "passive_sources (optional; raises limits)", "url": "https://hackertarget.com/scan-membership/"},
    {"env": "BRAVE_SEARCH_API_KEY", "service": "Brave Search", "used_by": "passive_sources (search-engine URLs)", "url": "https://api-dashboard.search.brave.com/"},
    {"env": "GREYNOISE_API_KEY", "service": "GreyNoise", "used_by": "ip_intelligence (optional)", "url": "https://viz.greynoise.io/account/api-key"},
    {"env": "IPINFO_TOKEN", "service": "IPinfo", "used_by": "ip_intelligence (optional)", "url": "https://ipinfo.io/account/token"},
]

AI_DEFAULTS = {"provider": "heuristic", "model": "", "base_url": "", "api_key": "", "api_key_env": "", "effort": "high"}
PROVIDER_INFO = {
    "heuristic": {"label": "Offline rule-based analyst (no data leaves this machine)", "needs_key": False},
    "anthropic": {"label": "Anthropic Claude (official SDK)", "needs_key": True, "default_model": "claude-opus-5-5",
                  "key_env": "ANTHROPIC_API_KEY"},
    "openai": {"label": "OpenAI (ChatGPT models, Chat Completions API)", "needs_key": True,
               "default_base_url": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY"},
    "openai_compatible": {"label": "Any OpenAI-compatible endpoint (Ollama, LM Studio, OpenRouter, vLLM, Azure, Groq...)",
                          "needs_key": False, "default_base_url": "http://localhost:11434/v1", "key_env": ""},
}


def _path(cfg) -> Path:
    return cfg.dir("data_dir") / "settings.json"


def _read(cfg) -> dict:
    p = _path(cfg)
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except ValueError:
        return {}


def _write(cfg, data: dict) -> None:
    p = _path(cfg)
    if not p.exists():
        p.touch(mode=0o600)
    os.chmod(p, 0o600)
    p.write_text(json.dumps(data, indent=2))
    os.chmod(p, 0o600)


def load_settings(cfg) -> dict:
    data = _read(cfg)
    from_cfg = {k: v for k, v in (cfg.get("ai") or {}).items() if k in AI_DEFAULTS and v} if cfg.get("ai.enabled") else {}
    ai = {**AI_DEFAULTS, **from_cfg, **data.get("ai", {})}
    return {"ai": ai}


def save_settings(cfg, new: dict) -> dict:
    cur = load_settings(cfg)
    ai = dict(cur["ai"])
    for k, v in (new.get("ai") or {}).items():
        if k not in AI_DEFAULTS:
            continue
        if k == "api_key" and v in (None, "", "********"):
            continue  # keep existing key unless a new one is supplied
        ai[k] = v
    if (new.get("ai") or {}).get("clear_api_key"):
        ai["api_key"] = ""
    if ai["provider"] not in PROVIDER_INFO:
        raise ValueError(f"unknown provider {ai['provider']}")
    _write(cfg, {**_read(cfg), "ai": ai})  # keep the other sections (API keys)
    return public_settings(cfg)


def resolve_key(ai: dict) -> str | None:
    if ai.get("api_key"):
        return ai["api_key"]
    env = ai.get("api_key_env") or PROVIDER_INFO.get(ai["provider"], {}).get("key_env")
    return os.environ.get(env) if env else None


def public_settings(cfg) -> dict:
    s = load_settings(cfg)
    ai = dict(s["ai"])
    ai["api_key_set"] = bool(resolve_key(ai))
    ai["api_key"] = "********" if s["ai"].get("api_key") else ""
    return {"ai": ai, "providers": PROVIDER_INFO}


# ----------------------------------------------------------------------------- API keys

def catalog(cfg=None) -> list[dict]:
    """The known keys plus any api_env declared by a registered tool."""
    out = {k["env"]: dict(k) for k in KEY_CATALOG}
    if cfg is not None:
        try:
            from .core.registry import load_registry

            for e in load_registry(cfg):
                for env in e.get("api_env") or []:
                    item = out.setdefault(env, {"env": env, "service": e["name"], "used_by": "", "url": ""})
                    if e["name"] not in item["used_by"]:
                        item["used_by"] = ", ".join(x for x in (item["used_by"], e["name"]) if x)
        except Exception:  # registry problems must never break the settings page
            pass
    return list(out.values())


def allowed_name(env: str, cfg=None) -> bool:
    if not ENV_NAME.match(env) or env.startswith(FORBIDDEN_PREFIX):
        return False
    return env in {k["env"] for k in catalog(cfg)} or bool(CREDENTIAL_NAME.search(env))


def stored_keys(cfg) -> dict[str, str]:
    return {k: v for k, v in (_read(cfg).get("api_keys") or {}).items()
            if isinstance(v, str) and v and allowed_name(k, cfg)}


def apply_api_keys(cfg) -> None:
    """Export stored keys to the process environment (dashboard values override the shell's)."""
    keys = stored_keys(cfg)
    for env in list(_APPLIED):
        if env not in keys:
            if env in _ORIGINAL_ENV:
                os.environ[env] = _ORIGINAL_ENV[env]
            else:
                os.environ.pop(env, None)
            _APPLIED.discard(env)
    for env, val in keys.items():
        os.environ[env] = val
        _APPLIED.add(env)
    if hasattr(cfg, "data"):
        apply_notification_settings(cfg)


def save_api_keys(cfg, set_keys: dict | None = None, clear: list | None = None) -> list[dict]:
    data = _read(cfg)
    keys = dict(data.get("api_keys") or {})
    for env, val in (set_keys or {}).items():
        env = str(env).strip().upper()
        if not allowed_name(env, cfg):
            raise ValueError(f"'{env}' is not accepted: use a listed key or a name ending in _API_KEY, _KEY, _TOKEN or _SECRET")
        val = str(val or "").strip()
        if not val:
            continue
        if len(val) > 4096 or any(c in val for c in "\r\n\x00"):
            raise ValueError(f"{env}: value looks malformed")
        keys[env] = val
    for env in clear or []:
        keys.pop(str(env).upper(), None)
    data["api_keys"] = keys
    _write(cfg, data)
    apply_api_keys(cfg)
    return public_api_keys(cfg)


def public_api_keys(cfg) -> list[dict]:
    """What the browser may see: never the value, only whether and where a key is set."""
    stored = stored_keys(cfg)
    rows = catalog(cfg)
    known = {r["env"] for r in rows}
    rows += [{"env": e, "service": "custom", "used_by": "", "url": ""} for e in sorted(stored) if e not in known]
    for r in rows:
        env = r["env"]
        r["source"] = "dashboard" if env in stored else "environment" if _ORIGINAL_ENV.get(env) else None
        r["set"] = bool(r["source"])
        r["hint"] = ""  # no part of a key is ever sent to the browser
    return rows


# ----------------------------------------------------------------------------- notifications
# Channel secrets are write-only (never returned); the other fields are plain settings. Everything is kept in
# settings.json (0600) and merged over the `notifications:` section of the config file at runtime.
NOTIFY_SECRET = {"slack": "webhook_url", "discord": "webhook_url", "telegram": "bot_token", "email": "password"}
NOTIFY_FIELDS = {
    "slack": {}, "discord": {},
    "telegram": {"chat_id": str},
    "email": {"smtp_host": str, "smtp_port": int, "starttls": bool, "username": str, "from": str, "to": list},
}
SIGNIFICANCE = ("low", "medium", "high")


def _notify_secret_present(ch_cfg: dict, ch: str) -> bool:
    if ch_cfg.get(NOTIFY_SECRET[ch]):
        return True
    env = ch_cfg.get({"slack": "webhook_url_env", "discord": "webhook_url_env", "telegram": "bot_token_env",
                      "email": "password_env"}[ch])
    return bool(env and os.environ.get(env))


def apply_notification_settings(cfg) -> None:
    """Merge dashboard notification settings (and secrets) over the config file's notifications section."""
    import copy

    if not hasattr(cfg, "_notify_base"):  # the config file's own values, before any dashboard override
        cfg._notify_base = copy.deepcopy(cfg.data.get("notifications") or {})
    merged = copy.deepcopy(cfg._notify_base)
    data = _read(cfg)
    stored = data.get("notifications") or {}
    secrets = data.get("notify_secrets") or {}
    for k in ("enabled", "min_significance"):
        if k in stored:
            merged[k] = stored[k]
    for ch in NOTIFY_SECRET:
        ch_cfg = dict(merged.get(ch) or {})
        ch_cfg.update((stored.get("channels") or {}).get(ch) or {})
        if secrets.get(ch):
            ch_cfg[NOTIFY_SECRET[ch]] = secrets[ch]
        merged[ch] = ch_cfg
    cfg.data["notifications"] = merged


def public_notification_settings(cfg) -> dict:
    n = cfg.get("notifications") or {}
    channels = {}
    for ch, fields in NOTIFY_FIELDS.items():
        c = n.get(ch) or {}
        channels[ch] = {"enabled": bool(c.get("enabled")), "secret_set": _notify_secret_present(c, ch),
                        **{f: c.get(f, [] if t is list else None) for f, t in fields.items()}}
    return {"enabled": bool(n.get("enabled")), "min_significance": n.get("min_significance", "low"), "channels": channels}


def save_notification_settings(cfg, body: dict) -> dict:
    data = _read(cfg)
    stored = dict(data.get("notifications") or {})
    secrets = dict(data.get("notify_secrets") or {})
    if "enabled" in body:
        stored["enabled"] = bool(body["enabled"])
    if "min_significance" in body:
        if body["min_significance"] not in SIGNIFICANCE:
            raise ValueError("min_significance must be low, medium or high")
        stored["min_significance"] = body["min_significance"]
    chans = dict(stored.get("channels") or {})
    for ch, upd in (body.get("channels") or {}).items():
        if ch not in NOTIFY_FIELDS or not isinstance(upd, dict):
            raise ValueError(f"unknown channel '{ch}'")
        cur = dict(chans.get(ch) or {})
        if "enabled" in upd:
            cur["enabled"] = bool(upd["enabled"])
        for f, typ in NOTIFY_FIELDS[ch].items():
            if f not in upd:
                continue
            v = upd[f]
            if typ is list:
                v = [str(x).strip() for x in (v if isinstance(v, list) else str(v).split(",")) if str(x).strip()]
                if any(not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", x) for x in v):
                    raise ValueError("email recipients must be e-mail addresses")
            elif typ is int:
                v = int(v)
                if not 1 <= v <= 65535:
                    raise ValueError("port must be 1-65535")
            elif typ is bool:
                v = bool(v)
            else:
                v = str(v or "").strip()[:300]
            cur[f] = v
        chans[ch] = cur
        secret = upd.get("secret")
        if upd.get("clear_secret"):
            secrets.pop(ch, None)
        elif secret:
            secret = str(secret).strip()
            if len(secret) > 2048 or any(c in secret for c in "\r\n\x00"):
                raise ValueError(f"{ch}: value looks malformed")
            if ch in ("slack", "discord") and not secret.startswith("https://"):
                raise ValueError(f"{ch}: the webhook URL must start with https://")
            secrets[ch] = secret
    stored["channels"] = chans
    data["notifications"], data["notify_secrets"] = stored, secrets
    _write(cfg, data)
    apply_notification_settings(cfg)
    return public_notification_settings(cfg)


def send_test_notification(cfg, channel: str) -> str:
    from .notify.dispatcher import CHANNELS

    if channel not in CHANNELS:
        raise ValueError(f"unknown channel '{channel}'")
    msg = {"title": "ReconForge test notification", "counts": "This is a test message; no scan data is included.",
           "text": "ReconForge test notification\nThis is a test message; no scan data is included.",
           "items": [], "report_link": "ReconForge dashboard", "more": 0}
    CHANNELS[channel](cfg.get(f"notifications.{channel}", {}), msg)
    return "sent"
