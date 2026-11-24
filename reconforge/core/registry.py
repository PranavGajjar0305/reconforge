"""Tool registry and selection engine.

The registry (data/tools.yaml, extendable via config `tool_registry:`) describes every
known tool. `select_tools()` decides, per category, which tools actually run:
installed? correct binary? API credentials present? profile allowed (passive /
active / opt-in / reference)? offline? Decisions and reasons are recorded per scan so
the coverage report can explain what did and did not run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent.parent / "data" / "tools.yaml"


@dataclass
class ToolStatus:
    name: str
    category: str
    profile: str
    maintenance: str
    installed: bool = False
    path: str | None = None
    version: str | None = None
    credentials: bool = True
    missing_env: list[str] = field(default_factory=list)
    selected: bool = False
    reason: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@lru_cache
def _builtin_registry() -> tuple:
    return tuple(yaml.safe_load(DATA.read_text()))


def load_registry(cfg) -> list[dict]:
    entries = {e["name"]: dict(e) for e in _builtin_registry()}
    for extra in cfg.get("tool_registry", []) or []:
        entries[extra["name"]] = {**entries.get(extra["name"], {}), **extra}
    return list(entries.values())


_version_cache: dict[str, tuple[str | None, str | None, bool]] = {}


def probe(entry: dict, cfg) -> tuple[str | None, str | None, bool]:
    """Return (path, version_line, signature_ok)."""
    tool_cfg = cfg.get(f"tools.{entry['name']}", {}) or {}
    exe = tool_cfg.get("path", entry["name"])
    if exe in _version_cache:
        return _version_cache[exe]
    path = shutil.which(exe)
    version, ok = None, False
    if path:
        try:
            out = subprocess.run([path, *entry.get("version_args", ["--version"])], capture_output=True, text=True, timeout=15)
            text = (out.stdout + out.stderr).strip()
            version = next((l.strip() for l in text.splitlines() if any(c.isdigit() for c in l)), text[:80] or None)
            sig = (entry.get("signature") or "").lower()
            ok = not sig or any(n.strip() in text.lower() for n in sig.split("|"))
        except Exception:
            ok = False
    _version_cache[exe] = (path, version, ok)
    return _version_cache[exe]


def tool_status(entry: dict, cfg, *, active_allowed: bool = True, offline: bool = False) -> ToolStatus:
    st = ToolStatus(entry["name"], entry.get("category", ""), entry.get("profile", "reference"), entry.get("maintenance", "unknown"))
    enabled = (cfg.get(f"tools.{entry['name']}", {}) or {}).get("enabled", "auto")
    opt_in = set(cfg.get("tools_opt_in", []) or [])
    if st.profile == "reference" and entry["name"] not in opt_in:
        st.reason = entry.get("notes") or "reference only (built-in equivalent or not executed by design)"
        path, version, ok = probe(entry, cfg) if entry.get("version_args") else (shutil.which(entry["name"]), None, True)
        st.installed, st.path, st.version = bool(path and ok), path, version
        return st
    path, version, ok = probe(entry, cfg)
    st.installed, st.path, st.version = bool(path and ok), path, version
    st.missing_env = [e for e in entry.get("api_env", []) or [] if not os.environ.get(e)]
    st.credentials = not st.missing_env
    if str(enabled).lower() == "false":
        st.reason = "disabled in config"
    elif st.profile == "opt-in" and entry["name"] not in opt_in:
        st.reason = "opt-in tool (add to tools_opt_in to enable)"
    elif not path:
        st.reason = f"not installed ({entry.get('install', 'see docs')})"
    elif not ok:
        st.reason = f"'{path}' does not match expected signature '{entry.get('signature')}'"
    elif st.missing_env:
        st.reason = f"missing API credentials: {', '.join(st.missing_env)}"
    elif st.profile == "active" and not active_allowed:
        st.reason = "active tool not allowed in this profile"
    elif offline and entry.get("phase") == "passive" and not entry.get("local"):
        st.reason = "network.offline is true"
    elif entry.get("maintenance") == "discontinued":
        st.reason = "discontinued upstream"
    else:
        st.selected = True
        st.reason = "selected"
    return st


def select_tools(cfg, category: str, *, active_allowed: bool = True, offline: bool = False,
                 runnable_only: bool = True) -> list[tuple[dict, ToolStatus]]:
    out = []
    for e in load_registry(cfg):
        if e.get("category") != category:
            continue
        if runnable_only and not e.get("command"):
            continue
        out.append((e, tool_status(e, cfg, active_allowed=active_allowed, offline=offline)))
    return out


def render_command(entry: dict, **values) -> list[str]:
    out = []
    for part in entry["command"]:
        for k, v in values.items():
            part = part.replace("{" + k + "}", str(v))
        while "{env:" in part:
            start = part.index("{env:")
            end = part.index("}", start)
            part = part[:start] + os.environ.get(part[start + 5:end], "") + part[end + 1:]
        out.append(part)
    return out
