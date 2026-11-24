"""Scan context passed to every module."""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..correlation.engine import CorrelationEngine
from ..db.models import Asset, Evidence, ModuleRun, Observation
from ..util import new_id, sha256, utcnow
from .observation import Obs
from .tools import Stopped, ToolInfo, detect_tool, stream_command

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config
    from ..scope import Scope

INLINE_EVIDENCE_LIMIT = 16_000


class RateLimiter:
    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            time.sleep(delay)


class ScanContext:
    def __init__(self, *, config: "Config", session: Session, scope: "Scope", target: dict, target_id: str,
                 scan_id: str, profile_name: str, profile: dict, incremental: bool, prev_scan_id: str | None,
                 logger: logging.Logger):
        self.config = config
        self.session = session
        self.scope = scope
        self.target = target
        self.target_id = target_id
        self.scan_id = scan_id
        self.profile_name = profile_name
        self.profile = profile
        self.incremental = incremental
        self.prev_scan_id = prev_scan_id
        self.log = logger
        self.engine = CorrelationEngine(session, config, scope, target_id, scan_id)
        self.limiter = RateLimiter(float(config.get("network.rate_limit_per_second", 5)))
        self.evidence_dir = config.dir("evidence_dir") / scan_id
        self.current_module: str = ""
        self.current_run: ModuleRun | None = None
        self.tools_used: set[str] = set()
        self.standalone = False  # single-module run: stored assets are valid inputs
        self.host_filter: set[str] | None = None  # restricts a re-run pass to newly discovered hosts
        self.shared: dict = {}  # in-memory data shared between modules during one scan (e.g. HTTP bodies)
        self.cancel = None  # threading.Event set when the user stops the run; running tools are terminated

    # ----------------------------------------------------------------- options
    def option(self, module: str, key: str, default=None):
        """Module option lookup: profile overrides > target overrides > global config section."""
        for layer in (self.profile.get("overrides", {}), self.target.get("module_options", {})):
            if module in layer and key in layer[module]:
                return layer[module][key]
        return self.config.get(f"{module}.{key}", default)

    @property
    def offline(self) -> bool:
        return bool(self.config.get("network.offline", False))

    # ---------------------------------------------------------------- emitting
    def emit(self, obs: Obs) -> Asset:
        asset = self.engine.ingest(obs, self.current_module)
        if self.current_run is not None:
            self.current_run.observations += 1
        return asset

    def evidence(self, kind: str, summary: str, content: str | bytes, suffix: str = ".txt") -> str:
        ev_id = new_id("ev")
        data = content.encode("utf-8", "replace") if isinstance(content, str) else content
        digest = sha256(data)
        ev = Evidence(id=ev_id, scan_id=self.scan_id, module=self.current_module, kind=kind,
                      summary=summary[:500], sha256=digest, created_at=utcnow())
        if len(data) <= INLINE_EVIDENCE_LIMIT and isinstance(content, str):
            ev.content = content
        else:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            path = self.evidence_dir / f"{ev_id}{suffix}"
            path.write_bytes(data)
            ev.path = str(path)
            ev.content = content[:2000] if isinstance(content, str) else None
        self.session.add(ev)
        return ev_id

    # ----------------------------------------------------------------- queries
    def assets(self, type_: str | list[str], scope: str | None = "in_scope", active_only: bool = True,
               exclude_fp: bool = True) -> list[Asset]:
        self.session.flush()
        types = [type_] if isinstance(type_, str) else type_
        q = select(Asset).where(Asset.target_id == self.target_id, Asset.type.in_(types))
        if scope:
            q = q.where(Asset.scope == scope)
        if active_only:
            q = q.where(Asset.status == "active")
        if exclude_fp:
            q = q.where(Asset.false_positive.is_(False))
        return list(self.session.execute(q).scalars())

    def hosts(self, resolved_only: bool = True) -> list[Asset]:
        """In-scope hosts: root domains, subdomains and IP addresses named as scan targets."""
        out = []
        for a in self.assets(["domain", "subdomain", "ip"]):
            if a.type == "ip" and not ((a.attributes or {}).get("target") and self.scope.ip_is_target(a.key)):
                continue
            if not self.in_filter(a.key):
                continue
            if resolved_only and not (a.attributes or {}).get("resolved"):
                continue
            out.append(a)
        return sorted(out, key=lambda a: a.key)

    def live(self, type_: str | list[str]) -> list[Asset]:
        """Assets of `type_` observed during this scan (or deliberately carried forward by an
        incremental skip). Prevents modules from acting on stale records from older scans."""
        if self.standalone:
            return self.assets(type_)
        skipped = self.shared.get("incremental_skipped_hosts", set())
        out = []
        for a in self.assets(type_):
            host = (a.attributes or {}).get("host") or (a.attributes or {}).get("ip")
            if self.seen_this_scan(a) or (self.incremental and host in skipped):
                out.append(a)
        return out

    def action(self, msg: str, *args) -> None:
        """Log one concrete action (request, query, connection, command) for the live console."""
        self.log.info("[%s] %s", self.current_module, msg % args if args else msg)

    def in_filter(self, host: str | None) -> bool:
        return self.host_filter is None or (host or "") in self.host_filter

    def seen_this_scan(self, asset: Asset) -> bool:
        return asset.id in self.engine.touched

    def needs_refresh(self, asset: Asset, module: str) -> bool:
        """Incremental mode: refresh only new assets or those not observed by `module` recently."""
        if not self.incremental:
            return True
        max_age = timedelta(hours=float(self.config.get("incremental.max_age_hours", 24)))
        last = self.session.execute(
            select(Observation.observed_at)
            .where(Observation.asset_id == asset.id, Observation.module == module, Observation.scan_id != self.scan_id)
            .order_by(Observation.observed_at.desc()).limit(1)
        ).scalar_one_or_none()
        if last is None:
            return True
        return utcnow() - last > max_age

    def mark_skipped_input(self, key: str) -> None:
        self.shared.setdefault("incremental_skipped_hosts", set()).add(key)
        if self.current_run is not None:
            self.current_run.skipped_inputs = [*(self.current_run.skipped_inputs or []), key]

    # ------------------------------------------------------------------- tools
    def tool(self, name: str) -> ToolInfo:
        return detect_tool(name, self.config.get(f"tools.{name}", {}) or {})

    def run_tool(self, name: str, args: list[str], input_text: str | None = None, timeout: int = 900,
                 echo=None, keep_partial: bool = False):
        """Run an external tool. `echo(stream, line)` returns a string to log for that output line
        (or None to stay quiet). Stopping the run terminates the tool: with `keep_partial` its
        output so far is returned, otherwise the module is recorded as skipped."""
        info = self.tool(name)
        if not info.available or not info.path:
            raise RuntimeError(f"tool {name} unavailable: {info.reason}")
        cmd = [info.path, *args]
        self.log.info("[%s] exec: %s", self.current_module, " ".join(cmd))
        if self.current_run is not None:
            self.current_run.tool = name
            self.current_run.command = " ".join(cmd)[:4000]
        self.tools_used.add(name)
        on_line = None
        if echo is not None:
            module = self.current_module

            def on_line(stream, line):
                msg = echo(stream, line)
                if msg:
                    self.log.info("[%s] %s", module, msg[:1000])
        try:
            # tools run inside the scan's own work directory, so any state/report files they drop
            # (feroxbuster .state, dirsearch reports/, resume files...) stay in the git-ignored data dir
            proc = stream_command(cmd, input_text=input_text, timeout=timeout, on_line=on_line, cancel=self.cancel,
                                  cwd=str(self.work_dir))
        except Stopped as stop:
            self.log.warning("[%s] %s stopped by user", self.current_module, name)
            if keep_partial:
                return stop.proc
            from .module import SkipModule
            raise SkipModule(f"{name} stopped by user") from None
        if proc.returncode not in (0,) and not proc.stdout:
            raise RuntimeError(f"{name} exited {proc.returncode}: {proc.stderr[-2000:]}")
        return proc

    @property
    def work_dir(self) -> Path:
        p = self.config.dir("work_dir") / self.scan_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def scan_path(self, *parts: str) -> Path:
        p = self.evidence_dir.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
