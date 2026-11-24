"""Scan orchestration: one command runs modules, correlation, change detection,
prioritization, AI analysis, reporting and notifications."""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field

from sqlalchemy import select

from ..config import Config
from ..db import Database
from ..db.models import Asset, ModuleRun, Scan, Target
from ..diff.changes import latest_previous_scan, snapshot_and_diff
from ..prioritize.engine import prioritize
from ..scope import Scope, ScopeError
from ..util import new_id, utcnow
from .context import ScanContext
from .module import PHASES, Module, SkipModule, load_modules

REDISCOVERY_PHASES = {"resolve", "network", "http", "fingerprint", "content", "assessment", "capture"}


@dataclass
class ScanOptions:
    target: str
    profile: str | None = None
    modules: list[str] | None = None     # explicit module list (replaces the profile's)
    add: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    incremental: bool | None = None
    trigger: str = "manual"
    reports: bool | None = None
    notify: bool | None = None
    ai: bool | None = None
    rediscovery_passes: int = 2
    scan_id: str | None = None             # pre-assigned id (dashboard runs return it immediately)
    only_tools: list[str] | None = None    # restrict registry tools (single-tool execution)
    standalone: bool = False               # single module run: use stored assets as input
    cancel: object | None = None           # threading.Event; checked between modules
    module_options: dict = field(default_factory=dict)  # per-run module option overrides (e.g. engine)


def ensure_target(db: Database, cfg: Config, name: str) -> tuple[str, dict]:
    from ..targets import resolve_target

    target = resolve_target(cfg, db, name)
    if not target:
        raise KeyError(f"target '{name}' not found (define it in the config or add it in the dashboard)")
    with db.session() as s:
        row = s.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
        if row is None:
            row = Target(id=new_id("tgt"), name=name, config=target)
            s.add(row)
        else:
            row.config = target
        return row.id, target


def plan_modules(cfg: Config, profile: dict, opts: ScanOptions) -> list[type[Module]]:
    registry = load_modules(cfg.get("plugins", []))
    names = list(opts.modules) if opts.modules else list(profile.get("modules", []))
    names += [m for m in opts.add if m not in names]
    names = [n for n in names if n not in set(opts.skip)]
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise KeyError(f"unknown module(s): {', '.join(unknown)}. Available: {', '.join(sorted(registry))}")
    classes = [registry[n] for n in names]
    return sorted(classes, key=lambda c: (c.order(), names.index(c.name)))


def setup_scan_logger(cfg: Config, scan_id: str) -> tuple[logging.Logger, str]:
    path = cfg.dir("logs_dir") / f"{scan_id}.log"
    logger = logging.getLogger(f"reconforge.scan.{scan_id}")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(path)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)
    logger.propagate = False
    console = logging.getLogger("reconforge.console")
    for h in console.handlers:  # CLI attaches a console handler when --verbose
        logger.addHandler(h)
    return logger, str(path)


def run_scan(cfg: Config, opts: ScanOptions, db: Database | None = None) -> str:
    db = db or Database(cfg.database_url)
    from ..settings import apply_api_keys

    apply_api_keys(cfg)  # keys saved in the dashboard also apply to CLI and scheduled scans
    target_id, target = ensure_target(db, cfg, opts.target)
    if opts.module_options:
        merged = {k: dict(v) for k, v in (target.get("module_options") or {}).items()}
        for mod, o in opts.module_options.items():
            merged.setdefault(mod, {}).update(o)
        target = {**target, "module_options": merged}
    profile_name = opts.profile or target.get("profile") or "standard"
    profile = cfg.profile(profile_name)
    modules = plan_modules(cfg, profile, opts)
    scope = Scope.from_target(target)
    if not scope.has_targets:
        raise ScopeError("nothing to scan: add at least one domain, IP address or CIDR range")
    if any(m.active for m in modules):
        scope.require_active_authorization()
    incremental = opts.incremental if opts.incremental is not None else bool(profile.get("incremental", False))

    scan_id = opts.scan_id or new_id("scn")
    logger, log_path = setup_scan_logger(cfg, scan_id)
    with db.session() as s:
        scan = Scan(id=scan_id, target_id=target_id, profile="single-action" if opts.standalone else profile_name,
                    status="running", trigger=opts.trigger,
                    incremental=incremental, started_at=utcnow(), modules_planned=[m.name for m in modules],
                    log_path=log_path)
        s.add(scan)
        s.flush()
        prev = latest_previous_scan(s, target_id, scan_id)
        scan.prev_scan_id = prev.id if prev else None

    logger.info("scan %s started: target=%s profile=%s incremental=%s modules=%s authorization=%s",
                scan_id, opts.target, profile_name, incremental, [m.name for m in modules], scope.authorization_reference)
    with db.session() as s:
        scan = s.get(Scan, scan_id)
        ctx = ScanContext(config=cfg, session=s, scope=scope, target=target, target_id=target_id, scan_id=scan_id,
                          profile_name=profile_name, profile=profile, incremental=incremental,
                          prev_scan_id=scan.prev_scan_id, logger=logger)
        ctx.standalone = opts.standalone
        ctx.cancel = opts.cancel
        if opts.only_tools:
            ctx.shared["only_tools"] = set(opts.only_tools)
        completed, failed, skipped = [], [], []
        cancelled = False
        try:
            # Seed root domains so every module has a starting point.
            for root in scope.root_domains:
                ctx.current_module = "seed"
                ctx.engine.upsert("domain", root, {"root": True}, "domain_intel", "seed")
            seeds = scope.seed_ips()
            for ip in seeds:  # IP / CIDR targets are hosts in their own right
                ctx.current_module = "seed"
                ctx.engine.upsert("ip", ip, {"target": True, "resolved": True, "ips": [ip], "host": ip,
                                             "version": 6 if ":" in ip else 4}, "target", "seed")
            if seeds:
                logger.info("[seed] %d IP target(s) from %s", len(seeds), ", ".join(scope.ip_targets))
            for mod_cls in modules:
                if opts.cancel is not None and opts.cancel.is_set():
                    cancelled = True
                    logger.warning("scan cancelled by user before module %s", mod_cls.name)
                    break
                status = _run_module(ctx, s, mod_cls, logger)
                {"completed": completed, "failed": failed, "skipped": skipped}[status].append(mod_cls.name)
            # Rediscovery: names found late (TLS SANs, JS, crawling) get resolved and probed too.
            for n in range(2, 2 + (0 if cancelled or opts.standalone else opts.rediscovery_passes)):
                new_hosts = {a.key for a in ctx.assets("subdomain")
                             if ctx.seen_this_scan(a) and "dns_status" not in (a.attributes or {})}
                if not new_hosts:
                    break
                logger.info("rediscovery pass %s for %d new host(s): %s", n, len(new_hosts), sorted(new_hosts))
                ctx.host_filter = new_hosts
                for mod_cls in modules:
                    if mod_cls.phase in REDISCOVERY_PHASES and mod_cls.name not in skipped:
                        status = _run_module(ctx, s, mod_cls, logger, suffix=f"#{n}")
                        if status == "failed" and mod_cls.name not in failed:
                            failed.append(mod_cls.name)
                ctx.host_filter = None
            scan.modules_completed = completed
            scan.modules_failed = failed
            scan.modules_skipped = skipped
            scan.tools_executed = sorted(ctx.tools_used | {"builtin:" + m for m in completed})
            scan.results_count = ctx.engine.observation_count
            s.flush()
            changes = snapshot_and_diff(s, scan, ctx.engine.touched, cfg, ctx.engine.referenced)
            scores = prioritize(s, target_id, scan_id)
            scan.status = "cancelled" if cancelled else "partial" if failed else "completed"
            scan.finished_at = utcnow()
            from ..coverage import compute_coverage

            summary = _summary(s, target_id, changes, scores)
            summary["coverage"] = compute_coverage(s, scan, ctx)
            scan.summary = summary
            logger.info("scan %s finished: status=%s observations=%d changes=%d", scan_id, scan.status,
                        scan.results_count, len(changes))
        except Exception as exc:
            logger.error("scan failed: %s\n%s", exc, traceback.format_exc())
            s.rollback()
            with db.session() as s2:
                sc = s2.get(Scan, scan_id)
                sc.status = "failed"
                sc.error = str(exc)
                sc.finished_at = utcnow()
            raise

    # Post-processing steps run in their own sessions; failures are logged, never lose the scan.
    want_ai = opts.ai if opts.ai is not None else bool(cfg.get("ai.enabled"))
    if want_ai:
        _safe(logger, "ai analysis", lambda: __import__("reconforge.ai.analyst", fromlist=["x"]).analyze_scan(cfg, db, scan_id))
    want_reports = opts.reports if opts.reports is not None else bool(cfg.get("reports.auto_generate", True))
    if want_reports:
        _safe(logger, "reporting", lambda: __import__("reconforge.reports.builder", fromlist=["x"]).generate_reports(cfg, db, scan_id))
    _safe(logger, "output files", lambda: __import__("reconforge.outputs", fromlist=["x"]).write_scan_outputs(cfg, db, scan_id))
    import shutil

    shutil.rmtree(cfg.dir("work_dir") / scan_id, ignore_errors=True)  # scratch space of external tools
    want_notify = opts.notify if opts.notify is not None else bool(cfg.get("notifications.enabled") or profile.get("notify"))
    if want_notify:
        _safe(logger, "notifications", lambda: __import__("reconforge.notify.dispatcher", fromlist=["x"]).notify_scan(cfg, db, scan_id))
    for h in list(logger.handlers):
        h.close()
        logger.removeHandler(h)
    return scan_id


def _safe(logger, label, fn):
    try:
        fn()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("%s failed: %s\n%s", label, exc, traceback.format_exc())


def _run_module(ctx: ScanContext, s, mod_cls: type[Module], logger, suffix: str = "") -> str:
    run = ModuleRun(scan_id=ctx.scan_id, module=mod_cls.name + suffix, tool="builtin", status="running",
                    started_at=utcnow(), skipped_inputs=[], observations=0, inputs=0)
    s.add(run)
    s.commit()  # make the running module visible to the live dashboard
    ctx.current_module = mod_cls.name
    ctx.current_run = run
    status = "completed"
    try:
        if (mod_cls.requires_internet and ctx.offline and not getattr(mod_cls, "handles_offline", False)
                and not _module_has_local_source(ctx, mod_cls)):
            raise SkipModule("network.offline is true")
        if getattr(mod_cls, "needs_domains", False) and not ctx.scope.root_domains:
            raise SkipModule("this scan has no domain targets (IP-only)")
        logger.info("[%s%s] starting", mod_cls.name, suffix)
        mod_cls().run(ctx)
        s.flush()
    except SkipModule as exc:
        status = "skipped"
        run.skip_reason = str(exc)
        logger.info("[%s%s] skipped: %s", mod_cls.name, suffix, exc)
    except Exception as exc:
        status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        logger.error("[%s%s] failed: %s\n%s", mod_cls.name, suffix, exc, traceback.format_exc())
        try:
            s.flush()
        except Exception:
            s.rollback()
    run.status = status
    run.finished_at = utcnow()
    ctx.current_run = None
    s.commit()
    logger.info("[%s%s] %s (%d observations)", mod_cls.name, suffix, status, run.observations)
    return status


def _module_has_local_source(ctx, mod_cls) -> bool:
    key = {"crtsh": "base_url", "historical_urls": "base_url"}.get(mod_cls.name)
    if mod_cls.name == "github_intel":
        base = ctx.option("github", "api_base", "")
    elif key:
        base = ctx.option(mod_cls.name, key, "")
    else:
        return False
    return str(base).startswith(("http://127.", "http://localhost"))


def _summary(s, target_id: str, changes, scores) -> dict:
    from collections import Counter

    assets = list(s.execute(select(Asset).where(Asset.target_id == target_id, Asset.status == "active",
                                                Asset.false_positive.is_(False))).scalars())
    by_type = Counter(a.type for a in assets)
    subs = [a for a in assets if a.type in ("subdomain", "domain") and a.scope == "in_scope"]
    return {
        "asset_counts": dict(by_type),
        "resolved_hosts": sum(1 for a in subs if (a.attributes or {}).get("resolved")),
        "unresolved_hosts": sum(1 for a in subs if not (a.attributes or {}).get("resolved")),
        "changes": len(changes),
        "change_categories": dict(Counter(c.category for c in changes)),
        "priority_tiers": dict(Counter(sc.tier for sc in scores)),
        "findings_by_severity": dict(Counter((a.attributes or {}).get("severity") for a in assets if a.type == "finding")),
    }


def phase_names() -> list[str]:
    return sorted(PHASES, key=PHASES.get)
