"""ReconForge command-line interface."""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path

from sqlalchemy import select

from .config import load_config
from .db import Database
from .db.models import Asset, Change, Scan, Schedule, Target
from .util import iso, utcnow


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in v.split(",") if x.strip()] if v else []


def _ctx(args):
    cfg = load_config(args.config)
    if getattr(args, "verbose", False):
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
        logging.getLogger("reconforge.console").addHandler(h)
    return cfg, Database(cfg.database_url)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _table(rows: list[list], header: list[str]) -> None:
    rows = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [min(60, max([len(h)] + [len(r[i]) for r in rows])) for i, h in enumerate(header)]
    print("  ".join(h.ljust(w) for h, w in zip(header, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(c[:w].ljust(w) for c, w in zip(r, widths)))


# ------------------------------------------------------------------ commands
def cmd_init(args):
    here = Path(__file__).resolve().parent.parent / "config" / "reconforge.example.yaml"
    dest = Path(args.config or "config/reconforge.yaml")
    if dest.exists() and not args.force:
        print(f"{dest} exists (use --force to overwrite)")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(here, dest)
        print(f"wrote {dest}")
    cfg = load_config(str(dest))
    Database(cfg.database_url)
    print(f"database ready: {cfg.database_url}")


def cmd_scan(args):
    from .core.pipeline import ScanOptions, run_scan

    cfg, db = _ctx(args)
    opts = ScanOptions(target=args.target, profile=args.profile, modules=_csv(args.modules) or None, add=_csv(args.add),
                       skip=_csv(args.skip), incremental=args.incremental, reports=False if args.no_report else None,
                       notify=False if args.no_notify else (True if args.notify else None), ai=True if args.ai else None)
    scan_id = run_scan(cfg, opts, db)
    with db.session() as s:
        sc = s.get(Scan, scan_id)
        print(f"scan {scan_id}: {sc.status} in {sc.duration_seconds}s — {sc.results_count} observations")
        print(f"  completed: {', '.join(sc.modules_completed)}")
        if sc.modules_skipped:
            print(f"  skipped:   {', '.join(sc.modules_skipped)}")
        if sc.modules_failed:
            print(f"  FAILED:    {', '.join(sc.modules_failed)}  (see {sc.log_path})")
        print(f"  changes vs previous scan: {sc.summary.get('changes', 0)}  {sc.summary.get('change_categories', {})}")
        print(f"  reports: {sc.report_dir}")
        print(f"  log: {sc.log_path}")
    return 0 if sc.status != "failed" else 1


def cmd_scans(args):
    _, db = _ctx(args)
    with db.session() as s:
        q = select(Scan, Target).join(Target).order_by(Scan.started_at.desc()).limit(args.limit)
        if args.target:
            q = q.where(Target.name == args.target)
        rows = [[sc.id, t.name, sc.profile, sc.trigger, sc.status, iso(sc.started_at), sc.duration_seconds,
                 len(sc.modules_completed or []), len(sc.modules_failed or []), sc.results_count,
                 (sc.summary or {}).get("changes", 0)] for sc, t in s.execute(q).all()]
    _table(rows, ["scan", "target", "profile", "trigger", "status", "started", "secs", "ok", "fail", "obs", "changes"])


def cmd_show(args):
    from .reports.data import build_report_data

    _, db = _ctx(args)
    with db.session() as s:
        d = build_report_data(s, args.scan_id)
    if args.json:
        return _print(d)
    _print({"scan": d["scan"], "overview": d["overview"], "coverage_gaps": d["coverage_gaps"]})


def cmd_changes(args):
    _, db = _ctx(args)
    with db.session() as s:
        rows = [[c.significance, c.category, c.summary[:90], json.dumps(c.previous, default=str)[:40],
                 json.dumps(c.current, default=str)[:40]]
                for c in sorted(s.execute(select(Change).where(Change.scan_id == args.scan_id)).scalars(),
                                key=lambda c: ({"high": 0, "medium": 1, "low": 2}.get(c.significance, 3), c.category))]
    _table(rows, ["sig", "category", "summary", "previous", "current"])


def cmd_diff(args):
    from .storage.maintenance import compare_scans

    _, db = _ctx(args)
    _print(compare_scans(db, args.scan_a, args.scan_b))


def cmd_report(args):
    from .reports.builder import generate_reports

    cfg, db = _ctx(args)
    sections = {s: False for s in _csv(args.disable)} | {s: True for s in _csv(args.enable)}
    written = generate_reports(cfg, db, args.scan_id, formats=_csv(args.formats) or None, sections=sections,
                               out_dir=Path(args.out) if args.out else None)
    for k, v in written.items():
        print(f"{k:24} {v}")


def cmd_notify(args):
    from .notify.dispatcher import notify_scan

    cfg, db = _ctx(args)
    _print(notify_scan(cfg, db, args.scan_id, _csv(args.channels) or None))


def cmd_analyze(args):
    from .ai.analyst import HeuristicProvider, analyze_scan, get_provider

    cfg, db = _ctx(args)
    provider = HeuristicProvider() if args.provider == "heuristic" else get_provider(cfg) if not args.provider else \
        __import__("reconforge.ai.analyst", fromlist=["x"]).AnthropicProvider(cfg.get("ai.model"), cfg.get("ai.effort"))
    aid = analyze_scan(cfg, db, args.scan_id, provider)
    from .db.models import AIAnalysis

    with db.session() as s:
        a = s.get(AIAnalysis, aid)
        print(f"analysis {aid}: provider={a.provider} model={a.model} status={a.status}")
        if a.error:
            print(f"  note: {a.error}")
        for sec, items in a.result.items():
            for it in items:
                print(f"  [{sec}] ({it['kind']}) {it['statement']}  refs={it['refs'][:4]}")
        print(f"  rejected by evidence guard: {len(a.rejected)}")
        for r in a.rejected[:10]:
            print(f"    - {r['reason']}: {str(r['item'].get('statement'))[:100]}")


def cmd_graph(args):
    from .graph.build import build_graph, to_cytoscape, to_dot, to_graphml

    _, db = _ctx(args)
    with db.session() as s:
        t = s.execute(select(Target).where(Target.name == args.target)).scalar_one()
        g = build_graph(s, t.id, types=_csv(args.types) or None)
    text = {"dot": to_dot, "graphml": to_graphml, "json": lambda g: json.dumps(to_cytoscape(g), default=str)}[args.format](g)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out} ({g.number_of_nodes()} nodes, {g.number_of_edges()} edges)")
    else:
        print(text)


def cmd_assets(args):
    _, db = _ctx(args)
    with db.session() as s:
        t = s.execute(select(Target).where(Target.name == args.target)).scalar_one()
        q = select(Asset).where(Asset.target_id == t.id)
        if args.type:
            q = q.where(Asset.type == args.type)
        if args.search:
            q = q.where(Asset.key.contains(args.search))
        if not args.all:
            q = q.where(Asset.status == "active")
        rows = [[a.id, a.type, a.display[:70], a.scope, round(a.confidence, 2), a.status, "FP" if a.false_positive else "",
                 iso(a.first_seen), iso(a.last_seen)] for a in s.execute(q.order_by(Asset.type, Asset.key)).scalars()]
    _table(rows, ["id", "type", "asset", "scope", "conf", "status", "fp", "first_seen", "last_seen"])


def cmd_fp(args):
    _, db = _ctx(args)
    with db.session() as s:
        a = s.get(Asset, args.asset_id)
        if a is None:
            print("no such asset")
            return 1
        a.false_positive = not args.unset
        a.fp_reason = None if args.unset else (args.reason or "marked by analyst")
        print(f"{a.id} ({a.display}) false_positive={a.false_positive}")


def cmd_history(args):
    from .storage.maintenance import asset_history

    _, db = _ctx(args)
    _print(asset_history(db, args.asset_id))


def cmd_schedule(args):
    from .scheduler.service import upsert_schedule

    cfg, db = _ctx(args)
    if args.action == "add":
        sc = upsert_schedule(db, name=args.name, target=args.target, frequency=args.frequency, profile=args.profile,
                             at=args.at, day=args.day, cron=args.cron, incremental=not args.full)
        print(f"schedule {sc.name}: cron='{sc.cron}' next run {iso(sc.next_run_at)} (UTC)")
    elif args.action == "list":
        with db.session() as s:
            rows = [[x.name, x.target_name, x.frequency, x.cron, x.profile, x.incremental, x.enabled, iso(x.next_run_at),
                     iso(x.last_run_at), x.last_status] for x in s.execute(select(Schedule).order_by(Schedule.name)).scalars()]
        _table(rows, ["name", "target", "freq", "cron", "profile", "incr", "enabled", "next_run", "last_run", "last_status"])
    else:
        with db.session() as s:
            sc = s.execute(select(Schedule).where(Schedule.name == args.name)).scalar_one()
            if args.action == "remove":
                s.delete(sc)
            else:
                sc.enabled = args.action == "enable"
        print(f"{args.action}d {args.name}")


def cmd_scheduler(args):
    from .scheduler.service import daemon, run_due, sync_config_schedules

    cfg, db = _ctx(args)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    if args.action == "sync":
        print("synced:", sync_config_schedules(cfg, db))
    elif args.action == "tick":
        sync_config_schedules(cfg, db)
        print(run_due(cfg, db))
    else:
        daemon(cfg, db, interval=args.interval)


def cmd_db(args):
    from .storage import maintenance as m

    cfg, db = _ctx(args)
    if args.action == "backup":
        print(m.backup(cfg, db))
    elif args.action == "export":
        out = Path(args.path or f"reconforge-export-{utcnow():%Y%m%dT%H%M%S}.json")
        print(m.export_json(db, out, args.target))
    elif args.action == "import":
        _print(m.import_json(db, Path(args.path)))
    elif args.action == "retention":
        _print(m.apply_retention(cfg, db, args.days, args.keep, dry_run=args.dry_run))


def cmd_modules(args):
    from .core.module import load_modules
    from .core.tools import detect_tool

    cfg = load_config(args.config)
    reg = load_modules(cfg.get("plugins", []))
    rows = []
    for name, cls in sorted(reg.items(), key=lambda kv: (kv[1].order(), kv[0])):
        tools = [f"{t}:{'yes' if detect_tool(t, cfg.get(f'tools.{t}', {})).available else 'no'}" for t in cls.tools]
        rows.append([name, cls.phase, "active" if cls.active else "passive", "yes" if cls.requires_internet else "",
                     " ".join(tools), cls.description[:70]])
    _table(rows, ["module", "phase", "traffic", "internet", "external tools", "description"])
    print()
    for pname, p in cfg.get("profiles").items():
        print(f"profile {pname}: {', '.join(p.get('modules', []))}")


def cmd_tools(args):
    from .core.registry import load_registry, tool_status

    if args.detect:
        from .core.tools import discover_tools, write_tool_paths

        cfg0 = load_config(args.config)
        found = discover_tools(load_registry(cfg0))
        out = write_tool_paths(found)
        for n, v in sorted(found.items()):
            mark = "OK  " if v["path"] else "BAD "
            print(f"  {mark}{n:20} {v['path'] or 'wrong program at ' + ', '.join(v['rejected'])}  {v['version'] or ''}")
        print(f"wrote {out} ({sum(1 for v in found.values() if v['path'])} verified tools)")
    cfg = load_config(args.config)
    rows = []
    for e in sorted(load_registry(cfg), key=lambda e: (e.get("category", ""), e["name"])):
        if args.category and e.get("category") != args.category:
            continue
        st = tool_status(e, cfg, offline=bool(cfg.get("network.offline")))
        rows.append([e["name"], e.get("category"), e.get("profile"), e.get("maintenance"), "yes" if st.installed else "no",
                     (st.version or "")[:30], ",".join(e.get("api_env", []) or []), "SELECTED" if st.selected else st.reason[:60]])
    _table(rows, ["tool", "category", "profile", "maintenance", "installed", "version", "api env", "selection"])
    if args.json:
        _print([{**e, "status": tool_status(e, cfg).as_dict()} for e in load_registry(cfg)])


def cmd_dashboard(args):
    """One command: start API + dashboard (+ scheduler) and open the browser."""
    import threading
    import webbrowser

    import uvicorn

    from .api.app import create_app

    cfg = load_config(args.config)
    host = getattr(args, "host", None) or cfg.get("api.host")
    port = int(getattr(args, "port", None) or cfg.get("api.port"))
    app = create_app(cfg, with_scheduler=not getattr(args, "no_scheduler", False), bind_host=host)
    if host in ("0.0.0.0", "::") and not os.environ.get(cfg.get("api.token_env", "RECONFORGE_API_TOKEN") or ""):
        print("  WARNING: listening on all interfaces without RECONFORGE_API_TOKEN; only localhost Host headers are accepted.",
              flush=True)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}"
    print(f"ReconForge dashboard: {url}", flush=True)
    print(f"  config:   {cfg.path or 'none (defaults; data in ~/.reconforge)'}", flush=True)
    print(f"  database: {cfg.database_url}", flush=True)
    print("  Add a target on the Scanner page, confirm authorization, and press Run. Ctrl+C to stop.", flush=True)
    if not getattr(args, "no_browser", False):
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")


def cmd_serve(args):
    import uvicorn

    from .api.app import create_app

    cfg = load_config(args.config)
    app = create_app(cfg, with_scheduler=args.with_scheduler, bind_host=args.host or cfg.get("api.host"))
    uvicorn.run(app, host=args.host or cfg.get("api.host"), port=int(args.port or cfg.get("api.port")), log_level="info")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconforge", description="ReconForge — attack surface intelligence platform")
    p.add_argument("-c", "--config", help="config file (default: $RECONFORGE_CONFIG or config/reconforge.yaml)")
    p.add_argument("--host", dest="top_host", help="dashboard host when no subcommand is given")
    p.add_argument("--port", dest="top_port", type=int, help="dashboard port when no subcommand is given")
    p.add_argument("--no-browser", dest="top_no_browser", action="store_true", help="don't open a browser (no subcommand)")
    sub = p.add_subparsers(dest="cmd", required=False)

    x = sub.add_parser("dashboard", help="start the dashboard and open it in the browser (default command)")
    x.add_argument("--host")
    x.add_argument("--port", type=int)
    x.add_argument("--no-browser", action="store_true")
    x.add_argument("--no-scheduler", action="store_true")
    x.set_defaults(fn=cmd_dashboard)

    x = sub.add_parser("init", help="create config and database")
    x.add_argument("--force", action="store_true")
    x.set_defaults(fn=cmd_init)

    x = sub.add_parser("scan", help="run reconnaissance against a configured target")
    x.add_argument("target")
    x.add_argument("-p", "--profile", help="passive|standard|comprehensive|continuous|<custom>")
    x.add_argument("--modules", help="comma list replacing the profile's modules")
    x.add_argument("--add", help="comma list of modules to add")
    x.add_argument("--skip", help="comma list of modules to skip")
    g = x.add_mutually_exclusive_group()
    g.add_argument("--incremental", dest="incremental", action="store_true", default=None)
    g.add_argument("--full", dest="incremental", action="store_false")
    x.add_argument("--no-report", action="store_true")
    x.add_argument("--notify", action="store_true", help="force notifications for this scan")
    x.add_argument("--no-notify", action="store_true")
    x.add_argument("--ai", action="store_true", help="run AI analysis for this scan")
    x.add_argument("-v", "--verbose", action="store_true")
    x.set_defaults(fn=cmd_scan)

    x = sub.add_parser("scans", help="scan execution history")
    x.add_argument("--target")
    x.add_argument("--limit", type=int, default=30)
    x.set_defaults(fn=cmd_scans)

    x = sub.add_parser("show", help="scan summary")
    x.add_argument("scan_id")
    x.add_argument("--json", action="store_true", help="full structured data")
    x.set_defaults(fn=cmd_show)

    x = sub.add_parser("changes", help="changes detected by a scan")
    x.add_argument("scan_id")
    x.set_defaults(fn=cmd_changes)

    x = sub.add_parser("diff", help="compare any two scans")
    x.add_argument("scan_a")
    x.add_argument("scan_b")
    x.set_defaults(fn=cmd_diff)

    x = sub.add_parser("report", help="(re)generate reports")
    x.add_argument("scan_id")
    x.add_argument("--formats", help="markdown,html,json,csv,pdf")
    x.add_argument("--disable", help="comma list of sections to disable")
    x.add_argument("--enable", help="comma list of sections to enable")
    x.add_argument("--out")
    x.set_defaults(fn=cmd_report)

    x = sub.add_parser("notify", help="send change notifications for a scan")
    x.add_argument("scan_id")
    x.add_argument("--channels", help="email,telegram,discord,slack")
    x.set_defaults(fn=cmd_notify)

    x = sub.add_parser("analyze", help="AI-assisted analysis of a scan")
    x.add_argument("scan_id")
    x.add_argument("--provider", choices=["anthropic", "heuristic"])
    x.set_defaults(fn=cmd_analyze)

    x = sub.add_parser("graph", help="export the relationship graph")
    x.add_argument("target")
    x.add_argument("--format", choices=["dot", "graphml", "json"], default="dot")
    x.add_argument("--types", help="comma list of asset types to include")
    x.add_argument("--out")
    x.set_defaults(fn=cmd_graph)

    x = sub.add_parser("assets", help="asset inventory")
    x.add_argument("target")
    x.add_argument("--type")
    x.add_argument("--search")
    x.add_argument("--all", action="store_true", help="include removed assets")
    x.set_defaults(fn=cmd_assets)

    x = sub.add_parser("fp", help="mark/unmark an asset or finding as false positive")
    x.add_argument("asset_id")
    x.add_argument("--reason")
    x.add_argument("--unset", action="store_true")
    x.set_defaults(fn=cmd_fp)

    x = sub.add_parser("history", help="historical states and observations of an asset")
    x.add_argument("asset_id")
    x.set_defaults(fn=cmd_history)

    x = sub.add_parser("schedule", help="manage scan schedules")
    x.add_argument("action", choices=["add", "list", "remove", "enable", "disable"])
    x.add_argument("--name")
    x.add_argument("--target")
    x.add_argument("--frequency", default="daily", help="once|hourly|daily|weekly|monthly|cron")
    x.add_argument("--cron", help="5-field cron expression (UTC) for --frequency cron")
    x.add_argument("--at", default="02:00", help="HH:MM UTC")
    x.add_argument("--day", help="weekday for weekly (mon..sun) or day-of-month for monthly")
    x.add_argument("--profile", default="continuous")
    x.add_argument("--full", action="store_true", help="non-incremental scans")
    x.set_defaults(fn=cmd_schedule)

    x = sub.add_parser("scheduler", help="run the scheduler")
    x.add_argument("action", choices=["run", "tick", "sync"])
    x.add_argument("--interval", type=int, default=30)
    x.set_defaults(fn=cmd_scheduler)

    x = sub.add_parser("db", help="backup / export / import / retention")
    x.add_argument("action", choices=["backup", "export", "import", "retention"])
    x.add_argument("--path")
    x.add_argument("--target")
    x.add_argument("--days", type=int)
    x.add_argument("--keep", type=int)
    x.add_argument("--dry-run", action="store_true")
    x.set_defaults(fn=cmd_db)

    x = sub.add_parser("modules", help="list modules, tool availability and profiles")
    x.set_defaults(fn=cmd_modules)

    x = sub.add_parser("tools", help="tool registry: installation, credentials, selection status")
    x.add_argument("--category")
    x.add_argument("--json", action="store_true")
    x.add_argument("--detect", action="store_true", help="find installed tools, verify them, record absolute paths")
    x.set_defaults(fn=cmd_tools)

    x = sub.add_parser("serve", help="start the dashboard/API server")
    x.add_argument("--host")
    x.add_argument("--port", type=int)
    x.add_argument("--with-scheduler", action="store_true", help="also run the scheduler in the server process")
    x.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "cmd", None):
        args.fn = cmd_dashboard  # `reconforge` with no subcommand opens the dashboard
        args.host, args.port, args.no_browser = args.top_host, args.top_port, args.top_no_browser
    try:
        return args.fn(args) or 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if getattr(args, "verbose", False):
            raise
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
