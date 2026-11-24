"""FastAPI backend for the ReconForge dashboard.

Read-mostly API. The only write operations are analyst actions on ReconForge's own data
(false-positive flags, schedules, triggering a scan of a *configured* target, regenerating
reports / AI analysis). The dashboard never sends requests to discovered endpoints.

Binds to 127.0.0.1 by default. If $RECONFORGE_API_TOKEN (or api.token_env) is set, every
/api request must carry `Authorization: Bearer <token>` (or `?token=` for downloads).
"""
from __future__ import annotations

import hmac
import logging
import os
import re
import threading
from urllib.parse import urlsplit
from collections import Counter, defaultdict
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select

from ..config import Config
from ..db import Database
from ..db.models import (AIAnalysis, Asset, AssetScore, AssetState, Change, Evidence, ModuleRun, NotificationLog,
                         Relation, Report, Scan, Schedule, Target)
from ..graph.build import build_graph, to_cytoscape, to_dot, to_graphml
from ..reports.data import build_report_data
from ..util import iso

STATIC = Path(__file__).resolve().parent / "static"


def _asset(a: Asset, score: AssetScore | None = None) -> dict:
    d = {"id": a.id, "type": a.type, "key": a.key, "display": a.display, "scope": a.scope,
         "confidence": round(a.confidence or 0, 2), "status": a.status, "first_seen": iso(a.first_seen),
         "last_seen": iso(a.last_seen), "sources": [x["source"] for x in a.sources or []],
         "false_positive": a.false_positive, "fp_reason": a.fp_reason,
         "evidence": (a.attributes or {}).get("_last_evidence"),
         "attributes": {k: v for k, v in (a.attributes or {}).items() if not k.startswith("_")}}
    if score is not None:
        d["priority"] = {"score": score.score, "tier": score.tier, "factors": score.factors}
    return d


class FPBody(BaseModel):
    false_positive: bool = True
    reason: str | None = None


class ScheduleBody(BaseModel):
    name: str
    target: str
    frequency: str = "daily"
    at: str = "02:00"
    day: str | None = None
    cron: str | None = None
    profile: str = "continuous"
    incremental: bool = True
    enabled: bool = True


class ScanBody(BaseModel):
    target: str
    profile: str | None = None
    incremental: bool | None = None
    modules: list[str] | None = None


class TargetBody(BaseModel):
    name: str
    targets: list[str] | None = None        # mixed: domains, IPs, CIDR ranges, URLs
    root_domains: list[str] = []
    ip_targets: list[str] = []
    profile: str | None = "standard"
    authorization: dict = {}
    scope: dict = {}
    ports: list[int] | None = None
    probe_ports: dict | None = None


class ActionBody(BaseModel):
    target: str
    action_id: str


class AnalyzeBody(BaseModel):
    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    consent: bool = False


class ImportBody(BaseModel):
    answer: str
    label: str | None = "manual import"


class KeysBody(BaseModel):
    keys: dict[str, str] = {}
    clear: list[str] = []


class NotifyBody(BaseModel):
    enabled: bool | None = None
    min_significance: str | None = None
    channels: dict[str, dict] = {}


class TriageBody(BaseModel):
    status: str
    note: str | None = None
    ids: list[str] | None = None   # bulk update (the path id is included too)


TRIAGE_STATES = ["new", "investigating", "confirmed", "false_positive", "accepted_risk", "fixed"]
SEV_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 3}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "testserver"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
log = logging.getLogger("reconforge.api")
_PATH_RULES: list[tuple[re.Pattern, bytes]] = []


def _path_rule(path: str, replacement: bytes) -> tuple[re.Pattern, bytes] | None:
    path = str(path).rstrip("/")
    if len(path) <= 1:
        return None
    # case-insensitive: on macOS/Windows the same folder can be reached (and recorded in older scans) as
    # "ReconForge" or "reconforge"; over-hiding a path is harmless, leaking one is not
    return re.compile(re.escape(path.encode()) + rb"(?=[/\"\\\s:]|$)", re.IGNORECASE), replacement


def set_hidden_paths(project_dir: str | None) -> None:
    """Paths inside the project are shown relative ('.'), anything else under the home directory as '~'."""
    rules = [_path_rule(os.path.realpath(project_dir), b".") if project_dir else None,
             _path_rule(project_dir, b".") if project_dir else None,
             _path_rule(os.path.expanduser("~"), b"~")]
    _PATH_RULES[:] = [r for r in rules if r]


set_hidden_paths(None)


def hide_home(data: bytes) -> bytes:
    """Strip the operator's account and folder names from paths in API output (project -> '.', home -> '~')."""
    for rx, repl in _PATH_RULES:
        data = rx.sub(repl, data)
    return data


class SafeJSONResponse(JSONResponse):
    def render(self, content) -> bytes:
        return hide_home(super().render(content))


def create_app(cfg: Config, with_scheduler: bool = False, bind_host: str | None = None) -> FastAPI:
    db = Database(cfg.database_url)
    set_hidden_paths(str(cfg.base_dir) if cfg.path else None)
    app = FastAPI(title="ReconForge", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
                  default_response_class=SafeJSONResponse)
    from fastapi.exceptions import HTTPException as _FastHTTPException
    from starlette.exceptions import HTTPException as _StarletteHTTPException

    @app.exception_handler(_StarletteHTTPException)
    async def _http_error(request: Request, exc: _StarletteHTTPException):
        return SafeJSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    assert issubclass(_FastHTTPException, _StarletteHTTPException)
    app.add_middleware(GZipMiddleware, minimum_size=2000)
    token = os.environ.get(cfg.get("api.token_env", "RECONFORGE_API_TOKEN") or "", "")
    from ..settings import apply_api_keys

    apply_api_keys(cfg)  # API keys saved in the dashboard reach providers and external tools
    allowed_hosts = set(LOOPBACK) | {h.strip().lower() for h in (cfg.get("api.allowed_hosts") or []) if h.strip()}
    allowed_hosts |= {h.strip().lower() for h in os.environ.get("RECONFORGE_ALLOWED_HOSTS", "").split(",") if h.strip()}
    if bind_host and bind_host not in ("0.0.0.0", "::"):
        allowed_hosts.add(bind_host.lower())

    def _hostname(value: str) -> str:
        value = (value or "").strip().lower()
        if value.startswith("["):
            return value[1:].split("]")[0]
        return value.rsplit(":", 1)[0] if value.count(":") == 1 else value

    @app.middleware("http")
    async def security(request: Request, call_next):
        """DNS-rebinding and cross-site request protection plus security headers on every response."""
        host = _hostname(request.headers.get("host", ""))
        if not token and host not in allowed_hosts:
            return JSONResponse({"detail": f"host '{host}' not allowed (set api.allowed_hosts or RECONFORGE_API_TOKEN)"},
                                status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin != "null" and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
            if origin == "null":
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        try:
            response = await call_next(request)
        except Exception as exc:  # never leak a stack trace or break the UI with an HTML 500
            log.exception("unhandled API error on %s %s", request.method, request.url.path)
            response = JSONResponse({"detail": f"internal error ({type(exc).__name__}); see the server log"}, status_code=500)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        if not request.url.path.startswith(("/api/docs", "/api/redoc")):
            h.setdefault("Content-Security-Policy", CSP)
        if request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
        return response
    from ..runs import RunManager

    manager = RunManager(cfg, db)
    from ..installer import InstallManager

    install_manager = InstallManager()
    app.state.manager = manager
    running: dict[str, str] = {}

    def auth(request: Request):
        if not token:
            return
        hdr = request.headers.get("authorization", "")
        supplied = hdr[7:] if hdr.startswith("Bearer ") else request.query_params.get("token", "")
        if supplied and hmac.compare_digest(supplied.encode(), token.encode()):
            return
        raise HTTPException(401, "missing or invalid API token")

    def target_id(s, name: str) -> str:
        t = s.execute(select(Target).where(Target.name == name)).scalar_one_or_none()
        if t is None:
            from ..targets import resolve_target

            if not resolve_target(cfg, db, name):
                raise HTTPException(404, f"scan '{name}' not found")
            # defined (e.g. in the config file) but never run yet: register it so every view shows "no scans"
            from ..core.pipeline import ensure_target

            return ensure_target(db, cfg, name)[0]
        return t.id

    def latest_scan(s, tid: str) -> Scan | None:
        # Single-item runs from "Tools & commands" are not full scans; views use the latest full scan.
        # Until a target's first scan finishes, views show what the running scan has committed so far.
        def newest(statuses):
            return s.execute(select(Scan).where(Scan.target_id == tid, Scan.status.in_(statuses),
                                                Scan.trigger != "dashboard-action")
                             .order_by(Scan.started_at.desc()).limit(1)).scalar_one_or_none()
        return newest(["completed", "partial"]) or newest(["running", "cancelled", "failed"])

    A = Depends(auth)

    # ---------------------------------------------------------------- meta
    @app.get("/api/meta", dependencies=[A])
    def meta():
        from ..core.module import load_modules

        reg = load_modules(cfg.get("plugins", []))
        from ..targets import list_targets

        defined = {t["name"]: t for t in list_targets(cfg, db)}
        with db.session() as s:
            rows = {t.name: t for t in s.execute(select(Target).order_by(Target.name)).scalars()}
            scan_counts = dict(s.execute(select(Scan.target_id, func.count()).group_by(Scan.target_id)).all())
        targets = []
        for name in sorted(set(defined) | {n for n, r in rows.items() if (r.config or {}).get("source") != "deleted"}):
            t = defined.get(name) or rows[name].config or {}
            row = rows.get(name)
            targets.append({"name": name, "id": row.id if row else None, "root_domains": t.get("root_domains", []),
                            "ip_targets": t.get("ip_targets", []),
                            "profile": t.get("profile"), "source": t.get("source", "config"),
                            "authorized": bool((t.get("authorization") or {}).get("confirmed")),
                            "authorization_reference": (t.get("authorization") or {}).get("reference"),
                            "scope": t.get("scope", {}), "scans": scan_counts.get(row.id, 0) if row else 0,
                            "runnable": name in defined})
        configured = sorted(defined)
        return {"targets": targets, "configured_targets": configured,
                "profiles": {k: {"description": v.get("description"), "modules": v.get("modules", [])} for k, v in cfg.get("profiles").items()},
                "modules": [{"name": n, "phase": c.phase, "active": c.active, "description": c.description}
                            for n, c in sorted(reg.items(), key=lambda kv: kv[1].order())],
                "auth": bool(token), "running": {r.target: r.scan_id for r in manager.active()},
                "offline": bool(cfg.get("network.offline"))}

    # ------------------------------------------------------------- targets
    @app.post("/api/targets", dependencies=[A])
    def create_target(body: TargetBody):
        from ..targets import save_target

        try:
            return save_target(cfg, db, body.model_dump())
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/targets/{name}/definition", dependencies=[A])
    def target_definition(name: str):
        from ..targets import resolve_target

        t = resolve_target(cfg, db, name)
        if not t:
            raise HTTPException(404)
        return {**t, "source": t.get("source", "config")}

    @app.delete("/api/targets/{name}", dependencies=[A])
    def remove_target(name: str):
        from ..targets import delete_target

        try:
            delete_target(cfg, db, name)
        except (ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc))
        return {"deleted": name}

    # ------------------------------------------------------------ overview
    @app.get("/api/targets/{name}/overview", dependencies=[A])
    def overview(name: str):
        with db.session() as s:
            tid = target_id(s, name)
            sc = latest_scan(s, tid)
            if sc is None:
                return {"scan": None}
            d = build_report_data(s, sc.id)
            scans = list(s.execute(select(Scan).where(Scan.target_id == tid).order_by(Scan.started_at)).scalars())
            trend = []
            for x in scans[-30:]:
                summ = x.summary or {}
                trend.append({"scan": x.id, "started_at": iso(x.started_at), "status": x.status,
                              "assets": sum((summ.get("asset_counts") or {}).values()), "changes": summ.get("changes", 0),
                              "subdomains": (summ.get("asset_counts") or {}).get("subdomain", 0),
                              "web_apps": (summ.get("asset_counts") or {}).get("web_app", 0),
                              "findings": (summ.get("asset_counts") or {}).get("finding", 0)})
            changes_by_cat = Counter(c.category for c in s.execute(select(Change).where(Change.target_id == tid)).scalars())
        return {"scan": d["scan"], "overview": d["overview"], "priorities": d["priorities"][:10],
                "changes": d["changes"][:15], "coverage_gaps": d["coverage_gaps"], "trend": trend,
                "change_categories_all_time": dict(changes_by_cat), "priority_disclaimer": d["priority_disclaimer"]}

    # -------------------------------------------------------------- assets
    @app.get("/api/targets/{name}/assets", dependencies=[A])
    def assets(name: str, type: str | None = None, q: str | None = None, scope: str | None = None,
               status: str = "active", include_fp: bool = True, limit: int = Query(2000, le=10000)):
        with db.session() as s:
            tid = target_id(s, name)
            sc = latest_scan(s, tid)
            stmt = select(Asset).where(Asset.target_id == tid)
            if type:
                stmt = stmt.where(Asset.type.in_(type.split(",")))
            if scope:
                stmt = stmt.where(Asset.scope == scope)
            if status != "all":
                stmt = stmt.where(Asset.status == status)
            if not include_fp:
                stmt = stmt.where(Asset.false_positive.is_(False))
            if q:
                stmt = stmt.where(Asset.key.ilike(f"%{q}%") | Asset.display.ilike(f"%{q}%"))
            rows = list(s.execute(stmt.order_by(Asset.type, Asset.key).limit(limit)).scalars())
            scores = {x.asset_id: x for x in s.execute(select(AssetScore).where(AssetScore.scan_id == sc.id)).scalars()} if sc else {}
            return [_asset(a, scores.get(a.id)) for a in rows]

    @app.get("/api/targets/{name}/inventory", dependencies=[A])
    def inventory(name: str):
        """One row per in-scope host, joined across DNS, IP/ASN, HTTP, ports, TLS and technologies."""
        with db.session() as s:
            tid = target_id(s, name)
            sc = latest_scan(s, tid)
            if sc is None:
                return []
            d = build_report_data(s, sc.id)
        ips = {i["key"]: i for i in d["ips"]}
        apps_by_host = defaultdict(list)
        for a in d["web_apps"]:
            apps_by_host[a["attributes"].get("host")].append(a)
        svc_by_ip = defaultdict(list)
        for sv in d["services"]:
            svc_by_ip[sv["ip"]].append(sv)
        rows = []
        for h in d["hosts"]:
            apps = apps_by_host.get(h["key"], [])
            hip = [ips[i] for i in h["ips"] if i in ips]
            rows.append({
                "id": h["id"], "domain": "IP target" if h["type"] == "ip" else next((r for r in d["target"]["root_domains"] if h["key"] == r or h["key"].endswith("." + r)), ""),
                "host": h["key"], "type": h["type"], "scope": h["scope"], "resolved": h["resolved"], "ips": h["ips"],
                "http_status": [f"{a['key']} → {a['status']}" for a in apps],
                "open_ports": sorted({sv["port"] for ip in h["ips"] for sv in svc_by_ip.get(ip, [])}),
                "technologies": sorted({f"{n} {v}".strip() for a in apps for n, v in a["technologies"].items()}),
                "hosting": sorted({i.get("provider") or "" for i in hip} - {""}),
                "asn": sorted({i.get("asn") or "" for i in hip} - {""}),
                "cdn_waf": sorted({x for a in apps for x in (a["cdn"], a["waf"]) if x} | {i.get("cdn") for i in hip if i.get("cdn")}),
                "tls": [{"app": a["key"], **(a["tls"] or {})} for a in apps if a.get("tls")],
                "last_seen": h["last_seen"], "first_seen": h["first_seen"], "discovered_via": h["discovered_via"],
                "cname": h["cname"], "confidence": h["confidence"],
            })
        return rows

    @app.get("/api/targets/{name}/report-data", dependencies=[A])
    def report_data(name: str, scan_id: str | None = None):
        with db.session() as s:
            tid = target_id(s, name)
            sc = s.get(Scan, scan_id) if scan_id else latest_scan(s, tid)
            if sc is None:
                raise HTTPException(404, "no scans")
            return build_report_data(s, sc.id)

    @app.get("/api/targets/{name}/findings-report", dependencies=[A])
    def findings_report(name: str, format: str = "html", scan_id: str | None = None):
        """A focused, downloadable report of security findings and CVE correlations (html | pdf)."""
        from ..reports.findings import findings_html, findings_pdf

        if format not in ("html", "pdf"):
            raise HTTPException(400, "format must be html or pdf")
        with db.session() as s:
            tid = target_id(s, name)
            sc = s.get(Scan, scan_id) if scan_id else latest_scan(s, tid)
            if sc is None:
                raise HTTPException(404, "no scans")
            data = build_report_data(s, sc.id)
        stamp = (data["scan"].get("started_at") or "")[:10]
        fname = f"reconforge-findings-{name}-{stamp}.{format}"
        if format == "pdf":
            return Response(findings_pdf(data), media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{fname}"'})
        return HTMLResponse(findings_html(data), headers={"Content-Disposition": f'inline; filename="{fname}"'})

    @app.get("/api/assets/{asset_id}", dependencies=[A])
    def asset_detail(asset_id: str):
        from ..storage.maintenance import asset_history

        with db.session() as s:
            a = s.get(Asset, asset_id)
            if a is None:
                raise HTTPException(404)
            rels = list(s.execute(select(Relation).where((Relation.src_id == asset_id) | (Relation.dst_id == asset_id))).scalars())
            others = {x.id: x for x in s.execute(select(Asset).where(Asset.id.in_({r.src_id for r in rels} | {r.dst_id for r in rels}))).scalars()}
            related = [{"relation": r.type, "direction": "out" if r.src_id == asset_id else "in", "confirmed": r.confirmed,
                        "confidence": r.confidence, "sources": r.sources, "evidence_ids": r.evidence_ids,
                        "asset": _asset(others[r.dst_id if r.src_id == asset_id else r.src_id])}
                       for r in rels if (r.dst_id if r.src_id == asset_id else r.src_id) in others]
            base = _asset(a)
        hist = asset_history(db, asset_id)
        return {**base, "related": related, "history": hist}

    @app.post("/api/assets/{asset_id}/false-positive", dependencies=[A])
    def mark_fp(asset_id: str, body: FPBody):
        with db.session() as s:
            a = s.get(Asset, asset_id)
            if a is None:
                raise HTTPException(404)
            a.false_positive = body.false_positive
            a.fp_reason = body.reason if body.false_positive else None
            return _asset(a)

    # ------------------------------------------------------------ evidence
    @app.get("/api/evidence/{evidence_id}", dependencies=[A])
    def evidence(evidence_id: str, raw: bool = False):
        with db.session() as s:
            e = s.get(Evidence, evidence_id)
            if e is None:
                raise HTTPException(404)
            if raw or (e.path and e.kind == "screenshot"):
                if e.path and Path(e.path).exists():
                    media = "image/png" if e.path.endswith(".png") else "text/plain; charset=utf-8"
                    return FileResponse(e.path, media_type=media)
                return PlainTextResponse(e.content or "")
            return {"id": e.id, "scan_id": e.scan_id, "module": e.module, "kind": e.kind, "summary": e.summary,
                    "sha256": e.sha256, "created_at": iso(e.created_at), "has_file": bool(e.path),
                    "content": (e.content or "")[:200000]}

    # --------------------------------------------------------------- scans
    @app.get("/api/scans", dependencies=[A])
    def scans(target: str | None = None, limit: int = 100):
        with db.session() as s:
            stmt = select(Scan, Target).join(Target).order_by(Scan.started_at.desc()).limit(limit)
            if target:
                stmt = stmt.where(Target.name == target)
            out = []
            for sc, t in s.execute(stmt).all():
                runs = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == sc.id)).scalars())
                out.append({"id": sc.id, "target": t.name, "profile": sc.profile, "status": sc.status, "trigger": sc.trigger,
                            "incremental": sc.incremental, "started_at": iso(sc.started_at), "finished_at": iso(sc.finished_at),
                            "duration_seconds": sc.duration_seconds, "modules_planned": sc.modules_planned,
                            "modules_completed": sc.modules_completed, "modules_failed": sc.modules_failed,
                            "modules_skipped": sc.modules_skipped, "tools_executed": sc.tools_executed,
                            "results_count": sc.results_count, "report_dir": sc.report_dir, "log_path": sc.log_path,
                            "changes": (sc.summary or {}).get("changes", 0), "error": sc.error,
                            "module_runs": [{"module": r.module, "tool": r.tool, "status": r.status, "observations": r.observations,
                                             "started_at": iso(r.started_at), "finished_at": iso(r.finished_at),
                                             "reason": r.skip_reason or r.error, "command": r.command,
                                             "skipped_inputs": len(r.skipped_inputs or [])} for r in runs]})
            return out

    @app.get("/api/scans/{scan_id}/log", dependencies=[A])
    def scan_log(scan_id: str, module: str | None = None, download: bool = False):
        """Execution log. `module` keeps only that module's lines (all passes); `download` returns the full file."""
        with db.session() as s:
            sc = s.get(Scan, scan_id)
            if sc is None or not sc.log_path or not Path(sc.log_path).exists():
                raise HTTPException(404)
            log_path = Path(sc.log_path)
        if download:
            return FileResponse(log_path, media_type="text/plain", filename=f"reconforge-{scan_id}.log")
        text = log_path.read_text(errors="replace")
        if module:
            tag = re.compile(r"\[" + re.escape(module) + r"(#\d+)?\]")
            text = "\n".join(l for l in text.splitlines() if tag.search(l))
            return PlainTextResponse(hide_home(text[-2_000_000:].encode()))
        return PlainTextResponse(hide_home(text[-400000:].encode()))

    @app.get("/api/scans/{scan_id}/reports", dependencies=[A])
    def scan_reports(scan_id: str):
        with db.session() as s:
            return [{"id": r.id, "format": r.format, "name": Path(r.path).name, "created_at": iso(r.created_at)}
                    for r in s.execute(select(Report).where(Report.scan_id == scan_id).order_by(Report.id.desc())).scalars()]

    @app.get("/api/reports/{report_id}", dependencies=[A])
    def report_file(report_id: int):
        with db.session() as s:
            r = s.get(Report, report_id)
            if r is None or not Path(r.path).exists():
                raise HTTPException(404)
            media = {"html": "text/html", "pdf": "application/pdf", "json": "application/json", "csv": "text/csv",
                     "markdown": "text/markdown"}.get(r.format, "application/octet-stream")
            return FileResponse(r.path, media_type=media, filename=None if r.format == "html" else Path(r.path).name)

    @app.post("/api/scans", dependencies=[A])
    def start_scan(body: ScanBody):
        from ..core.pipeline import ScanOptions
        from ..scope import ScopeError

        opts = ScanOptions(target=body.target, profile=body.profile, incremental=body.incremental,
                           modules=body.modules or None, trigger="dashboard")
        try:
            info = manager.start(opts, label=f"{body.profile or 'default'} scan", kind="scan")
        except (ValueError, KeyError, ScopeError) as exc:
            raise HTTPException(400, str(exc).strip("'\""))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        return run_dict(info)

    def run_dict(r) -> dict:
        return {"scan_id": r.scan_id, "target": r.target, "label": r.label, "kind": r.kind, "status": r.status,
                "error": r.error, "started_at": r.started_at, "finished_at": r.finished_at}

    @app.get("/api/runs", dependencies=[A])
    def runs():
        return sorted((run_dict(r) for r in manager.runs.values()), key=lambda r: r["started_at"], reverse=True)

    @app.post("/api/scans/{scan_id}/cancel", dependencies=[A])
    def cancel_scan(scan_id: str):
        if not manager.cancel(scan_id):
            raise HTTPException(409, "scan is not running in this server")
        return {"cancelling": scan_id}

    @app.get("/api/scans/{scan_id}/progress", dependencies=[A])
    def progress(scan_id: str):
        run = manager.runs.get(scan_id)
        with db.session() as s:
            sc = s.get(Scan, scan_id)
            if sc is None:
                if run:
                    return {"scan_id": scan_id, "status": run.status, "error": run.error, "modules": [], "planned": []}
                raise HTTPException(404)
            mruns = list(s.execute(select(ModuleRun).where(ModuleRun.scan_id == scan_id).order_by(ModuleRun.id)).scalars())
            counts = dict(s.execute(select(Asset.type, func.count()).where(Asset.target_id == sc.target_id,
                                                                           Asset.status == "active").group_by(Asset.type)).all())
            target = s.get(Target, sc.target_id).name
            return {"scan_id": scan_id, "target": target, "status": run.status if run and run.status in ("starting", "running") else sc.status,
                    "db_status": sc.status, "error": (run.error if run else None) or sc.error, "profile": sc.profile,
                    "started_at": iso(sc.started_at), "finished_at": iso(sc.finished_at), "duration_seconds": sc.duration_seconds,
                    "planned": sc.modules_planned,
                    "modules": [{"module": r.module, "status": r.status, "observations": r.observations, "tool": r.tool,
                                 "reason": r.skip_reason or r.error, "started_at": iso(r.started_at),
                                 "finished_at": iso(r.finished_at)} for r in mruns],
                    "asset_counts": counts, "changes": (sc.summary or {}).get("changes"),
                    "coverage": ((sc.summary or {}).get("coverage") or {}).get("statement")}

    @app.get("/api/scans/{scan_id}/stream", dependencies=[A])
    async def stream(scan_id: str, request: Request):
        import asyncio
        import json as _json

        from fastapi.responses import StreamingResponse

        path = cfg.dir("logs_dir") / f"{scan_id}.log"

        async def gen():
            pos, buf, waited = 0, "", 0.0
            while True:
                if await request.is_disconnected():
                    return
                chunk = ""
                if path.exists():
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        chunk = fh.read()
                        pos = fh.tell()
                buf += chunk
                *lines, buf = buf.split("\n")
                for line in lines:
                    if line:
                        yield f"data: {_json.dumps(line)}\n\n"
                run = manager.runs.get(scan_id)
                done = run is None or run.status not in ("starting", "running")
                if done and not chunk:
                    if buf:
                        yield f"data: {_json.dumps(buf)}\n\n"
                    yield f"event: done\ndata: {_json.dumps(run.status if run else 'finished')}\n\n"
                    return
                if not path.exists():
                    waited += 0.4
                    if waited > 30:
                        yield "event: done\ndata: \"no log\"\n\n"
                        return
                await asyncio.sleep(0.4)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------ module output
    from . import exports as X

    def _scan_or_404(s, scan_id: str) -> Scan:
        sc = s.get(Scan, scan_id)
        if sc is None:
            raise HTTPException(404, "unknown scan")
        return sc

    def _download(body: str, fmt: str, fname: str, inline: bool = False) -> Response:
        disp = "inline" if inline else "attachment"
        return Response(body, media_type=X.FORMATS[fmt], headers={"Content-Disposition": f'{disp}; filename="{fname}"'})

    @app.get("/api/scans/{scan_id}/modules", dependencies=[A])
    def scan_modules(scan_id: str):
        """Per-module summary of one scan: status, timing, results by asset type, evidence and log volume."""
        with db.session() as s:
            sc = _scan_or_404(s, scan_id)
            run = manager.runs.get(scan_id)
            return {"scan_id": sc.id, "target": s.get(Target, sc.target_id).name, "profile": sc.profile,
                    "status": run.status if run and run.status in ("starting", "running") else sc.status,
                    "started_at": iso(sc.started_at), "modules": X.module_summaries(s, sc)}

    @app.get("/api/scans/{scan_id}/modules/{module}", dependencies=[A])
    def scan_module_output(scan_id: str, module: str, limit: int = Query(2000, le=20000)):
        with db.session() as s:
            return X.module_output(s, _scan_or_404(s, scan_id), module, obs_limit=limit)

    @app.get("/api/scans/{scan_id}/modules/{module}/export", dependencies=[A])
    def scan_module_export(scan_id: str, module: str, format: str = "json"):
        if format not in ("json", "csv", "txt"):
            raise HTTPException(400, "format must be json, csv or txt")
        with db.session() as s:
            out = X.module_output(s, _scan_or_404(s, scan_id), module, full=True)
        return _download(X.module_bundle(out, format), format, f"reconforge-{scan_id}-{module}.{format}")

    @app.get("/api/scans/{scan_id}/modules-export", dependencies=[A])
    def scan_modules_export(scan_id: str):
        """Every module's output for one scan in a single zip (json + txt per module, plus the full log)."""
        import io
        import zipfile

        buf = io.BytesIO()
        with db.session() as s:
            sc = _scan_or_404(s, scan_id)
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for m in X.module_summaries(s, sc):
                    out = X.module_output(s, sc, m["module"], full=True)
                    z.writestr(f"{m['module']}/{m['module']}.json", X.module_bundle(out, "json"))
                    z.writestr(f"{m['module']}/{m['module']}.txt", X.module_bundle(out, "txt"))
                    if out["observations"]:
                        z.writestr(f"{m['module']}/{m['module']}.csv", X.module_bundle(out, "csv"))
                if sc.log_path and Path(sc.log_path).exists():
                    z.write(sc.log_path, "execution.log")
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="reconforge-{scan_id}-modules.zip"'})

    # ------------------------------------------------- Burp Suite scope
    @app.get("/api/targets/{name}/burp-scope", dependencies=[A])
    def burp_scope(name: str):
        """Target scope as a Burp Suite project-options file (Settings > Project > Scope > Load)."""
        from ..targets import resolve_target

        t = resolve_target(cfg, db, name)
        if not t:
            raise HTTPException(404, "target not found")
        return _download(X.burp_scope_json(t), "json", f"reconforge-{name}-burp-scope.json")

    # ------------------------------------------------------ surface export
    @app.get("/api/export-surfaces", dependencies=[A])
    def export_surfaces():
        return {"surfaces": sorted(X.REPORT_SURFACES) + X.OTHER_SURFACES, "formats": ["csv", "json", "md"]}

    @app.get("/api/targets/{name}/export/{surface}", dependencies=[A])
    def export_surface(name: str, surface: str, format: str = "csv", scan_id: str | None = None):
        """Download any dashboard surface as CSV, JSON or Markdown (full data, not just the visible page)."""
        if format not in ("csv", "json", "md"):
            raise HTTPException(400, "format must be csv, json or md")
        if surface not in X.REPORT_SURFACES and surface not in X.OTHER_SURFACES:
            raise HTTPException(404, f"unknown surface '{surface}'")
        if surface == "inventory":
            data = inventory(name)
        elif surface == "changes":
            data = changes(name, limit=100000)
        elif surface == "scans":
            data = scans(target=name, limit=10000)
        elif surface == "tools":
            data = actions(target=name)
        elif surface == "graph":
            data = graph(name)
            if format != "json":
                data = data.get("nodes", []) if isinstance(data, dict) else data
        else:
            with db.session() as s:
                tid = target_id(s, name)
                sc = s.get(Scan, scan_id) if scan_id else latest_scan(s, tid)
                if sc is None:
                    raise HTTPException(404, "no scans")
                d = build_report_data(s, sc.id)
            data = d if surface == "full" else d.get(X.REPORT_SURFACES[surface], [])
            if surface == "full" and format != "json":
                raise HTTPException(400, "the full export is JSON only")
        return _download(X.render(data, format, f"{name} — {surface}"), format, f"reconforge-{name}-{surface}.{format}")

    # ------------------------------------------------------------ API keys
    @app.get("/api/settings/keys", dependencies=[A])
    def get_keys():
        from ..settings import public_api_keys

        return public_api_keys(cfg)

    @app.put("/api/settings/keys", dependencies=[A])
    def put_keys(body: KeysBody):
        from ..settings import save_api_keys

        try:
            return save_api_keys(cfg, body.keys, body.clear)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    # ------------------------------------------------------- notifications
    @app.get("/api/settings/notifications", dependencies=[A])
    def get_notify():
        from ..settings import public_notification_settings

        return public_notification_settings(cfg)

    @app.put("/api/settings/notifications", dependencies=[A])
    def put_notify(body: NotifyBody):
        from ..settings import save_notification_settings

        try:
            return save_notification_settings(cfg, body.model_dump(exclude_none=True))
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/settings/notifications/test/{channel}", dependencies=[A])
    def test_notify(channel: str):
        from ..settings import send_test_notification

        try:
            return {"channel": channel, "status": send_test_notification(cfg, channel)}
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except Exception as exc:  # report delivery problems without echoing secrets (URLs, tokens)
            raise HTTPException(502, f"{channel} delivery failed ({type(exc).__name__})")

    # -------------------------------------------------------- output files
    from .. import outputs as OUT

    def _scan_files_root(scan_id: str, refresh: bool = False) -> Path:
        with db.session() as s:
            sc = _scan_or_404(s, scan_id)
            root = OUT.scan_output_dir(cfg, s, sc)
            running = sc.status == "running"
        if refresh or not root.exists():
            if running and not refresh and not root.exists():
                raise HTTPException(409, "output files are written when the execution finishes; use Regenerate to build them now")
            OUT.write_scan_outputs(cfg, db, scan_id)
        return root

    @app.get("/api/scans/{scan_id}/files", dependencies=[A])
    def scan_files(scan_id: str, refresh: bool = False):
        root = _scan_files_root(scan_id, refresh)
        return {"scan_id": scan_id, "folder": root.name, "files": OUT.list_files(root)}

    @app.get("/api/scans/{scan_id}/files-zip", dependencies=[A])
    def scan_files_zip(scan_id: str):
        import io
        import zipfile

        root = _scan_files_root(scan_id)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in OUT.list_files(root):
                z.write(root / f["path"], f"{root.name}/{f['path']}")
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{root.name}.zip"'})

    @app.get("/api/scans/{scan_id}/files/{path:path}", dependencies=[A])
    def scan_file(scan_id: str, path: str, download: bool = False, head: int | None = Query(None, ge=1, le=20000)):
        root = _scan_files_root(scan_id)
        try:
            f = OUT.safe_file(root, path)
        except FileNotFoundError:
            raise HTTPException(404, "no such file")
        if f.suffix == ".png":
            return FileResponse(f, media_type="image/png", filename=f.name if download else None)
        if head and not download:
            with open(f, errors="replace") as fh:
                lines = [next(fh, None) for _ in range(head)]
            return PlainTextResponse(hide_home("".join(l for l in lines if l is not None).encode()))
        return FileResponse(f, media_type="text/plain; charset=utf-8", filename=f.name if download else None,
                            content_disposition_type="attachment" if download else "inline")

    # --------------------------------------------------------- screenshots
    def _screenshots(s, tid: str) -> list[dict]:
        apps = s.execute(select(Asset).where(Asset.target_id == tid, Asset.type == "web_app")).scalars()
        out = []
        for a in apps:
            at = a.attributes or {}
            ev = at.get("screenshot_evidence")
            if not ev:
                continue
            out.append({"asset_id": a.id, "url": a.key, "host": at.get("host"), "status": at.get("status"), "title": at.get("title"),
                        "server": at.get("server"), "evidence_id": ev, "phash": at.get("screenshot_phash"),
                        "active": a.status == "active", "last_seen": iso(a.last_seen),
                        "technologies": sorted((at.get("technologies") or {}).keys())[:8]})
        return sorted(out, key=lambda x: (not x["active"], x["url"]))

    @app.get("/api/targets/{name}/screenshots", dependencies=[A])
    def screenshots(name: str):
        with db.session() as s:
            return _screenshots(s, target_id(s, name))

    @app.get("/api/targets/{name}/screenshots-zip", dependencies=[A])
    def screenshots_zip(name: str):
        import io
        import zipfile

        buf = io.BytesIO()
        with db.session() as s:
            shots = _screenshots(s, target_id(s, name))
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
                for sh in shots:
                    e = s.get(Evidence, sh["evidence_id"])
                    if e and e.path and Path(e.path).exists():
                        z.write(e.path, OUT.slug(sh["url"].split("://", 1)[-1].replace(":", "_"), 90) + ".png")
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="reconforge-{OUT.slug(name)}-screenshots.zip"'})

    # -------------------------------------------------------------- triage
    @app.get("/api/targets/{name}/triage", dependencies=[A])
    def triage(name: str):
        """Every observation with a review priority score, triage state and the exposure of its host."""
        with db.session() as s:
            tid = target_id(s, name)
            sc = latest_scan(s, tid)
            assets = list(s.execute(select(Asset).where(Asset.target_id == tid, Asset.type == "finding",
                                                         Asset.status == "active")).scalars())
            host_tier = {}
            if sc:
                for sco, a in s.execute(select(AssetScore, Asset).join(Asset, Asset.id == AssetScore.asset_id)
                                        .where(AssetScore.scan_id == sc.id)).all():
                    host_tier[a.key] = (sco.tier, sco.score)
            rows = []
            for f in assets:
                at = f.attributes or {}
                sev = at.get("severity") or "info"
                tri = at.get("triage") or {}
                state = tri.get("status") or ("false_positive" if f.false_positive else "new")
                tier, hscore = host_tier.get(at.get("host") or "", (None, 0))
                conf = f.confidence or 0.6
                score = SEV_WEIGHT.get(sev, 3) * (0.5 + conf / 2) + {"P1": 20, "P2": 10, "P3": 4}.get(tier or "", 0)
                if sc and f.first_scan_id == sc.id:
                    score += 8  # new in the latest execution
                if at.get("category") in ("exposure", "cve", "dns") and sev in ("medium", "high", "critical"):
                    score += 5
                if state in ("false_positive", "fixed", "accepted_risk"):
                    score *= 0.2
                rows.append({"id": f.id, "title": at.get("title") or f.display, "severity": sev, "category": at.get("category"),
                             "rule": at.get("rule"), "subject": at.get("subject") or f.key, "host": at.get("host"),
                             "description": at.get("description"), "recommendation": at.get("recommendation"),
                             "confidence": round(conf, 2), "evidence": at.get("_last_evidence"), "status": state,
                             "note": tri.get("note"), "updated_at": tri.get("updated_at"), "host_tier": tier,
                             "new": bool(sc and f.first_scan_id == sc.id), "first_seen": iso(f.first_seen),
                             "last_seen": iso(f.last_seen), "sources": [x["source"] for x in f.sources or []],
                             "cves": at.get("cves") or [], "score": round(score, 1)})
            rows.sort(key=lambda r: -r["score"])
            return {"states": TRIAGE_STATES, "items": rows}

    @app.post("/api/assets/{asset_id}/triage", dependencies=[A])
    def set_triage(asset_id: str, body: TriageBody):
        from ..util import utcnow

        if body.status not in TRIAGE_STATES:
            raise HTTPException(400, f"status must be one of {', '.join(TRIAGE_STATES)}")
        ids = list(dict.fromkeys([asset_id, *(body.ids or [])]))[:2000]
        with db.session() as s:
            done = 0
            for i in ids:
                a = s.get(Asset, i)
                if a is None or a.type != "finding":
                    continue
                a.attributes = {**(a.attributes or {}), "triage": {"status": body.status, "note": (body.note or "")[:2000] or None,
                                                                   "updated_at": iso(utcnow())}}
                a.false_positive = body.status == "false_positive"
                a.fp_reason = (body.note or "marked in triage") if a.false_positive else None
                done += 1
            if not done:
                raise HTTPException(404, "no such observation")
        return {"updated": done, "status": body.status}

    # -------------------------------------------------------------- search
    @app.get("/api/search", dependencies=[A])
    def search(target: str, q: str = Query(..., min_length=2, max_length=200), limit: int = Query(30, le=100)):
        with db.session() as s:
            tid = target_id(s, target)
            like = f"%{q}%"
            rows = s.execute(select(Asset).where(Asset.target_id == tid, Asset.status == "active",
                                                 Asset.key.ilike(like) | Asset.display.ilike(like))
                             .order_by(Asset.type, Asset.key).limit(limit)).scalars()
            return [{"id": a.id, "type": a.type, "key": a.key, "display": a.display,
                     "severity": (a.attributes or {}).get("severity") if a.type == "finding" else None} for a in rows]

    # ------------------------------------------------------------- actions
    @app.get("/api/actions", dependencies=[A])
    def actions(target: str | None = None):
        from ..runs import action_catalog
        from ..targets import resolve_target

        return action_catalog(cfg, resolve_target(cfg, db, target) if target else None)

    @app.post("/api/actions/run", dependencies=[A])
    def run_action(body: ActionBody):
        from ..runs import action_catalog, options_for_action
        from ..scope import ScopeError
        from ..targets import resolve_target

        t = resolve_target(cfg, db, body.target)
        if not t:
            raise HTTPException(404, "unknown target")
        act = next((a for a in action_catalog(cfg, t) if a["id"] == body.action_id), None)
        if act is None:
            raise HTTPException(404, "unknown action")
        if not act["runnable"]:
            raise HTTPException(400, f"{act['name']} cannot run: {act['reason']}")
        try:
            info = manager.start(options_for_action(cfg, body.target, act), label=f"{act['kind']}: {act['name']}", kind="action")
        except (ValueError, KeyError, ScopeError) as exc:
            raise HTTPException(400, str(exc))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        return run_dict(info)

    # ------------------------------------------------------------ settings
    @app.get("/api/settings", dependencies=[A])
    def get_settings():
        from ..settings import public_settings

        return public_settings(cfg)

    @app.put("/api/settings", dependencies=[A])
    def put_settings(body: dict):
        from ..settings import save_settings

        try:
            return save_settings(cfg, body)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/scans/{scan_id}/ai-bundle", dependencies=[A])
    def bundle(scan_id: str, format: str = "json"):
        from ..ai.analyst import ai_bundle

        b = ai_bundle(cfg, db, scan_id)
        if format == "prompt":
            return PlainTextResponse(b["prompt"], headers={"Content-Disposition": f"attachment; filename=reconforge-{scan_id}-prompt.txt"})
        return SafeJSONResponse(b, headers={"Content-Disposition": f"attachment; filename=reconforge-{scan_id}-ai-bundle.json"})

    @app.post("/api/scans/{scan_id}/ai-import", dependencies=[A])
    def ai_import(scan_id: str, body: ImportBody):
        from ..ai.analyst import import_analysis

        try:
            import_analysis(cfg, db, scan_id, body.answer, body.label or "manual import")
        except ValueError as exc:
            raise HTTPException(400, f"could not parse the answer as JSON: {exc}")
        return ai_result(scan_id)

    @app.post("/api/scans/{scan_id}/analyze", dependencies=[A])
    def analyze(scan_id: str, provider: str | None = None, body: AnalyzeBody | None = None):
        from ..ai.analyst import analyze_scan, get_provider

        body = body or AnalyzeBody(provider=provider)
        try:
            prov = get_provider(cfg, body.provider or provider, {"model": body.model, "base_url": body.base_url})
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if prov.name != "heuristic" and not body.consent:
            raise HTTPException(400, f"Sending the evidence pack to {prov.name} requires consent=true")
        aid = analyze_scan(cfg, db, scan_id, prov)
        return ai_result(scan_id) | {"id": aid}

    @app.get("/api/scans/{scan_id}/ai", dependencies=[A])
    def ai_result(scan_id: str):
        with db.session() as s:
            a = s.execute(select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at.desc())).scalars().first()
            if a is None:
                return {"status": "none"}
            return {"id": a.id, "provider": a.provider, "model": a.model, "status": a.status, "created_at": iso(a.created_at),
                    "result": a.result, "rejected": a.rejected, "error": a.error}

    @app.post("/api/scans/{scan_id}/reports", dependencies=[A])
    def regen_reports(scan_id: str):
        from ..reports.builder import generate_reports

        return generate_reports(cfg, db, scan_id)

    # ------------------------------------------------------------- changes
    @app.get("/api/targets/{name}/changes", dependencies=[A])
    def changes(name: str, category: str | None = None, limit: int = 1000):
        with db.session() as s:
            tid = target_id(s, name)
            stmt = select(Change, Scan).join(Scan, Scan.id == Change.scan_id).where(Change.target_id == tid)
            if category:
                stmt = stmt.where(Change.category == category)
            return [{"id": c.id, "scan_id": c.scan_id, "scan_started": iso(sc.started_at), "category": c.category,
                     "significance": c.significance, "summary": c.summary, "asset_type": c.asset_type, "asset": c.asset_display,
                     "asset_id": c.asset_id, "previous": c.previous, "current": c.current,
                     "first_observed": iso(c.first_observed), "evidence": c.evidence_id, "notified": c.notified}
                    for c, sc in s.execute(stmt.order_by(Scan.started_at.desc(), Change.significance).limit(limit)).all()]

    @app.get("/api/compare", dependencies=[A])
    def compare(a: str, b: str):
        from ..storage.maintenance import compare_scans

        return compare_scans(db, a, b)

    # --------------------------------------------------------------- graph
    @app.get("/api/targets/{name}/graph", dependencies=[A])
    def graph(name: str, types: str | None = None, format: str = "cytoscape"):
        with db.session() as s:
            tid = target_id(s, name)
            g = build_graph(s, tid, types=types.split(",") if types else None)
        if format == "dot":
            return PlainTextResponse(to_dot(g), headers={"Content-Disposition": f"attachment; filename={name}.dot"})
        if format == "graphml":
            return Response(to_graphml(g), media_type="application/xml",
                            headers={"Content-Disposition": f"attachment; filename={name}.graphml"})
        return to_cytoscape(g)

    # ----------------------------------------------------------- schedules
    @app.get("/api/schedules", dependencies=[A])
    def schedules():
        with db.session() as s:
            return [{"id": x.id, "name": x.name, "target": x.target_name, "frequency": x.frequency, "cron": x.cron,
                     "profile": x.profile, "incremental": x.incremental, "enabled": x.enabled,
                     "next_run_at": iso(x.next_run_at), "last_run_at": iso(x.last_run_at), "last_scan_id": x.last_scan_id,
                     "last_status": x.last_status} for x in s.execute(select(Schedule).order_by(Schedule.name)).scalars()]

    @app.post("/api/schedules", dependencies=[A])
    def add_schedule(body: ScheduleBody):
        from ..scheduler.service import upsert_schedule

        from ..targets import resolve_target

        if not resolve_target(cfg, db, body.target):
            raise HTTPException(404, "target not found")
        try:
            sc = upsert_schedule(db, name=body.name, target=body.target, frequency=body.frequency, profile=body.profile,
                                 at=body.at, day=body.day, cron=body.cron, incremental=body.incremental, enabled=body.enabled)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"name": sc.name, "cron": sc.cron, "next_run_at": iso(sc.next_run_at)}

    @app.delete("/api/schedules/{name}", dependencies=[A])
    def delete_schedule(name: str):
        with db.session() as s:
            sc = s.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
            if sc is None:
                raise HTTPException(404)
            s.delete(sc)
        return {"deleted": name}

    @app.get("/api/tools", dependencies=[A])
    def tools():
        from ..core.registry import load_registry, tool_status
        from ..installer import installable_names

        can_install = installable_names()
        return [{**{k: v for k, v in e.items() if k != "command"}, "command_template": e.get("command"),
                 "installable": e["name"] in can_install,
                 "status": tool_status(e, cfg, offline=bool(cfg.get("network.offline"))).as_dict()}
                for e in sorted(load_registry(cfg), key=lambda e: (e.get("category", ""), e["name"]))]

    @app.post("/api/tools/{name}/install", dependencies=[A])
    def install_tool_ep(name: str):
        try:
            return install_manager.start(name).as_dict()
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except RuntimeError as exc:
            raise HTTPException(500, str(exc))

    @app.get("/api/installs/{job_id}", dependencies=[A])
    def install_status(job_id: str):
        job = install_manager.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown install job")
        return job.as_dict()

    @app.get("/api/notifications", dependencies=[A])
    def notifications(limit: int = 100):
        with db.session() as s:
            return [{"id": n.id, "scan_id": n.scan_id, "channel": n.channel, "status": n.status, "sent_at": iso(n.sent_at),
                     "changes": len(n.change_ids or []), "error": n.error, "preview": n.preview}
                    for n in s.execute(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(limit)).scalars()]

    # ------------------------------------------------------------ frontend
    if (STATIC / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                raise HTTPException(404)
            f = STATIC / path
            if path and f.is_file() and STATIC in f.resolve().parents:
                return FileResponse(f)
            return HTMLResponse((STATIC / "index.html").read_text())
    else:
        @app.get("/", include_in_schema=False)
        def no_ui():
            return HTMLResponse("<h3>ReconForge API is running.</h3><p>Dashboard bundle not built: run "
                                "<code>cd frontend && npm install && npm run build</code>. API docs: <a href='/api/docs'>/api/docs</a></p>")

    if with_scheduler:
        from ..scheduler.service import daemon

        def _sched():
            try:
                daemon(cfg, db, interval=30)
            except RuntimeError as exc:
                print(f"scheduler not started: {exc}")

        threading.Thread(target=_sched, daemon=True, name="reconforge-scheduler").start()
    return app
