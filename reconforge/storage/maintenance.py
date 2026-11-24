"""Backups, portable JSON export/import, retention and historical queries."""
from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select

from ..db import Database
from ..db.models import (AIAnalysis, Asset, AssetScore, AssetState, Change, Evidence, ModuleRun, NotificationLog,
                         Observation, Relation, Report, Scan, Schedule, Target)
from ..util import iso, utcnow

EXPORT_TABLES = [Target, Scan, ModuleRun, Asset, Observation, Relation, Evidence, AssetState, Change, AssetScore,
                 AIAnalysis, Report, Schedule, NotificationLog]


def backup(cfg, db: Database) -> Path:
    dest_dir = cfg.dir("backups_dir")
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    url = db.url
    if url.startswith("sqlite:///"):
        src = url[len("sqlite:///"):]
        dest = dest_dir / f"reconforge-{stamp}.db"
        with sqlite3.connect(src) as source, sqlite3.connect(dest) as target:
            source.backup(target)  # consistent online backup
        return dest
    dest = dest_dir / f"reconforge-{stamp}.json"
    export_json(db, dest)
    return dest


def _row(obj) -> dict:
    out = {}
    for col in obj.__table__.columns:
        v = getattr(obj, col.name)
        out[col.name] = iso(v) if hasattr(v, "isoformat") else v
    return out


def export_json(db: Database, path: Path, target: str | None = None) -> Path:
    data = {"format": "reconforge-export", "version": 1, "exported_at": iso(utcnow()), "tables": {}}
    with db.session() as s:
        tid = None
        if target:
            t = s.execute(select(Target).where(Target.name == target)).scalar_one()
            tid = t.id
        for model in EXPORT_TABLES:
            q = select(model)
            if tid is not None:
                if hasattr(model, "target_id"):
                    q = q.where(model.target_id == tid)
                elif model is Target:
                    q = q.where(Target.id == tid)
                elif hasattr(model, "scan_id"):
                    q = q.where(model.scan_id.in_(select(Scan.id).where(Scan.target_id == tid)))
                elif model is Schedule:
                    q = q.where(Schedule.target_name == target)
            data["tables"][model.__tablename__] = [_row(r) for r in s.execute(q).scalars()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, default=str))
    return path


def import_json(db: Database, path: Path) -> dict[str, int]:
    from datetime import datetime

    data = json.loads(Path(path).read_text())
    if data.get("format") != "reconforge-export":
        raise ValueError("not a ReconForge export")
    counts = {}
    with db.session() as s:
        for model in EXPORT_TABLES:
            rows = data["tables"].get(model.__tablename__, [])
            n = 0
            for r in rows:
                for col in model.__table__.columns:
                    v = r.get(col.name)
                    if isinstance(v, str) and col.type.python_type is datetime:
                        r[col.name] = datetime.fromisoformat(v.rstrip("Z"))
                pk = [r[c.name] for c in model.__table__.primary_key.columns]
                if s.get(model, pk[0] if len(pk) == 1 else tuple(pk)) is None:
                    s.add(model(**{k: v for k, v in r.items() if k in model.__table__.columns}))
                    n += 1
            s.flush()
            counts[model.__tablename__] = n
    return counts


def apply_retention(cfg, db: Database, days: int | None = None, keep_min: int | None = None, dry_run: bool = False) -> dict:
    """Delete scans (and their observations/evidence/states) older than `days`, always keeping the
    newest `keep_min` scans per target. Assets themselves are kept (they hold first/last seen history)."""
    days = int(days if days is not None else cfg.get("storage.retention_days", 365))
    keep_min = int(keep_min if keep_min is not None else cfg.get("storage.keep_min_scans", 5))
    cutoff = utcnow() - timedelta(days=days)
    removed = []
    with db.session() as s:
        for t in s.execute(select(Target)).scalars():
            scans = list(s.execute(select(Scan).where(Scan.target_id == t.id).order_by(Scan.started_at.desc())).scalars())
            for sc in scans[keep_min:]:
                if sc.started_at < cutoff:
                    removed.append(sc.id)
        if not dry_run and removed:
            for model in (Observation, AssetState, Change, AssetScore, AIAnalysis, Report, ModuleRun):
                s.execute(delete(model).where(model.scan_id.in_(removed)))
            evs = list(s.execute(select(Evidence).where(Evidence.scan_id.in_(removed))).scalars())
            for e in evs:
                if e.path:
                    Path(e.path).unlink(missing_ok=True)
            s.execute(delete(Evidence).where(Evidence.scan_id.in_(removed)))
            s.execute(delete(Scan).where(Scan.id.in_(removed)))
            for sid in removed:
                d = cfg.dir("evidence_dir") / sid
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
    return {"cutoff": iso(cutoff), "scans_removed": removed, "dry_run": dry_run}


def asset_history(db: Database, asset_id: str) -> dict:
    """Per-scan states and every observation of one asset (historical query)."""
    with db.session() as s:
        a = s.get(Asset, asset_id)
        if a is None:
            raise KeyError(asset_id)
        states = s.execute(select(AssetState, Scan).join(Scan, Scan.id == AssetState.scan_id)
                           .where(AssetState.asset_id == asset_id).order_by(Scan.started_at)).all()
        obs = list(s.execute(select(Observation).where(Observation.asset_id == asset_id).order_by(Observation.observed_at)).scalars())
        changes = list(s.execute(select(Change).where(Change.asset_id == asset_id).order_by(Change.first_observed)).scalars())
        return {
            "asset": {"id": a.id, "type": a.type, "key": a.key, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
                      "status": a.status},
            "states": [{"scan_id": sc.id, "started_at": iso(sc.started_at), "carried": st.carried, "state": st.state,
                        "modules": st.modules} for st, sc in states],
            "observations": [{"id": o.id, "scan_id": o.scan_id, "module": o.module, "source": o.source,
                              "observed_at": iso(o.observed_at), "evidence_id": o.evidence_id, "confidence": o.confidence,
                              "data": o.data} for o in obs],
            "changes": [{"id": c.id, "scan_id": c.scan_id, "category": c.category, "summary": c.summary,
                         "previous": c.previous, "current": c.current} for c in changes],
        }


def compare_scans(db: Database, scan_a: str, scan_b: str) -> dict:
    """Ad-hoc comparison of any two scans of the same target using their asset states."""
    with db.session() as s:
        a_states = {st.asset_id: st for st in s.execute(select(AssetState).where(AssetState.scan_id == scan_a)).scalars()}
        b_states = {st.asset_id: st for st in s.execute(select(AssetState).where(AssetState.scan_id == scan_b)).scalars()}
        ids = set(a_states) | set(b_states)
        assets = {x.id: x for x in s.execute(select(Asset).where(Asset.id.in_(ids))).scalars()} if ids else {}

        def desc(aid):
            x = assets.get(aid)
            return {"id": aid, "type": x.type if x else "?", "key": x.key if x else "?"}

        return {
            "added": [desc(i) for i in sorted(set(b_states) - set(a_states))],
            "removed": [desc(i) for i in sorted(set(a_states) - set(b_states))],
            "changed": [{**desc(i), "before": a_states[i].state, "after": b_states[i].state}
                        for i in sorted(set(a_states) & set(b_states)) if a_states[i].state_hash != b_states[i].state_hash],
        }
