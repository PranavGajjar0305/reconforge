"""Indexes and JSON expressions that keep the dashboard fast on very large scans (hundreds of thousands of assets).

Endpoint filters (kind / host / historical) live inside the JSON `attributes` column. Expression indexes over those
fields let a filtered, ordered page of 100 rows come straight from an index instead of parsing every row's JSON.
Queries must build the expression with `jfield()` so it is written exactly like the index (SQLite matches indexes on
expressions textually).
"""
from __future__ import annotations

import logging
import time

from sqlalchemy import Index, func, literal_column, text
from sqlalchemy.engine import Engine

log = logging.getLogger("reconforge.db")

JSON_FIELDS = ("kind", "host", "historical")


def jfield(dialect: str, column, name: str):
    """Text/scalar value of a top-level JSON attribute, written the same way as the expression indexes."""
    assert name in JSON_FIELDS  # fixed names only: they are inlined into SQL
    if dialect == "postgresql":
        return column.op("->>")(literal_column(f"'{name}'"))
    return func.json_extract(column, literal_column(f"'$.{name}'"))


def live() -> list:
    """Equality terms on (status, false_positive) written so the composite indexes apply."""
    from .models import Asset

    return [Asset.status == "active", Asset.false_positive == False]  # noqa: E712 (an index needs "=", not "IS")


def is_historical(dialect: str, column):
    v = jfield(dialect, column, "historical")
    return v == ("true" if dialect == "postgresql" else 1)


def not_historical(dialect: str, column):
    # modules only ever set historical=true, so "live" is "no flag": a plain IS NULL the index answers directly
    return jfield(dialect, column, "historical").is_(None)


_PLAIN: list[Index] = []


def _plain_indexes() -> list[Index]:
    """Built once: an Index attaches itself to its table, so later create_all() calls include it for new databases."""
    from .models import Asset, Evidence, Observation, Relation

    if _PLAIN:
        return _PLAIN
    _PLAIN.extend([
        Index("ix_obs_scan_module", Observation.scan_id, Observation.module, Observation.id),
        Index("ix_obs_scan_module_asset", Observation.scan_id, Observation.module, Observation.asset_id),
        Index("ix_asset_id_type", Asset.id, Asset.type),
        Index("ix_rel_target_type", Relation.target_id, Relation.type),
        Index("ix_rel_src_type", Relation.src_id, Relation.type),
        Index("ix_rel_dst_type", Relation.dst_id, Relation.type),
        Index("ix_evidence_scan_module", Evidence.scan_id, Evidence.module),
        Index("ix_asset_target_status_type", Asset.target_id, Asset.status, Asset.type),
        Index("ix_asset_live_key", Asset.target_id, Asset.type, Asset.status, Asset.false_positive, Asset.key),
    ])
    return _PLAIN


def ensure_indexes(engine: Engine) -> None:
    """Create the performance indexes if they are missing (one-time; can take a minute on a multi-GB database)."""
    dialect = engine.dialect.name
    if dialect not in ("sqlite", "postgresql"):
        return
    # the catalog, not inspect(): SQLAlchemy's inspector does not list indexes on expressions
    catalog = ("SELECT name FROM sqlite_master WHERE type = 'index'" if dialect == "sqlite"
               else "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
    with engine.connect() as conn:
        existing = {r[0] for r in conn.execute(text(catalog))}
    todo = [ix for ix in _plain_indexes() if ix.name not in existing]
    expr = [f"ix_asset_json_{n}" for n in JSON_FIELDS if f"ix_asset_json_{n}" not in existing]
    if not todo and not expr:
        return
    t0 = time.time()
    with engine.connect() as conn:
        has_data = conn.execute(text("SELECT 1 FROM assets LIMIT 1")).first() is not None
    if has_data:  # an existing database: say why this start takes a moment (a new one is instant)
        log.warning("optimizing the database for large scans (one-time, %d index(es))…", len(todo) + len(expr))
    for ix in todo:
        ix.create(engine, checkfirst=True)
    with engine.begin() as conn:
        for name in expr:
            field = name.rsplit("_", 1)[1]
            e = (f"(attributes ->> '{field}')" if dialect == "postgresql" else f"json_extract(attributes, '$.{field}')")
            conn.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON assets (target_id, type, status, false_positive, {e}, key)"))
    if has_data:
        log.warning("database optimized in %.1fs", time.time() - t0)
