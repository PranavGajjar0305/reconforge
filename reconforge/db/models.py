"""Database schema (SQLAlchemy 2.0). Works with SQLite and PostgreSQL.

Core idea: an *asset* is one unique thing about the target's attack surface
(identified by target + type + normalized key). Every module emits *observations*
about assets; each observation keeps its source, timestamp and evidence reference.
*Relations* connect assets and are marked confirmed or inferred. *AssetState* rows
snapshot each asset per scan and drive change detection.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..util import utcnow


class Base(DeclarativeBase):
    pass


ASSET_TYPES = [
    "domain",          # root domain
    "subdomain",       # hostname under a root domain
    "ip",
    "asn",
    "provider",        # hosting provider / organisation
    "certificate",
    "service",         # ip:port/proto
    "web_app",         # origin, e.g. https://api.example.com
    "technology",
    "endpoint",        # URL path on a web app (API or page)
    "js_file",
    "cloud_resource",
    "third_party",     # external domain referenced by target assets
    "repository",      # public code repository reference
    "finding",         # security observation (not necessarily a vulnerability)
    "screenshot",
]


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    profile: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="running")  # running|completed|partial|failed
    trigger: Mapped[str] = mapped_column(String(32), default="manual")  # manual|schedule|api
    incremental: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    prev_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    modules_planned: Mapped[list] = mapped_column(JSON, default=list)
    modules_completed: Mapped[list] = mapped_column(JSON, default=list)
    modules_failed: Mapped[list] = mapped_column(JSON, default=list)
    modules_skipped: Mapped[list] = mapped_column(JSON, default=list)
    tools_executed: Mapped[list] = mapped_column(JSON, default=list)
    results_count: Mapped[int] = mapped_column(Integer, default=0)
    report_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)

    target: Mapped[Target] = relationship()
    module_runs: Mapped[list["ModuleRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at and self.started_at:
            return round((self.finished_at - self.started_at).total_seconds(), 2)
        return None


class ModuleRun(Base):
    __tablename__ = "module_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(64), default="builtin")
    status: Mapped[str] = mapped_column(String(32), default="pending")  # completed|failed|skipped
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    observations: Mapped[int] = mapped_column(Integer, default=0)
    inputs: Mapped[int] = mapped_column(Integer, default=0)
    skipped_inputs: Mapped[list] = mapped_column(JSON, default=list)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="module_runs")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("target_id", "type", "key", name="uq_asset_identity"), Index("ix_asset_type", "target_id", "type"))
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    type: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(1024))
    display: Mapped[str] = mapped_column(String(1024))
    scope: Mapped[str] = mapped_column(String(32), default="in_scope")  # in_scope|out_of_scope|third_party|n/a
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|removed
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    first_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    fp_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)


class Relation(Base):
    __tablename__ = "relations"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "type", name="uq_relation"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    src_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(64))
    confirmed: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(64))  # dns_answer|http_response|certificate|tool_output|banner|file|...
    summary: Mapped[str] = mapped_column(Text, default="")
    content: Mapped[str | None] = mapped_column(Text, nullable=True)  # small evidence inline
    path: Mapped[str | None] = mapped_column(Text, nullable=True)     # large evidence on disk
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AssetState(Base):
    __tablename__ = "asset_states"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", name="uq_asset_state"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    state_hash: Mapped[str] = mapped_column(String(32))
    state: Mapped[dict] = mapped_column(JSON, default=dict)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    carried: Mapped[bool] = mapped_column(Boolean, default=False)


class Change(Base):
    __tablename__ = "changes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    prev_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(32))
    asset_display: Mapped[str] = mapped_column(String(1024))
    category: Mapped[str] = mapped_column(String(64))
    significance: Mapped[str] = mapped_column(String(16), default="medium")
    summary: Mapped[str] = mapped_column(Text)
    previous: Mapped[dict | list | str | None] = mapped_column(JSON, nullable=True)
    current: Mapped[dict | list | str | None] = mapped_column(JSON, nullable=True)
    first_observed: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    evidence_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(32), index=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)


class AssetScore(Base):
    __tablename__ = "asset_scores"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", name="uq_asset_score"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    score: Mapped[float] = mapped_column(Float)
    tier: Mapped[str] = mapped_column(String(16))
    factors: Mapped[list] = mapped_column(JSON, default=list)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    target_name: Mapped[str] = mapped_column(String(200))
    frequency: Mapped[str] = mapped_column(String(16))  # once|daily|weekly|monthly|cron
    cron: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(64), default="continuous")
    incremental: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NotificationLog(Base):
    __tablename__ = "notification_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    channel: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))  # sent|failed|suppressed
    fingerprints: Mapped[list] = mapped_column(JSON, default=list)
    change_ids: Mapped[list] = mapped_column(JSON, default=list)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    preview: Mapped[str | None] = mapped_column(Text, nullable=True)


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    rejected: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
