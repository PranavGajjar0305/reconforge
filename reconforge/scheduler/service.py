"""Scheduled and continuous reconnaissance.

Schedules (once / daily / weekly / monthly / cron) live in the database and can be
declared in config (`schedules:`) or created from the CLI/API. A lightweight daemon
(`reconforge scheduler run`) wakes every N seconds, runs due scans sequentially and
computes the next run. `reconforge scheduler tick` runs due scans once, for use from
system cron/launchd/systemd timers. All times are UTC.
"""
from __future__ import annotations

import fcntl
import logging
import time
from datetime import datetime, timedelta

from sqlalchemy import select

from ..db import Database
from ..db.models import Schedule
from ..util import new_id, utcnow

log = logging.getLogger("reconforge.scheduler")
WEEKDAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}


class CronExpr:
    """Minimal 5-field cron (minute hour day-of-month month day-of-week), UTC."""

    RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]

    def __init__(self, expr: str):
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(f"cron expression needs 5 fields: {expr!r}")
        self.expr = expr
        self.fields = [self._parse(p, lo, hi, i == 4) for i, (p, (lo, hi)) in enumerate(zip(parts, self.RANGES))]
        self.dom_star, self.dow_star = parts[2] == "*", parts[4] == "*"

    @staticmethod
    def _parse(part: str, lo: int, hi: int, dow: bool) -> set[int]:
        out: set[int] = set()
        for chunk in part.lower().split(","):
            step = 1
            if "/" in chunk:
                chunk, s = chunk.split("/")
                step = int(s)
            if chunk in ("*", ""):
                a, b = lo, hi
            elif "-" in chunk:
                a, b = (WEEKDAYS.get(x, None) if dow and x in WEEKDAYS else int(x) for x in chunk.split("-"))
            else:
                a = b = WEEKDAYS[chunk] if dow and chunk in WEEKDAYS else int(chunk)
            if dow and b == 7:
                b = 6
                out.add(0)
            if not (lo <= a <= hi and lo <= b <= hi):
                raise ValueError(f"cron value out of range: {part}")
            out |= set(range(a, b + 1, step))
        return out

    def matches(self, dt: datetime) -> bool:
        mi, hr, dom, mon, dow = self.fields
        dow_val = (dt.weekday() + 1) % 7
        day_ok = (dt.day in dom) if self.dow_star else (dow_val in dow) if self.dom_star else (dt.day in dom or dow_val in dow)
        return dt.minute in mi and dt.hour in hr and dt.month in mon and day_ok

    def next_after(self, dt: datetime) -> datetime:
        t = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(366 * 24 * 60):
            if self.matches(t):
                return t
            t += timedelta(minutes=1)
        raise ValueError(f"no run time found within a year for {self.expr}")


def frequency_to_cron(frequency: str, at: str = "02:00", day: str | int | None = None, cron: str | None = None) -> str:
    hh, mm = (int(x) for x in (at or "02:00").split(":"))
    f = frequency.lower()
    if f == "cron":
        if not cron:
            raise ValueError("frequency=cron requires a cron expression")
        CronExpr(cron)
        return cron
    if f == "hourly":
        return f"{mm} * * * *"
    if f == "daily":
        return f"{mm} {hh} * * *"
    if f == "weekly":
        d = WEEKDAYS.get(str(day or "mon").lower()[:3], day if isinstance(day, int) else 1)
        return f"{mm} {hh} * * {d}"
    if f == "monthly":
        return f"{mm} {hh} {int(day or 1)} * *"
    if f == "once":
        return "once"
    raise ValueError(f"unknown frequency {frequency!r} (once|hourly|daily|weekly|monthly|cron)")


def compute_next(sched: Schedule, after: datetime | None = None) -> datetime | None:
    after = after or utcnow()
    if sched.cron == "once":
        return None if sched.last_run_at else (sched.next_run_at or after)
    return CronExpr(sched.cron).next_after(after)


def upsert_schedule(db: Database, *, name: str, target: str, frequency: str, profile: str = "continuous",
                    at: str = "02:00", day=None, cron: str | None = None, incremental: bool = True,
                    enabled: bool = True, run_at: datetime | None = None) -> Schedule:
    expr = frequency_to_cron(frequency, at, day, cron)
    with db.session() as s:
        sc = s.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
        if sc is None:
            sc = Schedule(id=new_id("sch"), name=name, target_name=target, frequency=frequency, cron=expr)
            s.add(sc)
        changed = sc.cron != expr
        sc.target_name, sc.frequency, sc.cron = target, frequency, expr
        sc.profile, sc.incremental, sc.enabled = profile, incremental, enabled
        if expr == "once":
            sc.next_run_at = run_at or sc.next_run_at or utcnow()
        elif changed or sc.next_run_at is None:
            sc.next_run_at = CronExpr(expr).next_after(utcnow())
        return sc


def sync_config_schedules(cfg, db: Database) -> list[str]:
    names = []
    for item in cfg.get("schedules", []) or []:
        upsert_schedule(db, name=item["name"], target=item["target"], frequency=item.get("frequency", "daily"),
                        profile=item.get("profile", "continuous"), at=str(item.get("at", "02:00")), day=item.get("day"),
                        cron=item.get("cron"), incremental=item.get("incremental", True), enabled=item.get("enabled", True))
        names.append(item["name"])
    return names


def run_due(cfg, db: Database, now: datetime | None = None, runner=None) -> list[tuple[str, str]]:
    """Run every enabled schedule whose next_run_at has passed. Returns [(schedule, scan_id|error)]."""
    from ..core.pipeline import ScanOptions, run_scan

    runner = runner or (lambda opts: run_scan(cfg, opts, db))
    now = now or utcnow()
    with db.session() as s:
        due = [(x.id, x.name, x.target_name, x.profile, x.incremental) for x in s.execute(
            select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None), Schedule.next_run_at <= now)
            .order_by(Schedule.next_run_at)).scalars()]
    results = []
    for sid, name, target, profile, incremental in due:
        log.info("running schedule %s (target=%s profile=%s)", name, target, profile)
        status, scan_id = "completed", None
        try:
            scan_id = runner(ScanOptions(target=target, profile=profile, incremental=incremental, trigger="schedule"))
            results.append((name, scan_id))
        except Exception as exc:  # keep the daemon alive
            status = f"failed: {exc}"
            results.append((name, status))
            log.error("schedule %s failed: %s", name, exc)
        with db.session() as s:
            sc = s.get(Schedule, sid)
            sc.last_run_at = utcnow()
            sc.last_scan_id = scan_id
            sc.last_status = status[:32]
            if sc.cron == "once":
                sc.enabled = False
                sc.next_run_at = None
            else:
                sc.next_run_at = CronExpr(sc.cron).next_after(max(utcnow(), now))
    return results


def daemon(cfg, db: Database, interval: int = 30, stop_after: int | None = None) -> None:
    lock_path = cfg.dir("data_dir") / "scheduler.lock"
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"another scheduler is already running (lock {lock_path})")
        sync_config_schedules(cfg, db)
        log.info("scheduler started (interval %ss)", interval)
        loops = 0
        while True:
            run_due(cfg, db)
            loops += 1
            if stop_after and loops >= stop_after:
                return
            time.sleep(interval)
