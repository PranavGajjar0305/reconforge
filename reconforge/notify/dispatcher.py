"""Change notifications: Email, Telegram, Discord and Slack.

One summary message per scan and channel, containing only meaningful changes that
were not already notified within `notifications.dedup_hours` (by change fingerprint).
Each channel can be enabled/disabled independently.
"""
from __future__ import annotations

import html
import json
import os
import smtplib
from collections import defaultdict
from datetime import timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from sqlalchemy import select

from ..db import Database
from ..db.models import Change, NotificationLog, Scan, Target
from ..util import iso, truncate, utcnow

SIG_RANK = {"high": 0, "medium": 1, "low": 2}


def select_changes(s, cfg, scan_id: str) -> tuple[list[Change], list[Change]]:
    """Return (to_send, suppressed_duplicates)."""
    cats = cfg.get("notifications.categories", "all")
    min_sig = cfg.get("notifications.min_significance", "low")
    changes = list(s.execute(select(Change).where(Change.scan_id == scan_id)).scalars())
    changes = [c for c in changes if (cats == "all" or c.category in cats)
               and SIG_RANK.get(c.significance, 2) <= SIG_RANK.get(min_sig, 2)]
    window = utcnow() - timedelta(hours=float(cfg.get("notifications.dedup_hours", 168)))
    sent: set[str] = set()
    for log in s.execute(select(NotificationLog).where(NotificationLog.status == "sent", NotificationLog.sent_at >= window,
                                                       NotificationLog.scan_id != scan_id)).scalars():
        sent |= set(log.fingerprints or [])
    fresh, dup = [], []
    seen_now: set[str] = set()
    for c in sorted(changes, key=lambda c: (SIG_RANK.get(c.significance, 2), c.category)):
        if c.fingerprint in sent or c.fingerprint in seen_now:
            dup.append(c)
        else:
            seen_now.add(c.fingerprint)
            fresh.append(c)
    return fresh, dup


def build_message(cfg, scan: Scan, target: Target, changes: list[Change], max_items: int = 25) -> dict:
    base = cfg.get("notifications.report_base_url", "").rstrip("/")
    report_link = f"{base}/scans/{scan.id}" if base else scan.report_dir or scan.id
    grouped = defaultdict(list)
    for c in changes:
        grouped[c.category].append(c)
    items = []
    for c in changes[:max_items]:
        items.append({
            "target": target.name, "asset": c.asset_display, "type": c.category, "significance": c.significance,
            "summary": c.summary, "first_observed": iso(c.first_observed),
            "previous": truncate(json.dumps(c.previous, default=str), 160) if c.previous is not None else "—",
            "current": truncate(json.dumps(c.current, default=str), 160) if c.current is not None else "—",
            "evidence": f"{base}/api/evidence/{c.evidence_id}" if (base and c.evidence_id) else (c.evidence_id or "—"),
        })
    title = f"ReconForge: {len(changes)} attack-surface change(s) for {target.name}"
    counts = ", ".join(f"{len(v)} {k.replace('_', ' ')}" for k, v in sorted(grouped.items(), key=lambda kv: -len(kv[1])))
    lines = [title, f"Scan {scan.id} ({scan.profile}) finished {iso(scan.finished_at)}", f"Summary: {counts}", ""]
    for it in items:
        lines.append(f"[{it['significance'].upper()}] {it['type']}: {it['summary']}")
        lines.append(f"    asset: {it['asset']} | first observed: {it['first_observed']}")
        lines.append(f"    previous: {it['previous']} | current: {it['current']}")
        lines.append(f"    evidence: {it['evidence']}")
    if len(changes) > max_items:
        lines.append(f"… and {len(changes) - max_items} more")
    lines += ["", f"Report: {report_link}"]
    return {"title": title, "text": "\n".join(lines), "items": items, "counts": counts, "report_link": report_link,
            "more": max(0, len(changes) - max_items)}


# ------------------------------------------------------------------ channels
def send_email(cfg: dict, msg: dict) -> None:
    to = cfg.get("to") or []
    if not to:
        raise ValueError("notifications.email.to is empty")
    mime = MIMEMultipart("alternative")
    mime["Subject"] = msg["title"]
    mime["From"] = cfg.get("from", "reconforge@localhost")
    mime["To"] = ", ".join(to)
    mime.attach(MIMEText(msg["text"], "plain", "utf-8"))
    rows = "".join(
        f"<tr><td>{html.escape(i['significance'])}</td><td>{html.escape(i['type'])}</td><td>{html.escape(i['summary'])}</td>"
        f"<td>{html.escape(i['first_observed'] or '')}</td><td><code>{html.escape(i['previous'])}</code></td>"
        f"<td><code>{html.escape(i['current'])}</code></td><td>{html.escape(i['evidence'])}</td></tr>" for i in msg["items"])
    mime.attach(MIMEText(
        f"<h2>{html.escape(msg['title'])}</h2><p>{html.escape(msg['counts'])}</p><table border=1 cellpadding=4 "
        f"style='border-collapse:collapse;font-family:sans-serif;font-size:12px'><tr><th>Sig.</th><th>Type</th><th>Change</th>"
        f"<th>First observed</th><th>Previous</th><th>Current</th><th>Evidence</th></tr>{rows}</table>"
        f"<p><a href='{html.escape(msg['report_link'])}'>Open report</a></p>", "html", "utf-8"))
    with smtplib.SMTP(cfg.get("smtp_host", "localhost"), int(cfg.get("smtp_port", 587)), timeout=20) as smtp:
        smtp.ehlo()
        if cfg.get("starttls", True):
            smtp.starttls()
            smtp.ehlo()
        if cfg.get("username"):
            smtp.login(cfg["username"], cfg.get("password") or os.environ.get(cfg.get("password_env", ""), ""))
        smtp.sendmail(mime["From"], to, mime.as_string())


def _env_or(cfg: dict, key: str, env_key: str) -> str:
    return cfg.get(key) or os.environ.get(cfg.get(env_key, "") or "", "")


def send_telegram(cfg: dict, msg: dict) -> None:
    token = os.environ.get(cfg.get("bot_token_env", ""), "") or cfg.get("bot_token", "")
    if not token or not cfg.get("chat_id"):
        raise ValueError("telegram bot token (env) and chat_id are required")
    text = f"<b>{html.escape(msg['title'])}</b>\n{html.escape(msg['counts'])}\n\n"
    for i in msg["items"][:15]:
        text += (f"• <b>{html.escape(i['type'])}</b>: {html.escape(i['summary'])}\n"
                 f"  prev: <code>{html.escape(i['previous'][:80])}</code> → now: <code>{html.escape(i['current'][:80])}</code>\n")
    text += f"\n<a href=\"{html.escape(msg['report_link'])}\">Report</a>"
    r = httpx.post(f"{cfg.get('api_base', 'https://api.telegram.org').rstrip('/')}/bot{token}/sendMessage",
                   json={"chat_id": cfg["chat_id"], "text": text[:4000], "parse_mode": "HTML",
                         "disable_web_page_preview": True}, timeout=20)
    r.raise_for_status()


def send_discord(cfg: dict, msg: dict) -> None:
    url = _env_or(cfg, "webhook_url", "webhook_url_env")
    if not url:
        raise ValueError("discord webhook url required")
    fields = [{"name": truncate(f"[{i['significance']}] {i['type']}", 250),
               "value": truncate(f"{i['summary']}\nprev: `{i['previous'][:70]}`\nnow: `{i['current'][:70]}`\nfirst seen {i['first_observed']}", 1000),
               "inline": False} for i in msg["items"][:20]]
    r = httpx.post(url, json={"username": "ReconForge", "content": truncate(msg["title"], 1900),
                              "embeds": [{"title": "Attack surface changes", "description": truncate(msg["counts"], 3500),
                                          "url": msg["report_link"] if msg["report_link"].startswith("http") else None,
                                          "fields": fields, "color": 0x4F46E5}]}, timeout=20)
    r.raise_for_status()


def send_slack(cfg: dict, msg: dict) -> None:
    url = _env_or(cfg, "webhook_url", "webhook_url_env")
    if not url:
        raise ValueError("slack webhook url required")
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": truncate(msg["title"], 150)}},
              {"type": "section", "text": {"type": "mrkdwn", "text": truncate(msg["counts"], 2900)}}]
    for i in msg["items"][:20]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": truncate(
            f"*[{i['significance']}] {i['type']}* — {i['summary']}\nfirst observed {i['first_observed']} · "
            f"prev `{i['previous'][:80]}` → now `{i['current'][:80]}` · evidence {i['evidence']}", 2900)}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"<{msg['report_link']}|Open report>"}]})
    r = httpx.post(url, json={"text": msg["title"], "blocks": blocks[:50]}, timeout=20)
    r.raise_for_status()


CHANNELS = {"email": send_email, "telegram": send_telegram, "discord": send_discord, "slack": send_slack}


def notify_scan(cfg, db: Database, scan_id: str, channels: list[str] | None = None) -> dict[str, str]:
    results: dict[str, str] = {}
    with db.session() as s:
        scan = s.get(Scan, scan_id)
        target = s.get(Target, scan.target_id)
        fresh, dup = select_changes(s, cfg, scan_id)
        enabled = [c for c in CHANNELS if cfg.get(f"notifications.{c}.enabled") and (not channels or c in channels)]
        if not fresh:
            for ch in enabled:
                s.add(NotificationLog(scan_id=scan_id, channel=ch, status="suppressed",
                                      fingerprints=[c.fingerprint for c in dup], change_ids=[c.id for c in dup],
                                      preview=f"no new changes ({len(dup)} duplicate(s) suppressed)"))
                results[ch] = "suppressed"
            return results
        msg = build_message(cfg, scan, target, fresh)
        for ch in enabled:
            try:
                CHANNELS[ch](cfg.get(f"notifications.{ch}", {}), msg)
                status, err = "sent", None
            except Exception as exc:
                status, err = "failed", f"{type(exc).__name__}: {exc}"
            s.add(NotificationLog(scan_id=scan_id, channel=ch, status=status, fingerprints=[c.fingerprint for c in fresh],
                                  change_ids=[c.id for c in fresh], error=err, preview=truncate(msg["text"], 1500)))
            results[ch] = status if not err else f"failed: {err}"
        if any(v == "sent" for v in results.values()):
            for c in fresh:
                c.notified = True
    return results
