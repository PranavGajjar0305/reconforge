"""Scheduler, AI evidence guard/providers, notifications, plugins, storage."""
import json
import types
from datetime import datetime

import pytest

from reconforge.ai.analyst import AnthropicProvider, EvidenceGuard, HeuristicProvider, OUTPUT_SCHEMA
from reconforge.scheduler.service import CronExpr, compute_next, frequency_to_cron, run_due, upsert_schedule


# ------------------------------------------------------------------ scheduler
def test_cron_next_runs():
    c = CronExpr("30 2 * * *")
    assert c.next_after(datetime(2026, 1, 1, 3, 0)) == datetime(2026, 1, 2, 2, 30)
    assert CronExpr("0 9 * * mon").next_after(datetime(2026, 11, 21, 0, 0)) == datetime(2026, 11, 23, 9, 0)  # Sat -> Mon
    assert CronExpr("*/15 * * * *").next_after(datetime(2026, 1, 1, 0, 7)) == datetime(2026, 1, 1, 0, 15)
    assert CronExpr("0 3 1 * *").next_after(datetime(2026, 1, 15)) == datetime(2026, 2, 1, 3, 0)
    with pytest.raises(ValueError):
        CronExpr("61 * * * *")


def test_frequency_mapping():
    assert frequency_to_cron("daily", "02:30") == "30 2 * * *"
    assert frequency_to_cron("weekly", "03:00", "fri") == "0 3 * * 5"
    assert frequency_to_cron("monthly", "04:00", 15) == "0 4 15 * *"
    assert frequency_to_cron("once") == "once"


def test_run_due_executes_and_reschedules(cfg, db):
    upsert_schedule(db, name="d", target="t", frequency="daily", at="02:00")
    upsert_schedule(db, name="o", target="t", frequency="once", run_at=datetime(2000, 1, 1))
    from reconforge.db.models import Schedule

    with db.session() as s:
        s.query(Schedule).filter_by(name="d").one().next_run_at = datetime(2000, 1, 1)
    calls = []
    res = run_due(cfg, db, runner=lambda opts: calls.append(opts) or f"scn_{len(calls)}")
    assert len(calls) == 2 and all(o.trigger == "schedule" for o in calls)
    with db.session() as s:
        d = s.query(Schedule).filter_by(name="d").one()
        o = s.query(Schedule).filter_by(name="o").one()
        assert d.next_run_at > datetime(2026, 1, 1) and d.last_scan_id
        assert o.enabled is False and o.next_run_at is None
    assert run_due(cfg, db, runner=lambda o: "x") == []  # nothing due any more


# ------------------------------------------------------------------- AI guard
PACK = {
    "hosts": [{"id": "ast_h1", "type": "subdomain", "key": "api.example.test", "evidence": "ev_1", "ips": ["192.0.2.5"]}],
    "services": [{"id": "ast_s1", "type": "service", "key": "192.0.2.5:22/tcp", "port": 22}],
    "findings": [{"id": "ast_f1", "type": "finding", "key": "cve.x", "cves": ["CVE-2021-23017"]}],
    "module_runs": [{"id": "module:crtsh", "status": "completed"}],
}


def test_guard_accepts_supported_statements():
    g = EvidenceGuard(PACK)
    ok = {"statement": "api.example.test resolves to 192.0.2.5 and exposes port 22.", "kind": "fact", "refs": ["ast_h1", "ev_1"]}
    assert g.check(ok) is None
    assert g.check({"statement": "CVE-2021-23017 may apply.", "kind": "hypothesis", "refs": ["ast_f1"]}) is None


@pytest.mark.parametrize("item,reason", [
    ({"statement": "admin.example.test is exposed", "kind": "fact", "refs": ["ast_h1"]}, "hostname"),
    ({"statement": "Host 203.0.113.9 is live", "kind": "fact", "refs": ["ast_h1"]}, "IP address"),
    ({"statement": "port 3389 is open", "kind": "fact", "refs": ["ast_s1"]}, "port"),
    ({"statement": "Vulnerable to CVE-2024-6387", "kind": "hypothesis", "refs": ["ast_f1"]}, "CVE"),
    ({"statement": "Something", "kind": "fact", "refs": ["ast_unknown"]}, "unknown evidence"),
    ({"statement": "Something", "kind": "fact", "refs": []}, "no evidence"),
    ({"statement": "Something", "kind": "opinion", "refs": ["ast_h1"]}, "kind"),
])
def test_guard_rejects_fabrication(item, reason):
    assert reason in EvidenceGuard(PACK).check(item)


def test_guard_filter_splits_results():
    clean, rejected = EvidenceGuard(PACK).filter({
        "executive_summary": [{"statement": "One host: api.example.test.", "kind": "fact", "refs": ["ast_h1"]},
                              {"statement": "Also secret.example.test.", "kind": "fact", "refs": ["ast_h1"]}]})
    assert len(clean["executive_summary"]) == 1 and len(rejected) == 1


def test_anthropic_provider_request_shape(monkeypatch):
    captured = {}
    payload = {k: [] for k in OUTPUT_SCHEMA["required"]}
    payload["executive_summary"] = [{"statement": "x", "kind": "fact", "refs": ["ast_h1"]}]

    class FakeMessages:
        def create(self, **kw):
            captured.update(kw)
            return types.SimpleNamespace(stop_reason="end_turn", model="claude-opus-5-5",
                                         content=[types.SimpleNamespace(type="text", text=json.dumps(payload))])

    fake = types.SimpleNamespace(beta=types.SimpleNamespace(messages=FakeMessages()))
    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda: fake)
    out = AnthropicProvider().analyze(PACK)
    assert out["executive_summary"][0]["refs"] == ["ast_h1"]
    assert captured["model"] == "claude-opus-5-5"
    assert captured["output_config"]["format"]["type"] == "json_schema"
    assert captured["fallbacks"] == "default" and "server-side-fallback-2026-07-01" in captured["betas"]
    assert "thinking" not in captured  # adaptive by default on this model


def test_anthropic_refusal_raises(monkeypatch):
    class FakeMessages:
        def create(self, **kw):
            return types.SimpleNamespace(stop_reason="refusal", stop_details=None, content=[])

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda: types.SimpleNamespace(beta=types.SimpleNamespace(messages=FakeMessages())))
    with pytest.raises(RuntimeError):
        AnthropicProvider().analyze(PACK)


# --------------------------------------------------------------- plugins
def test_plugin_loading_without_core_changes(tmp_path):
    p = tmp_path / "myplug.py"
    p.write_text("from reconforge.core.module import Module, register\n"
                 "@register\nclass Hello(Module):\n    name='hello_plugin'\n    def run(self, ctx): pass\n")
    from reconforge.core.module import load_modules

    reg = load_modules([str(p)])
    assert "hello_plugin" in reg and "dns_resolve" in reg
