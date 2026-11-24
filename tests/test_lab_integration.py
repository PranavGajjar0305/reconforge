"""End-to-end integration against the controlled lab (lab/lab_server.py).

Starts the lab (phase 1), runs a comprehensive scan, restarts the lab in phase 2,
scans again and verifies discovery, correlation, change detection, notifications,
reports, AI guard, storage and the dashboard API. Skipped if lab ports are busy.
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAB_PORTS = [8080, 8443, 8099, 2222, 2525, 9200]


def _busy(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


pytestmark = pytest.mark.skipif(any(_busy(p) for p in LAB_PORTS), reason="lab ports in use")


def _start(phase):
    p = subprocess.Popen([sys.executable, str(ROOT / "lab" / "lab_server.py"), "--phase", str(phase)]
                         + (["--reset-sinks"] if phase == 1 else []), stdout=subprocess.PIPE, text=True)
    assert "lab running" in p.stdout.readline()
    return p


@pytest.fixture(scope="module")
def lab_run(tmp_path_factory):
    from reconforge.config import load_config
    from reconforge.core.pipeline import ScanOptions, run_scan
    from reconforge.db import Database

    tmp = tmp_path_factory.mktemp("lab")
    os.environ["LAB_TELEGRAM_TOKEN"] = "000:test"
    cfg = load_config(str(ROOT / "config" / "lab.yaml"), overrides={
        "database": {"url": f"sqlite:///{tmp}/lab.db"},
        "storage": {k: str(tmp / k) for k in ("data_dir", "evidence_dir", "reports_dir", "backups_dir", "logs_dir")},
        "screenshots": {"chrome_path": "/nonexistent"},  # keep the test fast and browser-independent
        "tools": {"lab-subenum": {"path": str(ROOT / "lab" / "bin" / "lab-subenum")}},
    })
    db = Database(cfg.database_url)
    lab = _start(1)
    try:
        s1 = run_scan(cfg, ScanOptions(target="acme-lab"), db)
    finally:
        lab.terminate(); lab.wait()
    lab = _start(2)
    try:
        s2 = run_scan(cfg, ScanOptions(target="acme-lab"), db)
        s3 = run_scan(cfg, ScanOptions(target="acme-lab", profile="continuous", incremental=True), db)
    finally:
        lab.terminate(); lab.wait()
    return cfg, db, s1, s2, s3


def test_discovery_and_correlation(lab_run):
    from reconforge.db.models import Asset

    cfg, db, s1, *_ = lab_run
    with db.session() as s:
        keys = {(a.type, a.key) for a in s.query(Asset).all()}
        assert ("subdomain", "internal-admin.acme.test") in keys       # found only via TLS SAN -> rediscovery pass
        assert ("subdomain", "jenkins.acme.test") in keys              # public code reference
        assert ("web_app", "https://api.acme.test:8443") in keys
        assert ("endpoint", "https://api.acme.test:8443/v1/admin/export") in keys  # from OpenAPI, never requested
        assert ("endpoint", "wss://api.acme.test:8443/ws/notifications") in keys    # from JavaScript
        assert ("cloud_resource", "aws:s3:acme-assets-prod") in keys
        assert ("service", "127.0.0.1:2222/tcp") in keys
        assert ("third_party", "www.googletagmanager.com") in keys
        api = s.query(Asset).filter_by(type="subdomain", key="api.acme.test").one()
        assert len(api.sources) >= 3 and api.confidence > 0.95
        # shared IP: many hosts, one IP asset, hosts not merged
        assert s.query(Asset).filter_by(type="ip").count() == 1
        assert s.query(Asset).filter(Asset.type == "subdomain").count() >= 8
        # default-vhost responses are not recorded as applications
        assert ("web_app", "http://mail.acme.test:8080") not in keys


def test_expansion_intelligence(lab_run):
    from reconforge.db.models import Asset, Scan
    from reconforge.reports.data import build_report_data

    cfg, db, s1, s2, s3 = lab_run
    with db.session() as s:
        hosts = {a.key: {x["source"] for x in a.sources} for a in s.query(Asset).filter_by(type="subdomain")}
        assert "dns_bruteforce" in hosts["vpn.acme.test"]            # wordlist brute force
        assert "dns_permutation" in hosts["staging-api.acme.test"]   # permutation of discovered label
        assert "otx" in hosts["shop.acme.test"]                     # passive provider (emulated)
        assert "lab-subenum" in hosts["cdn-origin.acme.test"]       # registry-driven external tool
        d = build_report_data(s, s2)
    comp = {c["source"]: c for c in d["source_comparison"]}
    assert comp["dns_bruteforce"]["unique"] >= 1 and comp["otx"]["unique"] >= 1
    dns = d["dns_infrastructure"][0]
    assert dns["dkim_selectors_found"] == ["google"] and dns["dnssec"] == "unsigned" and dns["registration"]["registrar"]
    ident = {i["app"]: i for i in d["identity"]}["https://internal-admin.acme.test:8443"]
    assert "Okta" in ident["providers"] and ident["password_reset"]
    assert "identity" in d["third_party_inventory"] and "payments" in d["third_party_inventory"]
    assert [e["key"] for e in d["documents"]] == ["https://www.acme.test:8443/files/annual-report-2025.pdf"]
    keys = {e["key"] for e in d["endpoints"]}
    assert "https://www.acme.test:8443/.well-known/security.txt" in keys and "https://www.acme.test:8443/careers" in keys
    assert {"limit", "offset", "q"} <= {p["name"] for p in d["parameter_inventory"]}
    rules = {f["attributes"]["rule"] for f in d["findings"]}
    assert {"web.default_page", "exposure.indexed_ports", "dns.dnssec_unsigned", "email.mta_sts_missing"} <= rules
    # extended surface modules
    assert {"exposure.git_head", "exposure.env", "exposure.source_map", "panel.jenkins"} <= rules
    # web discovery + OSINT modules
    with db.session() as s:
        eps = {e.key: e.attributes for e in s.query(Asset).filter_by(type="endpoint")}
        found = {k for k, v in eps.items() if "content_discovery" in (v.get("discovered_via") or [])}
        assert "https://www.acme.test:8443/about" in found and "http://dev.acme.test:8080/.env" in found
        apps = {a.key: a.attributes for a in s.query(Asset).filter_by(type="web_app")}
        assert apps["https://www.acme.test:8443"]["cms"]["name"] == "WordPress"
        assert apps["https://www.acme.test:8443"]["cms"]["version"] == "6.4.2"
        root = s.query(Asset).filter_by(type="domain", key="acme.test").one().attributes
        assert root["url_patterns"].get("parameters") and root["dorks"] and root["lookalikes"]["checked"] > 0
    from reconforge.outputs import list_files, scan_output_dir
    from reconforge.db.models import Scan as _Scan
    with db.session() as s:
        out = scan_output_dir(cfg, s, s.get(_Scan, s2))
    files = {f["path"] for f in list_files(out)}
    assert {"00_INDEX.txt", "all/subdomains.txt", "all/content_discovery.txt", "modules/http_probe/http_probe_web_apps.txt",
            "logs/execution.log"} <= files
    assert not (cfg.dir("work_dir") / s2).exists()   # tool scratch space removed after the scan
    with db.session() as s:
        from reconforge.db.models import Evidence
        stored = [e.content or "" for e in s.query(Evidence).filter_by(module="exposed_files")]
        assert stored and not any("lab-not-a-secret" in c for c in stored)   # secret values are never stored
    cov = d["coverage"]
    assert cov["level"] == "partial" and "securitytrails" in cov["unavailable_sources"]
    assert cov["phases"]["resolve"]["status"] == "completed"
    assert cov["metrics"]["technologies_identified"] > 0 and "not a guarantee" in cov["statement"]


def test_change_detection(lab_run):
    from reconforge.db.models import Change, Scan

    cfg, db, s1, s2, s3 = lab_run
    with db.session() as s:
        assert s.query(Change).filter_by(scan_id=s1).count() == 0  # baseline
        cats = {(c.category, c.asset_display) for c in s.query(Change).filter_by(scan_id=s2)}
        names = {c for c, _ in cats}
        for expected in ["new_subdomain", "new_open_port", "new_web_application", "new_api_endpoint", "new_technology",
                         "tech_version_changed", "security_headers_changed", "certificate_changed", "new_certificate",
                         "new_third_party_integration", "dns_changed", "subdomain_unresolved", "removed_web_application",
                         "resolved_security_observation", "new_security_observation"]:
            assert expected in names, expected
        assert ("new_subdomain", "beta.acme.test") in cats
        assert ("removed_web_application", "http://old.acme.test:8080") in cats
        # incremental scan right after: nothing new, and no false removals
        assert s.query(Change).filter_by(scan_id=s3).count() == 0
        assert s.get(Scan, s3).status == "completed"


def test_notifications_delivered_and_deduplicated(lab_run):
    from reconforge.db.models import NotificationLog

    cfg, db, s1, s2, s3 = lab_run
    with db.session() as s:
        sent = {n.channel for n in s.query(NotificationLog).filter_by(scan_id=s2, status="sent")}
        assert sent == {"email", "telegram", "discord", "slack"}
        assert {n.status for n in s.query(NotificationLog).filter_by(scan_id=s3)} <= {"suppressed"}
    received = [json.loads(l) for l in (ROOT / "lab" / "runtime" / "notifications.jsonl").read_text().splitlines()]
    assert {r["channel"] for r in received} >= {"email", "telegram", "discord", "slack"}


def test_scanner_only_sends_safe_methods(lab_run):
    """ReconForge's own reconnaissance never sends anything but GET/HEAD to a target.

    (Nuclei is a separate, authorization-gated active engine that runs third-party detection
    templates; those may use other HTTP methods and are tested as the explicit exception below.)
    """
    from reconforge.config import load_config
    from reconforge.core.pipeline import ScanOptions, run_scan
    from reconforge.db import Database

    cfg, _db, *_ = lab_run
    log = ROOT / "lab" / "runtime" / "unexpected_methods.log"
    log.unlink(missing_ok=True)
    tmp = ROOT / "lab" / "runtime" / "safe-methods.db"
    tmp.unlink(missing_ok=True)
    cfg2 = load_config(str(ROOT / "config" / "lab.yaml"), overrides={
        "database": {"url": f"sqlite:///{tmp}"},
        "storage": {k: str(ROOT / "lab" / "runtime" / f"sm_{k}") for k in ("data_dir", "evidence_dir", "reports_dir", "backups_dir", "logs_dir")},
        "screenshots": {"chrome_path": "/nonexistent"},
    })
    db2 = Database(cfg2.database_url)
    lab = _start(2)
    try:  # comprehensive recon with Nuclei explicitly excluded: only built-in probing runs
        run_scan(cfg2, ScanOptions(target="acme-lab", profile="comprehensive", skip=["nuclei"]), db2)
    finally:
        lab.terminate(); lab.wait()
    assert not log.exists() or not log.read_text().strip(), \
        f"built-in recon sent non-GET/HEAD methods:\n{log.read_text()[:1000]}"


def test_reports_all_formats(lab_run):
    from reconforge.db.models import Scan

    cfg, db, s1, s2, s3 = lab_run
    with db.session() as s:
        d = Path(s.get(Scan, s2).report_dir)
    for f in ("report.md", "report.html", "report.json", "report.pdf", "findings.csv", "changes.csv", "graph.graphml", "graph.dot"):
        assert (d / f).stat().st_size > 0, f
    assert (d / "report.pdf").read_bytes()[:4] == b"%PDF"
    md = (d / "report.md").read_text()
    assert "## Historical changes" in md and "beta.acme.test" in md
    from reconforge.reports.builder import generate_reports

    out = generate_reports(cfg, db, s2, formats=["markdown"], sections={"cve": False}, out_dir=d / "partial")
    assert "## CVE intelligence" not in Path(out["markdown"]).read_text()


def test_ai_heuristic_and_fallback(lab_run):
    from reconforge.ai.analyst import analyze_scan
    from reconforge.db.models import AIAnalysis

    cfg, db, s1, s2, s3 = lab_run

    class Fabricator:
        name, model = "fake", "fake-1"

        def analyze(self, pack):
            return {"executive_summary": [
                {"statement": "Host vpn.acme.test exposes RDP on port 3389.", "kind": "fact", "refs": [pack["hosts"][0]["id"]]},
                {"statement": f"{pack['hosts'][0]['key']} was catalogued.", "kind": "fact", "refs": [pack["hosts"][0]["id"]]}]}

    class Broken:
        name, model = "broken", "x"

        def analyze(self, pack):
            raise ConnectionError("no network")

    with db.session() as s:
        pass
    a1 = analyze_scan(cfg, db, s2, Fabricator())
    a2 = analyze_scan(cfg, db, s2, Broken())
    with db.session() as s:
        r1, r2 = s.get(AIAnalysis, a1), s.get(AIAnalysis, a2)
        assert len(r1.result["executive_summary"]) == 1 and len(r1.rejected) == 1
        assert r2.status == "fallback" and "no network" in r2.error and r2.result["executive_summary"]
        assert not r2.rejected  # heuristic output passes the guard


def test_api_endpoints(lab_run):
    from fastapi.testclient import TestClient

    from reconforge.api.app import create_app

    cfg, db, *_ = lab_run
    c = TestClient(create_app(cfg))
    ov = c.get("/api/targets/acme-lab/overview").json()
    assert ov["overview"]["subdomains"] >= 8
    inv = c.get("/api/targets/acme-lab/inventory").json()
    assert any(r["host"] == "api.acme.test" and 8443 in r["open_ports"] for r in inv)
    g = c.get("/api/targets/acme-lab/graph").json()
    assert g["stats"]["inferred_edges"] > 0 and g["stats"]["confirmed_edges"] > 0
    assert any(n["data"]["type"] == "third_party" for n in g["nodes"])
    assert c.get("/api/targets/acme-lab/graph?format=graphml").status_code == 200
    fid = next(a["id"] for a in c.get("/api/targets/acme-lab/assets?type=finding").json())
    assert c.post(f"/api/assets/{fid}/false-positive", json={"false_positive": True, "reason": "test"}).json()["false_positive"]
    assert c.get(f"/api/assets/{fid}").json()["false_positive"] is True
    assert len(c.get("/api/scans?target=acme-lab").json()) == 3


def test_storage_backup_export_import_retention(lab_run, tmp_path):
    from reconforge.db import Database
    from reconforge.db.models import Asset
    from reconforge.storage.maintenance import apply_retention, backup, export_json, import_json

    cfg, db, *_ = lab_run
    assert backup(cfg, db).stat().st_size > 0
    out = export_json(db, tmp_path / "e.json", "acme-lab")
    db2 = Database(f"sqlite:///{tmp_path}/copy.db")
    counts = import_json(db2, out)
    assert counts["assets"] > 50
    with db2.session() as s:
        assert s.query(Asset).filter_by(key="beta.acme.test").count() == 1
    r = apply_retention(cfg, db, days=0, keep_min=1, dry_run=True)
    assert len(r["scans_removed"]) == 2 and r["dry_run"]


def test_dashboard_targets_runs_actions_and_ai(lab_run, monkeypatch):
    """Dashboard workflow: create a target, run a single action in the background, stream its log,
    configure an OpenAI-compatible provider and import an external answer through the guard."""
    import time

    import httpx
    from fastapi.testclient import TestClient

    from reconforge.api.app import create_app

    cfg, db, s1, s2, s3 = lab_run
    c = TestClient(create_app(cfg))
    # target validation and the authorization checkbox gate
    assert c.post("/api/targets", json={"name": "bad name!", "root_domains": ["x"]}).status_code == 400
    r = c.post("/api/targets", json={"name": "dash-t", "targets": ["acme.test"], "authorization": {"confirmed": False}})
    assert r.status_code == 200 and r.json()["source"] == "dashboard"
    assert any(t["name"] == "dash-t" and not t["authorized"] for t in c.get("/api/meta").json()["targets"])
    blocked = c.post("/api/scans", json={"target": "dash-t", "profile": "standard"})
    assert blocked.status_code == 400 and "authoriz" in blocked.json()["detail"]
    ok = c.post("/api/targets", json={"name": "dash-t", "targets": ["acme.test"], "authorization": {"confirmed": True}})
    assert ok.json()["authorization"]["confirmed"]
    from reconforge.core.pipeline import ScanOptions
    assert "http_probe" in c.app.state.manager.preflight(ScanOptions(target="dash-t", profile="standard"))["modules"]
    # single action on an existing target (no network: analyses stored data)
    acts = {a["id"]: a for a in c.get("/api/actions?target=acme-lab").json()}
    assert acts["module:cve_intel"]["runnable"] and not acts["tool:masscan"]["runnable"]
    run = c.post("/api/actions/run", json={"target": "acme-lab", "action_id": "module:cve_intel"}).json()
    sid = run["scan_id"]
    for _ in range(100):
        p = c.get(f"/api/scans/{sid}/progress").json()
        if p["status"] not in ("starting", "running"):
            break
        time.sleep(0.1)
    assert p["status"] == "completed" and p["planned"] == ["cve_intel"]
    body = c.get(f"/api/scans/{sid}/stream").text
    assert "[cve_intel] starting" in body and "event: done" in body
    # latest-scan views ignore single-action runs
    assert c.get("/api/targets/acme-lab/overview").json()["scan"]["id"] == s3
    # AI settings: key is stored but never returned
    st = c.put("/api/settings", json={"ai": {"provider": "openai_compatible", "model": "m", "base_url": "http://llm.local/v1",
                                            "api_key": "sk-secret"}}).json()
    assert st["ai"]["api_key"] == "********" and st["ai"]["api_key_set"]
    assert c.post(f"/api/scans/{s2}/analyze", json={"consent": False}).status_code == 400  # consent required

    def fake_post(url, json=None, headers=None, timeout=None):
        assert url == "http://llm.local/v1/chat/completions" and headers["Authorization"] == "Bearer sk-secret"
        pack = __import__("json").loads(json["messages"][1]["content"].split("Evidence pack:\n", 1)[1])
        fid = pack["findings"][0]["id"]
        answer = {"top_priorities": [{"statement": "Look at this first.", "kind": "fact", "refs": [fid], "priority": "high",
                                      "rationale": "Medium observation."},
                                     {"statement": "evil.acme.test is open", "kind": "fact", "refs": [fid], "priority": "critical",
                                      "rationale": "made up"}]}
        return httpx.Response(200, json={"model": "m", "choices": [{"finish_reason": "stop", "message": {"content": __import__("json").dumps(answer)}}]})

    monkeypatch.setattr(httpx, "post", fake_post)
    res = c.post(f"/api/scans/{s2}/analyze", json={"consent": True}).json()
    assert res["provider"] == "openai_compatible" and len(res["result"]["top_priorities"]) == 1
    assert res["result"]["top_priorities"][0]["priority"] == "high" and len(res["rejected"]) == 1
    # copy/paste flow: bundle + import through the guard
    b = c.get(f"/api/scans/{s2}/ai-bundle").json()
    assert "Evidence pack" in b["prompt"] and b["output_schema"]["required"][0] == "top_priorities"
    imp = c.post(f"/api/scans/{s2}/ai-import", json={"answer": '```json\n{"executive_summary": [{"statement": "x", "kind": "fact", "refs": ["nope"]}]}\n```'}).json()
    assert imp["provider"] == "manual import" and imp["rejected"][0]["reason"].startswith("unknown evidence")
    c.put("/api/settings", json={"ai": {"provider": "heuristic", "clear_api_key": True}})


def test_cancelled_run(lab_run):
    import threading

    from reconforge.core.pipeline import ScanOptions, run_scan
    from reconforge.db.models import Scan

    cfg, db, *_ = lab_run
    ev = threading.Event()
    ev.set()
    sid = run_scan(cfg, ScanOptions(target="acme-lab", modules=["cve_intel", "cloud_intel"], cancel=ev, reports=False, notify=False), db)
    with db.session() as s:
        sc = s.get(Scan, sid)
        assert sc.status == "cancelled" and sc.modules_completed == []


def test_multi_target_scan_domains_and_ips(lab_run):
    """One scan, several targets of mixed kinds: every module runs against the domain and the IP."""
    from reconforge.core.pipeline import ScanOptions, run_scan
    from reconforge.db.models import Asset, ModuleRun
    from reconforge.targets import save_target

    cfg, db, *_ = lab_run
    save_target(cfg, db, {"name": "mixed-lab", "targets": ["acme.test", "127.0.0.1", "https://www.acme.test:8443/x"],
                          "authorization": {"confirmed": True, "reference": "lab"}})
    save_target(cfg, db, {"name": "ip-only-lab", "targets": ["127.0.0.1/32"], "authorization": {"confirmed": True}})
    mods = ["crtsh", "dns_resolve", "port_scan", "http_probe", "tls_inspect", "waf_detect", "security_config", "panel_detect"]
    lab = _start(2)
    try:
        mixed = run_scan(cfg, ScanOptions(target="mixed-lab", modules=mods, reports=False, notify=False), db)
        only_ip = run_scan(cfg, ScanOptions(target="ip-only-lab", modules=mods, reports=False, notify=False), db)
    finally:
        lab.terminate(); lab.wait()
    with db.session() as s:
        def keys(scan_id, t):
            from reconforge.db.models import Scan
            tid = s.get(Scan, scan_id).target_id
            return {a.key for a in s.query(Asset).filter_by(target_id=tid, type=t)}
        # domain side still works
        assert "www.acme.test" in keys(mixed, "subdomain") and "https://www.acme.test:8443" in keys(mixed, "web_app")
        # IP side: probed directly as a host, never stored as a (sub)domain
        for sid in (mixed, only_ip):
            assert "http://127.0.0.1:8080" in keys(sid, "web_app")
            assert "127.0.0.1:2222/tcp" in keys(sid, "service")
            assert "127.0.0.1" in keys(sid, "ip")
            assert not any(k[0].isdigit() for k in keys(sid, "subdomain"))
        runs = {r.module: r for r in s.query(ModuleRun).filter_by(scan_id=only_ip)}
        assert runs["crtsh"].status == "skipped" and "no domain targets" in runs["crtsh"].skip_reason
        assert runs["http_probe"].status == "completed" and runs["port_scan"].status == "completed"


def test_target_entry_parsing():
    import pytest as _pt
    from reconforge.targets import split_targets, validate_target

    d, ips, errors = split_targets("example.com, https://a.example.org/x 10.0.0.1 10.0.0.0/30\n[2001:db8::1] 1.2.3.4:8443 nope 10.0.0.0/8")
    assert d == ["a.example.org", "example.com"] and "10.0.0.0/30" in ips and "2001:db8::1" in ips and "1.2.3.4" in ips
    assert len(errors) == 2  # 'nope' and the oversized range
    t = validate_target({"name": "x", "targets": ["192.0.2.0/29"]})
    assert t["root_domains"] == [] and t["ip_targets"] == ["192.0.2.0/29"]
    with _pt.raises(ValueError):
        validate_target({"name": "x", "targets": []})
