"""New modules' parsers/helpers, API key storage, output files and the API's security controls."""
import os

import pytest


# ------------------------------------------------------------------ module helpers
def test_content_discovery_parsers_and_calibration():
    from reconforge.modules.web_discovery import (Calibration, classify_hit, parse_dirb, parse_dirsearch, parse_feroxbuster,
                                                  parse_ffuf, parse_gobuster)

    ffuf = '{"results":[{"url":"https://a.example/admin","status":301,"length":0,"redirectlocation":"/admin/","input":{"FUZZ":"admin"}}]}'
    assert parse_ffuf(ffuf)[0]["redirect"] == "/admin/" and parse_ffuf("not json") == []
    gb = "/admin                (Status: 301) [Size: 169] [--> https://a.example/admin/]\n/.env (Status: 200) [Size: 42]"
    assert [(h["url"], h["status"]) for h in parse_gobuster(gb, "https://a.example")] == \
        [("https://a.example/admin", 301), ("https://a.example/.env", 200)]
    assert parse_dirb("+ https://a.example/x (CODE:200|SIZE:12)\n==> DIRECTORY: https://a.example/d/")[1]["status"] == 301
    assert parse_feroxbuster('{"type":"response","url":"https://a.example/y","status":403,"content_length":5}')[0]["status"] == 403
    assert parse_dirsearch('{"results":[{"url":"https://a.example/z","status":200,"content-length":1}]}')[0]["url"].endswith("/z")
    cal = Calibration()
    cal.add(200, b"<h1>Not found: rf-123</h1>" + b"x" * 500, "rf-123")
    assert cal.is_soft404(200, b"<h1>Not found: admin</h1>" + b"x" * 500, "admin")   # same page echoing the path
    assert not cal.is_soft404(200, b"<html>real admin console" + b"y" * 4000, "admin")
    assert classify_hit("/.git/HEAD", 200)[0] == "low" and classify_hit("/backup.zip", 200)[0] == "medium"
    assert classify_hit("/about", 200) is None and classify_hit("/.env", 404) is None


def test_url_patterns_lookalikes_and_registrable():
    from reconforge.modules.osint_intel import classify_url, dorks_for, lookalikes, redact_query, registrable

    classes, secrets = classify_url("https://a.example/r?next=/x&id=5&token=abcdef123456")
    assert {"redirect", "idor", "sqli", "secrets_in_url"} <= classes and secrets == ["token"]
    assert "abcdef123456" not in redact_query("https://a.example/r?token=abcdef123456&q=1")
    assert "interesting_files" in classify_url("https://a.example/db/backup.sql")[0]
    la = lookalikes("example.com", 400)
    assert "exampel.com" in la and la["example.net"] == "tld-swap" and "example.com" not in la and len(la) <= 400
    assert registrable("cdn.assets.example.co.uk") == "example.co.uk" and registrable("a.b.example.com") == "example.com"
    assert any(d["engine"] == "GitHub" for d in dorks_for("example.com"))


def test_cms_detection():
    from reconforge.modules.web_discovery import detect_cms

    assert detect_cms({}, '<link href="/wp-content/themes/x/style.css">') == "WordPress"
    assert detect_cms({"x-generator": "Drupal 10"}, "<html>") == "Drupal"
    assert detect_cms({}, '<meta name="generator" content="Joomla! - Open Source">') == "Joomla"
    assert detect_cms({}, "<html>plain</html>") is None


# ------------------------------------------------------------------ API keys
def test_api_keys_never_leak_and_reject_dangerous_names(cfg):
    import reconforge.settings as S

    for bad in ("PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "HTTP_PROXY", "RANDOM"):
        with pytest.raises(ValueError):
            S.save_api_keys(cfg, {bad: "x"})
    rows = S.save_api_keys(cfg, {"SHODAN_API_KEY": "s3cr3t-value-123456", "ACME_API_KEY": "abc123abc123"})
    assert os.environ["SHODAN_API_KEY"] == "s3cr3t-value-123456"
    assert "s3cr3t" not in repr(rows) and all(r["hint"] == "" for r in rows)
    assert {r["env"] for r in rows if r["source"] == "dashboard"} == {"SHODAN_API_KEY", "ACME_API_KEY"}
    path = cfg.dir("data_dir") / "settings.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    S.save_api_keys(cfg, clear=["SHODAN_API_KEY", "ACME_API_KEY"])
    assert "SHODAN_API_KEY" not in os.environ or os.environ["SHODAN_API_KEY"] != "s3cr3t-value-123456"


# ------------------------------------------------------------------ output files
def test_output_files_naming_and_traversal(cfg, db):
    from reconforge.core.observation import Obs
    from reconforge.core.pipeline import ensure_target
    from reconforge.correlation.engine import CorrelationEngine
    from reconforge.db.models import Observation, Scan
    from reconforge.outputs import list_files, safe_file, write_scan_outputs
    from reconforge.scope import Scope
    from reconforge.util import new_id, utcnow

    tid, target = ensure_target(db, cfg, "t")
    with db.session() as s:
        s.add(Scan(id="scn_0123456789abcdef", target_id=tid, profile="standard", status="completed", started_at=utcnow()))
        s.flush()
        eng = CorrelationEngine(s, cfg, Scope.from_target(target), tid, "scn_0123456789abcdef")
        for h in ("a.example.test", "b.example.test"):
            eng.ingest(Obs("subdomain", h, {"resolved": True}, source="subfinder"), "subfinder")
        eng.ingest(Obs("finding", "r|a.example.test", {"severity": "high", "title": "T", "subject": "a.example.test", "rule": "r"}), "nuclei")
    root = write_scan_outputs(cfg, db, "scn_0123456789abcdef")
    paths = {f["path"] for f in list_files(root)}
    assert {"00_INDEX.txt", "all/subdomains.txt", "modules/subfinder/subfinder_subdomains.txt", "findings/high.txt"} <= paths
    assert (root / "modules/subfinder/subfinder_subdomains.txt").read_text().split() == ["a.example.test", "b.example.test"]
    assert cfg.dir("data_dir") in root.parents   # inside the git-ignored data dir
    for evil in ("../../etc/passwd", "/etc/passwd", "all/../../x"):
        with pytest.raises(FileNotFoundError):
            safe_file(root, evil)


# ------------------------------------------------------------------ API security
@pytest.fixture
def client(cfg):
    from fastapi.testclient import TestClient

    from reconforge.api.app import create_app

    return TestClient(create_app(cfg))


def test_security_headers_and_json_errors(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"):
        assert h in r.headers
    assert "script-src 'self'" in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
    assert client.get("/api/scans/nope/modules").status_code == 404
    assert client.get("/api/targets/nope/triage").json()["detail"]


def test_dns_rebinding_and_csrf_are_refused(client):
    assert client.get("/api/meta", headers={"Host": "attacker.example"}).status_code == 403
    assert client.get("/api/meta", headers={"Host": "127.0.0.1:8765"}).status_code == 200
    r = client.put("/api/settings/keys", json={"keys": {"SHODAN_API_KEY": "x" * 12}}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.put("/api/settings/keys", json={"keys": {}}, headers={"Origin": "null"}).status_code == 403
    ok = client.put("/api/settings/keys", json={"keys": {}, "clear": []}, headers={"Origin": "http://testserver"})
    assert ok.status_code == 200 and all("value" not in row for row in ok.json())


def test_token_is_enforced_when_configured(cfg, monkeypatch):
    from fastapi.testclient import TestClient

    from reconforge.api.app import create_app

    monkeypatch.setenv("RECONFORGE_API_TOKEN", "tok-123456")
    c = TestClient(create_app(cfg))
    assert c.get("/api/meta").status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer tok-123456"}).status_code == 200


def test_triage_workflow(client, cfg, db):
    from reconforge.core.observation import Obs
    from reconforge.core.pipeline import ensure_target
    from reconforge.correlation.engine import CorrelationEngine
    from reconforge.db.models import Asset, Scan
    from reconforge.scope import Scope
    from reconforge.util import utcnow

    tid, target = ensure_target(db, cfg, "t")
    with db.session() as s:
        s.add(Scan(id="scn_aaaaaaaaaaaaaaaa", target_id=tid, profile="standard", status="completed", started_at=utcnow()))
        s.flush()
        eng = CorrelationEngine(s, cfg, Scope.from_target(target), tid, "scn_aaaaaaaaaaaaaaaa")
        eng.ingest(Obs("finding", "x|a.example.test", {"severity": "high", "title": "High", "subject": "a.example.test", "host": "a.example.test"}), "m")
        eng.ingest(Obs("finding", "y|a.example.test", {"severity": "low", "title": "Low", "subject": "a.example.test", "host": "a.example.test"}), "m")
    items = client.get("/api/targets/t/triage").json()["items"]
    assert [i["severity"] for i in items] == ["high", "low"] and items[0]["status"] == "new"
    assert client.post(f"/api/assets/{items[0]['id']}/triage", json={"status": "bogus"}).status_code == 400
    r = client.post(f"/api/assets/{items[0]['id']}/triage", json={"status": "false_positive", "note": "lab", "ids": [items[1]["id"]]})
    assert r.json()["updated"] == 2
    with db.session() as s:
        assert s.get(Asset, items[0]["id"]).false_positive
    after = {i["id"]: i for i in client.get("/api/targets/t/triage").json()["items"]}
    assert after[items[0]["id"]]["status"] == "false_positive" and after[items[0]["id"]]["note"] == "lab"


def test_gitignore_keeps_scan_data_out_and_source_in():
    import shutil
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    if not shutil.which("git") or not (root / ".git").exists():
        pytest.skip("not a git checkout")

    def ignored(path):
        return subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=root).returncode == 0

    for p in ("data/reconforge.db", "data/settings.json", "data/output/x/00_INDEX.txt", "data/evidence/s/e.txt",
              "data/logs/scn.log", "data/work/s/ferox.state", "config/reconforge.yaml", "lab/runtime/x.db",
              "reconforge-example-subdomains.csv", ".env"):
        assert ignored(p), f"{p} must be git-ignored"
    for p in ("reconforge/data/tools.yaml", "reconforge/data/wordlists/content.txt", "reconforge/reports/data.py",
              "config/reconforge.example.yaml", "install.sh", "frontend/src/App.jsx"):
        assert not ignored(p), f"{p} must be committed"


def test_home_and_project_paths_are_hidden_in_api_output(tmp_path):
    from reconforge.api.app import hide_home, set_hidden_paths

    home = os.path.expanduser("~")
    project = str(tmp_path / "work" / "ReconForge")
    old_case = str(tmp_path / "work" / "reconforge")   # same folder on a case-insensitive disk (renamed, or cd'd into)
    set_hidden_paths(project)
    try:
        out = hide_home(f'{{"path": "{home}/go/bin/subfinder", "log": "{project}/data/logs/s.log", "other": "{home}x/y", '
                        f'"old": "{old_case}/data/reports/r.html"}}'.encode())
    finally:
        set_hidden_paths(None)
    assert b'"~/go/bin/subfinder"' in out and b'"./data/logs/s.log"' in out and f"{home}/".encode() not in out
    assert b'"./data/reports/r.html"' in out
    assert f"{home}x/y".encode() in out   # only exact directories are replaced


def test_notification_settings_are_write_only(client, cfg):
    r = client.put("/api/settings/notifications", json={"channels": {"slack": {"secret": "http://insecure.example"}}})
    assert r.status_code == 400
    r = client.put("/api/settings/notifications", json={"enabled": True, "min_significance": "medium", "channels": {
        "discord": {"enabled": True, "secret": "https://discord.example/api/webhooks/1/abc"},
        "email": {"smtp_host": "smtp.example.com", "smtp_port": 2525, "to": "a@example.com, b@example.com", "secret": "pw-123"}}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "discord.example" not in r.text and "pw-123" not in r.text
    assert body["enabled"] and body["min_significance"] == "medium"
    assert body["channels"]["discord"] == {"enabled": True, "secret_set": True}
    assert body["channels"]["email"]["to"] == ["a@example.com", "b@example.com"] and body["channels"]["email"]["secret_set"]
    assert cfg.get("notifications.discord.webhook_url").startswith("https://discord.example")   # applied for the next scan
    assert client.put("/api/settings/notifications", json={"channels": {"email": {"to": "not-an-address"}}}).status_code == 400
    assert client.put("/api/settings/notifications", json={"channels": {"pager": {"enabled": True}}}).status_code == 400
    r = client.put("/api/settings/notifications", json={"channels": {"discord": {"clear_secret": True, "enabled": False}}})
    assert r.json()["channels"]["discord"] == {"enabled": False, "secret_set": False}


def test_burp_scope_export():
    import json

    from reconforge.api.exports import burp_scope_json

    doc = json.loads(burp_scope_json({"root_domains": ["example.com"], "ip_targets": ["192.0.2.8/30", "198.51.100.7"],
                                      "scope": {"include": ["*.example.com"], "exclude": ["legacy.example.com"]}}))
    inc = [r["host"] for r in doc["target"]["scope"]["include"]]
    assert inc[0] == r"^(.*\.)?example\.com$" and len(inc) == 3   # *.example.com is not repeated
    assert inc[1] == r"^(192\.0\.2\.8|192\.0\.2\.9|192\.0\.2\.10|192\.0\.2\.11)$" and inc[2] == r"^198\.51\.100\.7$"
    assert doc["target"]["scope"]["exclude"][0]["host"] == r"^legacy\.example\.com$"
