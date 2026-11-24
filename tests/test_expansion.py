"""Expansion modules: registry/selection, providers, classification, DNS techniques, HTTP intel, visual hashing."""
import json

import httpx
import pytest

from reconforge.correlation.classify import classify_third_party, query_params, url_categories
from reconforge.core.registry import load_registry, render_command, tool_status
from reconforge.modules.dns_extra import permutations, spf_lookups
from reconforge.modules.external_tools import extract_hostnames
from reconforge.modules import providers as P
from reconforge.modules.web_intel import csp_details, hsts_details


def test_url_categories_are_functional_labels():
    assert url_categories("https://a.example.test/login") == ["authentication"]
    assert "administrative" in url_categories("https://a.example.test/admin/users")
    assert "upload" in url_categories("https://a.example.test/api/upload")
    assert "dev_staging" in url_categories("https://staging.example.test/x")
    assert url_categories("https://a.example.test/about-us") == ["other"]
    assert query_params("https://a.example.test/s?q=&page=") == ["page", "q"]


def test_third_party_classification():
    assert classify_third_party("js.stripe.com") == ("payments", "Stripe")
    assert classify_third_party("acme.okta.com") == ("identity", "Okta")
    assert classify_third_party("o123.ingest.sentry.io")[0] == "error_tracking"
    assert classify_third_party("bucket.s3.amazonaws.com")[0] == "cloud_hosting"
    assert classify_third_party("unknown.example")[0] == "external"


def test_registry_and_selection(cfg, monkeypatch):
    cfg.data.setdefault("tools", {})["amass"] = {"enabled": "auto", "path": "/nonexistent/amass"}  # independent of this machine
    reg = {e["name"]: e for e in load_registry(cfg)}
    for name in ("amass", "findomain", "masscan", "sublist3r", "crobat", "trufflehog", "cloud_enum"):
        assert name in reg
    assert tool_status(reg["masscan"], cfg).selected is False  # reference only
    st = tool_status(reg["cloud_enum"], cfg)
    assert not st.selected and ("opt-in" in st.reason or "not installed" in st.reason)
    assert "not installed" in tool_status(reg["amass"], cfg).reason
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    assert render_command(reg["github-subdomains"], domain="example.test")[:4] == ["-d", "example.test", "-t", "t0k"]


def test_registry_extension_via_config(tmp_path):
    from reconforge.config import load_config

    tool = tmp_path / "mytool"
    tool.write_text("#!/bin/sh\necho mytool 1.0\n")
    tool.chmod(0o755)
    cfg = load_config("/nonexistent", overrides={
        "tool_registry": [{"name": "mytool", "category": "subdomain_enum", "phase": "passive", "profile": "passive",
                           "maintenance": "active", "version_args": ["--version"], "signature": "mytool", "command": ["{domain}"]}],
        "tools": {"mytool": {"path": str(tool)}}})
    st = tool_status(next(e for e in load_registry(cfg) if e["name"] == "mytool"), cfg)
    assert st.selected and st.installed and st.version == "mytool 1.0"


def test_generic_hostname_extraction():
    out = "foo.example.test\n[src] *.bar.example.test\napi.example.test (FQDN) --> a_record\nexample.org\nnotexample.test"
    assert extract_hostnames(out, ["example.test"]) == {"foo.example.test", "bar.example.test", "api.example.test"}


def test_permutations_and_spf():
    p = permutations({"api"}, ["staging", "dev"], 50)
    assert "staging-api" in p and "api-dev" in p and "api1" in p and "api" not in p
    assert spf_lookups("v=spf1 include:a include:b mx a:host ip4:1.2.3.4 ~all") == 4


def _client(routes):
    def handler(req):
        for prefix, payload in routes.items():
            if req.url.path.startswith(prefix):
                return httpx.Response(200, text=payload if isinstance(payload, str) else json.dumps(payload))
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_provider_parsers():
    c = _client({
        "/api/v1/indicators": {"passive_dns": [{"hostname": "a.example.test"}]},
        "/v1/domain/example.test/subdomains": {"subdomains": ["b", "c"]},
        "/dns/domain/example.test": {"subdomains": ["d"]},
        "/api/v3/domains": {"data": [{"id": "e.example.test"}]},
        "/hostsearch/": "f.example.test,192.0.2.1\n",
        "/203.0.113.5": {"ports": [22, 443], "hostnames": [], "cpes": [], "vulns": [], "tags": []},
        "/domain/example.test": {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]]}],
                                 "events": [{"eventAction": "registration", "eventDate": "2020"}], "nameservers": [{"ldhName": "NS1.X"}]},
        "/collinfo.json": [{"cdx-api": "http://cc/idx"}],
        "/idx": '{"url": "https://www.example.test/a?b=1"}\n',
    })
    assert P._otx(c, "http://x", "example.test", None)["hosts"] == ["a.example.test"]
    assert P._securitytrails(c, "http://x", "example.test", "k")["hosts"] == ["b.example.test", "c.example.test"]
    assert P._shodan_dns(c, "http://x", "example.test", "k")["hosts"] == ["d.example.test"]
    assert P._virustotal(c, "http://x", "example.test", "k")["hosts"] == ["e.example.test"]
    assert P._hackertarget(c, "http://x", "example.test", None)["hosts"] == ["f.example.test"]
    assert P._internetdb(c, "http://x", "203.0.113.5", None)["ports"] == [22, 443]
    r = P._rdap_domain(c, "http://x", "example.test", None)
    assert r["registrar"] == "Reg Inc" and r["nameservers"] == ["ns1.x"]
    assert P._commoncrawl(c, "http://x", "example.test", None)["urls"] == ["https://www.example.test/a?b=1"]


def test_provider_gating(cfg):
    class Ctx:
        config = cfg
        offline = False
        shared: dict = {}
    plan = {p.name for p, *_ in P.provider_plan(Ctx, "subdomains")}
    assert "otx" in plan and "securitytrails" not in plan  # key required, none set
    assert Ctx.shared["sources"]["securitytrails"]["status"] == "unavailable"


def test_header_details():
    assert hsts_details("max-age=600; includeSubDomains") == {"max_age": 600, "include_subdomains": True, "preload": False}
    c = csp_details("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert c["unsafe_inline"] and not c["unsafe_eval"] and c["directives"] == ["default-src", "script-src"]


def test_visual_hash_grouping(tmp_path):
    from PIL import Image, ImageDraw

    from reconforge.modules.screenshots import group_by_similarity, hamming, phash

    def page(path, shift=0, boxes=3):
        img = Image.new("RGB", (400, 300), "white")
        d = ImageDraw.Draw(img)
        for i in range(boxes):
            d.rectangle([20 + i * 90, 40 + shift + i * 30, 80 + i * 90, 120 + i * 40], fill="black")
        img.save(path)
        return phash(path)

    a, b, c = page(tmp_path / "a.png"), page(tmp_path / "b.png", shift=1), page(tmp_path / "c.png", boxes=1)
    blank = tmp_path / "blank.png"
    Image.new("RGB", (100, 100), "white").save(blank)
    assert phash(blank) == "0000000000000000"
    assert hamming(a, b) <= 6 < hamming(a, c)
    assert group_by_similarity([("a", a), ("b", b), ("c", c)]) == [["a", "b"], ["c"]]


def test_tool_discovery_rejects_wrong_binary_and_records_paths(tmp_path, monkeypatch):
    from reconforge.config import load_config
    from reconforge.core import tools as T

    wrong, right = tmp_path / "a", tmp_path / "b"
    wrong.mkdir(); right.mkdir()
    (wrong / "httpx").write_text("#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL'\n")       # the Python HTTP client CLI
    (right / "httpx").write_text("#!/bin/sh\necho '[INF] Current Version: v1.12.0' >&2\n")  # ProjectDiscovery httpx
    for f in (wrong / "httpx", right / "httpx"):
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{wrong}:{right}:/usr/bin:/bin")
    monkeypatch.setenv("RECONFORGE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(T, "tool_dirs", lambda: [])
    entry = {"name": "httpx", "version_args": ["-version"], "signature": "projectdiscovery|current version"}
    found = T.discover_tools([entry])
    assert found["httpx"]["path"] == str(right / "httpx") and found["httpx"]["rejected"] == [str(wrong / "httpx")]
    out = T.write_tool_paths(found)
    assert out == tmp_path / "home" / "tool-paths.yaml"
    cfg = load_config("/nonexistent", overrides={"storage": {"data_dir": str(tmp_path)}})
    assert cfg.get("tools.httpx.path") == str(right / "httpx")


def test_installer_rejects_unknown_tool_names():
    from reconforge.installer import InstallManager, installable_names

    names = installable_names()
    assert {"nuclei", "httpx", "subfinder"} <= names        # table tools
    assert {"waymore", "retire", "chrome"} <= names          # pseudo-tools
    mgr = InstallManager()
    with pytest.raises(ValueError):                           # never shell out an arbitrary name
        mgr.start("rm -rf /")
    with pytest.raises(ValueError):
        mgr.start("definitely-not-a-tool")


def test_nuclei_output_parsing_ignores_stats_lines():
    from reconforge.modules.assessment import parse_nuclei

    out = "\n".join([
        '{"percent":50,"requests":10,"total":20,"matched":1}',            # a -stats line, not a finding
        '{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"host":"x.acme.test","matched-at":"http://x.acme.test"}',
        "not json at all",
        '{"templateID":"old-key","info":{"name":"Old","severity":"low"},"host":"y.acme.test"}',
    ])
    rows = parse_nuclei(out)
    assert [r["template_id"] for r in rows] == ["tech-detect", "old-key"]
    assert rows[0]["severity"] == "info" and rows[1]["severity"] == "low"


def test_sslscan_parser_flags_deprecated_and_weak():
    from reconforge.modules.tls import _parse_sslscan

    xml = """<document><ssltest><protocol type="ssl" version="3" enabled="1"/>
      <protocol type="tls" version="1.0" enabled="1"/><protocol type="tls" version="1.2" enabled="1"/>
      <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-GCM-SHA256" strength="acceptable"/>
      <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA" strength="weak"/>
      <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="ECDHE-RSA-RC4-SHA" strength="acceptable"/></ssltest></document>"""
    protocols, weak = _parse_sslscan(xml)
    assert "SSLv3" in protocols and "TLSv1.0" in protocols and "TLSv1.2" in protocols
    assert any("3DES" in c or "DES-" in c for c in weak) and any("RC4" in c for c in weak)
    assert _parse_sslscan("") == (set(), [])


def test_retire_parser_normalises_versions():
    import json as _json
    from reconforge.modules.content import _parse_retire

    doc = {"data": [
        {"file": "/t/0.js", "results": [{"component": "jquery", "version": "1.7.1",
            "vulnerabilities": [{"severity": "medium", "identifiers": {"CVE": ["CVE-2012-6708"]}, "info": ["http://x"]}]}]},
        {"file": "/t/1.js", "results": [{"component": "clean", "version": "9.9.9"}]},  # no vulns -> dropped
    ]}
    recs = _parse_retire(_json.dumps(doc))
    assert len(recs) == 1 and recs[0]["results"][0]["component"] == "jquery"
    assert _parse_retire("not json") == []


def test_findings_report_html_and_pdf():
    from reconforge.reports.findings import findings_html, findings_pdf

    data = {"target": {"name": "acme", "root_domains": ["acme.test"]},
            "scan": {"id": "scn_x", "profile": "standard", "started_at": "2026-01-02T03:04:05Z"},
            "findings": [{"id": "a", "display": "Missing HSTS", "confidence": 0.9, "evidence": "ev_1",
                          "attributes": {"severity": "medium", "category": "security_header", "title": "Missing HSTS",
                                         "description": "No Strict-Transport-Security header.", "subject": "https://acme.test",
                                         "recommendation": "Add HSTS."}}],
            "cve_findings": [{"id": "b", "confidence": 0.6, "evidence": "ev_2",
                              "attributes": {"severity": "high", "category": "cve", "product": "nginx", "version": "1.18.0",
                                             "cves": ["CVE-2021-23017"], "subject": "https://acme.test", "description": "x"}}]}
    html = findings_html(data)
    assert "Missing HSTS" in html and "CVE-2021-23017" in html and "nginx" in html and "<!DOCTYPE html>" in html
    pdf = findings_pdf(data)
    assert pdf[:4] == b"%PDF" and len(pdf) > 1000


def test_surface_intel_helpers():
    from reconforge.modules.surface_intel import (classify_cors, detect_edge, detect_panels, extract_contacts, mmh3_32,
                                                  parse_well_known, redact, takeover_match)

    assert mmh3_32(b"foo") == -156908512 and mmh3_32(b"hello") == 613153351 and mmh3_32(b"") == 0  # == mmh3.hash
    edges = detect_edge({"Server": "cloudflare", "CF-RAY": "8a"}, ["__cf_bm=x; path=/"])
    assert edges[0]["vendor"] == "Cloudflare" and edges[0]["confidence"] > 0.9
    assert detect_edge({"Server": "nginx"}, []) == []
    assert [p["product"] for p in detect_panels({"X-Jenkins": "2.4"}, "<title>Dashboard</title>")] == ["Jenkins"]
    assert takeover_match(["x.github.io"], "There isn't a GitHub Pages site here.")["service"] == "GitHub Pages"
    assert takeover_match(["x.github.io"], "<h1>Welcome</h1>") is None
    out = redact("DB_PASSWORD=hunter2\nexport API_KEY=abc", "keys")
    assert "hunter2" not in out and "abc" not in out and "DB_PASSWORD=<redacted>" in out
    assert "hunter2" not in redact("x=hunter2", "all")
    assert parse_well_known("/.well-known/apple-app-site-association",
                            '{"applinks":{"details":[{"appID":"TEAM.com.ex"}]}}')["mobile_apps"] == ["ios:TEAM.com.ex"]
    assert parse_well_known("/ads.txt", "google.com, pub-1, DIRECT, f08c47fec0942fa0")["entries"] == 1
    emails, social = extract_contacts('security@ex.com logo@2x.png <a href="https://twitter.com/intent/tweet"> '
                                      '<a href="https://www.linkedin.com/company/exco">')
    assert emails == {"security@ex.com"} and social == {("linkedin.com", "company/exco")}
    assert classify_cors("https://a.example", "https://a.example", "true") == "reflects_with_credentials"
    assert classify_cors("https://a.example", "*", None) is None


def test_exports_flatten_and_render():
    from reconforge.api.exports import render, rows_of

    rows = rows_of([{"key": "a", "attributes": {"ips": ["1.1.1.1", "2.2.2.2"], "deep": {"x": 1}}}])
    assert rows == [{"key": "a", "attributes.ips": ["1.1.1.1", "2.2.2.2"], "attributes.deep": {"x": 1}}]
    csv_text = render([{"key": "a", "attributes": {"ips": ["1.1.1.1", "2.2.2.2"]}}], "csv", "t")
    assert csv_text.splitlines()[0] == "key,attributes.ips" and "1.1.1.1; 2.2.2.2" in csv_text
    assert render({"g": [{"k": 1}]}, "csv", "t").splitlines()[0] == "group,k"
    assert render([{"k": "a|b"}], "md", "Title").startswith("# Title") and "a\\|b" in render([{"k": "a|b"}], "md", "T")


def test_pdf_tables_survive_huge_cells(tmp_path):
    """A single very long cell used to abort the whole PDF with reportlab's LayoutError."""
    from reconforge.reports.findings import findings_pdf

    big = "x " * 20000
    d = {"target": {"name": "t", "root_domains": ["t.example"]}, "scan": {"id": "s", "profile": "p", "started_at": "", "finished_at": ""},
         "findings": [{"attributes": {"severity": "low", "title": "T", "description": big, "subject": big, "category": "c"},
                       "confidence": 0.5, "evidence": "ev"}], "cve_findings": []}
    assert findings_pdf(d)[:4] == b"%PDF"
