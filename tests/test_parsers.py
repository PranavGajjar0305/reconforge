"""External tool output parsers (validated against representative JSON/XML output) and pure analysers."""
import json

from reconforge.modules.assessment import cookie_issues, find_cloud_refs, in_range, match_cves, load_cve_db, parse_nuclei
from reconforge.modules.content import extract_js
from reconforge.modules.crawler import classify_endpoint, parse_katana, parse_robots
from reconforge.modules.dns_resolve import parse_dnsx
from reconforge.modules.http_probe import cdn_waf, parse_pd_httpx
from reconforge.modules.passive import parse_subfinder
from reconforge.modules.ports import identify, parse_naabu, parse_nmap_xml
from reconforge.modules.tech import fingerprint, parse_whatweb
from reconforge.modules.tls import host_matches, parse_tlsx


def test_subfinder():
    out = '{"host":"a.example.test","input":"example.test","source":"crtsh"}\nb.example.test\n'
    obs = parse_subfinder(out)
    assert [o.key for o in obs] == ["a.example.test", "b.example.test"]
    assert obs[0].attrs["+passive_sources"] == ["crtsh"]


def test_dnsx():
    out = json.dumps({"host": "a.example.test", "a": ["192.0.2.1"], "cname": ["x.cdn.example"], "status_code": "NOERROR"})
    o = parse_dnsx(out)[0]
    assert o.attrs["ips"] == ["192.0.2.1"] and o.attrs["dns"]["CNAME"] == ["x.cdn.example"]
    assert o.relations[0].target_key == "192.0.2.1"


def test_pd_httpx():
    out = json.dumps({"url": "https://a.example.test:8443", "status_code": 200, "title": "Hi", "webserver": "nginx",
                      "host": "192.0.2.1", "tech": ["Nginx:1.20", "React"], "cdn": True, "cdn_name": "cloudflare"})
    o = parse_pd_httpx(out)[0]
    assert o.key == "https://a.example.test:8443" and o.attrs["technologies_httpx"] == {"Nginx": "1.20", "React": ""}
    assert o.attrs["cdn"] == "cloudflare"


def test_nmap_and_naabu():
    xml = """<nmaprun><host><address addr="192.0.2.1"/><ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>"""
    r = parse_nmap_xml(xml)
    assert r == [{"ip": "192.0.2.1", "port": 22, "engine": "nmap", "service": "ssh", "product": "OpenSSH", "version": "8.9p1", "banner": ""}]
    assert parse_naabu('{"ip":"192.0.2.1","port":443}')[0]["service"] == "https"


def test_banner_identify():
    assert identify(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu") == ("ssh", "OpenSSH", "8.2p1")
    assert identify(25, "220 mail ESMTP Postfix")[0] == "smtp"
    assert identify(6379, "")[0] == "redis"


def test_katana_whatweb_nuclei_tlsx():
    k = parse_katana(json.dumps({"request": {"method": "GET", "endpoint": "https://a.example.test/x"}, "response": {"status_code": 200}}))
    assert k[0]["url"] == "https://a.example.test/x" and k[0]["status"] == 200
    w = parse_whatweb(json.dumps([{"target": "x", "plugins": {"WordPress": {"version": ["6.4"]}, "IP": {}}}]))
    assert w == [{"name": "WordPress", "version": "6.4", "categories": ["whatweb"], "confidence": 0.75, "evidence": ["whatweb plugin WordPress"]}]
    n = parse_nuclei(json.dumps({"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info",
                                 "classification": {"cve-id": ["CVE-2021-0001"]}}, "host": "https://a.example.test",
                                 "matched-at": "https://a.example.test/"}))
    assert n[0]["template_id"] == "tech-detect" and n[0]["cves"] == ["CVE-2021-0001"]
    t = parse_tlsx(json.dumps({"host": "a.example.test", "port": "443", "subject_an": ["A.example.test"],
                               "fingerprint_hash": {"sha256": "ab"}, "mismatched": True}))
    assert t[0]["sans"] == ["a.example.test"] and t[0]["hostname_match"] is False


def test_fingerprint():
    techs = {t["name"]: t for t in fingerprint(
        {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3", "cf-ray": "abc"},
        '<meta name="generator" content="WordPress 6.4.2"><script src="/js/jquery-3.4.1.min.js"></script>',
        ["PHPSESSID=1; path=/"])}
    assert techs["nginx"]["version"] == "1.18.0"
    assert techs["PHP"]["version"] == "7.4.3" and techs["PHP"]["confidence"] > 0.8  # header + cookie corroborate
    assert techs["WordPress"]["version"] == "6.4.2"
    assert techs["jQuery"]["version"] == "3.4.1"
    assert "Cloudflare" in techs


def test_cdn_waf_and_tls_match():
    assert cdn_waf({"cf-ray": "x", "server": "cloudflare"}) == ("Cloudflare", "Cloudflare (WAF capable)")
    assert host_matches("a.example.test", ["*.example.test"])
    assert not host_matches("a.b.example.test", ["*.example.test"])


def test_js_extraction():
    js = """fetch('/api/v1/session'); axios.post('https://api.example.test/v1/orders');
    fetch('/v2/pay', {method: 'PUT'}); new WebSocket('wss://api.example.test/ws');
    const k = "AKIAIOSFODNN7EXAMPLE"; //# sourceMappingURL=app.js.map"""
    r = extract_js(js, "https://www.example.test/static/app.js")
    assert r["urls"]["https://api.example.test/v1/orders"] == ["POST"]
    assert r["urls"]["https://www.example.test/v2/pay"] == ["PUT"]
    assert "wss://api.example.test/ws" in r["urls"]
    assert r["secrets"][0]["type"] == "AWS access key ID" and "AKIAIOSFODNN7EXAMPLE" not in r["secrets"][0]["redacted"]
    assert r["sourcemap"] == "https://www.example.test/static/app.js.map"


def test_endpoint_classification_and_robots():
    assert classify_endpoint("https://a/graphql") == "graphql"
    assert classify_endpoint("https://a/openapi.json") == "api_documentation"
    assert classify_endpoint("https://a/api/v1/x") == "api"
    assert classify_endpoint("wss://a/ws") == "websocket"
    assert parse_robots("User-agent: *\nDisallow: /admin\nSitemap: https://a/s.xml\nUser-agent: bot\nDisallow: /x") == (["/admin"], ["https://a/s.xml"])


def test_cloud_refs_and_cookies():
    refs = find_cloud_refs("img https://acme-prod.s3.amazonaws.com/a.png and https://acct1.blob.core.windows.net/c")
    assert ("aws", "s3", "acme-prod", "acme-prod.s3.amazonaws.com") in refs
    assert any(r[0] == "azure" and r[2] == "acct1" for r in refs)
    assert cookie_issues("sid=1; Path=/", https=True) == ("sid", ["missing Secure", "missing HttpOnly", "missing SameSite"])
    assert cookie_issues("sid=1; Secure; HttpOnly; SameSite=Lax", https=True)[1] == []


def test_cve_version_ranges():
    db = load_cve_db()
    assert in_range("2.4.49", {"versions": ["2.4.49"]})
    assert in_range("8.2p1", {"before": "9.3.2"}) and not in_range("8.2p1", {"from": "8.5.1", "before": "9.8.1"})
    cves, eol = match_cves("nginx", "1.18.0", db)
    assert "CVE-2021-23017" in [c["id"] for c in cves]
    cves, _ = match_cves("nginx", "1.24.0", db)
    assert cves == []
    _, eol = match_cves("PHP", "7.4.3", db)
    assert eol is not None
    assert match_cves("jQuery", "3.5.1", db)[0] == []
