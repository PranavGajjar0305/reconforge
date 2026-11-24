"""Normalization, scope, correlation engine and confidence scoring."""
from reconforge.core.observation import Obs, Rel
from reconforge.correlation.engine import CorrelationEngine, combine_confidence, merge_attrs
from reconforge.db.models import Asset, Observation, Relation, Scan, Target
from reconforge.scope import Scope, ScopeError
from reconforge.util import normalize_host, normalize_url, origin_of


def test_normalization():
    assert normalize_host("*.API.Example.TEST.") == "api.example.test"
    assert normalize_host("https://a.example.test:8443/x") == "a.example.test"
    assert normalize_url("HTTPS://A.example.test:443//x//y?b=2&a=1#frag") == "https://a.example.test/x/y?a=&b="
    assert origin_of("http://a.example.test:80/z") == "http://a.example.test"
    assert origin_of("https://a.example.test:8443/z") == "https://a.example.test:8443"


def test_scope(scope):
    assert scope.host_in_scope("www.example.test")
    assert scope.host_in_scope("example.test")
    assert not scope.host_in_scope("x.internal.example.test")
    assert scope.classify_host("x.internal.example.test") == "out_of_scope"
    assert scope.classify_host("cdn.vendor.example") == "third_party"
    assert scope.ip_allowed("192.0.2.10")
    assert not scope.ip_allowed("198.51.100.1")
    assert not scope.ip_allowed("10.0.0.1")


def test_active_requires_authorization():
    s = Scope.from_target({"root_domains": ["example.test"]})
    try:
        s.require_active_authorization()
        assert False, "should raise"
    except ScopeError:
        pass
    assert not s.ip_allowed("127.0.0.1")  # private ranges need an explicit allow entry


def test_merge_attrs_union_lists():
    out = merge_attrs({"+x": [], "a": 1, "src": ["crtsh"]}, {"+src": ["subfinder", "crtsh"], "a": 2})
    assert out["a"] == 2 and out["src"] == ["crtsh", "subfinder"]


def test_combine_confidence_noisy_or():
    assert combine_confidence([0.5, 0.5]) == 0.75
    assert combine_confidence([0.9]) == 0.9


def _engine(cfg, db, scope):
    s = db._factory()
    s.add(Target(id="tgt_1", name="t", config={}))
    s.add(Scan(id="scn_1", target_id="tgt_1", profile="x"))
    s.flush()
    return s, CorrelationEngine(s, cfg, scope, "tgt_1", "scn_1")


def test_cross_tool_dedup_and_provenance(cfg, db, scope):
    s, eng = _engine(cfg, db, scope)
    eng.ingest(Obs("subdomain", "API.example.test.", {"+discovered_via": ["crtsh"]}, source="crtsh"), "crtsh")
    eng.ingest(Obs("subdomain", "api.example.test", {"+discovered_via": ["subfinder"]}, source="subfinder"), "subfinder")
    eng.ingest(Obs("subdomain", "api.example.test", {"resolved": True, "ips": ["192.0.2.5"]}, source="dns_resolve",
                   relations=[Rel("resolves_to", "ip", "192.0.2.5")]), "dns_resolve")
    s.flush()
    subs = s.query(Asset).filter_by(type="subdomain").all()
    assert len(subs) == 1
    a = subs[0]
    assert sorted(x["source"] for x in a.sources) == ["crtsh", "dns_resolve", "subfinder"]
    assert a.attributes["discovered_via"] == ["crtsh", "subfinder"]
    assert a.confidence > 0.99  # three independent sources
    assert s.query(Observation).count() == 3  # every observation retained with its source
    assert s.query(Relation).filter_by(type="resolves_to").count() == 1


def test_shared_ip_does_not_merge_hosts(cfg, db, scope):
    s, eng = _engine(cfg, db, scope)
    for h in ("a.example.test", "b.example.test"):
        eng.ingest(Obs("subdomain", h, {"resolved": True}, relations=[Rel("resolves_to", "ip", "192.0.2.9")]), "dns_resolve")
    s.flush()
    assert s.query(Asset).filter_by(type="subdomain").count() == 2
    assert s.query(Asset).filter_by(type="ip").count() == 1
    assert s.query(Relation).filter_by(type="resolves_to").count() == 2


def test_root_domain_typed_as_domain_and_third_party_scope(cfg, db, scope):
    s, eng = _engine(cfg, db, scope)
    a = eng.ingest(Obs("subdomain", "example.test", {}), "x")
    b = eng.ingest(Obs("third_party", "js.vendor.example", {}), "x")
    assert a.type == "domain" and a.scope == "in_scope"
    assert b.scope == "third_party"


def test_false_positive_is_sticky(cfg, db, scope):
    s, eng = _engine(cfg, db, scope)
    a = eng.ingest(Obs("finding", "rule|x", {"severity": "low"}), "m")
    a.false_positive = True
    eng.ingest(Obs("finding", "rule|x", {"severity": "low"}), "m")
    assert a.false_positive is True
