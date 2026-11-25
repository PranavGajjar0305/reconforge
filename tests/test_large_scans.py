"""Large scans stay usable: paged endpoints, light report builds, windowed logs and module output."""
import sqlite3

import pytest

N_ARCHIVE = 3000
N_LIVE = 60


@pytest.fixture
def client(cfg):
    from fastapi.testclient import TestClient

    from reconforge.api.app import create_app

    return TestClient(create_app(cfg))


@pytest.fixture
def big(cfg, db, tmp_path):
    """A target with thousands of archive URLs, a few live endpoints, a log and a module with many results."""
    from reconforge.core.pipeline import ensure_target
    from reconforge.db.models import Asset, Evidence, ModuleRun, Observation, Relation, Scan
    from reconforge.util import utcnow

    tid, _ = ensure_target(db, cfg, "t")
    log = tmp_path / "logs" / "scn_big.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for i in range(5000):
        mod = "nuclei" if i % 2 else "crawler"
        lines.append(f"2026-01-01 00:00:{i % 60:02d} INFO [{mod}] {'exec: nuclei -u x' if i % 10 == 1 else f'line {i}'}")
    log.write_text("\n".join(lines) + "\n")
    now = utcnow()
    with db.session() as s:
        s.add(Scan(id="scn_big", target_id=tid, profile="standard", status="completed", started_at=now, finished_at=now,
                   log_path=str(log)))
        s.flush()
        s.add(Asset(id="sub1", target_id=tid, type="subdomain", key="www.example.test", display="www.example.test",
                    attributes={"resolved": True}, sources=[]))
        s.add(Asset(id="app1", target_id=tid, type="web_app", key="https://www.example.test", display="https://www.example.test",
                    attributes={"host": "www.example.test", "status": 200}, sources=[]))
        s.flush()
        rows, rels, obs = [], [], []
        for i in range(N_ARCHIVE):
            rows.append(dict(id=f"ea{i}", target_id=tid, type="endpoint", key=f"http://www.example.test/old/{i:05d}",
                             display=f"/old/{i}", attributes={"kind": "page", "host": "www.example.test", "historical": True,
                                                              "archived_status": "200"}, sources=[]))
            rels.append(dict(id=f"r{i}", target_id=tid, src_id="sub1", dst_id=f"ea{i}", type="historical_url"))
            obs.append(dict(id=f"o{i:06d}", scan_id="scn_big", asset_id=f"ea{i}", module="external_urls", source="waymore",
                            data={"n": i}))
        for i in range(N_LIVE):
            kind = "api" if i < 10 else "graphql" if i < 12 else "page"
            rows.append(dict(id=f"el{i}", target_id=tid, type="endpoint", key=f"https://api.example.test/v1/{i:03d}",
                             display=f"/v1/{i}", attributes={"kind": kind, "host": "api.example.test", "status": 200}, sources=[]))
        s.bulk_insert_mappings(Asset, rows)
        s.flush()
        s.bulk_insert_mappings(Relation, rels)
        s.bulk_insert_mappings(Observation, obs)
        s.add(ModuleRun(scan_id="scn_big", module="external_urls", status="completed", observations=N_ARCHIVE, started_at=now, finished_at=now))
        s.add(Evidence(id="ev_raw", scan_id="scn_big", module="nuclei", kind="tool_output", summary="nuclei raw output",
                       content="\n".join(f"[info] finding {i}" for i in range(12000))))
    return tid


def test_endpoint_indexes_are_used(cfg, db, big):
    path = cfg.database_url.split("sqlite:///", 1)[1]
    con = sqlite3.connect(path)
    names = {r[1] for r in con.execute("pragma index_list('assets')")}
    assert {"ix_asset_json_kind", "ix_asset_json_host", "ix_asset_json_historical", "ix_asset_live_key"} <= names
    plan = " ".join(r[3] for r in con.execute(
        "explain query plan select assets.id from assets where assets.target_id=? and assets.type='endpoint' "
        "and assets.status='active' and assets.false_positive=0 and json_extract(assets.attributes, '$.kind')='api' "
        "order by assets.key limit 100", (big,)))
    assert "ix_asset_json_kind" in plan and "TEMP B-TREE" not in plan


def test_endpoints_are_paged_and_filtered_on_the_server(client, big):
    r = client.get("/api/targets/t/endpoints", params={"limit": 100}).json()
    assert r["total"] == N_ARCHIVE + N_LIVE and len(r["rows"]) == 100
    assert [x["key"] for x in r["rows"]] == sorted(x["key"] for x in r["rows"])
    last = client.get("/api/targets/t/endpoints", params={"offset": N_ARCHIVE + N_LIVE - 10, "limit": 100}).json()
    assert len(last["rows"]) == 10
    assert client.get("/api/targets/t/endpoints", params={"kind": "api"}).json()["total"] == 10
    assert client.get("/api/targets/t/endpoints", params={"origin": "live"}).json()["total"] == N_LIVE
    assert client.get("/api/targets/t/endpoints", params={"origin": "archive"}).json()["total"] == N_ARCHIVE
    hit = client.get("/api/targets/t/endpoints", params={"q": "old/00042"}).json()
    assert hit["total"] == 1 and hit["rows"][0]["historical"] is True
    assert client.get("/api/targets/t/endpoints", params={"host": "api.example.test", "kind": "graphql"}).json()["total"] == 2
    desc = client.get("/api/targets/t/endpoints", params={"desc": True, "limit": 1}).json()["rows"][0]["key"]
    assert desc == "https://api.example.test/v1/059"
    f = client.get("/api/targets/t/endpoints/facets").json()
    assert f["total"] == N_ARCHIVE + N_LIVE and f["historical"] == N_ARCHIVE and f["api"] == 12
    assert f["by_kind"]["page"] == N_ARCHIVE + N_LIVE - 12 and ["www.example.test", N_ARCHIVE] in f["hosts"]


def test_dashboard_report_is_light_but_counts_are_exact(client, big):
    d = client.get("/api/targets/t/report-data").json()
    assert d["light"] is True
    assert len(d["endpoints"]) == 12                           # API endpoints only; the rest are paged, not shipped
    assert d["overview"]["endpoints"] == N_ARCHIVE + N_LIVE    # ...but counted
    assert d["overview"]["api_endpoints"] == 12 and d["endpoint_summary"]["historical"] == N_ARCHIVE
    assert "api.example.test" in d["api_hosts"]
    full = client.get("/api/targets/t/report-data", params={"full": True}).json()
    assert len(full["endpoints"]) == N_ARCHIVE + N_LIVE
    ov = client.get("/api/targets/t/overview").json()
    assert ov["overview"]["endpoints"] == N_ARCHIVE + N_LIVE


def test_graph_leaves_out_archive_urls_and_reports_it(client, big):
    g = client.get("/api/targets/t/graph", params={"types": "subdomain,web_app,endpoint"}).json()
    types = [n["data"]["type"] for n in g["nodes"]]
    assert types.count("endpoint") == N_LIVE and g["stats"]["omitted"]["endpoint"]["total"] == N_ARCHIVE + N_LIVE
    assert g["type_counts"]["endpoint"] == N_ARCHIVE + N_LIVE
    assert not any(e["data"]["label"] == "historical_url" for e in g["edges"])


def test_endpoint_export_streams_every_row(client, big):
    r = client.get("/api/targets/t/export/endpoints", params={"format": "csv"})
    assert r.status_code == 200 and r.text.count("\n") == N_ARCHIVE + N_LIVE + 1
    j = client.get("/api/targets/t/export/endpoints", params={"format": "json"}).json()
    assert len(j) == N_ARCHIVE + N_LIVE and j[0]["url"].startswith("http")


def test_log_is_served_in_windows(client, big):
    tail = client.get("/api/scans/scn_big/log/lines", params={"limit": 50}).json()
    assert tail["total"] == 5000 and tail["start"] == 4950 and len(tail["lines"]) == 50
    assert tail["lines"][-1].endswith("line 4999")
    mid = client.get("/api/scans/scn_big/log/lines", params={"start": 1002, "limit": 3}).json()
    assert [l.rsplit(" ", 1)[1] for l in mid["lines"]] == ["1002", "1003", "1004"]
    nuc = client.get("/api/scans/scn_big/log/lines", params={"module": "nuclei", "limit": 0}).json()
    assert nuc["total"] == 2500 and nuc["lines"] == []
    cmds = client.get("/api/scans/scn_big/log/lines", params={"kind": "commands", "limit": 5}).json()
    assert cmds["total"] == 500 and all("exec:" in l for l in cmds["lines"])
    q = client.get("/api/scans/scn_big/log/lines", params={"q": "LINE 4998", "limit": 5}).json()
    assert q["total"] == 1
    assert client.get("/api/scans/scn_big/log/lines", params={"limit": 5000}).status_code == 422  # window size is capped


def test_log_index_follows_a_growing_file(tmp_path):
    from reconforge.api.logview import LineIndexCache

    f = tmp_path / "grow.log"
    f.write_text("a [m] 1\nb [m] 2\npartial")
    c = LineIndexCache()
    assert c.window(f, limit=10)["total"] == 2           # the unfinished last line is not shown yet
    with open(f, "a") as fh:
        fh.write(" done\nc [m] 3\n")
    w = c.window(f, limit=10)
    assert w["total"] == 4 and w["lines"][2] == "partial done"
    assert c.window(f, limit=10, module="m")["total"] == 3
    f.write_text("new\n")                                  # rewritten: the index starts over
    assert c.window(f, limit=10)["total"] == 1


def test_raw_tool_output_and_module_results_are_paged(client, big):
    w = client.get("/api/evidence/ev_raw/lines", params={"start": 0, "limit": 2}).json()
    assert w["total"] == 12000 and w["lines"] == ["[info] finding 0", "[info] finding 1"]
    out = client.get("/api/scans/scn_big/modules/external_urls").json()
    assert out["observations_total"] == N_ARCHIVE and len(out["observations"]) == 200
    assert out["asset_types"] == {"endpoint": N_ARCHIVE} and out["log"] is None
    page = client.get("/api/scans/scn_big/modules/external_urls/observations", params={"offset": 2900, "limit": 500}).json()
    assert page["total"] == N_ARCHIVE and len(page["rows"]) == 100
    q = client.get("/api/scans/scn_big/modules/external_urls/observations", params={"q": "old/00007"}).json()
    assert q["total"] == 1
    ev = client.get("/api/scans/scn_big/modules/nuclei").json()
    assert ev["raw_outputs"][0]["id"] == "ev_raw" and "content" not in ev["raw_outputs"][0]
    summ = client.get("/api/scans/scn_big/modules").json()["modules"]
    assert next(m for m in summ if m["module"] == "external_urls")["asset_types"] == {"endpoint": N_ARCHIVE}


def test_search_reaches_endpoints(client, big):
    hits = client.get("/api/search", params={"target": "t", "q": "old/01234"}).json()
    assert [h["type"] for h in hits] == ["endpoint"]
