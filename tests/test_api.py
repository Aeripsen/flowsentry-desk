"""The web API: workspaces, decisions, the knob, the audit chain."""
import time

import numpy as np

from desk import core


def test_health_and_config(client):
    assert client.get("/api/health").json()["queue"] == 2315
    c = client.get("/api/config").json()
    assert c["auth"] == "anon" and c["live_engine"] is None and c["queue_size"] == 2315


def test_security_headers(client):
    h = client.get("/").headers
    assert "frame-ancestors 'self' https://huggingface.co" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"


def test_run_label_and_audit_chain(client, b):
    r = client.post("/api/case/C0002/run", json={"engine": "auto"}).json()
    assert r["engine"] == "policy" and r["outcome"] in core.OUTCOMES
    case = client.get("/api/case/C0002").json()
    assert case["run"]["case_id"] == "C0002"
    d = client.post("/api/case/C0002/decision", json={"action": "override", "label": "benign"})
    assert d.status_code == 200
    assert client.get("/api/case/C0002").json()["label"]["label"] == "benign"
    a = client.get("/api/audit").json()
    assert a["chain"]["ok"] and [x["action"] for x in a["rows"]][:2] == ["override", "agent_run"]


def test_audit_chain_detects_tampering(client):
    from desk import app as appmod

    client.post("/api/case/C0001/run", json={"engine": "policy"})
    client.post("/api/case/C0001/decision", json={"action": "override", "label": "UDP-RAW"})
    db = appmod.get_db()
    assert db.verify_chain()["ok"]
    db.conn.execute("UPDATE audit SET detail='{\"label\":\"benign\"}' WHERE action='override'")
    assert not db.verify_chain()["ok"]


def test_approve_needs_something_to_approve(client, b):
    d = core.decide(b, np.arange(b.n))
    ask = b.case_id(int(np.nonzero(d["verdict"] == "ask_human")[0][0]))
    client.post(f"/api/case/{ask}/run", json={"engine": "policy"})
    assert client.post(f"/api/case/{ask}/decision", json={"action": "approve"}).status_code == 409
    bad = client.post(f"/api/case/{ask}/decision", json={"action": "override", "label": "evil"})
    assert bad.status_code == 422


def test_workspaces_are_isolated(b):
    from fastapi.testclient import TestClient

    from desk import app as appmod
    from desk.db import DB

    appmod.set_db(DB(":memory:"))
    one, two = TestClient(appmod.app), TestClient(appmod.app)
    one.post("/api/case/C0003/run", json={"engine": "policy"})
    one.post("/api/case/C0003/decision", json={"action": "override", "label": "UDP-OVH"})
    assert one.get("/api/case/C0003").json()["label"]["label"] == "UDP-OVH"
    assert two.get("/api/case/C0003").json()["label"] is None
    assert one.get("/api/me").json()["workspace"] != two.get("/api/me").json()["workspace"]


def test_batch_preread_and_buckets(client):
    r = client.post("/api/batch", json={"n": 10}).json()
    assert r["ran"] == 10
    q = client.get("/api/queue?status=all&limit=5").json()
    c = q["counts"]
    assert c["all"] == 2315 and c["todo"] == 2305
    assert c["needs_you"] + c["escalated"] + c["closed"] == 10


def test_knob_validation_and_effect(client, b):
    assert client.post("/api/knob", json={"cap": 7}).status_code == 422
    assert client.post("/api/knob", json={"cap": 0}).json()["threshold"] > 1
    d = core.decide(b, np.arange(b.n))
    closable = b.case_id(int(np.nonzero(d["verdict"] == "close_benign")[0][0]))
    r = client.post(f"/api/case/{closable}/run", json={"engine": "auto"}).json()
    assert r["outcome"] != "AUTO_CLOSED"           # "never close" really never closes
    client.post("/api/knob", json={"cap": None})
    r = client.post(f"/api/case/{closable}/run", json={"engine": "auto"}).json()
    assert r["outcome"] == "AUTO_CLOSED"


def test_an_override_reports_what_it_changed(client, b):
    # label a desk-closed flow as an attack: closes of its close neighbours must stop
    d = core.decide(b, np.arange(b.n))
    closed = np.nonzero(d["verdict"] == "close_benign")[0]
    for pos in closed[:40]:
        cid = b.case_id(int(pos))
        client.post(f"/api/case/{cid}/run", json={"engine": "policy"})
        out = client.post(f"/api/case/{cid}/decision",
                          json={"action": "override", "label": "UDP-OVH"}).json()
        if out["changed"]:
            assert all("close" in c["before"] and "close" not in c["after"] for c in out["changed"])
            return
    raise AssertionError("no override changed a neighbour in 40 tries")


def test_model_engine_refused_without_a_key(client):
    r = client.post("/api/case/C0004/run", json={"engine": "model"})
    assert r.status_code == 409


def test_unknown_case_is_404(client):
    assert client.get("/api/case/C9999").status_code == 404
    assert client.get("/api/case/../../etc").status_code == 404


def test_reset_clears_the_workspace(client):
    client.post("/api/case/C0005/run", json={"engine": "policy"})
    client.post("/api/case/C0005/decision", json={"action": "override", "label": "benign"})
    client.post("/api/reset")
    assert client.get("/api/me").json()["labels"] == 0
    assert time.time() > 0
