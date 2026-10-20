"""The data bundle is FlowSentry's own queue, explained exactly, built without test labels."""
import hashlib
import json

import numpy as np

from desk import settings as S


def test_bundle_hash_matches_manifest(b):
    h = hashlib.sha256(S.BUNDLE_PATH.read_bytes()).hexdigest()
    assert h == b.manifest["bundle_sha256"]


def test_retrained_flowsentry_matched_the_published_metrics(b):
    assert b.manifest["provenance"]["metrics_match_published"] is True
    assert b.manifest["flowsentry_commit"] == S.FLOWSENTRY_COMMIT


def test_queue_is_flowsentrys_published_reject_queue(b):
    # FlowSentry's business_case.json: 2,315 sent to an analyst at 0.99, 1,824 of them benign
    assert b.n == 2315
    assert b.manifest["queue_by_class"]["benign"] == 1824
    assert (b.a["q_conf"] < S.REJECT_THRESHOLD).all()
    assert round(1824 / 2315, 3) == 0.788


def test_explanations_reconstruct_flowsentrys_probability(b):
    assert b.manifest["explanation_max_abs_error"] < 1e-6


def test_no_ip_or_port_is_stored(b):
    import re

    ip = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
    for k, v in b.a.items():
        if v.dtype.kind in "US":
            assert not any(ip.search(str(x)) for x in v.ravel()), k
    assert "src_ip" not in b.a and "dst_port" not in b.a


def test_gate_was_tuned_on_training_data_only(b):
    g = b.manifest["gate"]
    assert "training split only" in g["trained_on"]
    assert g["n_training_queue"] > 1000
    # the default is the strictest cap the training data could certify
    met = [r["cap_per_1000"] for r in g["knob"] if r["met_on_training"]]
    assert g["cap_per_1000"] == min(met)


def test_precedents_come_from_training_flows(b):
    assert b.manifest["precedent_pool"]["source"] == "training split"
    train_refs = set(map(str, b.a["p_flow_id"]))
    queue_refs = set(map(str, b.a["q_flow_id"]))
    assert not train_refs & queue_refs


def test_report_matches_a_fresh_run_of_the_rules(b):
    from desk import core

    rep = json.loads((S.REPORTS_DIR / "eval.json").read_text())
    truth = b.a["oracle_q_true"].astype(str)
    d = core.decide(b, np.arange(b.n))
    closed = d["verdict"] == "close_benign"
    k = [r for r in rep["knob"] if r["default"]][0]
    assert int(closed.sum()) == k["auto_closed"]
    assert int((closed & (truth != "benign")).sum()) == k["attacks_wrongly_closed"]
