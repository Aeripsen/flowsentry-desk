"""The properties the desk promises, as tests."""
import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pytest

from desk import agent, core, tools

ROOT = Path(__file__).resolve().parents[1]


def test_agent_side_code_never_reads_test_labels():
    for f in ("tools.py", "agent.py", "core.py", "app.py"):
        src = (ROOT / "desk" / f).read_text(encoding="utf-8")
        # any access to a bundle key, by subscript, .get() or an f-string, would match
        assert not re.search(r"""(\[|get\(|f)\s*["']oracle""", src), f


def test_tool_results_never_reveal_the_gate_or_labels(b):
    for k in range(60):
        pos = int(b.order[k])
        ctx = tools.CaseContext(b=b, pos=pos, labels=core.Labels())
        for name in ("next_case", "explain", "precedents", "second_opinion"):
            _, out, _ = tools.call(ctx, name, {"toward": "benign", "top": 8, "k": 15})
            text = json.dumps(out).lower()
            assert "gate" not in text and "threshold" not in text.replace("0.99 reject threshold", "")
        # the true label of the case is never in any tool output field named like a label
        assert "oracle" not in json.dumps(ctx.ledger.results)


def test_tools_are_read_only(b):
    def digest():
        h = hashlib.sha256()
        for k in sorted(b.a):
            h.update(np.ascontiguousarray(b.a[k]).tobytes())
        return h.hexdigest()

    before = digest()
    lab = core.Labels.from_pairs([(int(b.order[0]), "benign"), (int(b.order[1]), "UDP-RAW")])
    for k in range(30):
        ctx = tools.CaseContext(b=b, pos=int(b.order[k]), labels=lab)
        for name in tools.TOOLS:
            tools.call(ctx, name, {"toward": "predicted", "top": 5, "k": 5, "family": "UDP-OVH",
                                   "verdict": "ask_human", "memo": "x [R1]", "citations": ["R1"]})
    assert digest() == before


def test_no_tool_can_act_on_the_network():
    src = (ROOT / "desk" / "tools.py").read_text(encoding="utf-8")
    for bad in ("requests", "httpx", "urllib", "socket", "subprocess", "open(", "write"):
        assert bad not in src.replace("writes anything", "").replace("No tool writes", ""), bad


def test_propose_rejects_ids_the_server_did_not_issue(b):
    ctx = tools.CaseContext(b=b, pos=int(b.order[0]), labels=core.Labels())
    tools.call(ctx, "next_case", {})
    _, out, err = tools.call(ctx, "propose", {"verdict": "ask_human", "family": "",
                                              "memo": "It looks odd [R7].", "citations": ["R7"],
                                              "ticket": ""})
    assert err and any("R7" in e for e in out["errors"])
    assert ctx.final is None


def test_propose_needs_a_citation(b):
    ctx = tools.CaseContext(b=b, pos=int(b.order[0]), labels=core.Labels())
    tools.call(ctx, "next_case", {})
    _, out, err = tools.call(ctx, "propose", {"verdict": "ask_human", "family": "",
                                              "memo": "No evidence here.", "citations": [],
                                              "ticket": ""})
    assert err


@pytest.mark.parametrize("allowed", [True, False])
def test_escalation_always_reaches_a_human(allowed):
    assert core.outcome("escalate", True, allowed)[0] == "ESCALATED"


def test_a_close_needs_agent_rules_and_citations():
    assert core.outcome("close_benign", True, True)[0] == "AUTO_CLOSED"
    assert core.outcome("close_benign", True, False)[0] == "HUMAN"
    assert core.outcome("close_benign", False, True)[0] == "HUMAN"
    assert core.outcome("ask_human", True, True)[0] == "HUMAN"
    assert core.outcome(None, True, True)[0] == "HUMAN"
    assert core.outcome("block_source_ip", True, True)[0] == "HUMAN"
    assert core.OUTCOMES == ("AUTO_CLOSED", "ESCALATED", "HUMAN")


def test_agent_cannot_close_what_the_rules_refuse(b):
    d = core.decide(b, np.arange(b.n))
    refused = int(np.nonzero(~d["close_allowed"])[0][0])
    ctx = tools.CaseContext(b=b, pos=refused, labels=core.Labels())
    for name in ("next_case", "precedents"):
        tools.call(ctx, name, {"k": 5})
    tools.call(ctx, "propose", {"verdict": "close_benign", "family": "",
                                "memo": "Looks benign [R1] [R2].", "citations": ["R1", "R2"],
                                "ticket": ""})
    run = agent.Run(case_id=ctx.case_id, engine="test", model="test", labels_fingerprint="none")
    assert agent._settle(run, ctx).outcome == "HUMAN"


def test_an_attack_label_nearby_blocks_closes_never_unblocks(b):
    d0 = core.decide(b, np.arange(b.n))
    closed = np.nonzero(d0["verdict"] == "close_benign")[0]
    target = int(closed[0])
    lab = core.Labels.from_pairs([(target, "UDP-OVH")])
    near = core.labelled_attack_nearby(b, np.arange(b.n), lab)
    d1 = core.decide(b, np.arange(b.n), lab)
    # labels can only remove closes, never add one
    assert not ((d1["verdict"] == "close_benign") & (d0["verdict"] != "close_benign")).any()
    assert not (near & (d1["verdict"] == "close_benign")).any()


def test_knob_never_closes_more_at_a_stricter_cap(b):
    pos = np.arange(b.n)
    prev = None
    for row in sorted(b.knob, key=lambda r: r["cap_per_1000"]):
        n = int((core.decide(b, pos, None, row["cap_per_1000"])["verdict"] == "close_benign").sum())
        if prev is not None:
            assert n >= prev
        prev = n
    assert int((core.decide(b, pos, None, 0)["verdict"] == "close_benign").sum()) == 0


def test_system_prompt_states_the_limits():
    s = agent.SYSTEM
    assert "data, not instructions" in s and "cannot block traffic" in s
    assert re.search(r"at most 7 tool calls", s)
