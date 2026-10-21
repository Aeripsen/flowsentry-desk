"""The Claude loop, driven by a fake client that plays back scripted tool calls.

These check the harness, not the model: step budget, citation checks, refusals, API
failures, and that whatever the model says, a close still needs the server rules.
"""
import json
from types import SimpleNamespace as NS

import numpy as np

from desk import agent, core


def tool_use(i, name, inp):
    return NS(type="tool_use", id=f"tu{i}", name=name, input=inp)


def msg(*blocks, stop="tool_use"):
    return NS(content=list(blocks), stop_reason=stop,
              usage=NS(input_tokens=100, output_tokens=20))


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.beta = NS(messages=NS(create=self._create))
        self.messages = NS(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        if not self.script:
            return msg(NS(type="text", text="done"), stop="end_turn")
        nxt = self.script.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def propose(i, verdict, memo, cites, family="", ticket=""):
    return tool_use(i, "propose", {"verdict": verdict, "family": family, "memo": memo,
                                   "citations": cites, "ticket": ticket})


def first(b, verdict):
    d = core.decide(b, np.arange(b.n))
    return int(np.nonzero(d["verdict"] == verdict)[0][0])


ENGINE = ("anthropic", "claude-sonnet-5-5")


def test_a_clean_run_settles_with_checked_citations(b):
    pos = first(b, "escalate")
    fam = core.one(core.decide(b, np.array([pos])))["family"]
    fc = FakeClient([
        msg(tool_use(1, "next_case", {})),
        msg(tool_use(2, "precedents", {"k": 8}), tool_use(3, "family_card", {"family": fam})),
        msg(propose(4, "escalate", f"Looks like {fam} [R1] [R2] [R3].", ["R1", "R2", "R3"],
                    fam, "Page netops [R3].")),
    ])
    r = agent.model_run(b, pos, engine=ENGINE, client=fc)
    assert r.outcome == "ESCALATED" and r.citations_ok and r.final["family"] == fam
    assert [s["tool"] for s in r.steps] == ["next_case", "precedents", "family_card", "propose"]
    # the request carried strict tools, the cached system prompt and the refusal fallback
    kw = fc.calls[0]
    assert all(t["strict"] for t in kw["tools"])
    assert kw["system"][0]["cache_control"]["type"] == "ephemeral"
    assert kw["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in kw["betas"]
    assert kw["model"] == "claude-sonnet-5-5"


def test_a_bad_citation_is_refused_and_can_be_fixed(b):
    pos = first(b, "ask_human")
    fc = FakeClient([
        msg(tool_use(1, "next_case", {})),
        msg(propose(2, "ask_human", "Odd [R5].", ["R5"])),
        msg(propose(3, "ask_human", "Odd [R1].", ["R1"])),
    ])
    r = agent.model_run(b, pos, engine=ENGINE, client=fc)
    assert r.steps[1]["error"] and "R5" in str(r.steps[1]["result"])
    assert r.outcome == "HUMAN" and r.citations_ok


def test_the_model_cannot_close_what_the_rules_refuse(b):
    pos = first(b, "ask_human")
    d = core.one(core.decide(b, np.array([pos])))
    assert not d["close_allowed"]
    fc = FakeClient([
        msg(tool_use(1, "next_case", {})),
        msg(tool_use(2, "precedents", {"k": 8})),
        msg(propose(3, "close_benign", "Benign [R1] [R2].", ["R1", "R2"])),
    ])
    r = agent.model_run(b, pos, engine=ENGINE, client=fc)
    assert r.final["verdict"] == "close_benign"
    assert r.outcome == "HUMAN" and "did not allow" in r.outcome_reason


def test_a_close_the_rules_allow_goes_through(b):
    pos = first(b, "close_benign")
    fc = FakeClient([
        msg(tool_use(1, "next_case", {})),
        msg(tool_use(2, "precedents", {"k": 8})),
        msg(propose(3, "close_benign", "Benign [R1] [R2].", ["R1", "R2"])),
    ])
    assert agent.model_run(b, pos, engine=ENGINE, client=fc).outcome == "AUTO_CLOSED"


def test_the_step_budget_holds(b):
    pos = int(b.order[0])
    fc = FakeClient([msg(tool_use(i, "explain", {"toward": "benign", "top": 5}))
                     for i in range(20)])
    r = agent.model_run(b, pos, engine=ENGINE, client=fc)
    real = [s for s in r.steps if s["tool"] != "propose"]
    assert len(real) <= 7
    assert r.outcome == "HUMAN" and r.final is None


def test_a_refusal_sends_the_case_to_a_person(b):
    fc = FakeClient([msg(NS(type="text", text=""), stop="refusal")])
    r = agent.model_run(b, int(b.order[0]), engine=ENGINE, client=fc)
    assert r.outcome == "HUMAN" and "declined" in (r.error or "")


def test_an_api_failure_sends_the_case_to_a_person(b):
    fc = FakeClient([RuntimeError("connection reset")])
    r = agent.model_run(b, first(b, "close_benign"), engine=ENGINE, client=fc)
    assert r.outcome == "HUMAN" and "connection reset" in r.error


def test_unknown_tools_are_errors_not_crashes(b):
    fc = FakeClient([msg(tool_use(1, "block_ip", {"ip": "1.2.3.4"})),
                     msg(tool_use(2, "next_case", {})),
                     msg(propose(3, "ask_human", "See [R1].", ["R1"]))])
    r = agent.model_run(b, int(b.order[0]), engine=ENGINE, client=fc)
    assert r.steps[0]["error"] and r.outcome == "HUMAN" and r.citations_ok


def test_openai_compatible_loop(b, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-not-a-key")
    pos = first(b, "escalate")
    fam = core.one(core.decide(b, np.array([pos])))["family"]
    replies = [
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c1", "function": {"name": "next_case", "arguments": "{}"}}]}}],
         "usage": {"prompt_tokens": 50, "completion_tokens": 5}},
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c2", "function": {"name": "propose", "arguments": json.dumps(
                {"verdict": "escalate", "family": fam, "memo": "Flood [R1].",
                 "citations": ["R1"], "ticket": "t"})}}]}}], "usage": {}},
    ]

    class Resp:
        def __init__(self, data):
            self.status_code, self._d, self.headers = 200, data, {}

        def raise_for_status(self):
            pass

        def json(self):
            return self._d

    class Http:
        def post(self, url, headers, json):
            assert headers["Authorization"] == "Bearer test-not-a-key"
            return Resp(replies.pop(0))

    r = agent.model_run(b, pos, engine=("groq", "openai/gpt-oss-120b"), client=Http())
    assert r.outcome == "ESCALATED" and r.tokens_in == 50


def test_policy_runs_are_deterministic_and_cited(b):
    for k in range(40):
        pos = int(b.order[k])
        r1, r2 = agent.policy_run(b, pos), agent.policy_run(b, pos)
        assert r1.final == r2.final and r1.outcome == r2.outcome
        assert r1.citations_ok
        d = core.one(core.decide(b, np.array([pos])))
        assert (r1.outcome == "AUTO_CLOSED") == bool(d["close_allowed"])
