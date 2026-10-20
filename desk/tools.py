"""The six read-only tools, and the ledger that makes citations checkable.

Every tool result gets an id (R1, R2, ...) that only the server issues. A proposal must
cite ids from its own run; the server rejects any id it did not issue in that run, and
any close the decision core does not allow. No tool writes anything, touches a network,
or can block traffic: the worst a tool call can do is read the bundle.

None of these functions reads a key starting with "oracle_" (the held-out labels).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from . import core
from .features import describe
from .store import Bundle

VERDICTS = ("close_benign", "escalate", "ask_human")
CITE_RE = re.compile(r"\[(R\d+)\]")


@dataclass
class Ledger:
    """Tool results issued in one run, by id."""

    results: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, tool: str, args: dict, result: dict) -> str:
        rid = f"R{len(self.results) + 1}"
        self.results[rid] = {"tool": tool, "args": args, "result": result}
        return rid

    def has(self, rid: str) -> bool:
        return rid in self.results

    def tools_used(self) -> set[str]:
        return {r["tool"] for r in self.results.values()}


def _r(x: float, nd: int = 4) -> float:
    return float(f"{float(x):.{nd}g}")


@dataclass
class CaseContext:
    b: Bundle
    pos: int
    labels: core.Labels
    cap: float | None = None
    ledger: Ledger = field(default_factory=Ledger)
    final: dict | None = None
    propose_attempts: int = 0

    @property
    def case_id(self) -> str:
        return self.b.case_id(self.pos)

    def decision(self) -> dict:
        return core.one(core.decide(self.b, np.array([self.pos]), self.labels, self.cap))


# ----------------------------------------------------------------------- tools


def next_case(ctx: CaseContext, args: dict) -> dict:
    b, p = ctx.b, ctx.pos
    a = b.a
    classes = b.classes
    pr = a["q_proba"][p]
    top = np.argsort(-pr)[:3]
    keys = [str(k) for k in a["key_features"]]
    fn = [str(f) for f in a["feature_names"]]
    return {
        "case_id": ctx.case_id,
        "flow_ref": str(a["q_flow_id"][p]),
        "why_in_queue": f"FlowSentry confidence {_r(a['q_conf'][p])} is below the 0.99 reject "
                        "threshold, so FlowSentry refused to answer automatically",
        "flowsentry": {
            "predicted": str(a["q_pred"][p]),
            "confidence": _r(a["q_conf"][p]),
            "answered_by": "stage 2 (UDP + QUIC features)" if a["q_escalated"][p]
            else "stage 1 (UDP features only)",
            "p_benign": _r(pr[classes.index("benign")]),
            "top_classes": [{"class": classes[i], "p": _r(pr[i])} for i in top],
        },
        "key_features": [
            {"feature": k, "meaning": describe(k), "value": _r(a["q_X"][p][fn.index(k)]),
             "typical_benign": _r(a["benign_median_key"][i])}
            for i, k in enumerate(keys)
        ],
    }


def explain(ctx: CaseContext, args: dict) -> dict:
    b, p = ctx.b, ctx.pos
    a = b.a
    toward = args.get("toward", "predicted")
    if toward not in ("predicted", "benign"):
        raise ValueError("toward must be 'predicted' or 'benign'")
    fn = [str(f) for f in a["feature_names"]]
    pred = str(a["q_pred"][p])
    target = pred if toward == "predicted" else "benign"
    idx = a["q_top_pred_idx"][p] if toward == "predicted" else a["q_top_benign_idx"][p]
    val = a["q_top_pred_val"][p] if toward == "predicted" else a["q_top_benign_val"][p]
    n = int(min(max(int(args.get("top", 8)), 3), 12))
    rows = []
    for j, c in zip(idx[:n], val[:n], strict=True):
        rows.append({
            "feature": fn[int(j)],
            "meaning": describe(fn[int(j)]),
            "value": _r(a["q_X"][p][int(j)]),
            "contribution": _r(c, 3),
            "direction": f"raises P({target})" if c > 0 else f"lowers P({target})",
        })
    bias = float(a["q_explain_bias"][p][b.classes.index(target)])
    return {
        "case_id": ctx.case_id,
        "toward_class": target,
        "method": "exact path contributions on the FlowSentry forest that answered this flow; "
                  "base rate + all contributions = FlowSentry's probability",
        "base_rate": _r(bias, 3),
        "probability": _r(a["q_proba"][p][b.classes.index(target)], 3),
        "top_features": rows,
    }


def precedents(ctx: CaseContext, args: dict) -> dict:
    b, p = ctx.b, ctx.pos
    a = b.a
    k = int(min(max(int(args.get("k", 8)), 3), 15))
    nb = a["q_nb_idx"][p]
    dist = a["q_nb_dist"][p]
    keys = [str(x) for x in a["key_features"]]
    labs = a["p_label"][nb].astype(str)
    share, lead, _ = core.precedent_summary(b, np.array([p]))
    uniq, cnt = np.unique(labs, return_counts=True)
    rows = []
    for j in range(k):
        rows.append({
            "flow_ref": str(a["p_flow_id"][nb[j]]),
            "label": labs[j],
            "distance": _r(dist[j], 3),
            "key": {kk: _r(v) for kk, v in zip(keys[:5], a["p_key_X"][nb[j]][:5], strict=True)},
        })
    mine = []
    if len(ctx.labels):
        Zp = a["q_Z"][p].astype(np.float64)
        Zl = a["q_Z"][ctx.labels.pos].astype(np.float64)
        dl = np.sqrt(((Zl - Zp) ** 2).sum(1))
        for j in np.argsort(dl)[:5]:
            if ctx.labels.pos[j] == p:
                continue
            mine.append({"case_id": b.case_id(int(ctx.labels.pos[j])),
                         "analyst_label": str(ctx.labels.y[j]), "distance": _r(dl[j], 3),
                         "inside_neighbourhood": bool(dl[j] <= dist[-1])})
    return {
        "case_id": ctx.case_id,
        "source": "labelled flows from the training split (no test flow, no connection "
                  "shared with this one)",
        "of_15_nearest": {str(u): int(c) for u, c in zip(uniq, cnt, strict=True)},
        "benign_share_of_15": _r(share[0], 3),
        "leading_attack_family": str(lead[0]) or None,
        "nearest": rows,
        "your_labelled_cases_nearby": mine,
    }


def family_card(ctx: CaseContext, args: dict) -> dict:
    fam = str(args.get("family", ""))
    cards = ctx.b.manifest["family_cards"]
    if fam not in cards:
        raise ValueError(f"unknown family {fam!r}; one of {sorted(cards)}")
    return cards[fam]


def second_opinion(ctx: CaseContext, args: dict) -> dict:
    so = core.second_opinion(ctx.b, ctx.labels)
    if not so.ready:
        return {
            "case_id": ctx.case_id,
            "status": "not_trained",
            "analyst_labels_so_far": so.n_labels,
            "needs": f"at least {core.MIN_SECOND_OPINION_LABELS} analyst labels with two "
                     "different classes",
        }
    pr = so.proba(ctx.b.a["q_Z"][[ctx.pos]])[0]
    order = np.argsort(-pr)
    return {
        "case_id": ctx.case_id,
        "status": "trained",
        "analyst_labels_so_far": so.n_labels,
        "model": "100-tree extra-trees forest trained only on this analyst's labels",
        "probabilities": [{"class": so.classes[i], "p": _r(pr[i], 3)} for i in order[:4]],
    }


def propose(ctx: CaseContext, args: dict) -> dict:
    """Validate a proposed verdict. Accepted proposals end the run."""
    ctx.propose_attempts += 1
    errors: list[str] = []
    verdict = args.get("verdict")
    family = args.get("family") or ""
    memo = str(args.get("memo", "")).strip()
    cited = [str(c) for c in (args.get("citations") or [])]
    if verdict not in VERDICTS:
        errors.append(f"verdict must be one of {VERDICTS}")
    inline = CITE_RE.findall(memo)
    if not memo:
        errors.append("memo is empty")
    if not cited and not inline:
        errors.append("cite at least one tool result id, e.g. [R2]")
    for rid in sorted(set(cited) | set(inline)):
        if not ctx.ledger.has(rid):
            errors.append(f"{rid} was not issued in this run; cite only ids you received")
    if verdict == "close_benign" and "precedents" not in ctx.ledger.tools_used():
        errors.append("look at precedents before proposing a close")
    if verdict == "escalate" and family not in ctx.b.attack_classes:
        errors.append(f"escalate needs a family, one of {ctx.b.attack_classes}")
    if errors:
        return {"accepted": False, "errors": errors,
                "hint": "fix the errors, or choose ask_human if the evidence conflicts"}
    ctx.final = {
        "verdict": verdict,
        "family": family if verdict == "escalate" else "",
        "memo": memo,
        "citations": sorted(set(cited) | set(inline), key=lambda r: int(r[1:])),
        "ticket": str(args.get("ticket", "")).strip() if verdict == "escalate" else "",
    }
    return {"accepted": True, "verdict": verdict, "family": ctx.final["family"]}


TOOLS = {
    "next_case": next_case,
    "explain": explain,
    "precedents": precedents,
    "family_card": family_card,
    "second_opinion": second_opinion,
    "propose": propose,
}


def call(ctx: CaseContext, name: str, args: dict) -> tuple[str | None, dict, bool]:
    """Run one tool. Returns (result id or None for propose, result, is_error)."""
    fn = TOOLS.get(name)
    if fn is None:
        return None, {"error": f"unknown tool {name}"}, True
    try:
        result = fn(ctx, dict(args or {}))
    except (ValueError, KeyError, TypeError) as e:
        return None, {"error": str(e)}, True
    if name == "propose":
        return None, result, not result.get("accepted", False)
    rid = ctx.ledger.add(name, dict(args or {}), result)
    return rid, {"result_id": rid, **result}, False


# JSON schemas for the Claude API (strict tool use).
TOOL_SCHEMAS = [
    {
        "name": "next_case",
        "description": "Open the case assigned to you: FlowSentry's verdict and confidence, why "
                       "it was queued, and key flow statistics next to typical benign values. "
                       "Always call this first.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False,
                         "required": []},
    },
    {
        "name": "explain",
        "description": "Which features pushed FlowSentry's probability up or down for this flow, "
                       "exactly, on the forest that answered it. toward='predicted' explains "
                       "FlowSentry's predicted class; toward='benign' explains P(benign).",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": {"toward": {"type": "string",
                                                   "enum": ["predicted", "benign"]},
                                        "top": {"type": "integer"}},
                         "required": ["toward", "top"]},
    },
    {
        "name": "precedents",
        "description": "The nearest labelled flows from training history (label counts among "
                       "the 15 nearest, the nearest k rows), plus cases this analyst already "
                       "labelled that are close to this one.",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": {"k": {"type": "integer"}}, "required": ["k"]},
    },
    {
        "name": "family_card",
        "description": "What an attack family (or benign) typically looks like in training data, "
                       "how often FlowSentry is unsure about it, and its ATT&CK technique and "
                       "response playbook.",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": {"family": {"type": "string", "enum": [
                             "benign", "UDP-RAW", "UDP-VSE", "UDP-OVH", "UDP-MULTI",
                             "UDP-HULK", "UDP-bypass-v1", "UDP-GAME"]}},
                         "required": ["family"]},
    },
    {
        "name": "second_opinion",
        "description": "A small model trained only on this analyst's own labels so far. Says "
                       "'not_trained' until there are enough labels.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False,
                         "required": []},
    },
    {
        "name": "propose",
        "description": "Finish the case. verdict: close_benign (only when all the evidence "
                       "points to benign traffic; a close still needs an independent server "
                       "check you cannot see, and otherwise goes to a human), "
                       "escalate (attack; name the family and draft a short ticket), or "
                       "ask_human (evidence conflicts or is thin). The memo must cite result "
                       "ids inline like [R2]; list every cited id in citations.",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": {
                             "verdict": {"type": "string", "enum": list(VERDICTS)},
                             "family": {"type": "string"},
                             "memo": {"type": "string"},
                             "citations": {"type": "array", "items": {"type": "string"}},
                             "ticket": {"type": "string"}},
                         "required": ["verdict", "family", "memo", "citations", "ticket"]},
    },
]
