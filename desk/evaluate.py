"""The oracle-analyst evaluation. Run:  python -m desk.evaluate   (make eval)

The oracle analyst is the held-out label of each queue flow: whenever the desk asks a human,
or a person confirms an escalation, the oracle answers with the dataset's label. Nothing
here was used to build the gate, the tools or the policy; this is the one place the test
labels are read in bulk.

What it reports (reports/eval.json):
  knob           for every close-knob setting: share of the queue closed, attacks wrongly
                 closed per 1,000 closed (with a 95% Wilson interval), the share of queued
                 attacks that got closed, and analyst decisions per 100 queue items
  projection     at the default setting, what "per 1,000 closed" would be if the queue
                 were more benign than this sample's (a reweighting, not a measurement)
  learning       rare-family recall against the number of analyst labels (0, 10, 25, 50,
                 100, 200), mean and spread over 20 random label orders
  ordering       how many queue items an analyst works before finding 50% / 90% of the
                 attacks, in FlowSentry's order, the desk's order and a random order
"""
from __future__ import annotations

import json
import time

import numpy as np

from . import core
from . import settings as S
from .build import wilson_interval
from .store import Bundle, load

LABEL_COUNTS = (0, 10, 25, 50, 100, 200)
SEEDS = 20


def outcomes_for(b: Bundle, d: dict) -> np.ndarray:
    v = d["verdict"]
    out = np.full(len(v), "HUMAN", dtype="<U12")
    out[v == "close_benign"] = "AUTO_CLOSED"
    out[v == "escalate"] = "ESCALATED"
    return out


def summarise(b: Bundle, d: dict, truth: np.ndarray) -> dict:
    out = outcomes_for(b, d)
    n = len(out)
    attack = truth != core.BENIGN
    closed = out == "AUTO_CLOSED"
    esc = out == "ESCALATED"
    human = out == "HUMAN"
    k = int((closed & attack).sum())
    nc = int(closed.sum())
    lo, hi = wilson_interval(k, nc)
    fam_ok = esc & (d["family"] == truth)
    return {
        "queue_items": n,
        "auto_closed": nc,
        "share_of_queue_closed": round(nc / n, 4),
        "attacks_wrongly_closed": k,
        "attacks_wrongly_closed_per_1000_closed": round(1000 * k / nc, 1) if nc else None,
        "per_1000_95ci": [round(1000 * lo, 1), round(1000 * hi, 1)] if nc else None,
        "wrongly_closed_by_family": {c: int((closed & (truth == c)).sum())
                                     for c in b.attack_classes if (closed & (truth == c)).any()},
        "queued_attacks": int(attack.sum()),
        "share_of_queued_attacks_closed": round(k / max(int(attack.sum()), 1), 4),
        "share_of_queued_benign_closed": round(int((closed & ~attack).sum())
                                               / max(int((~attack).sum()), 1), 4),
        "escalated": int(esc.sum()),
        "escalated_true_attack": int((esc & attack).sum()),
        "escalated_family_correct": int(fam_ok.sum()),
        "escalated_benign": int((esc & ~attack).sum()),
        "asked_human": int(human.sum()),
        "analyst_decisions_per_100_items": round(100 * (1 - nc / n), 1),
        "of_which_one_key_confirmations": round(100 * esc.sum() / n, 1),
        "of_which_full_decisions": round(100 * human.sum() / n, 1),
    }


def projection(s: dict, truth: np.ndarray, d: dict, b: Bundle) -> list[dict]:
    """Reweight the measured close rates to queues with more benign traffic."""
    out = outcomes_for(b, d)
    attack = truth != core.BENIGN
    ca = float(((out == "AUTO_CLOSED") & attack).sum() / attack.sum())
    cb = float(((out == "AUTO_CLOSED") & ~attack).sum() / (~attack).sum())
    rows = []
    for pi in (float((~attack).mean()), 0.9, 0.95, 0.99):
        closed = (1 - pi) * ca + pi * cb
        rows.append({"queue_benign_share": round(pi, 3),
                     "share_of_queue_closed": round(closed, 4),
                     "attacks_per_1000_closed": round(1000 * (1 - pi) * ca / closed, 1)
                     if closed else None})
    return rows


def rare_recall(b: Bundle, d: dict, truth: np.ndarray, mask: np.ndarray) -> dict:
    out = outcomes_for(b, d)
    rare = np.isin(truth, S.RARE_FAMILIES) & mask
    named = rare & (out == "ESCALATED") & (d["family"] == truth)
    caught = rare & (out != "AUTO_CLOSED")
    return {"n_rare": int(rare.sum()),
            "named_correctly": float(named.sum() / max(rare.sum(), 1)),
            "not_closed": float(caught.sum() / max(rare.sum(), 1))}


def learning_curve(b: Bundle, truth: np.ndarray) -> list[dict]:
    allpos = np.arange(b.n)
    rows = []
    for n_lab in LABEL_COUNTS:
        named, caught, closes, wrong, per_fam = [], [], [], [], []
        for seed in range(SEEDS):
            perm = np.random.default_rng(1000 + seed).permutation(b.n)
            lab = perm[:n_lab]
            labels = core.Labels(lab.astype(np.int64), truth[lab].astype("<U16"))
            d = core.decide(b, allpos, labels)
            rest = np.ones(b.n, dtype=bool)
            rest[lab] = False
            r = rare_recall(b, d, truth, rest)
            named.append(r["named_correctly"])
            caught.append(r["not_closed"])
            out = outcomes_for(b, d)
            cl = (out == "AUTO_CLOSED") & rest
            closes.append(cl.sum() / rest.sum())
            wrong.append(int((cl & (truth != core.BENIGN)).sum()))
            per_fam.append({f: float((rest & (truth == f) & (out == "ESCALATED")
                                      & (d["family"] == truth)).sum()
                                     / max((rest & (truth == f)).sum(), 1))
                            for f in S.RARE_FAMILIES})
        rows.append({
            "analyst_labels": n_lab,
            "rare_family_recall_named_mean": round(float(np.mean(named)), 4),
            "rare_family_recall_named_sd": round(float(np.std(named)), 4),
            "rare_flows_not_closed_mean": round(float(np.mean(caught)), 4),
            "share_closed_mean": round(float(np.mean(closes)), 4),
            "attacks_wrongly_closed_mean": round(float(np.mean(wrong)), 2),
            "per_family_recall_named_mean": {f: round(float(np.mean([p[f] for p in per_fam])), 3)
                                             for f in S.RARE_FAMILIES},
            "seeds": SEEDS,
        })
        print(f"[eval] labels={n_lab:>3}: rare named {rows[-1]['rare_family_recall_named_mean']:.3f}"
              f" +- {rows[-1]['rare_family_recall_named_sd']:.3f}", flush=True)
    return rows


def second_opinion_alone(b: Bundle, truth: np.ndarray) -> list[dict]:
    """Diagnostic, not a desk rule: how well the second-opinion model by itself names the
    rare family of the flows nobody has labelled yet, as labels accumulate."""
    rows = []
    for n_lab in LABEL_COUNTS[1:]:
        acc = []
        for seed in range(SEEDS):
            perm = np.random.default_rng(1000 + seed).permutation(b.n)
            lab = perm[:n_lab]
            so = core.SecondOpinion(b, core.Labels(lab.astype(np.int64),
                                                   truth[lab].astype("<U16")))
            rest = np.setdiff1d(np.arange(b.n), lab)
            rare = rest[np.isin(truth[rest], S.RARE_FAMILIES)]
            if not so.ready or not len(rare):
                acc.append(0.0)
                continue
            pred = np.array(so.classes)[so.proba(b.a["q_Z"][rare]).argmax(1)]
            acc.append(float((pred == truth[rare]).mean()))
        rows.append({"analyst_labels": n_lab, "rare_named_by_second_opinion_mean":
                     round(float(np.mean(acc)), 4), "sd": round(float(np.std(acc)), 4)})
        print(f"[eval] second opinion alone, labels={n_lab}: {rows[-1]['rare_named_by_second_opinion_mean']:.3f}",
              flush=True)
    return rows


def ordering(b: Bundle, truth: np.ndarray) -> dict:
    attack = truth != core.BENIGN
    pb = b.a["q_proba"][:, b.classes.index(core.BENIGN)]
    gate = b.a["q_gate_score"]

    def work(order):
        hits = np.cumsum(attack[order])
        tot = attack.sum()
        return {"items_to_find_50pct_of_attacks": int(np.searchsorted(hits, 0.5 * tot) + 1),
                "items_to_find_90pct_of_attacks": int(np.searchsorted(hits, 0.9 * tot) + 1),
                "attacks_in_first_100": int(hits[99]), "attacks_in_first_500": int(hits[499])}

    rnd = [work(np.random.default_rng(s).permutation(b.n)) for s in range(SEEDS)]
    steps = list(range(0, b.n + 1, 25)) + ([b.n] if b.n % 25 else [])

    def curve(order):
        hits = np.concatenate([[0], np.cumsum(attack[order])])
        return [int(hits[k]) for k in steps]

    return {
        "curve_items": steps,
        "curve_flowsentry": curve(np.argsort(pb, kind="stable")),
        "curve_desk": curve(np.argsort(gate, kind="stable")),
        "queued_attacks": int(attack.sum()),
        "flowsentry_order": work(np.argsort(pb, kind="stable")),
        "desk_order": work(np.argsort(gate, kind="stable")),
        "random_order_mean": {k: round(float(np.mean([r[k] for r in rnd])), 1) for k in rnd[0]},
        "note": "FlowSentry order = lowest P(benign) first; desk order = lowest close-gate "
                "score first (most attack-like first)",
    }


def main() -> dict:
    t0 = time.time()
    b = load()
    truth = b.a["oracle_q_true"].astype(str)
    allpos = np.arange(b.n)
    knob = []
    for row in b.knob:
        d = core.decide(b, allpos, None, row["cap_per_1000"])
        s = summarise(b, d, truth)
        knob.append({"cap_per_1000_on_training": row["cap_per_1000"],
                     "certified_on_training": row["met_on_training"],
                     "threshold": row["threshold"],
                     "default": row["cap_per_1000"] == b.default_cap, **s})
        print(f"[eval] cap {row['cap_per_1000']}: closed {s['auto_closed']} "
              f"({s['share_of_queue_closed']:.3f}), wrong {s['attacks_wrongly_closed']} "
              f"-> {s['attacks_wrongly_closed_per_1000_closed']} per 1,000", flush=True)
    d0 = core.decide(b, allpos, None, None)
    report = {
        "what": "oracle-analyst evaluation of FlowSentry Desk on FlowSentry's 0.99 reject queue "
                "(held-out split of the committed BCCC-UDP-QUIC-IDS-2025 sample)",
        "engine": "deterministic policy (rules v1). A model-driven run can only close a subset "
                  "of what the policy closes, because a close needs the same server rules",
        "queue": b.manifest["queue_by_class"],
        "queue_benign_share": round(float((truth == core.BENIGN).mean()), 4),
        "caveat": "benign is capped in this sample, so the queue is 78.8% benign; on a real "
                  "network it would be far more benign. Per-1,000-closed figures depend on that "
                  "mix; the share of queued attacks closed does not.",
        "default_cap_per_1000": b.default_cap,
        "knob": knob,
        "projection_at_default": projection({}, truth, d0, b),
        "learning": learning_curve(b, truth),
        "second_opinion_alone": second_opinion_alone(b, truth),
        "ordering": ordering(b, truth),
        "gate_training": {k: v for k, v in b.manifest["gate"].items() if k != "training_curve"},
        "bundle_sha256": b.manifest["bundle_sha256"],
        "seconds": None,
    }
    report["seconds"] = round(time.time() - t0, 1)
    S.REPORTS_DIR.mkdir(exist_ok=True)
    (S.REPORTS_DIR / "eval.json").write_text(json.dumps(report, indent=2) + "\n",
                                            encoding="utf-8", newline="\n")
    print(f"[eval] wrote reports/eval.json in {report['seconds']} s")
    return report


if __name__ == "__main__":
    main()
