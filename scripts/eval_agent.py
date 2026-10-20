"""Evaluate model-driven runs against the oracle analyst.

    python scripts/eval_agent.py                      the recorded runs (no labels)
    python scripts/eval_agent.py --sample 60          fresh runs on a fixed random sample
                                                      (needs a key; costs tokens)

Writes reports/agent_eval.json: outcomes against the dataset labels, wrong closes,
agreement with the deterministic policy, citation pass rate, steps and tokens.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desk import agent  # noqa: E402
from desk import settings as S  # noqa: E402
from desk.store import load  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0)
    args = ap.parse_args()
    b = load()
    truth = b.a["oracle_q_true"].astype(str)
    runs: list[dict] = []
    if args.sample:
        eng = agent.available_engine()
        if eng is None:
            raise SystemExit("no model key configured")
        pick = np.random.default_rng(7).choice(b.n, size=args.sample, replace=False)
        for i, pos in enumerate(pick, 1):
            r = agent.model_run(b, int(pos), engine=eng).to_dict()
            runs.append(r)
            print(f"[{i}/{len(pick)}] {r['case_id']} {r['outcome']}", flush=True)
        with (S.RUNS_DIR / "eval_sample.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
            for r in runs:
                fh.write(json.dumps(r) + "\n")
    else:
        path = S.RUNS_DIR / "recorded.jsonl"
        seen = {}
        for line in path.read_text(encoding="utf-8").splitlines() if path.exists() else []:
            r = json.loads(line)
            if r.get("labels_fingerprint", "none") == "none" and r["engine"] != "policy":
                seen[r["case_id"]] = r
        runs = list(seen.values())
    if not runs:
        raise SystemExit("no model runs to evaluate")
    rows = collections.Counter()
    wrong_close = agree = cites = steps = tin = tout = errors = 0
    model_names = collections.Counter()
    for r in runs:
        pos = b.pos(r["case_id"])
        t = truth[pos]
        kind = "benign" if t == "benign" else "attack"
        rows[(kind, r["outcome"])] += 1
        if r["outcome"] == "AUTO_CLOSED" and kind == "attack":
            wrong_close += 1
        pol = agent.policy_run(b, pos)
        agree += int(pol.outcome == r["outcome"])
        cites += int(r["citations_ok"])
        steps += len(r["steps"])
        tin += r["tokens_in"]
        tout += r["tokens_out"]
        errors += int(bool(r.get("error")))
        model_names[f"{r['engine']} {r['model']}"] += 1
    n = len(runs)
    rep = {
        "what": "model-driven agent runs against the oracle analyst (dataset labels)",
        "runs": n,
        "models": dict(model_names),
        "outcomes": {f"{k} -> {o}": v for (k, o), v in sorted(rows.items())},
        "attacks_auto_closed": wrong_close,
        "same_outcome_as_policy": round(agree / n, 4),
        "citations_passed": round(cites / n, 4),
        "mean_steps": round(steps / n, 2),
        "runs_with_errors": errors,
        "mean_tokens_in": round(tin / n),
        "mean_tokens_out": round(tout / n),
        "caveat": "a small sample; a model close still needs the same server rules as the policy",
    }
    rep["summary"] = (f"{n} model runs ({', '.join(model_names)}): {wrong_close} attacks auto-closed, "
                      f"{100 * rep['same_outcome_as_policy']:.0f}% same outcome as the policy, "
                      f"{100 * rep['citations_passed']:.0f}% passed the citation check, "
                      f"{rep['mean_steps']} steps on average.")
    S.REPORTS_DIR.mkdir(exist_ok=True)
    (S.REPORTS_DIR / "agent_eval.json").write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8",
                                                  newline="\n")
    print(rep["summary"])


if __name__ == "__main__":
    main()
