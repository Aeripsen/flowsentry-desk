"""Record model runs for the demo queue, so the live link works with no API during judging.

    python scripts/record_agent.py --n 40              first 40 cases in queue order
    python scripts/record_agent.py --cases C0007 C0012
    python scripts/record_agent.py --demo-path         the video's override-then-next path

Needs a model key (ANTHROPIC_API_KEY in .env; DESK_PROVIDER picks another engine).
Appends to runs/recorded.jsonl; the app serves the latest run per case and label state.
Prints cost-relevant counts, never a key.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from desk import agent, core  # noqa: E402
from desk import settings as S  # noqa: E402
from desk.store import load  # noqa: E402


def demo_path() -> list[tuple[str, list[tuple[str, str]], float | None]]:
    path = ROOT / "runs" / "demo_path.json"
    if not path.exists():
        return []
    d = json.loads(path.read_text(encoding="utf-8"))
    return [(step["case_id"], [tuple(x) for x in step["labels"]], step.get("cap")) for step in d["steps"]]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=0)
    ap.add_argument("--cases", nargs="*", default=[])
    ap.add_argument("--demo-path", action="store_true")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between cases")
    args = ap.parse_args()
    eng = agent.available_engine()
    if eng is None:
        raise SystemExit("no model key configured: put ANTHROPIC_API_KEY in .env (see docs/HIS_CLICKS.md)")
    b = load()
    jobs: list[tuple[str, list[tuple[str, str]], float | None]] = [
        (b.case_id(int(b.order[k])), [], None) for k in range(args.n)]
    jobs += [(c, [], None) for c in args.cases]
    if args.demo_path:
        jobs += demo_path()
    S.RUNS_DIR.mkdir(exist_ok=True)
    out = S.RUNS_DIR / "recorded.jsonl"
    tin = tout = 0
    with out.open("a", encoding="utf-8", newline="\n") as fh:
        for i, (cid, pairs, cap) in enumerate(jobs, 1):
            labels = agent.labels_for(b, pairs) if pairs else core.Labels()
            r = agent.model_run(b, b.pos(cid), labels, eng, cap=cap)
            d = r.to_dict()
            d["recorded"] = True
            fh.write(json.dumps(d) + "\n")
            fh.flush()
            tin += r.tokens_in
            tout += r.tokens_out
            fin = r.final or {}
            print(f"[{i}/{len(jobs)}] {cid} labels={len(labels)} {r.outcome:<11} "
                  f"{fin.get('verdict', '-'):<12} steps={len(r.steps)} {r.seconds}s "
                  f"err={r.error or '-'}", flush=True)
            if args.sleep:
                time.sleep(args.sleep)
    print(f"done: {len(jobs)} runs with {eng[0]} {eng[1]}, {tin} input and {tout} output tokens")


if __name__ == "__main__":
    main()
