"""Rebuild the data bundle from FlowSentry and compare it with the committed one.

CI runs this on a clean Linux runner (`make verify-data`). It requires: the retrained
FlowSentry matches its published metrics, the same queue, explanations that reconstruct
FlowSentry's probabilities, and the same close-knob thresholds and gate scores up to
floating-point noise. Exact bytes can differ across platforms (thread and BLAS order), so
the check is on values, with the tolerances printed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def git_show(path: str) -> bytes:
    return subprocess.run(["git", "show", f"HEAD:{path}"], cwd=ROOT, check=True,
                          capture_output=True).stdout


def main() -> int:
    old_manifest = json.loads(git_show("data/desk_manifest.json"))
    old_npz = ROOT / "build" / "committed_bundle.npz"
    old_npz.parent.mkdir(exist_ok=True)
    old_npz.write_bytes(git_show("data/desk_bundle.npz"))
    subprocess.run([sys.executable, "-m", "desk.build"], cwd=ROOT, check=True)
    new_manifest = json.loads((ROOT / "data" / "desk_manifest.json").read_text())
    problems = []
    if not new_manifest["provenance"]["metrics_match_published"]:
        problems.append("retrained FlowSentry does not match its published metrics")
    for k in ("n_queue", "queue_by_class", "n_heldout"):
        if new_manifest[k] != old_manifest[k]:
            problems.append(f"{k} differs")
    if new_manifest["explanation_max_abs_error"] > 1e-6:
        problems.append("explanations do not reconstruct the probabilities")
    with np.load(old_npz) as a, np.load(ROOT / "data" / "desk_bundle.npz") as b:
        for key in ("q_flow_id", "q_pred", "p_label", "q_nb_idx", "oracle_q_true"):
            if not np.array_equal(a[key], b[key]):
                problems.append(f"{key} differs")
        for key, tol in (("q_conf", 1e-6), ("q_proba", 1e-6), ("q_gate_score", 1e-4), ("q_Z", 1e-4)):
            d = float(np.abs(a[key].astype(float) - b[key].astype(float)).max())
            print(f"max |diff| {key}: {d:.3g} (tolerance {tol})")
            if d > tol:
                problems.append(f"{key} differs by {d}")
    for o, n in zip(old_manifest["gate"]["knob"], new_manifest["gate"]["knob"], strict=True):
        if (o["threshold"] is None) != (n["threshold"] is None) or (
                o["threshold"] is not None and abs(o["threshold"] - n["threshold"]) > 1e-3):
            problems.append(f"knob threshold for cap {o['cap_per_1000']} differs")
    for p in problems:
        print("PROBLEM:", p)
    print("bundle verified" if not problems else f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
