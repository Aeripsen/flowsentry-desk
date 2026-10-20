"""Read-only access to the data bundle the build wrote.

The bundle is loaded once per process. Queue positions are the internal index; the
public case id is "C" plus a zero-padded position in a fixed shuffled order, so the
queue a judge sees is not sorted by class (the sample file is).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from . import settings as S

QUEUE_ORDER_SEED = 2026  # chosen once, before looking at which cases land first


@dataclass(frozen=True)
class Bundle:
    a: dict
    manifest: dict
    order: np.ndarray        # order[k] = queue position shown k-th
    rank: np.ndarray         # rank[pos] = k

    @property
    def n(self) -> int:
        return len(self.a["q_flow_id"])

    @property
    def classes(self) -> list[str]:
        return [str(c) for c in self.a["classes"]]

    @property
    def attack_classes(self) -> list[str]:
        return [c for c in self.classes if c != "benign"]

    @property
    def default_cap(self) -> float | None:
        return self.manifest["gate"]["cap_per_1000"]

    @property
    def knob(self) -> list[dict]:
        return self.manifest["gate"]["knob"]

    def threshold_for(self, cap: float | None = None) -> float:
        """Gate threshold for a close-knob cap; a cap training data cannot certify (or 0)
        means the desk closes nothing."""
        if cap is None:
            cap = self.default_cap
        for row in self.knob:
            if float(row["cap_per_1000"]) == float(cap or -1):
                return float(row["threshold"]) if row["threshold"] is not None else 1.01
        return 1.01

    def case_id(self, pos: int) -> str:
        return f"C{int(self.rank[pos]) + 1:04d}"

    def pos(self, case_id: str) -> int:
        cid = case_id.strip().upper()
        if not (cid.startswith("C") and cid[1:].isdigit()):
            raise KeyError(case_id)
        k = int(cid[1:]) - 1
        if not 0 <= k < self.n:
            raise KeyError(case_id)
        return int(self.order[k])


@lru_cache(maxsize=1)
def load() -> Bundle:
    with np.load(S.BUNDLE_PATH, allow_pickle=False) as z:
        a = {k: z[k] for k in z.files}
    manifest = json.loads(S.MANIFEST_PATH.read_text(encoding="utf-8"))
    n = len(a["q_flow_id"])
    order = np.random.default_rng(QUEUE_ORDER_SEED).permutation(n)
    rank = np.empty(n, dtype=np.int64)
    rank[order] = np.arange(n)
    return Bundle(a=a, manifest=manifest, order=order, rank=rank)
