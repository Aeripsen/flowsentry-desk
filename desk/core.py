"""The decision core: one set of rules shared by the tools, the deterministic policy, the
server-side check on every proposal, and the evaluation harness.

Everything is vectorised over queue positions, so the harness can score the whole
2,315-flow queue in one call and a single case is the same call with one position.

The rules, in plain words:

  close as benign   only if ALL hold:
                      - the calibrated close gate scores the flow at or above its threshold
                        (tuned on training data to a cap of attacks wrongly closed)
                      - at least half of the 15 nearest labelled training flows are benign
                      - no flow the analyst labelled as an attack sits within this flow's
                        neighbourhood (overrides can only make the desk MORE careful)
                      - the second opinion, once it exists, does not call it an attack
  escalate          when it is not closed, a majority of the available voters say attack
                    (FlowSentry, the precedents, the second opinion once trained) and at
                    least two of them name the same family
  ask a human       everything else: the evidence conflicts, so the desk abstains

The LLM never overrides these: it may propose a close, but the server only accepts one
the rules allow. It may always choose to escalate or ask a human instead.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .store import Bundle

BENIGN = "benign"
MIN_SECOND_OPINION_LABELS = 5


@dataclass
class Labels:
    """Analyst labels in one workspace: queue positions and their labels."""

    pos: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    y: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype="<U16"))

    @classmethod
    def from_pairs(cls, pairs: list[tuple[int, str]]) -> Labels:
        if not pairs:
            return cls()
        p, y = zip(*pairs, strict=True)
        return cls(np.asarray(p, dtype=np.int64), np.asarray(y, dtype="<U16"))

    def __len__(self) -> int:
        return len(self.pos)

    def fingerprint(self) -> str:
        if not len(self):
            return "none"
        import hashlib

        o = np.argsort(self.pos)
        raw = ",".join(f"{p}:{y}" for p, y in zip(self.pos[o], self.y[o], strict=True))
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class SecondOpinion:
    """A small forest trained only on this workspace's analyst labels."""

    def __init__(self, b: Bundle, labels: Labels):
        self.n_labels = len(labels)
        self.classes: list[str] = sorted(set(labels.y.tolist()))
        self.model = None
        if self.n_labels >= MIN_SECOND_OPINION_LABELS and len(self.classes) >= 2:
            from sklearn.ensemble import ExtraTreesClassifier

            self.model = ExtraTreesClassifier(
                n_estimators=100, random_state=0, class_weight="balanced", n_jobs=1,
                min_samples_leaf=1,
            ).fit(b.a["q_Z"][labels.pos], labels.y)
            self.classes = [str(c) for c in self.model.classes_]

    @property
    def ready(self) -> bool:
        return self.model is not None

    def proba(self, Z: np.ndarray) -> np.ndarray:
        assert self.model is not None
        return self.model.predict_proba(Z)


_SO_CACHE: dict[tuple[int, str], SecondOpinion] = {}


def second_opinion(b: Bundle, labels: Labels) -> SecondOpinion:
    key = (id(b), labels.fingerprint())
    so = _SO_CACHE.get(key)
    if so is None:
        if len(_SO_CACHE) > 256:
            _SO_CACHE.clear()
        so = SecondOpinion(b, labels)
        _SO_CACHE[key] = so
    return so


def precedent_summary(b: Bundle, pos: np.ndarray):
    """Label share and leading attack family among each flow's 15 training neighbours."""
    nb_lab = b.a["p_label"][b.a["q_nb_idx"][pos]]           # (n, k)
    benign_share = (nb_lab == BENIGN).mean(1)
    attacks = b.attack_classes
    counts = np.stack([(nb_lab == c).sum(1) for c in attacks], 1)
    lead = np.array(attacks)[counts.argmax(1)]
    lead = np.where(counts.max(1) > 0, lead, "")
    return benign_share, lead, counts


def labelled_attack_nearby(b: Bundle, pos: np.ndarray, labels: Labels) -> np.ndarray:
    """True where the analyst has labelled a different queue flow as an attack and that flow
    is at least as close as this flow's 15th nearest training precedent."""
    out = np.zeros(len(pos), dtype=bool)
    if not len(labels):
        return out
    att = labels.y != BENIGN
    if not att.any():
        return out
    Zl = b.a["q_Z"][labels.pos[att]].astype(np.float64)
    Zp = b.a["q_Z"][pos].astype(np.float64)
    d = np.sqrt(np.maximum(
        (Zp ** 2).sum(1)[:, None] + (Zl ** 2).sum(1)[None, :] - 2 * Zp @ Zl.T, 0))
    same = pos[:, None] == labels.pos[att][None, :]
    d[same] = np.inf
    radius = b.a["q_nb_dist"][pos, -1].astype(np.float64)
    return (d <= radius[:, None]).any(1)


def fs_attack_family(b: Bundle, pos: np.ndarray) -> np.ndarray:
    classes = b.classes
    att_idx = [classes.index(c) for c in b.attack_classes]
    pa = b.a["q_proba"][pos][:, att_idx]
    return np.array(b.attack_classes)[pa.argmax(1)]


def decide(b: Bundle, pos: np.ndarray, labels: Labels | None = None,
           cap: float | None = None) -> dict[str, np.ndarray]:
    """cap: the close knob (attacks wrongly closed per 1,000, certified on training data);
    None means the default, the strictest cap training data can certify."""
    labels = labels or Labels()
    pos = np.asarray(pos, dtype=np.int64)
    n = len(pos)
    gate = b.a["q_gate_score"][pos].astype(float)
    gate_pass = gate >= b.threshold_for(cap)
    nb_benign_share, nb_family, _ = precedent_summary(b, pos)
    blocked = labelled_attack_nearby(b, pos, labels)
    so = second_opinion(b, labels)

    fs_pred = b.a["q_pred"][pos].astype(str)
    fs_says_attack = fs_pred != BENIGN
    fs_family = np.where(fs_says_attack, fs_pred, fs_attack_family(b, pos))
    nb_says_attack = nb_benign_share < 0.5

    so_ready = so.ready
    so_says_attack = np.zeros(n, dtype=bool)
    so_family = np.full(n, "", dtype="<U16")
    so_p_benign = np.full(n, np.nan)
    if so_ready:
        pr = so.proba(b.a["q_Z"][pos])
        cls = so.classes
        top = np.array(cls)[pr.argmax(1)]
        so_says_attack = top != BENIGN
        so_p_benign = pr[:, cls.index(BENIGN)] if BENIGN in cls else np.zeros(n)
        att_cols = [i for i, c in enumerate(cls) if c != BENIGN]
        if att_cols:
            so_family = np.array(cls)[att_cols][pr[:, att_cols].argmax(1)]

    close_ok = gate_pass & (nb_benign_share >= 0.5) & ~blocked
    if so_ready:
        close_ok &= ~(so_p_benign < 0.5)

    verdict = np.full(n, "ask_human", dtype="<U12")
    family = np.full(n, "", dtype="<U16")
    verdict[close_ok] = "close_benign"
    for i in np.nonzero(~close_ok)[0]:
        voters = [(fs_says_attack[i], fs_family[i]), (nb_says_attack[i], nb_family[i])]
        if so_ready:
            voters.append((so_says_attack[i], so_family[i]))
        attack_votes = [f for a, f in voters if a and f]
        if len(attack_votes) * 2 > len(voters):
            fams, cnt = np.unique(attack_votes, return_counts=True)
            if cnt.max() >= 2:
                verdict[i] = "escalate"
                family[i] = fams[cnt.argmax()]
    return {
        "pos": pos,
        "verdict": verdict,
        "family": family,
        "close_allowed": close_ok,
        "gate_score": gate,
        "gate_pass": gate_pass,
        "nb_benign_share": nb_benign_share,
        "nb_family": nb_family,
        "blocked_by_label": blocked,
        "fs_pred": fs_pred,
        "fs_family": fs_family,
        "so_ready": np.full(n, so_ready),
        "so_says_attack": so_says_attack,
        "so_family": so_family,
        "so_p_benign": so_p_benign,
        "so_n_labels": np.full(n, so.n_labels),
    }


def one(d: dict[str, np.ndarray], i: int = 0) -> dict:
    """Row i of a decide() result as plain Python values."""
    out = {}
    for k, v in d.items():
        x = v[i]
        if isinstance(x, np.generic):
            x = x.item()
        if isinstance(x, float) and np.isnan(x):
            x = None
        out[k] = x
    return out


# ----------------------------------------------------------------------- outcome

OUTCOMES = ("AUTO_CLOSED", "ESCALATED", "HUMAN")


def outcome(verdict: str | None, citations_ok: bool, close_allowed: bool) -> tuple[str, str]:
    """What actually happens to a case. The agent can add human attention, never remove it:
    a close needs the agent's close AND the server rules AND checked citations."""
    if not citations_ok:
        return "HUMAN", "the memo did not pass the citation check"
    if verdict == "escalate":
        return "ESCALATED", "escalated with a family and a ticket draft"
    if verdict == "close_benign":
        if close_allowed:
            return "AUTO_CLOSED", "agent proposed a close and the server rules allow it"
        return "HUMAN", "agent leaned benign, but the server rules did not allow a close"
    return "HUMAN", "the agent asked for a human: the evidence conflicts or is thin"
