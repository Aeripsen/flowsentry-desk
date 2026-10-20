"""Build the desk's data bundle from FlowSentry.

Run:  python -m desk.build        (make data)

What it does, in order:
  1. Downloads the pinned FlowSentry sample and published artifacts, checking sha256.
  2. Retrains FlowSentry with FlowSentry's own training code, then requires the fresh
     metrics.json to equal the published one. Same code, same data, same model.
  3. Scores the held-out split and takes the reject queue: every flow with confidence
     below 0.99 (FlowSentry's headline threshold). Checks the size and benign count
     against FlowSentry's published business_case.json.
  4. Explains each queue flow with exact per-flow path contributions on the forest that
     actually answered it (Stage 1 or Stage 2), so explain() is the shipped model's own
     arithmetic, not a second model's opinion.
  5. Trains the close gate on TRAINING data only: out-of-fold FlowSentry predictions on
     the training split (grouped by connection), the flows those folds would have sent to
     an analyst, and a calibrated benign-vs-attack model on top. Its threshold is the
     loosest one whose 95% Wilson upper bound on attacks closed stays under the cap.
  6. Precomputes each queue flow's nearest labelled training flows (precedents), family
     cards from training data, and writes data/desk_bundle.npz + data/desk_manifest.json.

The test labels of the queue are stored under keys starting with "oracle_". Only the
evaluation harness and the optional "show dataset label" switch read them; no agent tool
does (tests/test_guardrails.py checks this).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.request

import numpy as np

from . import settings as S

# FlowSentry reads its paths at import time, so point it at the build folder first.
os.environ.setdefault(
    "FLOWSENTRY_SAMPLE_PATH", str(S.UPSTREAM_DIR / "data/sample/bccc_udp_quic_sample.csv.gz")
)
os.environ.setdefault("FLOWSENTRY_ARTIFACT_DIR", str(S.FS_ARTIFACT_DIR))
os.environ.setdefault("FLOWSENTRY_MLFLOW", "0")


def log(msg: str) -> None:
    print(f"[build {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_upstream() -> None:
    for rel, want in S.UPSTREAM_FILES.items():
        dest = S.UPSTREAM_DIR / rel
        if dest.exists() and sha256(dest) == want:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = S.FLOWSENTRY_RAW + rel
        log(f"download {url}")
        urllib.request.urlretrieve(url, dest)
        got = sha256(dest)
        if got != want:
            dest.unlink()
            raise SystemExit(f"sha256 mismatch for {rel}: got {got}, want {want}")


def retrain_flowsentry() -> dict:
    """Train with FlowSentry's own code and check the result against the published metrics."""
    from flowsentry import train as fs_train

    model_path = S.FS_ARTIFACT_DIR / "flowsentry.joblib"
    metrics_path = S.FS_ARTIFACT_DIR / "metrics.json"
    if not (model_path.exists() and metrics_path.exists()):
        log("retraining FlowSentry with flowsentry.train (about 30 s)")
        fs_train.main()
    ours = json.loads(metrics_path.read_text())
    theirs = json.loads((S.UPSTREAM_DIR / "artifacts/metrics.json").read_text())
    same = ours == theirs
    diff = [k for k in theirs if ours.get(k) != theirs.get(k)]
    log(f"metrics.json equals the published one: {same}" + ("" if same else f" (differs: {diff})"))
    if not same and os.environ.get("DESK_ALLOW_METRIC_DRIFT") != "1":
        raise SystemExit(
            "retrained FlowSentry does not match the published metrics; "
            "install the versions in requirements.lock or set DESK_ALLOW_METRIC_DRIFT=1"
        )
    return {"metrics_match_published": same, "differing_keys": diff}


# ----------------------------------------------------------------- explanations


def _tree_parent(tree) -> np.ndarray:
    t = tree.tree_
    parent = np.full(t.node_count, -1, dtype=np.int64)
    for children in (t.children_left, t.children_right):
        has = children >= 0
        parent[children[has]] = np.nonzero(has)[0]
    return parent


def forest_contributions(forest, X: np.ndarray, n_classes: int) -> tuple[np.ndarray, np.ndarray]:
    """Exact path contributions for a fitted random forest.

    For every tree, walking a flow from the root to its leaf changes the class
    distribution at each split; that change is credited to the split's feature. Summed
    over the path it telescopes to leaf minus root, so for every flow
        bias + contributions.sum(over features) == forest.predict_proba(flow)
    exactly (tests check this). Returns (bias[n_classes], contrib[n, features, classes]).
    """
    from scipy import sparse

    X32 = np.ascontiguousarray(X, dtype=np.float32)
    n, F = X32.shape
    total = np.zeros((n, F * n_classes), dtype=np.float64)
    bias = np.zeros(n_classes, dtype=np.float64)
    for est in forest.estimators_:
        t = est.tree_
        val = t.value[:, 0, :].astype(np.float64)
        val = val / val.sum(axis=1, keepdims=True)
        parent = _tree_parent(est)
        nodes = np.nonzero(parent >= 0)[0]
        feats = t.feature[parent[nodes]]
        delta = val[nodes] - val[parent[nodes]]  # (m, C)
        rows = np.repeat(nodes, n_classes)
        cols = (np.repeat(feats, n_classes) * n_classes) + np.tile(np.arange(n_classes), len(nodes))
        M = sparse.csr_matrix(
            (delta.ravel(), (rows, cols)), shape=(t.node_count, F * n_classes)
        )
        ind = est.decision_path(X32)
        total += (ind @ M).toarray()
        bias += val[0]
    k = len(forest.estimators_)
    return bias / k, (total / k).reshape(n, F, n_classes)


def explain_queue(model, Xq: np.ndarray, escalated: np.ndarray, classes: list[str]):
    """Per queue flow: bias and full contribution matrix from the stage that answered."""
    C = len(classes)
    contrib = np.zeros((Xq.shape[0], Xq.shape[1], C), dtype=np.float64)
    bias = np.zeros((Xq.shape[0], C), dtype=np.float64)
    s1 = ~escalated
    for mask, forest, cols in (
        (s1, model.stage1_, model.stage1_features_),
        (escalated, model.stage2_, list(range(Xq.shape[1]))),
    ):
        if not mask.any():
            continue
        assert list(forest.classes_) == classes
        b, c = forest_contributions(forest, Xq[mask][:, cols], C)
        full = np.zeros((int(mask.sum()), Xq.shape[1], C))
        full[:, cols, :] = c
        contrib[mask] = full
        bias[mask] = b
    return bias, contrib


# ----------------------------------------------------------------- neighbours + gate


def knn(query: np.ndarray, pool: np.ndarray, k: int, chunk: int = 256):
    """Exact Euclidean k nearest neighbours, chunked to fit a small memory budget.

    Deterministic across machines: squared distances are rounded to 1e-5 before ranking and
    ties go to the lower pool index, so BLAS rounding differences between CPUs cannot reorder
    near-identical flows (the sample has many exact duplicates)."""
    from threadpoolctl import threadpool_limits

    idx = np.empty((query.shape[0], k), dtype=np.int64)
    dist = np.empty((query.shape[0], k), dtype=np.float32)
    P = pool.astype(np.float64)
    pool_sq = (P ** 2).sum(1)
    with threadpool_limits(1):
        for s in range(0, query.shape[0], chunk):
            q = query[s:s + chunk].astype(np.float64)
            d2 = (q ** 2).sum(1)[:, None] + pool_sq[None, :] - 2.0 * q @ P.T
            np.maximum(d2, 0, out=d2)
            d2 = np.round(d2, 5)
            kth = np.partition(d2, k - 1, axis=1)[:, k - 1]
            for r in range(d2.shape[0]):
                row = d2[r]
                less = np.nonzero(row < kth[r])[0]
                eq = np.nonzero(row == kth[r])[0][: k - len(less)]
                sel = np.concatenate([less, eq])
                order = np.lexsort((sel, row[sel]))
                idx[s + r] = sel[order]
                dist[s + r] = np.sqrt(row[sel[order]])
    return idx, dist


GATE_FEATURES = [
    "fs_p_benign", "fs_confidence", "fs_escalated", "knn_benign_share",
    "knn_benign_share_weighted", "log_d_nearest_benign", "log_d_nearest_attack",
    "log_d_ratio",
]


def gate_features(p_benign, conf, esc, nb_labels_benign, nb_dist, d_benign, d_attack):
    w = 1.0 / (nb_dist + 1e-3)
    share = nb_labels_benign.mean(1)
    wshare = (nb_labels_benign * w).sum(1) / w.sum(1)
    return np.column_stack([
        p_benign, conf, esc.astype(float), share, wshare,
        np.log1p(d_benign), np.log1p(d_attack),
        np.log1p(d_benign) - np.log1p(d_attack),
    ])


def wilson_upper(k: int, n: int, z: float = 1.959964) -> float:
    if n == 0:
        return 1.0
    p = k / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return float((centre + half) / den)


def wilson_interval(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (float(max(0.0, (centre - half) / den)), float(min(1.0, (centre + half) / den)))


def pick_threshold(scores: np.ndarray, is_attack: np.ndarray, cap_per_1000: float):
    """Loosest threshold whose Wilson upper bound on attacks-closed share is under the cap."""
    cap = cap_per_1000 / 1000.0
    best = None
    for t in np.unique(scores)[::-1]:
        closed = scores >= t
        n = int(closed.sum())
        k = int(is_attack[closed].sum())
        if wilson_upper(k, n) <= cap:
            best = (float(t), n, k)
    return best


def make_gate_model():
    from sklearn.ensemble import HistGradientBoostingClassifier

    return HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.05, max_leaf_nodes=31, l2_regularization=1.0,
        random_state=0,
    )


class FoldEnsemble:
    """The gate: one model per grouped fold, scores averaged. The threshold is chosen on the
    out-of-fold scores of these same models, so test scores are on the same scale."""

    def __init__(self, models):
        self.models = models

    def score(self, M: np.ndarray) -> np.ndarray:
        from threadpoolctl import threadpool_limits

        with threadpool_limits(1):
            return np.mean([m.predict_proba(M)[:, 1] for m in self.models], axis=0)


def gate_matrix(Z, gfeats, proba):
    return np.hstack([Z, gfeats, proba]).astype(np.float64)


def build_gate(X, y, groups, tr, classes, med, scale):
    """Out-of-fold FlowSentry on the training split, then the close gate on the flows those
    folds would have queued. Nothing here sees the test split."""
    from flowsentry.config import get_settings
    from flowsentry.data import STAGE1_INDICES
    from flowsentry.model import TwoStageRejectClassifier
    from flowsentry.registry import make_stage_estimator
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupKFold

    from .features import to_space

    cfg = get_settings().training
    gtr = groups[tr]
    ytr = y[tr]
    n = len(tr)
    cache = S.BUILD_DIR / "gate_oof_v3.npz"
    if cache.exists():
        z = np.load(cache)
        oof_conf, oof_proba, feats = z["conf"], z["proba"], z["feats"]
        log("gate: reusing cached out-of-fold FlowSentry from build/gate_oof_v2.npz")
    else:
        oof_conf = np.zeros(n)
        oof_proba = np.zeros((n, len(classes)))
        oof_esc = np.zeros(n, dtype=bool)
        feats = np.zeros((n, len(GATE_FEATURES)))
        b_idx = classes.index("benign")
        for f, (a, b) in enumerate(GroupKFold(n_splits=3).split(tr, groups=gtr)):
            log(f"gate fold {f + 1}/3: FlowSentry on {len(a)} training flows, scoring {len(b)}")
            imp = SimpleImputer(strategy="median").fit(X[tr[a]])
            Xa, Xb = imp.transform(X[tr[a]]), imp.transform(X[tr[b]])
            m = TwoStageRejectClassifier(
                stage1_features=STAGE1_INDICES,
                escalate_threshold=cfg.escalate_threshold,
                stage1_estimator=make_stage_estimator(cfg.stage_estimator, **cfg.stage1_params),
                stage2_estimator=make_stage_estimator(cfg.stage_estimator, **cfg.stage2_params),
            ).fit(Xa, ytr[a])
            assert list(m.classes_) == classes
            _, conf, esc, proba = m._stage_predict(Xb, sequential=True)
            oof_conf[b], oof_esc[b], oof_proba[b] = conf, esc, proba
            del m
            # precedents for these flows come from the other folds only, the way test
            # flows only ever see training connections
            Za, Zb = to_space(Xa, med, scale), to_space(Xb, med, scale)
            nb_i, nb_d = knn(Zb, Za, S.K_NEIGHBOURS)
            ya = ytr[a]
            benign_a = ya == "benign"
            _, db = knn(Zb, Za[benign_a], 1)
            _, dt = knn(Zb, Za[~benign_a], 1)
            feats[b] = gate_features(proba[:, b_idx], conf, esc,
                                     (ya[nb_i] == "benign").astype(float), nb_d,
                                     db[:, 0], dt[:, 0])
        np.savez(cache, conf=oof_conf, proba=oof_proba, esc=oof_esc, feats=feats)

    Xtr_imp = SimpleImputer(strategy="median").fit(X[tr]).transform(X[tr])
    Ztr = to_space(Xtr_imp, med, scale)
    hard = oof_conf < S.REJECT_THRESHOLD
    target = (ytr == "benign").astype(int)
    log(f"gate training rows (training flows the out-of-fold model would queue): "
        f"{int(hard.sum())}, benign share {target[hard].mean():.3f}")
    M = gate_matrix(Ztr[hard], feats[hard], oof_proba[hard])
    th, gh = target[hard], gtr[hard]
    oof_scores = np.zeros(len(th))
    models = []
    from threadpoolctl import threadpool_limits

    # one thread: histogram sums in a fixed order, so the gate is the same on every machine
    with threadpool_limits(1):
        for a, b in GroupKFold(n_splits=5).split(M, groups=gh):
            mdl = make_gate_model().fit(M[a], th[a])
            oof_scores[b] = mdl.predict_proba(M[b])[:, 1]
            models.append(mdl)
    auc = float(roc_auc_score(th, oof_scores))
    log(f"gate out-of-fold AUC (benign vs attack, training queue): {auc:.4f}")
    n_att = int((th == 0).sum())
    knob = []
    for cap in S.GATE_CAPS_PER_1000:
        c = pick_threshold(oof_scores, th == 0, cap)
        row = {"cap_per_1000": cap, "met_on_training": c is not None,
               "threshold": None if c is None else c[0]}
        if c is not None:
            row.update({"training_closed": c[1], "training_attacks_closed": c[2],
                        "training_share_closed": round(c[1] / len(th), 4),
                        "training_share_of_attacks_closed": round(c[2] / n_att, 4)})
        knob.append(row)
        log(f"gate cap {cap} per 1,000: " + ("not met on training data" if c is None else
            f"threshold {c[0]:.5f} closes {c[1]} of {len(th)}, {c[2]} attacks"))
    met = [r for r in knob if r["met_on_training"]]
    if met:
        cap, tau = met[0]["cap_per_1000"], met[0]["threshold"]
        n_closed, k_attack = met[0]["training_closed"], met[0]["training_attacks_closed"]
    else:
        log("gate: no cap met; the desk will close nothing")
        cap, tau, n_closed, k_attack = None, 1.01, 0, 0
    log(f"default close knob: strictest certifiable cap = {cap} per 1,000")
    curve = []
    for t in sorted({0.5, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.998}):
        c = oof_scores >= t
        nn, kk = int(c.sum()), int((th[c] == 0).sum())
        curve.append({"threshold": t, "closed": nn, "attacks_closed": kk,
                      "share_closed": round(nn / len(th), 4),
                      "wilson_upper_per_1000": round(1000 * wilson_upper(kk, nn), 2)})
    info = {
        "trained_on": "training split only: out-of-fold FlowSentry (3 connection-grouped folds) "
                      "and the flows those folds would send to an analyst at 0.99",
        "n_training_queue": int(len(th)),
        "training_queue_benign_share": round(float(th.mean()), 4),
        "inputs": "132 flow features (signed log, robust scaled) + FlowSentry's 8 out-of-fold "
                  "class probabilities + 8 precedent statistics: " + ", ".join(GATE_FEATURES),
        "model": "5 HistGradientBoosting models, one per connection-grouped fold; the score is "
                 "their mean; the threshold is picked on their out-of-fold scores",
        "out_of_fold_auc": round(auc, 4),
        "knob": knob,
        "default_rule": "the strictest cap in the knob that the training data can certify",
        "cap_per_1000": cap,
        "threshold": tau,
        "training_closed": n_closed,
        "training_attacks_closed": k_attack,
        "training_wilson_upper_per_1000": round(1000 * wilson_upper(k_attack, n_closed), 2),
        "training_curve": curve,
    }
    oof_stats = {"conf": oof_conf, "y": ytr}
    return FoldEnsemble(models), tau, info, oof_stats


# ----------------------------------------------------------------- main


def family_cards(Xtr_raw, ytr, oof, classes, feature_names):
    from flowsentry.attack_map import lookup

    from .features import KEY_FEATURES, describe

    cols = [feature_names.index(f) for f in KEY_FEATURES]
    cards = {}
    for c in classes:
        m = ytr == c
        om = oof["y"] == c
        queued = float((oof["conf"][om] < S.REJECT_THRESHOLD).mean()) if om.any() else None
        med = np.median(Xtr_raw[m][:, cols], axis=0)
        p25 = np.percentile(Xtr_raw[m][:, cols], 25, axis=0)
        p75 = np.percentile(Xtr_raw[m][:, cols], 75, axis=0)
        att = lookup(c)
        cards[c] = {
            "family": c,
            "training_flows": int(m.sum()),
            "share_of_training": round(float(m.mean()), 4),
            "share_flowsentry_unsure_out_of_fold": None if queued is None else round(queued, 4),
            "typical": {
                f: {"label": describe(f), "median": float(f"{md:.6g}"),
                    "p25": float(f"{a:.6g}"), "p75": float(f"{b:.6g}")}
                for f, md, a, b in zip(KEY_FEATURES, med, p25, p75, strict=True)
            },
            "attack_technique": att.get("technique_id"),
            "technique_name": att.get("technique_name"),
            "playbook": att.get("playbook"),
            "rare": c in S.RARE_FAMILIES,
        }
    return cards


def main() -> None:
    t0 = time.time()
    fetch_upstream()
    provenance = retrain_flowsentry()

    import joblib
    from flowsentry.data import STAGE2_FEATURES, build_matrices, leakage_safe_split, load_sample

    from .features import KEY_FEATURES, fit_scaler, to_space

    bundle = joblib.load(S.FS_ARTIFACT_DIR / "flowsentry.joblib")
    imputer, model = bundle["imputer"], bundle["model"]
    classes = list(model.classes_)
    df = load_sample()
    X, y, groups = build_matrices(df)
    tr, te = leakage_safe_split(groups, test_size=0.25, seed=42)
    assert [int(i) for i in te] == bundle["test_indices"], "split differs from the model's"
    # the sample has no flow id column; a flow is cited by its row in the public sample
    # file (after FlowSentry's closed-set filter). IPs and ports are never stored.
    flow_ids = np.array([f"S{i:05d}" for i in range(len(df))])

    Xtr, Xte = imputer.transform(X[tr]), imputer.transform(X[te])
    labels, conf, esc, proba = model._stage_predict(Xte, sequential=True)
    q = conf < S.REJECT_THRESHOLD
    yq = y[te][q]
    business = json.loads((S.UPSTREAM_DIR / "artifacts/business_case.json").read_text())
    pub = next(r for r in business["analyst_share_by_class"] if r["reject_threshold"] == 0.99)
    assert int(q.sum()) == pub["all_test_flows"]["sent_to_analyst"], "queue size differs"
    assert int((yq == "benign").sum()) == pub["per_class"]["benign"]["sent_to_analyst"]
    log(f"queue: {int(q.sum())} of {len(te)} held-out flows, benign {int((yq == 'benign').sum())} "
        f"({(yq == 'benign').mean():.3f}); matches business_case.json")

    Xq = Xte[q]
    log("explaining queue flows with exact path contributions")
    ex_bias, ex_contrib = explain_queue(model, Xq, esc[q], classes)
    recon = ex_bias + ex_contrib.sum(1)
    err = float(np.abs(recon - proba[q]).max())
    log(f"explanation check: max |bias + sum(contrib) - proba| = {err:.2e}")
    assert err < 1e-6
    # keep the top 12 features per flow toward its predicted class and toward benign
    pred_idx = np.array([classes.index(c) for c in labels[q]])
    b_idx = classes.index("benign")
    TOP = 12
    c_pred = ex_contrib[np.arange(len(pred_idx)), :, pred_idx]
    c_ben = ex_contrib[:, :, b_idx]
    top_pred = np.argsort(-np.abs(c_pred), axis=1)[:, :TOP]
    top_ben = np.argsort(-np.abs(c_ben), axis=1)[:, :TOP]
    del ex_contrib

    med, scale = fit_scaler(Xtr)
    Ztr, Zq = to_space(Xtr, med, scale), to_space(Xq, med, scale)
    log("precedents: nearest training flows for each queue flow")
    nb_i, nb_d = knn(Zq, Ztr, S.K_NEIGHBOURS)
    ytr = y[tr]
    benign_tr = ytr == "benign"
    _, db = knn(Zq, Ztr[benign_tr], 1)
    _, dt = knn(Zq, Ztr[~benign_tr], 1)

    log("close gate: out-of-fold FlowSentry on the training split")
    gate, tau, gate_info, oof = build_gate(X, y, groups, tr, classes, med, scale)
    gfe = gate_features(proba[q][:, b_idx], conf[q], esc[q],
                        (ytr[nb_i] == "benign").astype(float), nb_d, db[:, 0], dt[:, 0])
    gate_score = gate.score(gate_matrix(Zq, gfe, proba[q]))

    cards = family_cards(Xtr, ytr, oof, classes, list(STAGE2_FEATURES))

    # only the training rows some queue flow cites as a precedent are stored
    used = np.unique(nb_i)
    remap = {int(u): i for i, u in enumerate(used)}
    key_cols = [list(STAGE2_FEATURES).index(f) for f in KEY_FEATURES]
    out = {
        "classes": np.array(classes),
        "feature_names": np.array(STAGE2_FEATURES),
        "key_features": np.array(KEY_FEATURES),
        "q_flow_id": flow_ids[te][q],
        "q_X": Xq.astype(np.float32),
        "q_Z": Zq,
        "q_pred": labels[q].astype(str),
        "q_conf": conf[q].astype(np.float32),
        "q_escalated": esc[q],
        "q_proba": proba[q].astype(np.float32),
        "q_explain_bias": ex_bias.astype(np.float32),
        "q_top_pred_idx": top_pred.astype(np.int16),
        "q_top_pred_val": np.take_along_axis(c_pred, top_pred, 1).astype(np.float32),
        "q_top_benign_idx": top_ben.astype(np.int16),
        "q_top_benign_val": np.take_along_axis(c_ben, top_ben, 1).astype(np.float32),
        "q_nb_idx": np.vectorize(remap.get)(nb_i).astype(np.int32),
        "q_nb_dist": nb_d,
        "q_d_nearest_benign": db[:, 0],
        "q_d_nearest_attack": dt[:, 0],
        "q_gate_features": gfe.astype(np.float32),
        "q_gate_score": gate_score.astype(np.float32),
        "p_flow_id": flow_ids[tr][used],
        "p_label": ytr[used].astype(str),
        "p_key_X": Xtr[used][:, key_cols].astype(np.float32),
        "benign_median_key": np.median(Xtr[benign_tr][:, key_cols], 0).astype(np.float32),
        "oracle_q_true": yq.astype(str),
    }
    S.DATA_DIR.mkdir(exist_ok=True)
    np.savez_compressed(S.BUNDLE_PATH, **out)
    manifest = {
        "what": "FlowSentry Desk data bundle: FlowSentry's 0.99 reject queue on the held-out "
                "split of the committed BCCC-UDP-QUIC-IDS-2025 sample, with explanations, "
                "precedents, family cards and the close gate's scores",
        "dataset": "BCCC-UDP-QUIC-IDS-2025 (public, CC BY 4.0), FlowSentry's stratified sample",
        "flowsentry_commit": S.FLOWSENTRY_COMMIT,
        "upstream_sha256": S.UPSTREAM_FILES,
        "provenance": provenance,
        "reject_threshold": S.REJECT_THRESHOLD,
        "n_heldout": int(len(te)),
        "n_queue": int(q.sum()),
        "queue_by_class": {c: int((yq == c).sum()) for c in classes},
        "explanation_max_abs_error": err,
        "gate": gate_info,
        "family_cards": cards,
        "precedent_pool": {"source": "training split", "n_training_flows": int(len(tr)),
                           "n_stored": int(len(used)), "k": S.K_NEIGHBOURS},
        "bundle_sha256": sha256(S.BUNDLE_PATH),
        "versions": {"python": sys.version.split()[0], "numpy": np.__version__,
                     "scikit-learn": __import__("sklearn").__version__},
    }
    S.MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                               newline="\n")
    log(f"wrote {S.BUNDLE_PATH.name} ({S.BUNDLE_PATH.stat().st_size / 1e6:.1f} MB) "
        f"and {S.MANIFEST_PATH.name} in {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
