"""FlowSentry Desk web app.   uvicorn desk.app:app   (make serve)

Engines for a run, in order (engine="auto"):
  1. a live model run, if a model key is set AND DESK_LIVE_AGENT=1 AND today's caps allow
  2. a recorded run from runs/recorded.jsonl, if one exists for this case and this
     workspace has no labels yet (recorded runs were made with no labels) and the default
     close knob
  3. the deterministic policy, live (no network, a few milliseconds)
So the app works with no key and no network, which keeps the demo link alive during
judging even if a model API is down.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agent, auth, core
from . import settings as S
from .db import DB
from .store import Bundle, load

app = FastAPI(title="FlowSentry Desk", version="0.1.0", docs_url="/api/docs",
              redoc_url=None, openapi_url="/api/openapi.json")
_db: DB | None = None


def get_db() -> DB:
    global _db
    if _db is None:
        _db = DB()
    return _db


def set_db(d: DB) -> None:
    """Tests swap in an in-memory database."""
    global _db
    _db = d


@lru_cache(maxsize=1)
def recorded_runs() -> dict[tuple[str, str, float | None], dict]:
    """(case_id, labels fingerprint, knob cap or None for the default) -> latest recorded run."""
    out: dict[tuple[str, str, float | None], dict] = {}
    path = S.RUNS_DIR / "recorded.jsonl"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                out[(r["case_id"], r.get("labels_fingerprint", "none"), r.get("cap"))] = r
    return out


def live_engine() -> tuple[str, str] | None:
    if not S.env_flag("DESK_LIVE_AGENT"):
        return None
    try:
        return agent.available_engine()
    except RuntimeError:
        return None


# extra origins allowed to frame the app (the CI iframe test sets one); space separated
EXTRA_FRAME_ANCESTORS = "".join(" " + o for o in os.environ.get("DESK_FRAME_ANCESTORS", "").split())
RUNS_PER_WORKSPACE_PER_DAY = int(os.environ.get("DESK_RUNS_PER_WORKSPACE", "25"))
RUNS_PER_DAY = int(os.environ.get("DESK_RUNS_PER_DAY", "300"))


# ----------------------------------------------------------------------- security headers


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    clerk = ""
    fapi = auth.frontend_api() if auth.clerk_enabled() else None
    if fapi:
        clerk = f" https://{fapi}"
    cf = " https://challenges.cloudflare.com" if clerk else ""
    frames = (clerk + cf) or " 'none'"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self'{clerk}{cf}; "
        f"connect-src 'self'{clerk}; "
        f"img-src 'self' data:{clerk}{' https://img.clerk.com' if clerk else ''}; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        f"frame-src{frames}; worker-src 'self' blob:; "
        f"frame-ancestors 'self' https://huggingface.co{EXTRA_FRAME_ANCESTORS}; base-uri 'none'; "
        "form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ----------------------------------------------------------------------- who is asking


def analyst(request: Request, response: Response) -> auth.Analyst:
    try:
        a, new_cookie = auth.from_request(
            {k.lower(): v for k, v in request.headers.items()}, dict(request.cookies))
    except auth.AuthError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
    if new_cookie:
        response.set_cookie(auth.COOKIE, new_cookie, httponly=True, samesite="lax",
                            secure=request.url.scheme == "https", max_age=60 * 60 * 24 * 30)
    get_db().ensure_workspace(a.workspace, a.kind)
    return a


def ws_labels(b: Bundle, a: auth.Analyst) -> core.Labels:
    pairs = [(c, y) for c, y in get_db().labels(a.workspace)]
    return agent.labels_for(b, pairs)


def ws_cap(a: auth.Analyst) -> float | None:
    return get_db().close_cap(a.workspace)


# ----------------------------------------------------------------------- views


def case_row(b: Bundle, pos: int, run: dict | None, label: dict | None) -> dict:
    a = b.a
    return {
        "case_id": b.case_id(pos),
        "flow_ref": str(a["q_flow_id"][pos]),
        "fs_pred": str(a["q_pred"][pos]),
        "fs_conf": round(float(a["q_conf"][pos]), 4),
        "outcome": run["outcome"] if run else None,
        "verdict": (run.get("final") or {}).get("verdict") if run else None,
        "family": (run.get("final") or {}).get("family") if run else None,
        "engine": run["engine"] if run else None,
        "label": label["label"] if label else None,
        "label_source": label["source"] if label else None,
    }


def bucket(row: dict) -> str:
    if row["label"]:
        return "done"
    o = row["outcome"]
    if o is None:
        return "todo"
    return {"AUTO_CLOSED": "closed", "ESCALATED": "escalated"}.get(o, "needs_you")


@app.get("/api/config")
def config():
    b = load()
    eng = live_engine()
    return {
        "auth": auth.mode(),
        "clerk_publishable_key": auth.publishable_key() if auth.clerk_enabled() else None,
        "clerk_frontend_api": auth.frontend_api() if auth.clerk_enabled() else None,
        "live_engine": {"engine": eng[0], "model": eng[1]} if eng else None,
        "recorded_runs": len(recorded_runs()),
        "queue_size": b.n,
        "classes": b.classes,
        "knob": b.knob,
        "default_cap": b.default_cap,
        "flowsentry_commit": S.FLOWSENTRY_COMMIT,
    }


@app.get("/api/me")
def me(a: auth.Analyst = Depends(analyst)):
    d = get_db()
    return {"workspace": a.workspace, "kind": a.kind, "labels": len(d.labels(a.workspace)),
            "close_cap": d.close_cap(a.workspace)}


def queue_order(b: Bundle, order: str) -> np.ndarray:
    """desk: least benign-looking first (lowest close-gate score), the order the evaluation's
    'finding attacks sooner' result measures. arrival: the fixed shuffled order of case ids."""
    if order == "arrival":
        return b.order
    return np.argsort(b.a["q_gate_score"], kind="stable")


@app.get("/api/queue")
def queue(status: str = "all", offset: int = 0, limit: int = 60, order: str = "desk",
          a: auth.Analyst = Depends(analyst)):
    b = load()
    d = get_db()
    runs = d.latest_runs(a.workspace)
    labels = {c: {"label": y, "source": "?"} for c, y in d.labels(a.workspace)}
    rows, counts = [], {"all": 0, "todo": 0, "needs_you": 0, "escalated": 0, "closed": 0,
                        "done": 0}
    for pos in queue_order(b, order):
        pos = int(pos)
        cid = b.case_id(pos)
        lab = d.label_of(a.workspace, cid) if cid in labels else None
        r = case_row(b, pos, runs.get(cid), lab)
        bk = bucket(r)
        counts["all"] += 1
        counts[bk] += 1
        if status == "all" or status == bk:
            rows.append(r)
    limit = max(1, min(limit, 200))
    return {"counts": counts, "total": len(rows), "offset": offset,
            "rows": rows[offset:offset + limit]}


@app.get("/api/case/{case_id}")
def case(case_id: str, a: auth.Analyst = Depends(analyst)):
    b = load()
    try:
        pos = b.pos(case_id)
    except KeyError as e:
        raise HTTPException(404, "no such case") from e
    cid = b.case_id(pos)
    d = get_db()
    run = d.latest_run(a.workspace, cid)
    lab = d.label_of(a.workspace, cid)
    return {"case": case_row(b, pos, run, lab), "run": run, "label": lab}


class RunReq(BaseModel):
    engine: str = Field("auto", pattern="^(auto|policy|model)$")


def _do_run(b: Bundle, pos: int, a: auth.Analyst, engine: str) -> dict:
    d = get_db()
    labels = ws_labels(b, a)
    cap = ws_cap(a)
    cid = b.case_id(pos)
    eng = live_engine()
    if engine == "model" and eng is None:
        raise HTTPException(409, "no live model is configured on this server")
    use_model = eng is not None and engine in ("auto", "model")
    if use_model and not d.reserve_model_run(a.workspace, eng[0], RUNS_PER_WORKSPACE_PER_DAY,
                                             RUNS_PER_DAY):
        if engine == "model":
            raise HTTPException(429, "today's live model runs are used up; the policy still works")
        use_model = False
    rec = recorded_runs().get((cid, labels.fingerprint(), cap))
    replay = None
    if not use_model and engine in ("auto", "recorded_or_policy") and rec:
        # a recording is re-checked against today's bundle and rules before it is served
        replay = agent.revalidate(b, pos, rec, labels, cap)
    if use_model:
        run = agent.model_run(b, pos, labels, eng, cap=cap).to_dict()
    elif replay is not None:
        run = replay
    else:
        run = agent.policy_run(b, pos, labels, cap=cap).to_dict()
    run["run_id"] = d.add_run(a.workspace, run, a.actor)
    return run


@app.post("/api/case/{case_id}/run")
def run_case(case_id: str, req: RunReq, a: auth.Analyst = Depends(analyst)):
    b = load()
    try:
        pos = b.pos(case_id)
    except KeyError as e:
        raise HTTPException(404, "no such case") from e
    return _do_run(b, pos, a, req.engine)


class BatchReq(BaseModel):
    n: int = Field(25, ge=1, le=200)
    order: str = Field("desk", pattern="^(desk|arrival)$")


@app.post("/api/batch")
def batch(req: BatchReq, a: auth.Analyst = Depends(analyst)):
    """Pre-read the next n untouched cases with the policy or recorded runs (never a live
    model: a batch must be instant and free)."""
    b = load()
    d = get_db()
    done = set(d.latest_runs(a.workspace)) | {c for c, _ in d.labels(a.workspace)}
    out = []
    for pos in queue_order(b, req.order):
        if len(out) >= req.n:
            break
        pos = int(pos)
        if b.case_id(pos) in done:
            continue
        r = _do_run(b, pos, a, "recorded_or_policy")
        out.append({"case_id": r["case_id"], "outcome": r["outcome"]})
    return {"ran": len(out), "results": out}


class DecisionReq(BaseModel):
    action: str = Field(..., pattern="^(approve|override|reopen)$")
    label: str | None = None


@app.post("/api/case/{case_id}/decision")
def decision(case_id: str, req: DecisionReq, a: auth.Analyst = Depends(analyst)):
    b = load()
    try:
        pos = b.pos(case_id)
    except KeyError as e:
        raise HTTPException(404, "no such case") from e
    cid = b.case_id(pos)
    d = get_db()
    run = d.latest_run(a.workspace, cid)
    if req.action == "reopen":
        d.clear_label(a.workspace, cid, a.actor)
        if run:
            body = {k: v for k, v in run.items() if k != "run_id"}
            body.update(engine="analyst", model="reopen", outcome="HUMAN", recorded=False,
                        outcome_reason="reopened by the analyst; the desk's earlier memo is kept")
            d.add_run(a.workspace, body, a.actor, action="reopened")
        return {"ok": True, "changed": []}
    before = ws_labels(b, a)
    if req.action == "approve":
        if not run or run["outcome"] not in ("AUTO_CLOSED", "ESCALATED"):
            raise HTTPException(409, "nothing to approve: choose a label")
        label = "benign" if run["outcome"] == "AUTO_CLOSED" else run["final"]["family"]
        source = "approve"
    else:
        if req.label not in b.classes:
            raise HTTPException(422, f"label must be one of {b.classes}")
        label = req.label
        source = "override"
    agreed = None
    if run and run.get("final"):
        fin = run["final"]
        agent_label = "benign" if fin["verdict"] == "close_benign" else fin.get("family") or None
        agreed = agent_label == label if agent_label else None
    d.set_label(a.workspace, cid, label, source, a.actor,
                {"run_id": run.get("run_id") if run else None, "agreed_with_agent": agreed})
    after = ws_labels(b, a)
    return {"ok": True, "label": label, "changed": what_changed(b, pos, before, after, a)}


def what_changed(b: Bundle, pos: int, before: core.Labels, after: core.Labels,
                 a: auth.Analyst) -> list[dict]:
    """Among the 30 queue cases nearest the one just labelled, which would the desk now
    handle differently? This is how an override visibly teaches the desk."""
    Z = b.a["q_Z"].astype(np.float64)
    dist = np.sqrt(((Z - Z[pos]) ** 2).sum(1))
    dist[pos] = np.inf
    labelled = set(after.pos.tolist())
    near = [int(i) for i in np.argsort(dist)[:60] if int(i) not in labelled][:30]
    if not near:
        return []
    cap = ws_cap(a)
    d0 = core.decide(b, np.array(near), before, cap)
    d1 = core.decide(b, np.array(near), after, cap)
    out = []
    for i, p in enumerate(near):
        v0 = (d0["verdict"][i], d0["family"][i])
        v1 = (d1["verdict"][i], d1["family"][i])
        if v0 != v1:
            out.append({"case_id": b.case_id(p), "before": " ".join(x for x in v0 if x),
                        "after": " ".join(x for x in v1 if x),
                        "distance": round(float(dist[p]), 2)})
    return out[:8]


class KnobReq(BaseModel):
    cap: float | None = None


@app.post("/api/knob")
def knob(req: KnobReq, a: auth.Analyst = Depends(analyst)):
    b = load()
    caps = [r["cap_per_1000"] for r in b.knob] + [0]
    if req.cap is not None and req.cap not in caps:
        raise HTTPException(422, f"cap must be one of {caps} or null for the default")
    get_db().set_close_cap(a.workspace, req.cap, a.actor)
    return {"ok": True, "cap": req.cap, "threshold": b.threshold_for(req.cap)}


@app.post("/api/reset")
def reset(a: auth.Analyst = Depends(analyst)):
    get_db().reset(a.workspace, a.actor)
    return {"ok": True}


@app.get("/api/audit")
def audit(limit: int = 200, a: auth.Analyst = Depends(analyst)):
    d = get_db()
    return {"rows": d.audit(a.workspace, max(1, min(limit, 1000))),
            "chain": d.verify_chain()}


@app.get("/api/metrics")
def metrics():
    p = S.REPORTS_DIR / "eval.json"
    ag = S.REPORTS_DIR / "agent_eval.json"
    return {"eval": json.loads(p.read_text(encoding="utf-8")) if p.exists() else None,
            "agent_eval": json.loads(ag.read_text(encoding="utf-8")) if ag.exists() else None,
            "manifest": {k: v for k, v in load().manifest.items() if k != "family_cards"}}


@app.api_route("/api/health", methods=["GET", "HEAD"])
def health():
    b = load()
    return {"ok": True, "queue": b.n, "recorded_runs": len(recorded_runs())}


app.mount("/static", StaticFiles(directory=S.WEB_DIR), name="static")


@app.api_route("/", methods=["GET", "HEAD"])
def index():
    return FileResponse(S.WEB_DIR / "index.html")


@app.exception_handler(KeyError)
def key_error(request: Request, exc: KeyError):
    return JSONResponse({"detail": "not found"}, status_code=404)
