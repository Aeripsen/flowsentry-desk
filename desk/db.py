"""SQLite storage: workspaces, analyst labels, agent runs, and a hash-chained audit log.

Each analyst works in their own workspace (their Clerk user id when sign-in is on, a
random browser id otherwise), so one judge's overrides never change another judge's
queue. Nothing personal is stored: a workspace id, the labels, the runs, the audit rows.

The audit log is append-only and tamper-evident: each row stores the sha256 of the
previous row's hash plus its own content, and verify_chain() recomputes the whole chain.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import settings as S

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at TEXT NOT NULL,
  close_cap REAL
);
CREATE TABLE IF NOT EXISTS labels (
  workspace TEXT NOT NULL, case_id TEXT NOT NULL, label TEXT NOT NULL,
  source TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (workspace, case_id)
);
CREATE TABLE IF NOT EXISTS runs (
  run_id INTEGER PRIMARY KEY AUTOINCREMENT, workspace TEXT NOT NULL, case_id TEXT NOT NULL,
  engine TEXT NOT NULL, model TEXT NOT NULL, outcome TEXT NOT NULL, body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_ws_case ON runs (workspace, case_id);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, workspace TEXT NOT NULL, at TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, case_id TEXT, detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ws ON audit (workspace, seq);
"""

GENESIS = "0" * 64
_lock = threading.Lock()


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class DB:
    def __init__(self, path: Path | str | None = None):
        self.path = str(path or S.db_path())
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextmanager
    def tx(self):
        with _lock:
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    # ------------------------------------------------------------ workspaces

    def ensure_workspace(self, ws: str, kind: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR IGNORE INTO workspaces (id, kind, created_at) VALUES (?,?,?)",
                      (ws, kind, now()))

    def close_cap(self, ws: str) -> float | None:
        r = self.conn.execute("SELECT close_cap FROM workspaces WHERE id=?", (ws,)).fetchone()
        return None if r is None else r["close_cap"]

    def set_close_cap(self, ws: str, cap: float | None, actor: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE workspaces SET close_cap=? WHERE id=?", (cap, ws))
            self._audit(c, ws, actor, "set_close_knob", None, {"cap_per_1000": cap})

    def reset(self, ws: str, actor: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM labels WHERE workspace=?", (ws,))
            c.execute("DELETE FROM runs WHERE workspace=?", (ws,))
            c.execute("UPDATE workspaces SET close_cap=NULL WHERE id=?", (ws,))
            self._audit(c, ws, actor, "reset_workspace", None, {})

    # ------------------------------------------------------------ labels

    def labels(self, ws: str) -> list[tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT case_id, label FROM labels WHERE workspace=? ORDER BY created_at, case_id",
            (ws,)).fetchall()
        return [(r["case_id"], r["label"]) for r in rows]

    def label_of(self, ws: str, case_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM labels WHERE workspace=? AND case_id=?",
                              (ws, case_id)).fetchone()
        return dict(r) if r else None

    def set_label(self, ws: str, case_id: str, label: str, source: str, actor: str,
                  detail: dict) -> None:
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO labels VALUES (?,?,?,?,?)",
                      (ws, case_id, label, source, now()))
            self._audit(c, ws, actor, source, case_id, {"label": label, **detail})

    def clear_label(self, ws: str, case_id: str, actor: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM labels WHERE workspace=? AND case_id=?", (ws, case_id))
            self._audit(c, ws, actor, "reopen", case_id, {})

    # ------------------------------------------------------------ runs

    def add_run(self, ws: str, run: dict, actor: str) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO runs (workspace, case_id, engine, model, outcome, body, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (ws, run["case_id"], run["engine"], run["model"], run["outcome"],
                 json.dumps(run), now()))
            rid = int(cur.lastrowid)
            fin = run.get("final") or {}
            self._audit(c, ws, actor, "agent_run", run["case_id"], {
                "run_id": rid, "engine": run["engine"], "model": run["model"],
                "verdict": fin.get("verdict"), "family": fin.get("family"),
                "outcome": run["outcome"], "citations_ok": run["citations_ok"],
                "cited": fin.get("citations", []), "recorded": run.get("recorded", False)})
            return rid

    def latest_runs(self, ws: str) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT r.case_id, r.body FROM runs r JOIN (SELECT case_id, MAX(run_id) m FROM runs "
            "WHERE workspace=? GROUP BY case_id) t ON r.run_id=t.m", (ws,)).fetchall()
        return {r["case_id"]: json.loads(r["body"]) for r in rows}

    def latest_run(self, ws: str, case_id: str) -> dict | None:
        r = self.conn.execute(
            "SELECT run_id, body FROM runs WHERE workspace=? AND case_id=? "
            "ORDER BY run_id DESC LIMIT 1", (ws, case_id)).fetchone()
        if not r:
            return None
        body = json.loads(r["body"])
        body["run_id"] = r["run_id"]
        return body

    def runs_today(self, ws: str | None, engine_prefix: str) -> int:
        day = time.strftime("%Y-%m-%d")
        q = "SELECT COUNT(*) n FROM runs WHERE engine=? AND created_at LIKE ?"
        args: list = [engine_prefix, f"{day}%"]
        if ws:
            q += " AND workspace=?"
            args.append(ws)
        return int(self.conn.execute(q, args).fetchone()["n"])

    # ------------------------------------------------------------ audit

    def _audit(self, c, ws: str, actor: str, action: str, case_id: str | None,
               detail: dict) -> None:
        prev = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = prev["hash"] if prev else GENESIS
        at = now()
        body = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        h = _row_hash(prev_hash, ws, at, actor, action, case_id, body)
        c.execute("INSERT INTO audit (workspace, at, actor, action, case_id, detail, prev_hash,"
                  " hash) VALUES (?,?,?,?,?,?,?,?)",
                  (ws, at, actor, action, case_id, body, prev_hash, h))

    def audit(self, ws: str, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM audit WHERE workspace=? ORDER BY seq DESC LIMIT ?", (ws, limit))
        out = []
        for r in rows.fetchall():
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def verify_chain(self) -> dict:
        prev = GENESIS
        n = 0
        for r in self.conn.execute("SELECT * FROM audit ORDER BY seq"):
            want = _row_hash(prev, r["workspace"], r["at"], r["actor"], r["action"],
                             r["case_id"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != want:
                return {"ok": False, "rows_checked": n, "broken_at_seq": r["seq"]}
            prev = r["hash"]
            n += 1
        return {"ok": True, "rows_checked": n, "head": prev}


def _row_hash(prev, ws, at, actor, action, case_id, body) -> str:
    raw = "\x1f".join([prev, ws, at, actor, action, case_id or "", body])
    return hashlib.sha256(raw.encode()).hexdigest()
