# Working on FlowSentry Desk

Ten minutes from clone to a running desk. No model key, no Docker and no dataset download are needed for the app.

## Set up

```bash
git clone https://github.com/Aeripsen/flowsentry-desk && cd flowsentry-desk
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
make serve        # http://localhost:8000
make test         # all tests, about 5 seconds
```

Windows without `make`: every target in the `Makefile` is one line; run that line directly
(for example `python -m uvicorn desk.app:app --port 8000`).

## Where things are

| Path | What it is |
|---|---|
| `desk/build.py` | builds `data/desk_bundle.npz` from FlowSentry; only needed to change the data |
| `desk/core.py` | the decision rules; read this first |
| `desk/tools.py` | the six tools and the citation ledger |
| `desk/agent.py` | the policy, the Claude loop, the OpenAI-compatible loop |
| `desk/app.py` | the FastAPI app and its routes |
| `desk/db.py` | SQLite: workspaces, labels, runs, audit chain |
| `web/` | the interface: plain HTML, CSS and JavaScript, no build step |
| `desk/evaluate.py` | the oracle-analyst evaluation behind `reports/eval.json` |

## Good first tasks for a front-end teammate

The whole UI is `web/index.html`, `web/style.css` and `web/app.js`. Colours are tokens at the top of `style.css`
(light and dark). Run `make dev` for auto-reload of the Python side; the browser picks up front-end edits on refresh.
CI loads the page in headless Chromium and clicks through the demo (`scripts/ui_check.py`); its screenshots are the
`ui-shots` artifact on each Actions run.

## Rules that keep the numbers honest

- `reports/eval.json` is the only place test labels are read in bulk. Agent-side code (`tools.py`, `agent.py`,
  `core.py`, `app.py`) must never read a bundle key that starts with `oracle`; a test enforces it.
- If you change the rules in `desk/core.py`, rerun `make eval` and say in the commit message that the numbers moved
  and why. Do not tune the rules against `reports/eval.json`.
- Never commit `.env` or a key. `.env.example` lists every setting.

## Using a model locally

Copy `.env.example` to `.env`, set `ANTHROPIC_API_KEY`, then either set `DESK_LIVE_AGENT=1` for live runs in the UI,
or run `make record-agent` to record runs that the app serves without a key.
