# Prior work, and what was built during Build North (Oct 16 to 25, 2026)

Build North asks every team to disclose prior work, templates and scaffolding. Here it is.

## Existing before Build Week

- **FlowSentry** (github.com/Aeripsen/flowsentry, MIT, my own repository): the two-stage UDP/QUIC intrusion detector
  with a reject option, its leakage-safe connection-grouped split, its training code and its published metrics. The
  desk imports it unchanged at commit `1299cd8c3ed19f0677d170b8973e64589d070430` and only calls its data loader,
  split, model class and attack map. Nothing in FlowSentry was modified.
- **BCCC-UDP-QUIC-IDS-2025** (public, CC BY 4.0), the dataset from my SECRYPT 2026 paper, in the stratified sample
  FlowSentry ships.

## New in Build Week (everything in this repository)

- The evidence layer over FlowSentry's 0.99 reject queue (`desk/build.py`): exact per-flow path contributions on the
  forest that answered each flow, training-split precedents, family cards, and the close gate trained on the
  training split's out-of-fold predictions, with its close knob.
- The six read-only tools, the server-issued result ids and the citation check (`desk/tools.py`), and the decision
  rules that let the agent add human attention but never remove it (`desk/core.py`).
- The agent loops: Claude through the Anthropic API, an OpenAI-compatible loop for testing, and the deterministic
  policy (`desk/agent.py`).
- The desk: API, per-analyst workspaces, labels that flow back into the second opinion and the nearby-attack rule,
  the hash-chained audit log, Clerk sign-in behind a flag, and the web interface (`desk/app.py`, `desk/db.py`,
  `desk/auth.py`, `web/`).
- The oracle-analyst evaluation (`desk/evaluate.py`, `scripts/eval_agent.py`), the tests, CI and the deploy setup.

Tools used while building: Claude (Anthropic) as a coding assistant. A sibling project, LedgerSentry Desk, applies the
same desk pattern to card fraud; it is a separate repository and not part of this submission.
