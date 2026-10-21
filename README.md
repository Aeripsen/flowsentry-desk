# FlowSentry Desk

**A triage agent for the network flows FlowSentry refuses to call. Six read-only tools, a memo where every claim cites
evidence the server issued, and a close that needs three independent yeses.**

Built for Build North 2026 (Georgian) on top of my open-source detector
[FlowSentry](https://github.com/Aeripsen/flowsentry). What existed before Build Week and what is new is in
[PRIOR_WORK.md](PRIOR_WORK.md).

## The problem, in one queue

FlowSentry is a UDP/QUIC intrusion detector that is allowed to say "I don't know". At its 0.99 confidence bar it
refuses 2,315 of its 6,570 held-out flows and sends them to an analyst. In that queue, 1,824 flows (78.8%) are
benign, 144 are UDP-RAW floods and 347 belong to six rare flood families. The analyst spends the shift closing benign
flows, and the rare floods hide among them.

The 78.8% is a property of FlowSentry's committed sample, which caps benign traffic. On a real network the queue would
be far more benign, which makes the analyst's day worse, not better.

## What the desk does

1. **Pre-reads each case with six read-only tools.** `next_case` (FlowSentry's verdict, confidence and key flow
   statistics next to typical benign values), `explain` (the exact path contributions of the FlowSentry forest that
   answered this flow: base rate plus contributions equals FlowSentry's probability, checked to 1e-6),
   `precedents` (the 15 nearest labelled flows from the training split), `family_card` (what an attack family looks
   like in training data, its ATT&CK technique and playbook), `second_opinion` (a small model trained only on this
   analyst's labels) and `propose`. No tool writes anything, blocks traffic or reaches the network.
2. **Cites everything.** Each tool result gets an id (R1, R2, ...) that only the server issues. The memo must cite them
   inline; an id that was not issued in that run is refused, and a memo that never passes goes to a person.
3. **Proposes, never decides.** The agent proposes close, escalate or ask a human. A case closes only if the agent
   proposes a close, the server rules allow it, and the citations check out. The rules: a calibrated close gate
   (trained on training data only) clears the flow, at least half of its 15 precedents are benign, no flow the analyst
   labelled as an attack sits in its neighbourhood, and the second opinion does not object. The agent cannot see the
   gate. It can add human attention, never remove it.
4. **Has a close knob.** Like FlowSentry's reject knob, the analyst picks a cap on attacks wrongly closed per 1,000
   closed. Each cap maps to a gate threshold chosen on training data by a test that holds at the 5% level even though
   many thresholds are searched. The default is the strictest cap the training data supports.
5. **Learns from the analyst, in the safe direction.** Labels train the second opinion and feed the nearby-attack
   rule, so an override can only make the desk more careful near that flow. After each label the desk reports which
   nearby cases it would now handle differently.
6. **Keeps a tamper-evident audit log.** Every run, label, reopen and knob change is a row that stores the hash of the
   row before it; the Audit view re-checks the whole chain. Each analyst works a separate workspace (their Clerk user
   when sign-in is on, a random browser id otherwise).

## Results

Measured once on the 2,315-flow queue, with an oracle analyst that answers with the dataset's label. Everything below is
in [reports/eval.json](reports/eval.json) and is rebuilt by `make eval`. The engine is the deterministic policy; a
model-driven run can only close a subset of what the policy closes, because a close needs the same server rules.

**The close knob.** Each cap's threshold was chosen on a calibration part of the training split; the test queue was
scored once at every setting.

| Cap | Supported on training data | Queue closed | Attacks closed | Per 1,000 closed (95% CI) | Queued attacks closed | Decisions per 100 |
|---|---|---|---|---|---|---|
| 10 per 1,000 | no | 0% | 0 | n/a | 0% | 100 |
| **20 per 1,000 (default)** | yes | **8.6% (199)** | **1** | **5.0 (0.9 to 27.9)** | **0.2%** | **91.4** |
| 30 per 1,000 | yes | 19.7% (456) | 13 | 28.5 (16.7 to 48.2) | 2.6% | 80.3 |
| 50 per 1,000 | yes | 28.1% (651) | 37 | 56.8 (41.5 to 77.4) | 7.5% | 71.9 |
| 100 per 1,000 | yes | 77.5% (1,793) | 183 | 102.1 (88.9 to 116.9) | 37.3% | 22.5 |

At the default the desk closes 199 flows and one of them is an attack (a UDP-bypass-v1 flow). At 30 per 1,000 the
test rate stays under the cap. At 50 and 100 it does not: 56.8 and 102.1 per 1,000. Those two settings are where the
calibration assumption (calibration flows behave like queued test flows) visibly fails, so the loose end of the knob
should be read as a guide, not a guarantee. At every setting, 8.0 of the decisions per 100 items are one-key
confirmations of an escalation rather than full investigations.

**Finding attacks sooner.** The queue is served in the desk's order by default: least benign-looking first. In that
order an analyst finds half of the 491 queued attacks after 341 items, against 866 in FlowSentry's own order (lowest
P(benign) first) and about 1,161 at random. The advantage is at the top of the queue: finding 90% takes 1,607 items,
slightly more than FlowSentry's 1,570.

**Escalations.** The desk escalates 186 queue flows: 166 are attacks (89%), and 156 carry the right family name (84%).

**Learning from labels is small on this sample.** With 0, 10, 25, 50, 100 and 200 oracle labels (20 random label
orders each), the share of rare-family flows the desk escalates under the right name goes 8.9%, 9.4%, 10.0%, 10.1%,
10.1%, 10.7%. Attacks wrongly closed at the default go from 1 to between 0.75 and 0.9 on average, because a labelled
attack blocks closes in its neighbourhood. The video shows one case where that matters: at 30 per 1,000, relabelling
C1099 (a UDP-OVH flood the desk closed) stops the desk from closing C1127, which is a UDP-HULK flood. That example was
picked after the evaluation; it illustrates the mechanism and is not a measurement.

**What the numbers do not say.**
- Per-1,000-closed figures depend on how benign the queue is, and this sample caps benign traffic. Reweighting the
  measured close rates at the default to a 95% benign queue gives about 1.0 attack per 1,000 closed; that is a
  projection, not a measurement. The share of queued attacks closed (0.2% at the default) does not depend on the mix.
- The rare families are flood variants from one dataset's generator, not real-world zero-days.
- One flood is many flows. The evaluation counts flows, not incidents.
- The headline uses the deterministic policy. Recorded Claude runs, once recorded, are evaluated separately in
  `reports/agent_eval.json` by `make eval-agent`.

## How the gate was chosen, including what did not work

The gate is trained on the training split only. FlowSentry is retrained on three connection-grouped folds, and the
6,945 training flows those folds would have queued become the gate's data. They are split by connection into a fit
part (4,129 flows) and a calibration part (2,816 flows, 546 of them attacks). Five gradient-boosting models are fitted
on the fit part; the deployed score is their mean. Inputs: the 132 flow features, FlowSentry's out-of-fold class
probabilities and eight precedent statistics. On the calibration part the deployed ensemble has an AUC of 0.85.

Each knob threshold is picked on the calibration part by fixed-sequence testing (the Learn-then-Test procedure):
thresholds are tested from strictest to loosest with an exact binomial test of "attacks among closed flows are at
least the cap" at the 5% level, and the sequence stops at the first threshold that fails. That keeps the 5% level valid
even though many thresholds are searched. The cap of 10 per 1,000 is not supported: it would need about 300 closes in
a row with no attack.

Three earlier versions did not survive review, and the log keeps their numbers, marked superseded:
- The first gate picked the loosest threshold whose Wilson bound passed, searched on the same out-of-fold scores, and
  scored calibration rows with single fold models while deploying their average. An independent review (Codex)
  pointed out that this search breaks the 95% bound; the calibration split above replaced it.
- That first gate was also not reproducible across machines: precedent ties broke on floating-point noise and the
  boosted trees summed in thread order. The build now rounds distances before ranking, breaks ties by index and fits
  on one thread; CI rebuilds the bundle on Linux and requires identical gate scores.
- The first plan was a single cap of 10 per 1,000. The data cannot support it, so the single cap became the knob.

## Run it

```bash
git clone https://github.com/Aeripsen/flowsentry-desk && cd flowsentry-desk
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
make serve                                             # http://localhost:8000, no key needed
make test
```

No model key is needed: the desk serves recorded runs and runs the deterministic policy live. To add Claude, copy
`.env.example` to `.env`, set `ANTHROPIC_API_KEY` and `DESK_LIVE_AGENT=1`. The default model is `claude-sonnet-5-5`;
requests opt into Anthropic's server-side refusal fallback, and any API failure sends the case to a person.

| Command | What it does |
|---|---|
| `make serve` | the desk on port 8000 |
| `make test` | 58 tests: guardrails, the agent loop against a scripted client, the API, Clerk token checks, the bundle |
| `make data` | rebuild `data/desk_bundle.npz` from FlowSentry (needs `requirements-build.txt`, about a minute) |
| `make verify-data` | rebuild and compare with the committed bundle (CI runs this on Linux) |
| `make eval` | the oracle-analyst evaluation |
| `make record-agent` | record Claude runs for the first 40 queue cases into `runs/recorded.jsonl` |
| `make eval-agent` | evaluate recorded model runs against the oracle |
| `make docker && make docker-run` | the container on port 7860 |

## Architecture

```mermaid
flowchart LR
    FS["FlowSentry (pinned commit)<br/>retrained, metrics checked"] --> B["desk.build<br/>queue, explanations, precedents,<br/>family cards, close gate"]
    B --> BUN[("data/desk_bundle.npz")]
    BUN --> T["six read-only tools<br/>result ids R1..Rn"]
    T --> A{"agent<br/>Claude, or the deterministic policy"}
    A -->|propose + citations| R["server rules<br/>gate, precedents, labels, second opinion,<br/>citation check"]
    R --> O["AUTO_CLOSED / ESCALATED / HUMAN"]
    O --> UI["queue UI"]
    UI -->|approve or override| L[("SQLite: labels, runs,<br/>hash-chained audit")]
    L --> T
```

The app needs only the bundle at runtime (1.2 MB, no pickled models). FlowSentry itself is needed only to rebuild it.

## Security and ethics

- Read-only by construction: no tool writes, blocks, or calls out. A test hashes every bundle array before and after
  calling every tool, and another scans the tool code for network and file calls.
- The agent never sees labels, the gate, or its threshold; tool results are passed as data, and the system prompt says
  so. Tests check that no agent-side module reads the held-out labels and no tool output mentions the gate.
- A close needs the agent, the rules and the citations to agree; escalations always reach a person; a refusal, timeout,
  bad citation or exhausted step budget (8 steps) sends the case to a person.
- Live model runs are capped per workspace and per day; the batch pre-read never calls a model.
- Clerk session tokens are verified on the server: RS256 only, expiry, not-before, and `azp` against the allowed
  origins. Tests cover expired, wrong-key, wrong-origin and HS256-downgrade tokens.
- Data: public BCCC-UDP-QUIC-IDS-2025 only (CC BY 4.0), the sample FlowSentry ships. No IP address or port is stored or
  shown; flows are cited by their row in the public sample. No lab, private or partner data is in this repository.
- Strict Content-Security-Policy, no inline scripts, and every model or data string is escaped before it reaches the
  page.

## Data and credit

BCCC-UDP-QUIC-IDS-2025 is the public dataset from my SECRYPT 2026 paper on hierarchical UDP/QUIC intrusion detection,
released under CC BY 4.0. FlowSentry ships a stratified sample of it; this repository uses only that sample.

MIT licence.
