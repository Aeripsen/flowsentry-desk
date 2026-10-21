# FlowSentry Desk

**A triage agent for the network flows FlowSentry refuses to call. Six read-only tools, a memo where every claim cites
evidence the server issued, and a close that needs three independent yeses.**

**Live demo:** https://sepehrjafari81-flowsentry-desk.hf.space (no sign-in, no key needed; Space page:
https://huggingface.co/spaces/sepehrjafari81/flowsentry-desk)

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
   closed. Each cap maps to a gate threshold chosen on a held-out pool of the training data by fixed-sequence binomial
   tests at the 5% level (approximate, see below). The default is the strictest cap the training data supports.
5. **Learns from the analyst, in the safe direction.** Labels train the second opinion and feed the nearby-attack
   rule, so an override can only make the desk more careful near that flow. After each label the desk reports which
   nearby cases it would now handle differently.
6. **Keeps a tamper-evident audit log.** Every run, label, reopen and knob change is a row that stores the hash of the
   row before it; the Audit view re-checks the whole chain. Each analyst works a separate workspace (their Clerk user
   when sign-in is on, a random browser id otherwise).

## Results

Measured on the 2,315-flow queue, with an oracle analyst that answers with the dataset's label. The evaluation was
re-run after each review fix (three runs in all, see below) and never tuned to the test numbers. Everything below is
in [reports/eval.json](reports/eval.json) and is rebuilt by `make eval`. The engine is the deterministic policy; a
model-driven run can only close a subset of what the policy closes, because a close needs the same server rules.

**The close knob.** Each cap's threshold was chosen on a calibration pool of the training split; the test queue was
scored at every setting, and every setting is reported.

| Cap | Supported on training data | Queue closed | Attacks closed | Per 1,000 closed (95% CI) | Queued attacks closed | Decisions per 100 |
|---|---|---|---|---|---|---|
| 10 per 1,000 | no | 0% | 0 | n/a | 0% | 100 |
| 20 per 1,000 | no | 0% | 0 | n/a | 0% | 100 |
| **30 per 1,000 (default)** | yes | **5.4% (124)** | **0** | **0 (0 to 30.0)** | **0%** | **94.6** |
| 50 per 1,000 | yes | 9.0% (209) | 2 | 9.6 (2.6 to 34.2) | 0.4% | 91.0 |
| 100 per 1,000 | yes | 20.4% (472) | 27 | 57.2 (39.6 to 81.9) | 5.5% | 79.6 |

At the default the desk closes 124 queue flows and none is an attack. At every supported setting the test rate stayed
under its cap. At every setting, 8.0 of the decisions per 100 items are one-key confirmations of an escalation rather
than full investigations. The default is strict on purpose: it saves the analyst about 5 decisions in 100, and the
larger saving comes from the order and the pre-read below.

**Finding attacks sooner.** The queue is served in the desk's order by default: least benign-looking first. In that
order an analyst finds half of the 491 queued attacks after 324 items, against 866 in FlowSentry's own order (lowest
P(benign) first) and about 1,161 at random. The advantage is at the top of the queue: finding 90% takes 1,612 items,
slightly more than FlowSentry's 1,570.

**Escalations.** The desk escalates 186 queue flows: 166 are attacks (89%), and 156 carry the right family name (84%).

**Learning from labels is small on this sample.** With 0, 10, 25, 50, 100 and 200 oracle labels (20 random label
orders each), the share of rare-family flows the desk escalates under the right name goes 8.9%, 9.4%, 10.0%, 10.1%,
10.1%, 10.7%. What labels do reliably is block closes near a labelled attack. The video shows one case where that
matters: at 100 per 1,000, relabelling C1681 (a UDP-OVH flood the desk closed) stops the desk from closing C1986 and
C1967, both UDP-OVH floods. That example was picked after the evaluation; it illustrates the mechanism and is not a
measurement.

**What the numbers do not say.**
- Per-1,000-closed figures depend on how benign the queue is, and this sample caps benign traffic. A reweighting of
  the measured close rates to more benign queues is in `reports/eval.json` and on the Results page, labelled as a
  projection. The share of queued attacks closed does not depend on the mix.
- The rare families are flood variants from one dataset's generator, not real-world zero-days.
- One flood is many flows. The evaluation counts flows, not incidents.
- The headline uses the deterministic policy. Recorded Claude runs, once recorded, are evaluated separately in
  `reports/agent_eval.json` by `make eval-agent`.

## How the gate was chosen, including what did not work

Everything about the gate comes from the training split. Its connections are divided first, before any model is
trained, into a fit pool (11,305 flows) and a calibration pool (7,740 flows). In the fit pool, FlowSentry is retrained
on three connection-grouped folds; the 4,257 fit flows those folds would have queued train five gradient-boosting
models, and the deployed gate score is their mean. Inputs: the 132 flow features, FlowSentry's out-of-fold class
probabilities and eight precedent statistics. The calibration pool is scored by a FlowSentry trained on the whole fit
pool, with precedents from the fit pool only, so none of its labels touch anything that scores it. Its 2,871 queued
flows (696 of them attacks) are read once, to pick the thresholds. On them the gate's AUC is 0.80.

Each knob threshold is picked on the calibration pool by fixed-sequence testing (the Learn-then-Test procedure):
thresholds are tested from strictest to loosest with an exact binomial test of "attacks among closed flows are at
least the cap" at the 5% level, and the sequence stops at the first threshold that fails. Read the 5% as approximate:
the test treats flows as independent, but flows of one connection are correlated, and calibration flows are scored by
a FlowSentry trained on a smaller pool than the one that scores test flows. The caps of 10 and 20 per 1,000 are not
supported: they would need roughly 300 and 150 closes in a row with no attack.

The evaluation was run three times. Each run followed a methodology fix found by review, and none was tuned to the test
numbers; the build log keeps every superseded number with its date.
- The first gate picked the loosest threshold whose Wilson bound passed, searched on the same out-of-fold scores, and
  scored calibration rows with single fold models while deploying their average. An independent review (Codex,
  read-only) showed that this search breaks the 95% bound.
- The second split the gated rows into fit and calibration parts, but only after the out-of-fold FlowSentry features
  and precedent pools had been built from all training labels. A second review pass caught that the calibration
  labels still reached the gate that way. The pools are now split before anything is trained.
- Separately, CI caught that an early gate was not reproducible across machines (precedent ties broke on
  floating-point noise; the boosted trees summed in thread order). The build now rounds distances before ranking,
  breaks ties by index and fits on one thread, and CI rebuilds the bundle on Linux and requires identical gate scores.

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
| `make test` | 59 tests: guardrails, the agent loop against a scripted client, the API, Clerk token checks, the bundle |
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
