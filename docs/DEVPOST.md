# Devpost page, ready to paste

Paste each section into the field of the same name. Two lines depend on your steps in docs/HIS_CLICKS.md and are
marked **[check]**: keep them only if that step is done. Everything else is true as written; every number is in
`reports/eval.json`.

---

## Project name

FlowSentry Desk

## Elevator pitch (one line)

An AI triage agent for the alerts a network detector refuses to call: it cites every claim, abstains on conflict, and
can never close a case on its own say-so.

## Inspiration

I built FlowSentry, an open-source intrusion detector for UDP and QUIC traffic, on the public dataset from my SECRYPT
2026 paper. Its best feature is that it is allowed to say "I don't know". At its 0.99 confidence bar it refuses 2,315
of its 6,570 held-out flows and sends them to an analyst. Then I looked at that queue: 78.8% of it is benign, and the
rare flood families hide in the rest. The model had moved the problem, not solved it. The person who gets that queue
is one analyst at a small managed security provider or a university IT team, and nobody was helping them.

Most AI triage demos let the model decide. I wanted the opposite: an agent that does the reading, shows its evidence,
and is structurally unable to close an alert unless an independent, measured check agrees.

## What it does

FlowSentry Desk works FlowSentry's reject queue.

- **Pre-reads each case with six read-only tools.** `next_case` opens the flow; `explain` gives the exact path
  contributions of the FlowSentry forest that answered it (base rate plus contributions equals FlowSentry's
  probability, checked to 1e-6); `precedents` returns the nearest labelled flows from training history; `family_card`
  describes an attack family and its ATT&CK playbook; `second_opinion` is a small model trained only on the analyst's
  own labels; `propose` ends the case. No tool writes, blocks traffic or calls out.
- **Cites everything, and the server checks it.** Every tool result gets an id that only the server issues. The memo
  must cite those ids inline. A citation the agent never received is refused.
- **Proposes, never decides.** The agent proposes close, escalate (with the family and a ticket draft for on-call) or
  ask a human. A case closes only if three things agree: the agent proposes a close, the server rules allow it (a
  calibrated gate trained on training data only, a benign majority among precedents, no analyst-labelled attack
  nearby, no objection from the second opinion), and the citations check out. The agent never sees the gate. It can
  add human attention, never remove it.
- **A close knob instead of a magic threshold.** Like FlowSentry's reject knob, the analyst picks a cap on attacks
  wrongly closed per 1,000 closed. Each setting maps to a gate threshold chosen on a held-out pool of training data
  by fixed-sequence binomial tests, and the analyst sees how each setting did on the held-out queue.
- **Learns from the analyst, in the safe direction.** Approvals and overrides become labels. They train the second
  opinion and feed a rule that blocks closes near any flow the analyst marked as an attack. After each label the desk
  shows which nearby cases it would now handle differently.
- **Auditable.** Every run, label and setting change goes into a hash-chained audit log that the app re-verifies.
  Each analyst works their own workspace.

## How we built it

- FlowSentry is imported unchanged at a pinned commit. The build retrains it with its own code and refuses to continue
  unless the result matches FlowSentry's published metrics exactly, then rebuilds the exact 2,315-flow queue.
- The close gate is trained only on the training split. Its connections are divided before anything is trained into
  a fit pool and a calibration pool. In the fit pool FlowSentry is retrained on three connection-grouped folds and the
  flows those folds would have queued train five gradient-boosting models; the calibration pool is scored by that
  exact ensemble, and each knob threshold is picked there by fixed-sequence exact binomial tests (Learn then Test).
  The test queue is used by an oracle-analyst evaluation that answers with the dataset's labels.
- The agent loop is Claude Sonnet 5.5 through the Anthropic API with strict tool schemas, an 8-step budget, prompt
  caching and Anthropic's server-side refusal fallback. A deterministic policy runs the same tools in a fixed order;
  it is what runs when no model key is set, and the yardstick in the evaluation. If a live model call fails, the case
  goes to a person. Recorded Claude runs replay with no API at all, and are re-checked against the current rules
  before they are shown.
- FastAPI, SQLite, a plain HTML, CSS and JavaScript interface with no build step, Docker, deployed on a Hugging Face
  Space. CI runs 59 tests, rebuilds the data on Linux and requires it to match, smoke-tests the container, and clicks
  through the interface in headless Chromium at desktop and phone widths.

## Results (on the held-out queue)

- At the default setting (30 attacks per 1,000 closed), the desk closes **5.4% of the queue (124 flows) and not one
  of them is an attack**. Looser settings close more: 9.0% with 2 attacks (9.6 per 1,000) at 50, 20.4% with 27
  attacks (57.2 per 1,000) at 100. **Every setting stayed under its cap on the held-out queue.**
- The queue is served least benign-looking first: an analyst finds **half of the 491 queued attacks after 324 cases
  instead of 866** in FlowSentry's own order (about 1,161 at random).
- Of 186 escalations, 166 are attacks and 156 name the right family, each with a ticket draft.
- Where it falls short: the strict default saves only about 5 decisions in 100; reaching 90% of the attacks takes
  1,612 cases in the desk's order against 1,570 in FlowSentry's; caps of 10 and 20 per 1,000 cannot be supported by
  this data; and learning from labels is small here (rare-family naming goes from 8.9% to 10.7% with 200 labels).
  This sample caps benign traffic, so per-1,000 figures would be lower on a real, more benign queue (we publish a
  reweighting, labelled as a projection). The rare families are flood variants from one dataset, not real zero-days.

## Challenges we ran into

- **The data said no.** The first plan was to promise 10 attacks wrongly closed per 1,000. The training data cannot
  support it: inside the queue the rare floods look like benign traffic, and a bound that tight needs about 300 clean
  closes in a row. Rather than relax one number until it passed, we turned it into a knob and report every setting.
- **A reviewer broke our statistics, twice, and was right both times.** An independent model review (Codex,
  read-only) found that our first threshold search reused the same data for searching and bounding, so the advertised
  95% did not hold. Our fix split off a calibration part, and the second pass found that its labels still reached the
  gate through upstream features. The calibration pool is now separated before anything is trained, and the 5% level
  is described as approximate because flows of one connection are correlated. The evaluation was re-run after each
  fix, never tuned to the test numbers. The same reviews found smaller problems (a quota a reset could erase, replays
  that skipped validation, an origin check that failed open, reopen semantics); all are fixed and tested.
- **Reproducibility across machines.** CI caught that an early gate was not reproducible: precedent ties broke on
  floating-point noise and the boosted trees summed in thread order. The build now rounds before ranking, breaks ties
  by index and fits on one thread, and CI requires identical gate scores on Linux.
- **A real UI bug found by a robot.** The headless click-through found an invisible sign-in overlay that swallowed every
  click. Fixed before any human saw it.

## Accomplishments that we're proud of

- An agent whose safety is a property of the system, not of the prompt: the server issues the evidence ids, owns the
  gate, and decides the outcome.
- Every number on the page traces to a file in the repo and a command that rebuilds it.
- The safety rules survived an adversarial review: every finding is fixed and has a test.
- The negative results are published next to the positive ones.

## What we learned

Abstention is a pipeline property. A detector that says "I don't know" creates a queue, and the queue needs its own
measured "I don't know". The useful product is not a smarter guess; it is a calibrated decision about when not to
guess, and a fast way to show the human why.

## What's next for FlowSentry Desk

- Bring your own detector: the desk needs only a reject queue, a labelled history and a training split. LedgerSentry,
  my fraud model, is the next adapter.
- Incident-level grouping, so one flood becomes one ticket instead of many flows.
- Per-seat pricing for small security teams; the analyst workspace and audit log are already per user.

## Built with

python, fastapi, scikit-learn, numpy, sqlite, anthropic, claude, javascript, html, css, docker, hugging-face,
github-actions, playwright, clerk **[check: step 5]**

## Partner platforms used

- **Anthropic (Claude API):** Claude Sonnet 5.5 drives the triage agent's tool loop, with strict tool use, prompt
  caching and server-side refusal fallback.
- **Clerk [check: step 5]:** optional analyst sign-in. Anyone can work the desk anonymously; signing in gives an
  analyst a workspace, labels and audit trail that follow them across devices. Session tokens are verified on our
  server (RS256, expiry, authorised origin).

## Prior work and scaffolding

Built on my open-source FlowSentry (public repo, model and scoring API). New in Build North: the triage agent, the case
queue, the feedback loop, the oracle-analyst evaluation, Clerk auth **[check: step 5; drop "Clerk auth" if not done]**. Details in PRIOR_WORK.md in the repository.

## Links

- Code: https://github.com/Aeripsen/flowsentry-desk
- Live demo: https://sepehrjafari81-flowsentry-desk.hf.space (the Space page:
  https://huggingface.co/spaces/sepehrjafari81/flowsentry-desk)
- Video: (your YouTube link)
- FlowSentry: https://github.com/Aeripsen/flowsentry
