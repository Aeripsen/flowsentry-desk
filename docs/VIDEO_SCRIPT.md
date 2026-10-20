# Two-minute demo video

Record on the live Space (or `make serve` locally) in a fresh browser window, 1440 x 900, zoom 110%. Speak slowly;
the timings leave room. Every number spoken is in `reports/eval.json`. If the Claude runs are recorded (docs/HIS_CLICKS.md
step 1), the case pages show "anthropic claude-sonnet-5-5"; if not, say "the desk" instead of "Claude" in 0:30 to 1:00.

Before recording: open the Audit log view and click **Reset my workspace**, then go back to Desk.

| Time | On screen | Say |
|---|---|---|
| 0:00 | The Desk view, untouched queue, tally at the top | "This is FlowSentry, my open-source network intrusion detector. It's allowed to say I don't know. On held-out traffic it says it 2,315 times, and in this sample four in five of those flows are benign. That's one analyst's queue." |
| 0:15 | Click **Pre-read the next 25**. The tally fills in: closed, escalated, need you | "The desk pre-reads every case. Claude works it with six read-only tools: the case, an exact explanation of FlowSentry's own forest, the nearest labelled flows, family cards, and a second opinion trained on my labels." |
| 0:30 | Escalated tab, open the first case. Click a citation chip in the memo; the evidence on the right lights up | "Every claim in the memo cites a tool result, and the ids come from the server. If the agent cites something it never fetched, the server refuses it." |
| 0:42 | Scroll to the ticket draft, press **A** to confirm | "Attacks get escalated with the family and a ticket draft for on-call. One key to confirm." |
| 0:50 | Needs-you tab, open a case whose memo says the signals disagree | "When the evidence conflicts, it doesn't guess. It asks me." |
| 0:58 | Set the **Close knob** to 30 per 1,000. Open `/#C0072`, press **R**; it shows "Closed by the desk" | "Closing is a knob, like FlowSentry's. Each setting is certified on training data only. Here I spot-check something the desk closed." |
| 1:08 | In C0072 choose **UDP-bypass-v1**, click **Save label**. The panel lists three nearby cases that changed | "It's actually a bypass flood. I relabel it, and the desk stops auto-closing three flows that look like it: they come to me now. My overrides can only make it more careful, never less." |
| 1:22 | Click C0896 in that list: it now needs you | "And the agent can never close on its own say-so: a close needs the agent, the server rules and the citations to agree." |
| 1:30 | **Results** view, the four figures and the ordering chart | "Measured once on the held-out queue. At the strict default it closes 2.5 percent with zero attacks. At 30 per thousand, 13.7 percent with 4 attacks. And in the desk's order I find half the attacks after 325 cases instead of 866." |
| 1:48 | **Audit log** view, chain intact | "Every run and every label is in a hash-chained audit log." |
| 1:53 | Back to Desk | "Bring your own detector: the desk needs a reject queue and a labelled history. FlowSentry Desk." |

Notes for the take:
- Keep the cursor still while talking about a number; move it to point at the number.
- If a run is slow on the live Space, cut it in editing; do not speed the video up.
- Title card is optional. If used: "FlowSentry Desk, Build North 2026".
- Upload to YouTube as **Unlisted**.
- The knob must be at 30 before C0072 is run (runs use the knob of the moment). If a recorded Claude run of C0072
  proposes "ask a human" instead of a close, say "here is a flow the rules would close" and carry on: the list of
  changed neighbours comes from the rules, not from that run.
