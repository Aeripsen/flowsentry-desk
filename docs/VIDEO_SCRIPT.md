# Two-minute demo video

Record on the live Space (or `make serve` locally) in a fresh browser window, 1440 x 900, zoom 110%. Speak slowly;
the timings leave room. Every number spoken is in `reports/eval.json`. If the Claude runs are recorded
(docs/HIS_CLICKS.md step 1), the case pages say "anthropic claude-sonnet-5-5"; if not, say "the desk" instead of
"Claude" at 0:15 to 0:50.

Before recording: open the Audit log view, click **Reset my workspace**, go back to Desk. The close knob should show
"20 per 1,000, default".

| Time | On screen | Say |
|---|---|---|
| 0:00 | The Desk view, untouched queue, tally at the top | "This is FlowSentry, my open-source network intrusion detector. It's allowed to say I don't know. On held-out traffic it says it 2,315 times, and in this sample four in five of those flows are benign. That's one analyst's queue." |
| 0:15 | Click **Pre-read the next 25**. The tally fills in | "The desk pre-reads the queue, least benign-looking first. Claude works each case with six read-only tools: the case, an exact explanation of FlowSentry's own forest, the nearest labelled flows, family cards, and a second opinion trained on my labels." |
| 0:30 | Escalated tab, open the first case. Click a citation chip in the memo; the evidence on the right lights up | "Every claim in the memo cites a tool result, and the ids come from the server. Cite something you never fetched, and the server refuses it." |
| 0:42 | Scroll to the ticket draft, press **A** to confirm | "Attacks get escalated with the family and a ticket draft for on-call. One key to confirm." |
| 0:50 | Set the **Close knob** to 30 per 1,000. Open `/#C1099`, press **R**: "Closed by the desk" | "Closing is a knob, like FlowSentry's, and every setting is tested on training data. Here I spot-check something the desk closed." |
| 1:00 | In C1099 pick **UDP-OVH**, click **Save label**. The panel lists C1127 and C1022 as changed | "It's actually an OVH flood. I relabel it, and the desk stops auto-closing the two flows right next to it." |
| 1:12 | Click C1127, press **R**: "Needs you", memo names C1099 | "And this one is a real HULK flood that the desk would have closed. My override can only make it more careful, never less. A close needs the agent, the rules and the citations to agree." |
| 1:28 | **Results** view, the four figures, then the chart | "Measured once on the held-out queue. At the strict default it closes 8.6 percent of the queue, with one attack in 199 closes, and only 0.2 percent of the attacks get closed. In the desk's order I find half the attacks after 341 cases instead of 866. And we publish where it falls short: the loose settings went over their caps." |
| 1:48 | **Audit log** view, chain intact | "Every run and every label is in a hash-chained audit log." |
| 1:53 | Back to Desk | "Bring your own detector: the desk needs a reject queue and a labelled history. FlowSentry Desk." |

Notes for the take:
- Keep the cursor still while talking about a number; point at it.
- If a run is slow on the live Space, cut it in editing; do not speed the video up.
- The knob must be at 30 before C1099 is run (runs use the knob of the moment).
- C1099 and C1127 were picked after the evaluation as an example. The script says "here" and "this one", never "always".
- Backup take if anything differs on the day: leave the knob at the default, open `/#C0072` (the default's one wrong
  close, a UDP-bypass-v1 flow), relabel it UDP-bypass-v1, and C0896, C1340, C1353 move to "needs you". Those three are
  benign, so say "it sends me the look-alikes", not "it caught three more".
- If a recorded Claude run of the spot-check case proposes "ask a human" instead of a close, say "here is a flow the
  rules would close" and carry on: the list of changed neighbours comes from the rules, not from that run.
- Title card is optional: "FlowSentry Desk, Build North 2026". Upload to YouTube as **Unlisted**.
