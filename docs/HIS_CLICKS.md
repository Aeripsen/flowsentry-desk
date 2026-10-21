# What only Sepehr can do, in order

Submission closes **Sun Oct 25 2026, 11:59 PM ET** on Devpost. Plan: everything ready by **Sat Oct 24, 6:00 PM**, submit
by **Sun Oct 25, 8:00 PM**. Each step says the page, the field, and what to paste. Nothing here needs a card.

Steps 1 to 3 unlock the rest; do them Thursday evening (Oct 22) after the test if you can.

## 1. Anthropic API key (5 minutes, by Fri Oct 23 noon)

Anthropic emailed on Oct 20 at 09:45 that $200 in API credits were added to "sep's Individual Org" from your Max plan.

1. Open https://console.anthropic.com and sign in with sepehr1381ja@gmail.com.
2. Top left, make sure the organisation is **sep's Individual Org**.
3. Left menu **API keys** > **Create key**. Name: `flowsentry-desk`. Workspace: Default. Click **Add**.
4. Copy the key (it starts with `sk-ant-`). It is shown once.
5. Open `F:\temppcfiles\SEP\PROJECTS\flowsentry-desk\.env` in Notepad (create it if missing; it is gitignored) and
   put one line: `ANTHROPIC_API_KEY=` followed by the key. Save.
6. Tell the lane "key is in". The lane then records the Claude runs (`make record-agent`, about 40 cases plus the
   video path, a few dollars of credit) and the agent evaluation, and commits them. If you do it yourself:
   `python scripts/record_agent.py --n 40 --demo-path`, then `python scripts/eval_agent.py`.

Optional: Console > **Limits** > set a monthly spend limit of $20 for this organisation.

## 2. Hugging Face write token (5 minutes, by Fri Oct 23 noon)

The live link is a Hugging Face Space (Docker, free CPU, no card). Your existing account is `sepehrjafari81`; the
token in the Transcendent `.env` is read-only, so it cannot deploy.

1. Open https://huggingface.co/settings/tokens > **Create new token**.
2. Token type: **Write**. Name: `flowsentry-desk-deploy`. Click **Create token** and copy it (starts with `hf_`).

## 3. Connect GitHub to the Space (3 minutes, right after step 2)

1. Open https://github.com/Aeripsen/flowsentry-desk/settings/secrets/actions
2. Tab **Secrets** > **New repository secret**. Name: `HF_TOKEN`. Secret: the token from step 2. **Add secret**.
3. Tab **Variables** > **New repository variable**. Name: `HF_SPACE`. Value: `sepehrjafari81/flowsentry-desk`.
   **Add variable**.
4. Open https://github.com/Aeripsen/flowsentry-desk/actions/workflows/deploy-hf.yml > **Run workflow** > **Run
   workflow**. It creates the Space as **private** and uploads the app. The Space then builds for about 3 minutes.
5. Check https://huggingface.co/spaces/sepehrjafari81/flowsentry-desk shows the desk, then open the direct app URL
   https://sepehrjafari81-flowsentry-desk.hf.space (this is the link to give judges). From then on every green CI run
   on `main` redeploys it.

## 4. Optional: live Claude in the Space (2 minutes)

Without this the Space serves recorded Claude runs and the policy, which is enough for judging. With it, the Run
button calls Claude live, capped at 25 runs per visitor per day and 300 per day in total.

1. https://huggingface.co/spaces/sepehrjafari81/flowsentry-desk/settings > **Variables and secrets**.
2. **New secret**: `ANTHROPIC_API_KEY` = your key. **New variable**: `DESK_LIVE_AGENT` = `1`.

## 5. Optional: Clerk sign-in, for the Best Use of Clerk prize (10 minutes, by Sat Oct 24)

Recommended mode is `optional`: judges can work the desk without an account, and signing in keeps a workspace across
devices.

1. Open https://dashboard.clerk.com and create the account yourself (sign up with Google is fine).
2. **Create application**. Name: `FlowSentry Desk`. Sign-in options: Email and Google. **Create application**.
3. Left menu **API keys**. Copy the **Publishable key** (starts with `pk_test_`). Do not copy the secret key; the app
   does not need it.
4. In the Space settings (step 4 page) add variables: `DESK_AUTH` = `optional`, `CLERK_PUBLISHABLE_KEY` = the
   publishable key, `DESK_ALLOWED_ORIGINS` = `https://sepehrjafari81-flowsentry-desk.hf.space`.
5. Open the direct URL https://sepehrjafari81-flowsentry-desk.hf.space (not the huggingface.co page, where the app
   sits in a frame and sign-in may not work), click **Sign in to keep your workspace**, and sign in to check it.
6. If every request then fails with "sign in first" or "token issued for another origin", the origin check is the
   first suspect: make sure `DESK_ALLOWED_ORIGINS` is exactly the direct URL above, with https and no trailing slash.
   Anonymous use keeps working either way.

## 6. Make things public (2 minutes, Sat Oct 24 evening, after the lane says "ready")

The rules require a public repo and a live link.

1. https://github.com/Aeripsen/flowsentry-desk/settings > bottom, **Danger Zone** > **Change visibility** > **Make
   public**, type the repo name to confirm.
2. https://huggingface.co/spaces/sepehrjafari81/flowsentry-desk/settings > **Change Space visibility** > **Public**.
3. Open both in a private browser window to confirm they load without signing in.

## 6b. Wake the Space before judging (1 minute each, Sun Oct 25 evening and Mon Oct 26 morning)

Free Spaces go to sleep after a while with no visitors, and the first visit then waits for a restart. Open
https://sepehrjafari81-flowsentry-desk.hf.space on Sun Oct 25 after you submit, and again on Mon Oct 26 before 9:00 AM
(online judging day). If it shows "Sleeping", click **Restart this Space** and wait until the queue appears.

## 7. Record the 2-minute video (Sat Oct 24, about 1 hour with retakes)

Follow `docs/VIDEO_SCRIPT.md`. Screen recording with your voice is enough (Windows: Win+G, or OBS). Upload to YouTube as
**Unlisted** (the rules need a link that plays without login), title `FlowSentry Desk, Build North 2026`.

## 8. Devpost (30 minutes, by Sun Oct 25 8:00 PM)

1. Open the Build North Devpost page (from the Luma event or the hackathon Discord, discord.gg/Vm9JB82kun) >
   **Create project** (or **Enter a submission**).
2. Paste the sections of `docs/DEVPOST.md` into the matching fields. "Built with" tags are listed there.
3. Add every teammate by their Devpost username (the rules say all members must be named).
4. Links: GitHub repo, the direct app URL https://sepehrjafari81-flowsentry-desk.hf.space, the YouTube link.
5. Read the preview once, then **Submit**.

## 9. Demo Day, if top 10 (Thu Oct 29, 5:30 to 8:30 PM, 2 St Clair Ave W, 14th floor)

At least one team member must attend. The lane writes the 3-minute pitch on Oct 26.
