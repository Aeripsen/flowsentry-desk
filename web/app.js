/* FlowSentry Desk front end. No framework, no build step. Every string that came from a
   model or the data is escaped before it touches the DOM. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (x, d = 3) => (typeof x === "number" ? (Math.abs(x) >= 1000 ? x.toLocaleString("en-CA", { maximumFractionDigits: 1 }) : String(+x.toPrecision(d))) : esc(x));
  const pct = (x, d = 1) => (x == null ? "n/a" : (100 * x).toFixed(d) + "%");

  const S = { cfg: null, order: "desk", tab: "all", rows: [], total: 0, offset: 0, sel: null, current: null, clerk: null, view: "desk" };
  const OUT = { AUTO_CLOSED: "Closed by the desk", ESCALATED: "Escalated", HUMAN: "Needs you" };
  const TABS = [["all", "All"], ["needs_you", "Needs you"], ["escalated", "Escalated"], ["closed", "Closed"], ["todo", "Not read"], ["done", "Labelled"]];

  // A random workspace id kept in this browser. Sent as a header because the Hugging Face page
  // shows the app in a cross-site iframe, where cookies are not sent.
  const WS = (() => {
    let id = null;
    try { id = localStorage.getItem("desk_ws"); } catch (_) { /* storage blocked */ }
    if (!id || id.length < 20) {
      const b = new Uint8Array(24);
      crypto.getRandomValues(b);
      id = Array.from(b, (x) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[x % 64]).join("");
      try { localStorage.setItem("desk_ws", id); } catch (_) { /* keep it in memory */ }
    }
    return id;
  })();

  async function token() {
    if (S.clerk && S.clerk.isSignedIn && S.clerk.session) return await S.clerk.session.getToken();
    return null;
  }
  async function api(path, opts = {}) {
    const headers = { "Content-Type": "application/json", "X-Desk-Workspace": WS };
    const t = await token();
    if (t) headers.Authorization = "Bearer " + t;
    const r = await fetch(path, { credentials: "same-origin", ...opts, headers });
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).detail || msg; } catch (_) { /* not json */ }
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    return r.json();
  }
  function toast(html, ms = 5200) {
    const t = $("#toast");
    t.innerHTML = html;
    t.hidden = false;
    clearTimeout(toast.h);
    toast.h = setTimeout(() => { t.hidden = true; }, ms);
  }

  /* ---------------------------------------------------------------- sign-in (Clerk, optional) */
  function loadScript(src, attrs = {}) {
    return new Promise((ok, fail) => {
      const s = document.createElement("script");
      s.src = src; s.async = true; s.crossOrigin = "anonymous";
      Object.entries(attrs).forEach(([k, v]) => s.setAttribute(k, v));
      s.onload = ok; s.onerror = () => fail(new Error("could not load " + src));
      document.head.appendChild(s);
    });
  }
  async function setupClerk() {
    const fapi = S.cfg.clerk_frontend_api;
    await loadScript(`https://${fapi}/npm/@clerk/ui@1/dist/ui.browser.js`);
    await loadScript(`https://${fapi}/npm/@clerk/clerk-js@6/dist/clerk.browser.js`, { "data-clerk-publishable-key": S.cfg.clerk_publishable_key });
    await window.Clerk.load({ ui: { ClerkUI: window.__internal_ClerkUICtor } });
    S.clerk = window.Clerk;
    if (!S.clerk.isSignedIn && S.cfg.auth === "optional") {
      $("#who").innerHTML = '<button class="ghost signin-btn" id="signin-open">Sign in to keep your workspace</button>';
      S.clerk.addListener(({ user }) => { if (user) location.reload(); });
      return true;
    }
    if (!S.clerk.isSignedIn) {
      $("#signin").hidden = false;
      S.clerk.mountSignIn($("#clerk-signin"));
      S.clerk.addListener(({ user }) => { if (user) location.reload(); });
      return false;
    }
    $("#who").innerHTML = "";
    S.clerk.mountUserButton($("#who"));
    return true;
  }

  /* ---------------------------------------------------------------- queue */
  function renderTabs(counts) {
    $("#tabs").innerHTML = TABS.map(([k, l]) => `<button role="tab" data-tab="${k}" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}">${l} <span>${counts[k] ?? 0}</span></button>`).join("");
    const c = counts;
    $("#tally").innerHTML = `<span><b>${c.all}</b>in queue</span><span class="closed"><b>${c.closed}</b>closed by the desk</span><span class="esc"><b>${c.escalated}</b>escalated</span><span class="human"><b>${c.needs_you}</b>need you</span><span><b>${c.todo}</b>not read yet</span>`;
  }
  function pillFor(r) {
    if (r.label) return `<span class="pill done">${esc(r.label)}</span>`;
    if (!r.outcome) return `<span class="pill todo">not read</span>`;
    const t = r.outcome === "ESCALATED" ? esc(r.family) : OUT[r.outcome];
    return `<span class="pill ${r.outcome}">${t}</span>`;
  }
  function renderRows(append) {
    const html = S.rows.map((r) => `<li><button data-case="${r.case_id}" class="${S.sel === r.case_id ? "sel" : ""}"><span class="cid">${r.case_id}</span>${pillFor(r)}<span class="fs">FlowSentry: ${esc(r.fs_pred)} at ${fmt(r.fs_conf)}</span></button></li>`).join("");
    $("#rows").innerHTML = html;
    $("#more").hidden = S.rows.length >= S.total;
    if (!append) $("#rows").scrollTop = 0;
  }
  async function loadQueue(append = false) {
    const off = append ? S.rows.length : 0;
    const q = await api(`/api/queue?status=${S.tab}&order=${S.order}&offset=${off}&limit=60`);
    S.rows = append ? S.rows.concat(q.rows) : q.rows;
    S.total = q.total;
    renderTabs(q.counts);
    renderRows(append);
  }

  /* ---------------------------------------------------------------- case */
  function meter(conf) {
    return `<div class="meter"><div class="track"><div class="fill" style="width:${(100 * conf).toFixed(1)}%"></div><div class="bar99" title="0.99 reject bar"></div></div><span>FlowSentry confidence ${fmt(conf)} (bar 0.99)</span></div>`;
  }
  function memoHtml(text, ok) {
    return esc(text).replace(/\[(R\d+)\]/g, (_, id) => `<button class="cite${ok.has(id) ? "" : " bad"}" data-rid="${id}" title="${ok.has(id) ? "Show the tool result this rests on" : "Not issued in this run"}">${id}</button>`);
  }
  function keyFeatures(run) {
    const nc = run && run.steps.find((s) => s.tool === "next_case" && !s.error);
    if (!nc) return "";
    const rows = nc.result.key_features.map((k) => `<tr><td>${esc(k.meaning)}</td><td class="num">${fmt(k.value)}</td><td class="num">${fmt(k.typical_benign)}</td></tr>`).join("");
    return `<table class="keyfeat"><thead><tr><th>Flow statistic</th><th class="num">This flow</th><th class="num">Typical benign</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  function renderCase(data) {
    const c = data.case, run = data.run, lab = data.label;
    S.current = data;
    const cls = S.cfg.classes;
    let body = `<div class="case-head"><h2>${c.case_id}</h2><span class="ref">flow ${esc(c.flow_ref)} in the public BCCC sample</span></div>`;
    body += `<p class="fsline">FlowSentry leaned <b>${esc(c.fs_pred)}</b> but would not call it.</p>${meter(c.fs_conf)}`;
    if (!run) {
      body += `<div class="outcome HUMAN"><h3>Not read yet</h3><p>Run the desk on this case to see its evidence and proposal.</p></div>`;
      body += `<div class="actions"><button class="primary" id="run">Run the desk on ${c.case_id}</button>${S.cfg.live_engine ? `<span class="meta">Live: ${esc(S.cfg.live_engine.model)}</span>` : ""}</div>`;
    } else {
      const fin = run.final || {};
      const ok = new Set(run.steps.filter((s) => s.result_id).map((s) => s.result_id));
      const head = run.outcome === "ESCALATED" ? `Escalated as ${esc(fin.family)}` : OUT[run.outcome];
      body += `<div class="outcome ${run.outcome}"><h3>${head}</h3><p class="why">${esc(run.outcome_reason)}${fin.verdict && run.outcome === "HUMAN" && fin.verdict !== "ask_human" ? ` (agent proposed ${esc(fin.verdict.replace("_", " "))})` : ""}</p></div>`;
      if (fin.memo) body += `<p class="memo">${memoHtml(fin.memo, ok)}</p>`;
      if (run.error) body += `<p class="meta">Run error: ${esc(run.error)}. The case went to a person; nothing was closed.</p>`;
      if (fin.ticket) body += `<div class="ticket"><h4>Ticket draft for on-call</h4>${memoHtml(fin.ticket, ok)}</div>`;
      const eng = run.engine === "policy" ? "deterministic policy (no model)" : `${esc(run.engine)} ${esc(run.model)}`;
      body += `<p class="meta">${run.recorded ? "Recorded run" : "Run"} by ${eng}. ${run.steps.length} steps, ${fmt(run.seconds)} s${run.tokens_in ? `, ${run.tokens_in} tokens in, ${run.tokens_out} out` : ""}. ${run.citations_ok ? "Every cited id was issued in this run" : "The citation check failed"}.</p>`;
      const pre = fin.verdict === "escalate" ? fin.family : "benign";
      const opts = cls.map((k) => `<option value="${k}"${k === pre ? " selected" : ""}>${k}</option>`).join("");
      if (lab) {
        body += `<div class="actions labelled"><span>You labelled this <b>${esc(lab.label)}</b> (${esc(lab.source)}).</span><button class="ghost" id="reopen">Reopen</button></div>`;
      } else {
        const can = run.outcome === "AUTO_CLOSED" || run.outcome === "ESCALATED";
        body += `<div class="actions">${can ? `<button class="primary" id="approve">${run.outcome === "AUTO_CLOSED" ? "Confirm benign" : `Confirm ${esc(fin.family)}`} <kbd>A</kbd></button>` : ""}<label for="lab">Your label</label><select id="lab">${opts}</select><button class="ghost" id="override">Save label <kbd>O</kbd></button><button class="ghost" id="rerun">Run again</button></div>`;
      }
      body += `<div id="changed"></div>`;
      body += keyFeatures(run);
    }
    $("#case").innerHTML = body;
    renderTrail(run);
    $("#case").scrollTop = 0;
  }

  function stepBody(s) {
    const r = s.result;
    if (r.error) return `<p>${esc(r.error)}</p>`;
    if (s.tool === "explain") {
      return `<p>Toward ${esc(r.toward_class)}: base rate ${fmt(r.base_rate)}, probability ${fmt(r.probability)}</p><table>${r.top_features.map((f) => `<tr><td>${esc(f.meaning)}</td><td class="num">${fmt(f.value)}</td><td class="num">${f.contribution > 0 ? "+" : ""}${fmt(f.contribution)}</td></tr>`).join("")}</table>`;
    }
    if (s.tool === "precedents") {
      const cnt = Object.entries(r.of_15_nearest).map(([k, v]) => `${esc(k)} ${v}`).join(", ");
      const mine = (r.your_labelled_cases_nearby || []).map((m) => `<tr><td>${esc(m.case_id)} (yours)</td><td>${esc(m.analyst_label)}</td><td class="num">${fmt(m.distance)}</td></tr>`).join("");
      return `<p>15 nearest training flows: ${cnt}</p><table>${r.nearest.map((n) => `<tr><td>${esc(n.flow_ref)}</td><td>${esc(n.label)}</td><td class="num">${fmt(n.distance)}</td></tr>`).join("")}${mine}</table>`;
    }
    if (s.tool === "next_case") {
      const f = r.flowsentry;
      return `<p>${esc(r.why_in_queue)}.</p><p>Answered by ${esc(f.answered_by)}. Top classes: ${f.top_classes.map((t) => `${esc(t.class)} ${fmt(t.p)}`).join(", ")}.</p>`;
    }
    if (s.tool === "family_card") {
      return `<p>${esc(r.family)}: ${fmt(r.training_flows)} training flows; FlowSentry unsure on ${pct(r.share_flowsentry_unsure_out_of_fold)} of them out of fold.${r.attack_technique ? ` ATT&amp;CK ${esc(r.attack_technique)}.` : ""}</p><p>${esc(r.playbook)}</p>`;
    }
    if (s.tool === "second_opinion") {
      return r.status === "trained" ? `<p>Trained on ${r.analyst_labels_so_far} of your labels: ${r.probabilities.map((p) => `${esc(p.class)} ${fmt(p.p)}`).join(", ")}</p>` : `<p>Not trained yet: ${r.analyst_labels_so_far} labels. It needs ${esc(r.needs)}.</p>`;
    }
    if (s.tool === "propose") {
      return r.accepted ? `<p>Accepted: ${esc(r.verdict)} ${esc(r.family || "")}</p>` : `<p>Refused: ${esc((r.errors || []).join("; "))}</p>`;
    }
    return `<pre>${esc(JSON.stringify(r, null, 1)).slice(0, 1500)}</pre>`;
  }
  function renderTrail(run) {
    if (!run) { $("#trail").innerHTML = `<h3>Evidence trail</h3><p class="hint">Each tool call the desk makes shows up here with the id its memo cites.</p>`; return; }
    const steps = run.steps.map((s) => {
      const args = Object.keys(s.args || {}).length ? Object.entries(s.args).filter(([k]) => k !== "memo").map(([k, v]) => `${esc(k)}=${esc(Array.isArray(v) ? v.join(",") : v)}`).join(" ").slice(0, 80) : "";
      return `<details class="step${s.error ? " err" : ""}" data-rid="${s.result_id || ""}" ${s.tool === "propose" ? "" : ""}><summary><span class="rid">${s.result_id || (s.tool === "propose" ? "end" : "!")}</span><span class="tool">${esc(s.tool)}</span><span class="args">${args}</span></summary><div class="body">${s.note ? `<p class="note">${esc(s.note).slice(0, 400)}</p>` : ""}${stepBody(s)}</div></details>`;
    }).join("");
    $("#trail").innerHTML = `<h3>Evidence trail</h3><p class="hint">Click a citation in the memo to see what it rests on. Ids are issued by the server; a memo cannot cite one it did not receive.</p>${steps}`;
  }
  function light(rid) {
    document.querySelectorAll(".step.lit, .cite.lit").forEach((e) => e.classList.remove("lit"));
    const st = document.querySelector(`.step[data-rid="${rid}"]`);
    document.querySelectorAll(`.cite[data-rid="${rid}"]`).forEach((e) => e.classList.add("lit"));
    if (st) { st.open = true; st.classList.add("lit"); st.scrollIntoView({ block: "nearest", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" }); }
  }
  async function openCase(id) {
    S.sel = id;
    if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
    document.querySelectorAll(".rows button").forEach((b) => b.classList.toggle("sel", b.dataset.case === id));
    renderCase(await api(`/api/case/${id}`));
  }
  async function runCase(engine = "auto") {
    const id = S.current.case.case_id;
    const b = $("#run") || $("#rerun");
    if (b) { b.disabled = true; b.textContent = "Reading the case..."; }
    try {
      await api(`/api/case/${id}/run`, { method: "POST", body: JSON.stringify({ engine }) });
      await openCase(id);
      await loadQueue();
    } catch (e) { toast(esc(e.message)); if (b) b.disabled = false; }
  }
  async function decide(action, label) {
    const id = S.current.case.case_id;
    try {
      const r = await api(`/api/case/${id}/decision`, { method: "POST", body: JSON.stringify({ action, label }) });
      await openCase(id);
      await loadQueue();
      if (r.changed && r.changed.length) {
        $("#changed").innerHTML = `<div class="changed"><b>Your label changed how the desk would handle ${r.changed.length} nearby case${r.changed.length > 1 ? "s" : ""}:</b><ul>${r.changed.map((c) => `<li><a href="#" data-case="${c.case_id}">${c.case_id}</a>: ${esc(c.before.replace("_", " "))} now ${esc(c.after.replace("_", " "))}</li>`).join("")}</ul></div>`;
        toast(`Saved ${esc(r.label || "")}. ${r.changed.length} nearby case${r.changed.length > 1 ? "s" : ""} would now be handled differently.`);
      } else if (action !== "reopen") {
        toast(`Saved ${esc(r.label)}. It now teaches the second opinion and the nearby-attack check.`);
      }
    } catch (e) { toast(esc(e.message)); }
  }

  /* ---------------------------------------------------------------- pages */
  function lineChart(xs, series, w = 720, h = 300) {
    const pad = { l: 46, r: 14, t: 12, b: 34 };
    const maxX = xs[xs.length - 1], maxY = Math.max(...series.flatMap((s) => s.ys));
    const X = (x) => pad.l + (x / maxX) * (w - pad.l - pad.r), Y = (y) => h - pad.b - (y / maxY) * (h - pad.t - pad.b);
    let g = `<line class="axis" x1="${pad.l}" y1="${h - pad.b}" x2="${w - pad.r}" y2="${h - pad.b}"/><line class="axis" x1="${pad.l}" y1="${pad.t}" x2="${pad.l}" y2="${h - pad.b}"/>`;
    for (let i = 0; i <= 4; i++) { const y = (maxY * i) / 4; g += `<text x="${pad.l - 6}" y="${Y(y) + 4}" text-anchor="end">${Math.round(y)}</text>`; }
    for (let i = 0; i <= 4; i++) { const x = (maxX * i) / 4; g += `<text x="${X(x)}" y="${h - 12}" text-anchor="middle">${Math.round(x)}</text>`; }
    series.forEach((s) => { g += `<polyline fill="none" stroke="${s.color}" stroke-width="${s.w || 2.5}" ${s.dash ? `stroke-dasharray="${s.dash}"` : ""} points="${xs.map((x, i) => `${X(x).toFixed(1)},${Y(s.ys[i]).toFixed(1)}`).join(" ")}"/>`; });
    return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(series.map((s) => s.name).join(", "))}">${g}</svg>`;
  }
  async function renderResults() {
    const m = await api("/api/metrics");
    const e = m.eval;
    if (!e) { $("#view-results").innerHTML = "<h2>Results</h2><p>No evaluation report yet. Run <kbd>make eval</kbd>.</p>"; return; }
    const css = getComputedStyle(document.documentElement);
    const def = e.knob.find((k) => k.default);
    const o = e.ordering;
    const knobRows = e.knob.map((k) => `<tr class="${k.default ? "def" : ""}"><td>${k.cap_per_1000_on_training} per 1,000${k.default ? " (default)" : ""}</td><td>${k.certified_on_training ? "yes" : "no"}</td><td>${pct(k.share_of_queue_closed)}</td><td>${k.attacks_wrongly_closed}</td><td>${k.attacks_wrongly_closed_per_1000_closed ?? "n/a"}${k.per_1000_95ci ? ` (${k.per_1000_95ci[0]} to ${k.per_1000_95ci[1]})` : ""}</td><td>${pct(k.share_of_queued_attacks_closed)}</td><td>${k.analyst_decisions_per_100_items}</td></tr>`).join("");
    const learn = e.learning.map((l) => `<tr><td>${l.analyst_labels}</td><td>${pct(l.rare_family_recall_named_mean)} (sd ${pct(l.rare_family_recall_named_sd)})</td><td>${pct(l.rare_flows_not_closed_mean)}</td><td>${fmt(l.attacks_wrongly_closed_mean)}</td></tr>`).join("");
    const cert = e.knob.filter((k) => k.certified_on_training && k.cap_per_1000_on_training < 100);
    const projHead = cert.map((k) => `<th>At ${k.cap_per_1000_on_training} per 1,000</th>`).join("");
    const proj = cert[0] ? cert[0].projection.map((p, i) => `<tr><td>${pct(p.queue_benign_share)}${i === 0 ? " (this sample)" : ""}</td>${cert.map((k) => `<td>${k.projection[i].attacks_per_1000_closed ?? "n/a"}</td>`).join("")}</tr>`).join("") : "";
    const k30 = e.knob.find((k) => k.cap_per_1000_on_training === 30) || def;
    const chart = lineChart(o.curve_items, [
      { name: "desk order", ys: o.curve_desk, color: css.getPropertyValue("--closed").trim() },
      { name: "FlowSentry order", ys: o.curve_flowsentry, color: css.getPropertyValue("--human").trim(), dash: "6 4" },
      { name: "random order", ys: o.curve_items.map((x) => (x * o.queued_attacks) / e.knob[0].queue_items), color: css.getPropertyValue("--muted").trim(), w: 1.5, dash: "2 4" },
    ]);
    const ag = m.agent_eval;
    $("#view-results").innerHTML = `
      <h2>What the desk does to the queue</h2>
      <p class="lede">Measured on FlowSentry's 2,315-flow reject queue from the held-out split, with an oracle analyst who answers with the dataset's label. The evaluation was re-run after each review fix and never tuned to these numbers. Every number below is in <code>reports/eval.json</code>.</p>
      <div class="figs">
        <div class="fig"><div class="n">${pct(def.share_of_queue_closed)}</div><div class="l">of the queue closed at the default setting (${def.cap_per_1000_on_training} per 1,000): ${def.auto_closed} flows, ${def.attacks_wrongly_closed === 0 ? "none of them an attack" : def.attacks_wrongly_closed === 1 ? "one of them an attack" : def.attacks_wrongly_closed + " of them attacks"}</div></div>
        <div class="fig"><div class="n">${pct(def.share_of_queued_attacks_closed)}</div><div class="l">of the ${def.queued_attacks} queued attacks closed at the default; the rest are escalated or sent to you</div></div>
        <div class="fig"><div class="n">${o.desk_order.items_to_find_50pct_of_attacks}</div><div class="l">items worked to find half the attacks in the desk's order, against ${o.flowsentry_order.items_to_find_50pct_of_attacks} in FlowSentry's</div></div>
        <div class="fig"><div class="n">${def.escalated_true_attack} of ${def.escalated}</div><div class="l">escalations are attacks; ${def.escalated_family_correct} name the right family</div></div>
      </div>
      <p class="caveat">${esc(e.caveat.charAt(0).toUpperCase() + e.caveat.slice(1))}</p>
      <h3>The close knob</h3>
      <p>Each setting is a cap on attacks wrongly closed per 1,000 closed. Its threshold is chosen on a calibration pool of the training split, kept apart before anything was trained, by fixed-sequence binomial tests at an approximate 5% level (flows of one connection are correlated). Every setting is reported, including the ones that close nothing. Caps the calibration data cannot support close nothing.</p>
      <div class="panel"><table class="data"><thead><tr><th>Cap</th><th>Supported on training data</th><th>Queue closed</th><th>Attacks closed</th><th>Per 1,000 closed (95% CI)</th><th>Queued attacks closed</th><th>Decisions per 100</th></tr></thead><tbody>${knobRows}</tbody></table></div>
      <h3>Finding the attacks sooner</h3>
      <p>Attacks found against queue items worked. The desk serves the queue least benign-looking first; its lead is at the top of the queue, and FlowSentry's order catches up near 90%.</p>
      <div class="panel">${chart}<div class="legend"><span><i style="background:var(--closed)"></i>desk order</span><span><i style="background:var(--human)"></i>FlowSentry order (lowest P(benign) first)</span><span><i style="background:var(--muted)"></i>random order</span></div></div>
      <h3>Learning from analyst labels</h3>
      <p>Rare-family flows the desk escalates under the right family name, on the flows nobody labelled yet, as labels accumulate (20 random label orders). This effect is small on this sample. What labels do reliably is block closes near a labelled attack.</p>
      <div class="panel"><table class="data"><thead><tr><th>Analyst labels</th><th>Rare family named correctly</th><th>Rare flows not closed</th><th>Attacks wrongly closed</th></tr></thead><tbody>${learn}</tbody></table></div>
      <h3>If the queue were more benign</h3>
      <p>Attacks per 1,000 closed if the queue were more benign. A reweighting of the measured close rates, not a measurement: this sample caps benign traffic.</p>
      <div class="panel"><table class="data"><thead><tr><th>Benign share of queue</th>${projHead}</tr></thead><tbody>${proj}</tbody></table></div>
      ${ag ? `<h3>The model-driven agent</h3><p>${esc(ag.summary || "")}</p>` : `<h3>The model-driven agent</h3><p>Recorded model runs are evaluated separately in <code>reports/agent_eval.json</code> once a model key is configured. A model run can only close a subset of what these rules close.</p>`}
    `;
  }
  async function renderAudit() {
    const a = await api("/api/audit?limit=300");
    const rows = a.rows.map((r) => `<tr><td>${r.seq}</td><td>${esc(r.at.replace("T", " "))}</td><td>${esc(r.action)}</td><td>${esc(r.case_id || "")}</td><td class="detail">${esc(JSON.stringify(r.detail))}</td><td><code>${esc(r.hash.slice(0, 12))}</code></td></tr>`).join("");
    $("#view-audit").innerHTML = `<h2>Audit log</h2>
      <p class="lede">Every agent run, label, reopen and knob change in your workspace. Each row stores the hash of the row before it, so editing any row breaks the chain.</p>
      <p>Chain check over all ${a.chain.rows_checked} rows: ${a.chain.ok ? `<span class="chain-ok">intact</span>` : `<span class="chain-bad">broken at row ${a.chain.broken_at_seq}</span>`}</p>
      <div class="panel"><table class="data audit"><thead><tr><th>#</th><th>When</th><th>Action</th><th>Case</th><th>Detail</th><th>Hash</th></tr></thead><tbody>${rows || `<tr><td colspan="6">Nothing yet. Run the desk or label a case.</td></tr>`}</tbody></table></div>
      <p><button class="ghost" id="reset">Reset my workspace</button></p>`;
  }
  function renderAbout() {
    $("#view-about").innerHTML = `<h2>How the desk works</h2>
      <p class="lede">FlowSentry is a network intrusion detector that is allowed to say "I don't know". On its held-out flows it refuses 2,315 of 6,570 at the 0.99 bar, and 78.8% of those refusals are benign in this sample. The desk works that queue.</p>
      <h3>Six read-only tools</h3>
      <p><b>next_case</b> opens the flow. <b>explain</b> gives the exact path contributions of the FlowSentry forest that answered it. <b>precedents</b> returns the nearest labelled training flows. <b>family_card</b> describes an attack family from training data. <b>second_opinion</b> is a small model trained only on your labels. <b>propose</b> ends the case. No tool writes anything, blocks traffic or reaches the network.</p>
      <h3>Citations the server checks</h3>
      <p>Every tool result gets an id the server issues. The memo must cite them; an id that was not issued in that run fails the check and sends the case to a person.</p>
      <h3>A close needs three yeses</h3>
      <p>The agent proposes; it never decides. A case closes only if the agent proposes a close, the server rules allow it (a calibrated gate trained on training data, a benign majority among precedents, no attack you labelled nearby, no objection from the second opinion), and the citations check out. The agent cannot see the gate. It can add human attention, never remove it.</p>
      <h3>Learning from you</h3>
      <p>Your labels train the second opinion and feed the nearby-attack check, so an override can only make the desk more careful near that flow. Each analyst works a separate copy of the queue.</p>
      <h3>Data</h3>
      <p>Public BCCC-UDP-QUIC-IDS-2025 (CC BY 4.0), the stratified sample FlowSentry ships. No IP address or port is stored or shown. FlowSentry is imported unchanged at commit <code>${esc((S.cfg.flowsentry_commit || "").slice(0, 7))}</code>.</p>`;
  }
  async function show(view) {
    S.view = view;
    document.querySelectorAll(".views button").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
    ["desk", "results", "audit", "about"].forEach((v) => { $(`#view-${v}`).hidden = v !== view; });
    $("#strip").hidden = view !== "desk";
    try {
      if (view === "results") await renderResults();
      if (view === "audit") await renderAudit();
      if (view === "about") renderAbout();
    } catch (e) { toast(esc(e.message)); }
  }

  /* ---------------------------------------------------------------- knob */
  function renderKnob(current) {
    const opts = S.cfg.knob.map((k) => `<option value="${k.cap_per_1000}" ${k.met_on_training ? "" : ""}>${k.cap_per_1000} per 1,000${k.met_on_training ? "" : " (closes nothing)"}${k.cap_per_1000 === S.cfg.default_cap ? ", default" : ""}</option>`).join("");
    $("#cap").innerHTML = opts + `<option value="0">Never close</option>`;
    $("#cap").value = String(current ?? S.cfg.default_cap);
    const k = S.cfg.knob.find((x) => String(x.cap_per_1000) === $("#cap").value);
    $("#knob-note").textContent = k && k.met_on_training ? `closes ${pct(k.training_share_closed)} of a training queue` : "the desk will not close anything";
  }

  /* ---------------------------------------------------------------- wiring */
  document.addEventListener("click", async (ev) => {
    const t = ev.target.closest("button, a");
    if (!t) return;
    if (t.dataset.tab) { S.tab = t.dataset.tab; await loadQueue(); return; }
    if (t.dataset.case) { ev.preventDefault(); if (S.view !== "desk") await show("desk"); await openCase(t.dataset.case); return; }
    if (t.dataset.rid && t.classList.contains("cite")) { light(t.dataset.rid); return; }
    if (t.dataset.view) { await show(t.dataset.view); return; }
    switch (t.id) {
      case "more": await loadQueue(true); break;
      case "signin-open": S.clerk.openSignIn(); break;
      case "run": await runCase("auto"); break;
      case "rerun": await runCase("auto"); break;
      case "approve": await decide("approve"); break;
      case "override": await decide("override", $("#lab").value); break;
      case "reopen": await decide("reopen"); break;
      case "reset":
        if (confirm("Clear your labels, runs and knob setting? The audit log keeps a record of the reset.")) { await api("/api/reset", { method: "POST" }); toast("Workspace reset."); await loadQueue(); await show("audit"); }
        break;
      case "batch": {
        t.disabled = true; t.textContent = "Pre-reading...";
        try { const r = await api("/api/batch", { method: "POST", body: JSON.stringify({ n: 25, order: S.order }) }); toast(`Pre-read ${r.ran} cases.`); await loadQueue(); }
        catch (e) { toast(esc(e.message)); }
        t.disabled = false; t.textContent = "Pre-read the next 25";
        break;
      }
      default:
    }
  });
  $("#order").addEventListener("change", async () => { S.order = $("#order").value; await loadQueue(); });
  $("#cap").addEventListener("change", async () => {
    const v = $("#cap").value;
    const cap = Number(v) === S.cfg.default_cap ? null : Number(v);
    try { await api("/api/knob", { method: "POST", body: JSON.stringify({ cap }) }); renderKnob(cap); toast("Close knob saved. New runs use it."); }
    catch (e) { toast(esc(e.message)); }
  });
  document.addEventListener("keydown", async (ev) => {
    if (S.view !== "desk" || ev.target.closest("select, input, textarea") || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    const k = ev.key.toLowerCase();
    if (k === "j" || k === "k") {
      const i = S.rows.findIndex((r) => r.case_id === S.sel);
      const n = S.rows[Math.max(0, Math.min(S.rows.length - 1, i + (k === "j" ? 1 : -1)))];
      if (n) { await openCase(n.case_id); document.querySelector(`.rows button[data-case="${n.case_id}"]`)?.scrollIntoView({ block: "nearest" }); }
    } else if (k === "r" && S.current) { await runCase("auto"); }
    else if (k === "a" && $("#approve")) { await decide("approve"); }
    else if (k === "o" && $("#lab")) { $("#lab").focus(); }
  });

  async function boot() {
    S.cfg = await api("/api/config");
    if (S.cfg.auth === "clerk" || S.cfg.auth === "optional") {
      try { if (!(await setupClerk())) return; } catch (e) { toast("Sign-in could not load: " + esc(e.message), 12000); return; }
    } else {
      $("#who").textContent = "Demo analyst";
    }
    const me = await api("/api/me");
    renderKnob(me.close_cap);
    await loadQueue();
    const m = /^#(C\d{4})$/i.exec(location.hash);
    if (m) await openCase(m[1].toUpperCase());
  }
  window.addEventListener("hashchange", () => {
    const m = /^#(C\d{4})$/i.exec(location.hash);
    if (m) openCase(m[1].toUpperCase()).catch((e) => toast(esc(e.message)));
  });
  boot().catch((e) => toast("The desk could not start: " + esc(e.message), 12000));
})();
