"use strict";
(() => {
  const { api, el, setBusy, scoreBlock, trace, renderStages, renderChat, renderAnalysis, renderDocScan, reducedMotion, DEC_WORD, cap } = PG;
  const grid = document.getElementById("demo-grid");
  const panel = document.getElementById("demo-panel");
  const resultEl = document.getElementById("demo-result");
  const statusEl = document.getElementById("demo-status");
  const scoreEl = document.getElementById("demo-score");
  const finalEl = document.getElementById("demo-final");
  const traceEl = document.getElementById("demo-trace");
  let running = false;

  async function runScenario(scenario, cardEl) {
    if (running) return;
    running = true;
    document.querySelectorAll(".demo-card").forEach((c) => { c.classList.remove("active"); c.setAttribute("aria-pressed", "false"); });
    cardEl.classList.add("active");
    cardEl.setAttribute("aria-pressed", "true");
    panel.classList.remove("hidden");

    document.getElementById("demo-title").textContent = `${scenario.number}. ${scenario.title}`;
    document.getElementById("demo-category").textContent = scenario.category;
    document.getElementById("demo-description").textContent = scenario.description;
    document.getElementById("demo-prompt").textContent = scenario.display_prompt;
    document.getElementById("demo-expected").textContent = scenario.expected;
    document.getElementById("demo-talking").textContent = scenario.talking_point + (scenario.mode ? ` The input firewall runs in ${scenario.mode} mode for this scenario.` : "");
    document.getElementById("demo-doc-wrap").classList.toggle("hidden", !scenario.document);
    document.getElementById("demo-doc").textContent = scenario.document || "";

    const stagesEl = document.getElementById("demo-stages");
    stagesEl.textContent = "";
    resultEl.textContent = "";
    scoreEl.textContent = "";
    scoreEl.append(el("span", { class: "spinner" }));
    finalEl.textContent = "";
    traceEl.textContent = "";
    setBusy(null, statusEl, true, "Running");
    panel.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" });
    try {
      const res = await api(`/api/demo/${scenario.id}`, { method: "POST" });
      const chat = res.result;
      // Show the most severe analysed source, the user prompt or the untrusted document.
      const analyses = [chat.input_analysis, chat.document_scan && chat.document_scan.analysis].filter(Boolean);
      const worst = analyses.reduce((a, b) => (b.risk_score > a.risk_score ? b : a));
      scoreEl.textContent = "";
      scoreEl.append(scoreBlock(worst.risk_score, worst.severity, worst.source === "USER_INPUT" ? "Threat score, user prompt" : "Threat score, document"));
      renderStages(stagesEl, chat.stages, true);
      const delay = reducedMotion() || document.hidden ? 0 : 60 * chat.stages.length;
      setTimeout(() => {
        finalEl.textContent = DEC_WORD[chat.final_decision];
        traceEl.append(trace(chat.stages, true));
        renderChat(resultEl, chat);
        if (chat.document_scan) renderDocScan(resultEl, chat.document_scan);
        renderAnalysis(resultEl, chat.input_analysis, "Input firewall, user prompt");
      }, delay);
      setBusy(null, statusEl, false, `${cap(chat.final_decision)} · ${res.event_id}`);
    } catch (err) {
      scoreEl.textContent = "";
      resultEl.append(el("div", { class: "alert bad" }, el("div", { class: "alert-title", text: "The scenario failed to run" }), err.message));
      setBusy(null, statusEl, false, "");
    } finally {
      running = false;
    }
  }

  api("/api/demo").then((scenarios) => {
    for (const s of scenarios) {
      const benign = s.category === "BENIGN";
      const cardEl = el("button", { class: "demo-card", type: "button", "aria-pressed": "false", "data-benign": String(benign) },
        el("div", { class: "num", text: String(s.number).padStart(2, "0") }),
        el("div", { class: "title", text: s.title }),
        el("div", { class: "cat", text: benign ? "Benign control" : PG.catLabel(s.category) }));
      cardEl.addEventListener("click", () => runScenario(s, cardEl));
      grid.append(cardEl);
    }
  }).catch((err) => grid.append(el("div", { class: "alert bad", text: "Could not load scenarios: " + err.message })));
})();
