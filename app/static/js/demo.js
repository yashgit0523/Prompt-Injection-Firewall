"use strict";
(() => {
  const { api, el, setBusy, gauge, renderStages, renderChat, renderAnalysis, renderDocScan, reducedMotion, DEC_COLOR } = PG;
  const grid = document.getElementById("demo-grid");
  const panel = document.getElementById("demo-panel");
  const resultEl = document.getElementById("demo-result");
  const statusEl = document.getElementById("demo-status");
  const gaugeEl = document.getElementById("demo-gauge");
  const finalEl = document.getElementById("demo-final");
  const WORD = { ALLOW: "ALLOWED", WARN: "WARNING", SANITIZE: "SANITIZED", BLOCK: "BLOCKED" };
  let running = false;

  async function runScenario(scenario, cardEl) {
    if (running) return;
    running = true;
    document.querySelectorAll(".demo-card").forEach((c) => { c.classList.remove("active"); c.setAttribute("aria-pressed", "false"); });
    cardEl.classList.add("active");
    cardEl.setAttribute("aria-pressed", "true");
    panel.classList.remove("hidden");

    document.getElementById("demo-title").textContent = `${String(scenario.number).padStart(2, "0")} · ${scenario.title}`;
    document.getElementById("demo-category").textContent = scenario.category;
    document.getElementById("demo-description").textContent = scenario.description;
    document.getElementById("demo-prompt").textContent = scenario.display_prompt;
    document.getElementById("demo-expected").textContent = scenario.expected;
    document.getElementById("demo-talking").textContent = scenario.talking_point + (scenario.mode ? ` (Input firewall mode for this scenario: ${scenario.mode}.)` : "");
    const docWrap = document.getElementById("demo-doc-wrap");
    docWrap.classList.toggle("hidden", !scenario.document);
    document.getElementById("demo-doc").textContent = scenario.document || "";

    const stagesEl = document.getElementById("demo-stages");
    stagesEl.textContent = "";
    resultEl.textContent = "";
    gaugeEl.textContent = "";
    gaugeEl.append(el("span", { class: "spinner" }));
    finalEl.textContent = "";
    setBusy(null, statusEl, true, "Running through the firewall…");
    panel.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" });
    try {
      const res = await api(`/api/demo/${scenario.id}`, { method: "POST" });
      const chat = res.result;
      // Show the most severe analysed source (the user prompt, or the untrusted document).
      const analyses = [chat.input_analysis, chat.document_scan && chat.document_scan.analysis].filter(Boolean);
      const worst = analyses.reduce((a, b) => (b.risk_score > a.risk_score ? b : a));
      gaugeEl.textContent = "";
      gaugeEl.append(gauge(worst.risk_score, worst.severity, { label: worst.source === "USER_INPUT" ? worst.severity : `${worst.severity} · DOC` }));
      renderStages(stagesEl, chat.stages, true);
      const delay = reducedMotion() ? 0 : 110 * chat.stages.length;
      setTimeout(() => {
        finalEl.textContent = WORD[chat.final_decision];
        finalEl.style.color = DEC_COLOR[chat.final_decision];
        finalEl.style.textShadow = `0 0 16px ${DEC_COLOR[chat.final_decision]}`;
        renderChat(resultEl, chat);
        if (chat.document_scan) renderDocScan(resultEl, chat.document_scan);
        renderAnalysis(resultEl, chat.input_analysis, "Input firewall (user prompt)");
      }, delay);
      setBusy(null, statusEl, false, `Final decision: ${chat.final_decision} · event ${res.event_id}`);
    } catch (err) {
      gaugeEl.textContent = "";
      resultEl.append(el("div", { class: "alert bad" }, el("div", { class: "alert-title", text: "ERROR" }), err.message));
      setBusy(null, statusEl, false, "");
    } finally {
      running = false;
    }
  }

  api("/api/demo").then((scenarios) => {
    for (const s of scenarios) {
      const cardEl = el("button", { class: "demo-card", type: "button", "aria-pressed": "false", "data-benign": String(s.category === "BENIGN") },
        el("div", { class: "num", text: `#${String(s.number).padStart(2, "0")}` }),
        el("div", { class: "title", text: s.title }),
        el("div", { class: "cat", text: s.category }));
      cardEl.addEventListener("click", () => runScenario(s, cardEl));
      grid.append(cardEl);
    }
  }).catch((err) => grid.append(el("div", { class: "alert bad", text: "Failed to load scenarios: " + err.message })));
})();
