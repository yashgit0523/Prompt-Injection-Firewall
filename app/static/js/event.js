"use strict";
(() => {
  const { api, el, badge, fmtTime, scoreBlock, trace, renderAnalysis, renderStages, renderChat, renderDocScan } = PG;
  const root = document.getElementById("inspector");
  const eventId = root.dataset.eventId;

  function summaryCard(e) {
    const row = (label, value) => el("li", {}, el("span", { text: label }), el("span", {}, value));
    return el("div", { class: "card" },
      el("div", { class: "verdict" },
        scoreBlock(e.risk_score, e.severity, "Final threat score"),
        el("div", {},
          el("ul", { class: "sys-list" },
            row("Time", fmtTime(e.created_at)),
            row("Event type", e.event_type + (e.scenario ? ` · ${e.scenario.replace(/_/g, " ")}` : "")),
            row("Source", e.source),
            row("Mode", e.mode),
            row("Policy decision", badge("dec", e.decision)),
            row("Tool firewall", badge("tool", e.tool_decision)),
            row("Output firewall", badge("out", e.output_decision)),
            row("Processing time", `${e.processing_ms} ms`)))),
      el("div", { class: "why" }, el("div", { class: "why-title", text: "Explanation" }), el("div", { text: e.explanation })));
  }

  function stagesCard(stages) {
    const list = el("ol", { class: "stages" });
    renderStages(list, stages, false);
    return el("div", { class: "card" }, el("div", { class: "card-title" }, el("h3", { text: "Pipeline stages" }), trace(stages, true)), list);
  }

  async function load() {
    const e = await api(`/api/events/${encodeURIComponent(eventId)}`);
    root.textContent = "";
    root.append(summaryCard(e));
    const d = e.details;
    if (d.kind === "analysis") {
      root.append(stagesCard(d.analysis.stages));
      renderAnalysis(root, d.analysis, "Input firewall analysis");
    } else if (d.kind === "document") {
      renderDocScan(root, d.document_scan);
      renderAnalysis(root, d.document_scan.analysis, "Document analysis");
    } else if (d.kind === "chat") {
      root.append(stagesCard(d.chat.stages));
      renderChat(root, d.chat);
      if (d.chat.document_scan) {
        renderDocScan(root, d.chat.document_scan);
        renderAnalysis(root, d.chat.document_scan.analysis, "Document analysis (UNTRUSTED_DOCUMENT)");
      }
      renderAnalysis(root, d.chat.input_analysis, "Input firewall analysis (USER_INPUT)");
    }
  }

  load().catch((err) => { root.textContent = ""; root.append(el("div", { class: "alert bad", text: "Could not load event: " + err.message })); });
})();
