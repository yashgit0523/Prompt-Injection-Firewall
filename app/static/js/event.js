"use strict";
(() => {
  const { api, el, badge, card, fmtTime, renderAnalysis, renderStages, renderChat, renderDocScan } = PG;
  const root = document.getElementById("inspector");
  const eventId = root.dataset.eventId;

  function summaryCard(e) {
    const row = (label, value) => el("tr", {}, el("th", { text: label, style: "width:220px" }), el("td", {}, value));
    return card("Event summary", el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {},
      row("Event ID", el("span", { class: "mono", text: e.id })),
      row("Timestamp", fmtTime(e.created_at)),
      row("Event type", e.event_type + (e.scenario ? ` (demo scenario: ${e.scenario})` : "")),
      row("Source / provenance", e.source),
      row("Mode", e.mode),
      row("Final threat score", el("b", { text: `${e.risk_score} / 100` })),
      row("Severity", badge("sev", e.severity)),
      row("Policy decision", badge("dec", e.decision)),
      row("Tool security result", badge("tool", e.tool_decision)),
      row("Output security result", badge("out", e.output_decision)),
      row("Processing time", `${e.processing_ms} ms`),
      row("Explanation", e.explanation),
    ))));
  }

  function stagesCard(stages) {
    const list = el("ol", { class: "stages" });
    renderStages(list, stages, false);
    return card("Pipeline stages", list);
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
