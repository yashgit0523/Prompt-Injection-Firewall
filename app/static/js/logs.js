"use strict";
(() => {
  const { api, el, badge, fmtTime, catLabel } = PG;
  const body = document.getElementById("events-body");
  const filters = ["f-severity", "f-category", "f-decision"].map((id) => document.getElementById(id));

  async function load() {
    const params = new URLSearchParams({ limit: "200" });
    const [severity, category, decision] = filters.map((f) => f.value);
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    if (decision) params.set("decision", decision);
    const events = await api(`/api/events?${params}`);
    document.getElementById("count").textContent = `${events.length} event(s)`;
    body.textContent = "";
    if (!events.length) {
      body.append(el("tr", {}, el("td", { colspan: 9, class: "empty", text: "No matching events." })));
      return;
    }
    for (const e of events) {
      body.append(el("tr", { class: "clickable", tabindex: "0", title: e.input_preview,
        onclick: () => { location.href = `/events/${e.id}`; },
        onkeydown: (ev) => { if (ev.key === "Enter") location.href = `/events/${e.id}`; } },
        el("td", { class: "small", text: fmtTime(e.created_at) }),
        el("td", { class: "mono small" }, el("a", { href: `/events/${e.id}`, text: e.id })),
        el("td", { class: "small", text: e.source + (e.scenario ? ` (demo: ${e.scenario})` : "") }),
        el("td", { class: "num", style: `color:${PG.SEV_COLOR[e.severity]}`, text: String(e.risk_score) }),
        el("td", {}, badge("sev", e.severity)),
        el("td", { class: "small", text: e.categories.length ? e.categories.map(catLabel).join(", ") : "-" }),
        el("td", {}, badge("dec", e.decision)),
        el("td", {}, badge("tool", e.tool_decision)),
        el("td", {}, badge("out", e.output_decision))));
    }
  }

  filters.forEach((f) => f.addEventListener("change", load));
  document.getElementById("refresh-btn").addEventListener("click", load);
  load().catch((err) => body.append(el("tr", {}, el("td", { colspan: 9, text: "Error: " + err.message }))));
})();
