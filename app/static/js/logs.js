"use strict";
(() => {
  const { api, el, badge, trace, fmtTime, catLabel } = PG;
  const body = document.getElementById("events-body");
  const filters = ["f-severity", "f-category", "f-decision"].map((id) => document.getElementById(id));

  async function load() {
    const params = new URLSearchParams({ limit: "200" });
    const [severity, category, decision] = filters.map((f) => f.value);
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    if (decision) params.set("decision", decision);
    const events = await api(`/api/events?${params}`);
    document.getElementById("count").textContent = `${events.length} ${events.length === 1 ? "event" : "events"}`;
    body.textContent = "";
    if (!events.length) {
      body.append(el("tr", {}, el("td", { colspan: 10, class: "empty", text: "No matching events" })));
      return;
    }
    for (const e of events) {
      const open = () => { location.href = `/events/${e.id}`; };
      body.append(el("tr", { class: "clickable", tabindex: "0", title: e.input_preview, onclick: open,
        onkeydown: (ev) => { if (ev.key === "Enter") open(); } },
        el("td", { class: "small muted nowrap", text: fmtTime(e.created_at) }),
        el("td", { class: "mono small nowrap" }, el("a", { href: `/events/${e.id}`, text: e.id })),
        el("td", { class: "small", text: e.scenario ? `Demo · ${e.scenario.replace(/_/g, " ")}` : e.source }),
        el("td", {}, trace(e.trace)),
        el("td", { class: "num", text: String(e.risk_score) }),
        el("td", {}, badge("sev", e.severity)),
        el("td", { class: "small", text: e.categories.length ? e.categories.map(catLabel).join(", ") : "None" }),
        el("td", {}, badge("dec", e.decision)),
        el("td", {}, badge("tool", e.tool_decision)),
        el("td", {}, badge("out", e.output_decision))));
    }
  }

  filters.forEach((f) => f.addEventListener("change", load));
  document.getElementById("refresh-btn").addEventListener("click", load);
  load().catch((err) => body.append(el("tr", {}, el("td", { colspan: 10, text: "Could not load events: " + err.message }))));
})();
