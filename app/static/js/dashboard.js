"use strict";
(() => {
  const { api, el, badge, rank, shareBar, riskChart, heatmap, trace, fmtTime, catLabel, SEV_COLOR, DEC_COLOR, SEVERITIES } = PG;
  const REFRESH_MS = 10000;
  let paused = false;
  let config = null;

  const setText = (id, value) => { document.getElementById(id).textContent = value; };

  function setLive(state) {
    const chip = document.getElementById("live-chip");
    chip.className = "status-chip" + (state === "live" ? " online" : state === "stale" ? " stale" : "");
    setText("live-text", { live: "Refreshing every 10 s", paused: "Paused", stale: "Connection lost, retrying" }[state]);
  }

  function renderConfig() {
    if (!config) return;
    const t = config.thresholds;
    const list = document.getElementById("sys-list");
    list.textContent = "";
    const row = (k, v) => el("li", {}, el("span", { text: k }), el("span", { text: v }));
    list.append(
      row("Mode", config.mode),
      row("Severity thresholds", `${t.LOW} · ${t.MEDIUM} · ${t.HIGH} · ${t.CRITICAL}`),
      row("Max decode depth", String(config.max_decode_depth)),
      row("Output leak action", config.output_leak_action),
      row("Detection rules", String(config.rule_count)),
      row("Model", config.llm_provider),
    );
  }

  async function load() {
    const [s, events] = await Promise.all([api("/api/stats"), api("/api/events?limit=500")]);
    if (!config) config = await api("/api/config").catch(() => null);
    renderConfig();

    setText("s-total", s.total_requests.toLocaleString());
    setText("s-threats", s.threats_detected.toLocaleString());
    setText("s-threats-hint", s.total_requests ? `${Math.round((s.threats_detected / s.total_requests) * 100)}% of all requests` : "risk 20 or above, or a capability block");
    setText("s-blocked", s.requests_blocked.toLocaleString());
    setText("s-tools", s.tool_calls_blocked.toLocaleString());
    setText("s-leaks", s.leakage_attempts.toLocaleString());
    setText("s-avg", Number(s.average_risk_score).toFixed(1));

    riskChart(document.getElementById("chart-risk"), s.recent_scores);
    setText("chart-sub", `last ${s.recent_scores.length} requests, thresholds as bands`);
    rank(document.getElementById("chart-category"), Object.entries(s.by_category), catLabel);
    shareBar(document.getElementById("bar-decision"), document.getElementById("legend-decision"),
      ["ALLOW", "WARN", "SANITIZE", "BLOCK"].map((k) => [k, s.by_decision[k] || 0]), (k) => DEC_COLOR[k], "dec");
    shareBar(document.getElementById("bar-severity"), document.getElementById("legend-severity"),
      SEVERITIES.map((k) => [k, s.by_severity[k] || 0]), (k) => SEV_COLOR[k], "sev");
    heatmap(document.getElementById("chart-heatmap"), events);

    const body = document.getElementById("recent-body");
    body.textContent = "";
    if (!s.recent_events.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "empty", text: "No events yet" })));
    for (const e of s.recent_events) {
      const open = () => { location.href = `/events/${e.id}`; };
      body.append(el("tr", { class: "clickable", tabindex: "0", onclick: open, onkeydown: (ev) => { if (ev.key === "Enter") open(); } },
        el("td", { class: "small muted nowrap", text: new Date(e.created_at).toLocaleTimeString() }),
        el("td", { class: "small", text: e.scenario ? `Demo · ${e.scenario.replace(/_/g, " ")}` : e.source }),
        el("td", {}, trace(e.trace)),
        el("td", { class: "num", text: String(e.risk_score) }),
        el("td", {}, badge("sev", e.severity)),
        el("td", {}, badge("dec", e.decision))));
    }
    setText("updated-at", `Updated ${new Date().toLocaleTimeString()}`);
  }

  async function tick() {
    try {
      await load();
      setLive(paused ? "paused" : "live");
    } catch {
      setLive("stale");
    }
  }

  const pauseBtn = document.getElementById("pause-btn");
  pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.setAttribute("aria-pressed", String(paused));
    pauseBtn.querySelector("use").setAttribute("href", paused ? "#i-play" : "#i-pause");
    pauseBtn.querySelector("span").textContent = paused ? "Resume" : "Pause";
    setLive(paused ? "paused" : "live");
  });
  document.getElementById("refresh-btn").addEventListener("click", tick);
  document.getElementById("clear-btn").addEventListener("click", async () => {
    if (!confirm("Delete every event from the local SQLite log? This cannot be undone.")) return;
    await api("/api/events", { method: "DELETE" });
    tick();
  });

  // Refresh only while the tab is visible and not paused.
  setInterval(() => { if (!paused && !document.hidden) tick(); }, REFRESH_MS);
  tick();
})();
