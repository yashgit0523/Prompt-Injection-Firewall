"use strict";
(() => {
  const { api, el, badge, bars, sparkline, heatmap, gauge, fmtTime, catLabel, SEV_COLOR, DEC_COLOR, SEVERITIES } = PG;
  const REFRESH_MS = 10000;
  let paused = false;
  let lastScore = null;
  let config = null;

  const severityOf = (score) => (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : score >= 20 ? "LOW" : "SAFE");
  const setText = (id, value) => { document.getElementById(id).textContent = value; };

  function setLive(state) {
    const chip = document.getElementById("live-chip");
    const label = { live: "LIVE · 10s", paused: "PAUSED", stale: "STALE · retrying" }[state];
    chip.className = "status-chip" + (state === "live" ? " online" : state === "stale" ? " stale" : "");
    setText("live-text", label);
  }

  function renderSystem() {
    if (!config) return;
    setText("layers-mode", `MODE ${config.mode}`);
    const t = config.thresholds;
    const list = document.getElementById("sys-list");
    list.textContent = "";
    const row = (k, v, cls) => el("li", {}, el("span", { text: k }), el("span", { class: cls || "", text: v }));
    list.append(
      row("Input firewall", config.mode, "on"),
      row("Severity thresholds", `LOW ${t.LOW} · MED ${t.MEDIUM} · HIGH ${t.HIGH} · CRIT ${t.CRITICAL}`),
      row("Max decode depth", String(config.max_decode_depth)),
      row("Output leak action", config.output_leak_action, "on"),
      row("Detection rules", `${config.rule_count} enabled`, "on"),
      row("LLM provider", config.llm_provider.toUpperCase()),
    );
  }

  async function load() {
    const [s, events] = await Promise.all([api("/api/stats"), api("/api/events?limit=500")]);
    if (!config) config = await api("/api/config").catch(() => null);
    renderSystem();

    setText("s-total", s.total_requests);
    setText("s-threats", s.threats_detected);
    setText("s-blocked", s.requests_blocked);
    setText("s-tools", s.tool_calls_blocked);
    setText("s-leaks", s.leakage_attempts);
    setText("s-avg", s.average_risk_score);

    const avg = Math.round(s.average_risk_score);
    if (avg !== lastScore) {
      const holder = document.getElementById("avg-gauge");
      holder.textContent = "";
      holder.append(gauge(avg, severityOf(avg), { label: `${severityOf(avg)} AVG` }));
      lastScore = avg;
    }
    setText("avg-caption", s.total_requests ? `${s.threats_detected} of ${s.total_requests} requests carried threat signals` : "No requests yet - run the Attack Demo Lab.");

    bars(document.getElementById("chart-severity"), SEVERITIES.map((k) => [k, s.by_severity[k] || 0]), (k) => SEV_COLOR[k]);
    bars(document.getElementById("chart-decision"), ["ALLOW", "WARN", "SANITIZE", "BLOCK"].map((k) => [k, s.by_decision[k] || 0]), (k) => DEC_COLOR[k]);
    bars(document.getElementById("chart-category"), Object.entries(s.by_category), () => "var(--cyan)", catLabel);
    sparkline(document.getElementById("chart-spark"), s.recent_scores);
    heatmap(document.getElementById("chart-heatmap"), events);

    const body = document.getElementById("recent-body");
    body.textContent = "";
    if (!s.recent_events.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "empty", text: "No events yet." })));
    for (const e of s.recent_events) {
      body.append(el("tr", { class: "clickable", tabindex: "0", onclick: () => { location.href = `/events/${e.id}`; },
        onkeydown: (ev) => { if (ev.key === "Enter") location.href = `/events/${e.id}`; } },
        el("td", { class: "small", text: fmtTime(e.created_at) }),
        el("td", { class: "small", text: e.scenario ? `demo: ${e.scenario}` : e.source }),
        el("td", { class: "num", style: `color:${SEV_COLOR[e.severity]}`, text: String(e.risk_score) }),
        el("td", {}, badge("sev", e.severity)),
        el("td", { class: "small", text: e.categories.length ? catLabel(e.categories[0]) + (e.categories.length > 1 ? ` +${e.categories.length - 1}` : "") : "-" }),
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
    if (!confirm("Delete all security events from the local SQLite log?")) return;
    await api("/api/events", { method: "DELETE" });
    lastScore = null;
    tick();
  });

  // Auto-refresh only while visible and not paused (no hidden background work).
  setInterval(() => { if (!paused && !document.hidden) tick(); }, REFRESH_MS);
  tick();
})();
