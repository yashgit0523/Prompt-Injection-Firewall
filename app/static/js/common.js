/* PromptGuard shared UI helpers.
 * SECURITY: every piece of dynamic text is inserted with textContent / text nodes,
 * never innerHTML - logged prompts are attacker-controlled and must not become markup.
 */
"use strict";

const PG = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const CAT_LABEL = {
    DIRECT_INJECTION: "Direct Prompt Injection",
    INSTRUCTION_OVERRIDE: "Instruction Override",
    SYSTEM_PROMPT_EXTRACTION: "System Prompt Extraction",
    ROLE_HIJACKING: "Role Hijacking",
    JAILBREAK: "Jailbreak Attempt",
    DATA_EXFILTRATION: "Data Exfiltration",
    DELIMITER_INJECTION: "Delimiter Injection",
    TOOL_MANIPULATION: "Tool Manipulation",
    ENCODED_INJECTION: "Encoded Injection",
    INDIRECT_INJECTION: "Indirect Prompt Injection",
    UNICODE_SMUGGLING: "Unicode Smuggling",
  };
  const SEVERITIES = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const SEV_COLOR = { SAFE: "var(--good)", LOW: "var(--info)", MEDIUM: "var(--warning)", HIGH: "var(--serious)", CRITICAL: "var(--critical)" };
  const DEC_COLOR = { ALLOW: "var(--good)", WARN: "var(--warning)", SANITIZE: "var(--serious)", BLOCK: "var(--critical)" };
  const DEC_WORD = { ALLOW: "ALLOWED", WARN: "WARNING", SANITIZE: "SANITIZED", BLOCK: "BLOCKED" };
  const STATUS_COLOR = { PASS: "var(--good)", INFO: "var(--info)", FLAG: "var(--warning)", WARN: "var(--warning)", SANITIZE: "var(--serious)", BLOCK: "var(--critical)", ERROR: "var(--critical)", SKIP: "var(--text-muted)", ALLOW: "var(--good)" };
  const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  async function api(path, options = {}) {
    const init = { headers: { "Content-Type": "application/json" }, ...options };
    if (init.body && typeof init.body !== "string") init.body = JSON.stringify(init.body);
    const res = await fetch(path, init);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail ? JSON.stringify(data.detail) : `HTTP ${res.status}`);
    return data;
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key === "style") node.setAttribute("style", value);
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    return node;
  }

  /** Decorative icon from the sprite in base.html (meaning is always carried by text). */
  function icon(name, cls = "icon") {
    const node = svg("svg", { class: cls, "aria-hidden": "true" });
    node.append(svg("use", { href: `#i-${name}` }));
    return node;
  }

  const badge = (kind, value) => el("span", { class: `badge ${kind}-${value}`, text: value });
  const catLabel = (c) => CAT_LABEL[c] || c;
  const fmtTime = (iso) => { try { return new Date(iso).toLocaleString(); } catch { return iso; } };
  const asciiMeter = (score) => { const n = Math.round(score / 5); return "█".repeat(n) + "░".repeat(20 - n); };
  const card = (title, ...children) => el("div", { class: "card" }, title ? el("h3", { text: title }) : null, ...children);

  function setBusy(button, statusEl, busy, text) {
    if (button) button.disabled = busy;
    if (statusEl) {
      statusEl.textContent = "";
      if (busy) statusEl.append(el("span", { class: "spinner" }), " ", text || "Working…");
      else if (text) statusEl.textContent = text;
    }
  }

  // --------------------------------------------------------------- gauge
  /** 270-degree threat gauge with ticks at the severity thresholds. */
  function gauge(score, severity, { size = "lg", label } = {}) {
    const R = 50, C = 2 * Math.PI * R, ARC = 0.75 * C;
    const color = SEV_COLOR[severity] || "var(--cyan)";
    const root = svg("svg", { viewBox: "0 0 120 120", role: "img", "aria-label": `Threat score ${score} of 100, ${severity}` });
    const g = svg("g", { transform: "rotate(135 60 60)" });
    g.append(svg("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: "rgba(255,255,255,0.07)", "stroke-width": 9, "stroke-dasharray": `${ARC} ${C}`, "stroke-linecap": "round" }));
    const arc = svg("circle", {
      class: "gauge-arc", cx: 60, cy: 60, r: R, fill: "none", stroke: color, "stroke-width": 9, "stroke-linecap": "round",
      "stroke-dasharray": `0 ${C}`, style: `filter: drop-shadow(0 0 5px ${color}); transition: stroke-dasharray 900ms cubic-bezier(.2,.8,.2,1)`,
    });
    g.append(arc);
    root.append(g);
    for (const t of [20, 40, 60, 80]) {
      const a = ((135 + (270 * t) / 100) * Math.PI) / 180;
      root.append(svg("line", {
        x1: 60 + Math.cos(a) * 41, y1: 60 + Math.sin(a) * 41, x2: 60 + Math.cos(a) * 36, y2: 60 + Math.sin(a) * 36,
        stroke: "rgba(255,255,255,0.35)", "stroke-width": 1.2,
      }));
    }
    const target = `${(ARC * Math.max(0, Math.min(100, score))) / 100} ${C}`;
    if (reducedMotion() || document.hidden) arc.setAttribute("stroke-dasharray", target);
    else requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dasharray", target)));

    return el("div", { class: `gauge${size === "sm" ? " gauge-sm" : ""}` }, root,
      el("div", { class: "gauge-center" }, el("div", {},
        el("div", { class: "gauge-value", style: `color:${color};text-shadow:0 0 18px ${color}`, text: String(score) }),
        el("span", { class: "gauge-unit", text: "/ 100" }),
        el("div", { class: "gauge-label", text: label || severity }))));
  }

  // ------------------------------------------------------------ verdict
  function verdictCard(a, heading) {
    const whyTitle = { BLOCK: "WHY WAS THIS BLOCKED?", WARN: "WHY THE WARNING?", SANITIZE: "WHY WAS IT SANITIZED?", ALLOW: "WHY WAS THIS ALLOWED?" }[a.decision];
    const decColor = DEC_COLOR[a.decision];
    return el("div", { class: "card" },
      heading ? el("h3", { text: heading }) : null,
      el("div", { class: "verdict" },
        gauge(a.risk_score, a.severity),
        el("div", {},
          el("div", { class: "why-title", text: "FIREWALL VERDICT" }),
          el("div", { class: "verdict-headline", style: `color:${decColor};text-shadow:0 0 14px ${decColor}`, text: DEC_WORD[a.decision] }),
          el("div", { class: "meter" }, el("span", { style: `width:${a.risk_score}%;background:${SEV_COLOR[a.severity]};color:${SEV_COLOR[a.severity]}` })),
          el("div", { class: "meter-ascii", text: asciiMeter(a.risk_score), "aria-hidden": "true" }),
          el("div", { class: "verdict-meta" },
            el("div", {}, "SEVERITY", el("br"), badge("sev", a.severity)),
            el("div", {}, "DECISION", el("br"), badge("dec", a.decision)),
            el("div", {}, "SOURCE", el("br"), el("span", { class: "tag " + (a.source === "USER_INPUT" ? "trusted" : "untrusted"), text: a.source })),
            el("div", {}, "MODE", el("br"), el("span", { class: "tag", text: a.mode })),
            el("div", {}, "LATENCY", el("br"), el("span", { class: "tag", text: `${a.processing_ms} ms` })),
          ),
        ),
      ),
      el("div", { class: "why", style: "margin-top:1.1rem" }, el("div", { class: "why-title", text: whyTitle }), el("div", { text: a.explanation })),
      a.invariant_violations && a.invariant_violations.length
        ? el("p", { class: "small", style: "color:#ff6680" }, "Invariant violations: " + a.invariant_violations.join(", ")) : null,
    );
  }

  function categoriesAndRules(a) {
    const cats = a.categories.length
      ? el("div", {}, a.categories.map((c) => el("span", { class: "tag attack", text: catLabel(c) })))
      : el("div", { class: "empty", text: "No attack categories detected." });
    const rows = a.triggered_rules.map((m) => el("tr", {},
      el("td", { class: "mono nowrap", text: m.rule_id }),
      el("td", {}, el("span", { class: m.dampened ? "dampened" : "", text: m.name }),
        m.dampened ? el("div", { class: "small muted", text: m.dampening_reason }) : null),
      el("td", { class: "mono small", text: m.category }),
      el("td", { class: "num" }, m.dampened ? `${m.weight} → ${m.effective_weight}` : String(m.weight)),
      el("td", { class: "small mono", text: m.origin }),
      el("td", { class: "small mono", text: `"${m.matched_text}"` }),
    ));
    return el("div", { class: "grid grid-1-2" },
      card("Detected attacks", cats),
      card("Triggered rules", rows.length
        ? el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, ["Rule", "Name", "Category", "Weight", "Origin", "Matched"].map((h) => el("th", { text: h })))),
            el("tbody", {}, rows)))
        : el("div", { class: "empty", text: "No rules matched." })),
    );
  }

  function breakdownCard(a) {
    const rows = a.score_breakdown.map((c) => el("tr", {},
      el("td", { text: c.component }),
      el("td", { class: "num" }, el("span", { class: "points" + (c.points < 0 ? " neg" : ""), text: (c.points >= 0 ? "+" : "") + c.points })),
      el("td", { class: "small muted", text: c.reason }),
    ));
    rows.push(el("tr", {}, el("td", {}, el("b", { text: "Threat score" })),
      el("td", { class: "num" }, el("b", { style: `color:${SEV_COLOR[a.severity]}`, text: String(a.risk_score) })),
      el("td", { class: "small muted", text: "capped at 100" })));
    return card("Score breakdown", el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, rows))));
  }

  function layerDetails(a) {
    const enc = a.encoding.findings.map((f) => el("li", {},
      el("span", { class: "mono", text: f.chain.join(" → ") }), " (depth ", String(f.depth), "): ",
      el("span", { class: "mono", text: `"${f.decoded}"` }),
      f.malicious ? el("b", { style: "color:#ff6680", text: "  → injection detected: " + f.rule_matches.map((m) => m.rule_id).join(", ") })
        : el("span", { class: "muted", text: "  → benign after decoding" })));
    const uni = a.unicode.findings.map((f) => el("li", {},
      el("b", { text: f.kind }), ` ×${f.count} (${f.codepoints.join(", ")}) +${f.score} - `, f.reason));
    const heur = a.heuristics.map((h) => el("tr", {},
      el("td", { class: "mono small", text: h.name }),
      el("td", { class: "num" }, el("span", { class: h.score ? "points" : "muted", text: h.score ? `+${h.score}` : "0" })),
      el("td", { class: "small muted", text: h.reason })));
    const ctx = a.context;
    return el("div", { class: "grid grid-2" },
      card("Normalization",
        el("div", { class: "why-title", text: "ORIGINAL INPUT (preserved for forensics)" }), el("div", { class: "box", text: a.original_input }),
        el("div", { class: "why-title", style: "margin-top:.8rem", text: "NORMALIZED INPUT (what the detectors scanned)" }), el("div", { class: "box", text: a.normalized_input }),
        el("ul", { class: "small" }, (a.normalization.steps.length ? a.normalization.steps : ["No normalization needed."]).map((s) => el("li", { text: s })))),
      el("div", { class: "stack" },
        card("Context analysis (discuss vs. perform)",
          el("p", { class: "small", style: "margin-top:0", text: ctx.summary }),
          el("ul", { class: "small" },
            el("li", {}, "Discussion framing: ", el("b", { text: ctx.discussion_framing ? "yes" : "no" }), ctx.framing_cues.length ? ` (${ctx.framing_cues.join(", ")})` : ""),
            el("li", {}, "Analysis wrapper: ", el("b", { text: ctx.analysis_wrapper ? "yes" : "no" })),
            el("li", {}, "Commands to the assistant: ", el("b", { text: ctx.imperative_signals.length ? ctx.imperative_signals.join("; ") : "none" })),
            el("li", {}, "Dampened matches: ", el("b", { text: String(ctx.dampened_matches) })))),
        card("Encoding analysis", enc.length ? el("ul", { class: "small" }, enc) : el("div", { class: "empty", text: "No encoded content found." }),
          el("div", { class: "small muted", text: `Candidates examined: ${a.encoding.candidates_examined}${a.encoding.depth_limit_reached ? " - MAX_DECODE_DEPTH reached" : ""}` })),
        card("Unicode analysis", uni.length ? el("ul", { class: "small" }, uni) : el("div", { class: "empty", text: "No suspicious Unicode." }),
          a.unicode.hidden_text ? el("div", {}, el("div", { class: "why-title", text: "HIDDEN TEXT DECODED FROM TAG CHARACTERS" }), el("div", { class: "box", text: a.unicode.hidden_text })) : null),
      ),
      el("div", { class: "card", style: "grid-column:1/-1" }, el("h3", { text: "Heuristic analysis" }),
        el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, heur)))),
    );
  }

  function renderAnalysis(container, a, heading) {
    container.append(verdictCard(a, heading), categoriesAndRules(a), breakdownCard(a), layerDetails(a));
  }

  // ------------------------------------------------------------- stages
  function stageItem(s) {
    const color = STATUS_COLOR[s.status] || "var(--text-muted)";
    return el("li", { class: "stage" },
      el("span", { class: "stage-dot", style: `color:${color}`, "aria-hidden": "true" }),
      el("div", { class: "stage-name", text: s.stage }),
      el("div", { class: "stage-status" }, el("span", { class: `badge st-${s.status}`, text: s.status })),
      el("div", { class: "stage-summary", text: s.summary }));
  }

  function renderStages(listEl, stages, animate) {
    listEl.textContent = "";
    const doAnimate = animate && !reducedMotion();
    stages.forEach((s, i) => {
      const item = stageItem(s);
      if (doAnimate) {
        item.classList.add("pending");
        setTimeout(() => item.classList.remove("pending"), 110 * i);
      }
      listEl.append(item);
    });
  }

  // --------------------------------------------------------------- chat
  function alertBox(kind, title, ...children) {
    const ic = { bad: "x", good: "check", warn: "alert" }[kind];
    return el("div", { class: `alert ${kind}` }, el("div", { class: "alert-title" }, icon(ic), title), ...children);
  }

  function checkItem(passed, ...children) {
    return el("li", {}, el("span", { class: passed ? "ok" : "fail" }, icon(passed ? "check" : "x", "icon icon-sm"),
      el("span", { class: "sr-only", text: passed ? "passed" : "failed" })), el("span", {}, ...children));
  }

  function toolCard(decisions) {
    if (!decisions.length) return card("Tool firewall", el("div", { class: "empty", text: "The model proposed no tool calls." }));
    return card("Tool firewall", decisions.map((d) => alertBox(d.decision === "BLOCK" ? "bad" : "good",
      d.decision === "BLOCK" ? `TOOL CALL BLOCKED · ${d.tool}` : `TOOL CALL ALLOWED · ${d.tool}`,
      el("div", { class: "small" }, "Reason: ", d.reason),
      el("div", { class: "small muted" }, "Requested by: ", d.origin_source || "unknown", d.origin_block_id ? ` (${d.origin_block_id})` : ""),
      el("div", { class: "box", style: "margin-top:.5rem", text: JSON.stringify(d.arguments, null, 2) }),
      el("ul", { class: "checklist" }, d.checks.map((c) => checkItem(c.passed, el("b", { text: c.check }), " - ", c.detail))),
      d.executed ? el("div", { class: "small" }, "Result: ", el("span", { class: "mono", text: d.result })) : null,
    )));
  }

  function outputCard(check) {
    if (!check) return card("Output firewall", el("div", { class: "empty", text: "Not reached (request blocked before the LLM)." }));
    const cls = { SAFE: "good", REDACTED: "warn", BLOCKED: "bad" }[check.decision];
    const title = { SAFE: "OUTPUT SAFE", REDACTED: "OUTPUT REDACTED", BLOCKED: "OUTPUT BLOCKED" }[check.decision];
    return card("Output firewall", alertBox(cls, title + (check.findings.length ? " · LEAK DETECTED" : ""),
      el("div", { class: "small" }, "Reason: ", check.reason),
      check.findings.length ? el("ul", { class: "checklist" }, check.findings.map((f) => checkItem(false,
        el("b", { text: f.kind }), " - ", f.detail, " ", el("span", { class: "muted mono", text: f.evidence })))) : null));
  }

  function provenanceCard(chat) {
    const rows = chat.provenance.map((b) => el("tr", {},
      el("td", { class: "mono", text: b.block_id }),
      el("td", {}, el("span", { class: "tag " + (b.trusted ? "trusted" : "untrusted"), text: b.source })),
      el("td", { class: "mono small", style: `color:${b.trusted ? "var(--good)" : "var(--serious)"}`, text: b.trusted ? "TRUSTED" : "TAINTED" }),
      el("td", { class: "small", text: b.label + (b.parent_ids.length ? `  ← derived from ${b.parent_ids.join(", ")}` : "") }),
      el("td", { class: "small mono", text: b.preview })));
    return card("Provenance & taint tracking",
      el("p", { class: "small muted", style: "margin-top:0", text: `Per-request fence nonce: ${chat.fence_nonce}. Untrusted blocks are wrapped in <UNTRUSTED_DOCUMENT nonce=…> fences and treated as DATA.` }),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ["Block", "Source", "Trust", "Label / lineage", "Preview"].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows))),
      chat.rendered_prompt_preview ? el("details", {}, el("summary", { text: "Show the fenced prompt sent to the LLM (secrets redacted)" }),
        el("div", { class: "box", text: chat.rendered_prompt_preview })) : null);
  }

  function renderChat(container, chat) {
    const finalCls = { ALLOW: "good", WARN: "warn", SANITIZE: "warn", BLOCK: "bad" }[chat.final_decision];
    container.append(el("div", { class: "card" },
      el("div", { class: "card-title" }, el("h3", { text: "Final result delivered to the user" }), badge("dec", chat.final_decision)),
      alertBox(finalCls, DEC_WORD[chat.final_decision], el("div", { class: "box response-box", style: "background:transparent;border:0;padding:0;margin-top:.3rem", text: chat.response })),
      el("div", { class: "small muted" }, `LLM called: ${chat.llm_called ? "yes (" + chat.llm_provider + ")" : "no"} · total ${chat.processing_ms} ms`,
        chat.event_id ? el("span", {}, " · ", el("a", { href: `/events/${chat.event_id}`, text: `Inspect ${chat.event_id}` })) : null)));
    container.append(el("div", { class: "grid grid-2" }, toolCard(chat.tool_decisions), outputCard(chat.output_check)));
    container.append(provenanceCard(chat));
  }

  // ----------------------------------------------------------- documents
  function renderDocView(target, documentText, segments) {
    target.textContent = "";
    let cursor = 0;
    for (const seg of [...segments].filter((s) => s.suspicious).sort((x, y) => x.start - y.start)) {
      if (seg.start > cursor) target.append(document.createTextNode(documentText.slice(cursor, seg.start)));
      target.append(el("mark", { class: "seg-bad", title: `Risk ${seg.risk_score} · ${seg.categories.join(", ")} · ${seg.rules.join(", ")}`, text: documentText.slice(seg.start, seg.end) }));
      cursor = seg.end;
    }
    target.append(document.createTextNode(documentText.slice(cursor)));
  }

  function untrustedBanner(text) {
    return el("div", { class: "untrusted-banner" }, icon("alert"), el("span", { text }));
  }

  function renderDocScan(container, scan) {
    const flagged = scan.segments.filter((s) => s.suspicious);
    container.append(el("div", { class: "card" },
      untrustedBanner("PROVENANCE: UNTRUSTED_DOCUMENT · instructions found here did NOT come from the user"),
      el("div", { class: "card-title" }, el("h3", { text: "Document verdict" }), badge("dec", scan.decision)),
      el("p", { class: "small", text: scan.explanation }),
      el("h3", { text: `Suspicious sections (${flagged.length})` }),
      flagged.length ? el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ["#", "Segment", "Risk", "Injection category", "Rules"].map((h) => el("th", { text: h })))),
        el("tbody", {}, flagged.map((s) => el("tr", {},
          el("td", { class: "mono", text: String(s.index) }),
          el("td", { class: "small", text: s.text }),
          el("td", { class: "num" }, badge("sev", s.severity), " ", String(s.risk_score)),
          el("td", { class: "small mono", text: s.categories.join(", ") }),
          el("td", { class: "small mono", text: s.rules.join(", ") }))))))
        : el("div", { class: "empty", text: "No suspicious segments." }),
      scan.sanitized_document ? el("details", { open: "open" }, el("summary", { text: `Sanitized document passed to the LLM (re-scored ${scan.sanitized_analysis_score}/100)` }),
        el("div", { class: "box", text: scan.sanitized_document })) : null));
  }

  // -------------------------------------------------------------- charts
  function bars(container, entries, colorFn, labelFn) {
    container.textContent = "";
    const max = Math.max(1, ...entries.map(([, v]) => v));
    if (!entries.length || entries.every(([, v]) => !v)) {
      container.append(el("div", { class: "empty", text: "No data yet - run a few scans or demos." }));
      return;
    }
    for (const [key, value] of entries) {
      const color = colorFn(key);
      container.append(el("div", { class: "bar-row", title: `${labelFn ? labelFn(key) : key}: ${value}` },
        el("span", { class: "bar-label", text: labelFn ? labelFn(key) : key }),
        el("span", { class: "bar-track" }, el("span", { class: "bar-fill", style: `display:block;width:${(value / max) * 100}%;background:${color};color:${color}` })),
        el("span", { class: "bar-value", text: String(value) })));
    }
  }

  /** Area sparkline of recent risk scores with threshold gridlines and a hover tooltip. */
  function sparkline(container, values) {
    container.textContent = "";
    if (!values.length) { container.append(el("div", { class: "empty", text: "No data yet." })); return; }
    const W = 300, H = 120, P = 6;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": `Risk scores of the last ${values.length} requests, latest ${values[values.length - 1]}` });
    const x = (i) => P + (values.length === 1 ? (W - 2 * P) / 2 : (i * (W - 2 * P)) / (values.length - 1));
    const y = (v) => H - P - (v / 100) * (H - 2 * P);
    const defs = svg("defs");
    const grad = svg("linearGradient", { id: "spark-fill", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.append(svg("stop", { offset: "0%", "stop-color": "#22d3ee", "stop-opacity": "0.35" }), svg("stop", { offset: "100%", "stop-color": "#22d3ee", "stop-opacity": "0" }));
    defs.append(grad);
    root.append(defs);
    for (const t of [20, 40, 60, 80]) {
      root.append(svg("line", { x1: 0, x2: W, y1: y(t), y2: y(t), stroke: "rgba(110,200,255,0.10)", "stroke-width": 1, "stroke-dasharray": "3 4", "vector-effect": "non-scaling-stroke" }));
    }
    const pts = values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
    root.append(svg("polygon", { points: `${x(0)},${H - P} ${pts} ${x(values.length - 1)},${H - P}`, fill: "url(#spark-fill)" }));
    root.append(svg("polyline", { points: pts, fill: "none", stroke: "#22d3ee", "stroke-width": 2, "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round", style: "filter: drop-shadow(0 0 4px #22d3ee)" }));
    const dot = svg("circle", { r: 4.5, fill: "#22d3ee", stroke: "#030507", "stroke-width": 2, style: "display:none" });
    root.append(dot);
    const tip = el("div", { class: "spark-tip hidden" });
    root.addEventListener("mousemove", (ev) => {
      const rect = root.getBoundingClientRect();
      const rel = ((ev.clientX - rect.left) / rect.width) * W;
      let best = 0;
      values.forEach((_, i) => { if (Math.abs(x(i) - rel) < Math.abs(x(best) - rel)) best = i; });
      dot.setAttribute("cx", x(best)); dot.setAttribute("cy", y(values[best])); dot.style.display = "";
      tip.textContent = `REQ ${best + 1} · RISK ${values[best]}`;
      tip.style.left = `${(x(best) / W) * rect.width}px`;
      tip.style.top = `${(y(values[best]) / H) * rect.height}px`;
      tip.classList.remove("hidden");
    });
    root.addEventListener("mouseleave", () => { dot.style.display = "none"; tip.classList.add("hidden"); });
    container.append(root, tip, el("div", { class: "small muted", text: "Dashed lines: LOW / MEDIUM / HIGH / CRITICAL thresholds (20 / 40 / 60 / 80)" }));
  }

  /** Category x severity heat map. Sequential single hue; every cell prints its value. */
  function heatmap(container, events) {
    container.textContent = "";
    const counts = {};
    for (const e of events) for (const c of e.categories) {
      counts[c] = counts[c] || {};
      counts[c][e.severity] = (counts[c][e.severity] || 0) + 1;
    }
    const cats = Object.keys(CAT_LABEL).filter((c) => counts[c]);
    if (!cats.length) { container.append(el("div", { class: "empty", text: "No attacks recorded yet." })); return; }
    const max = Math.max(1, ...cats.flatMap((c) => SEVERITIES.map((s) => counts[c][s] || 0)));
    const grid = el("div", { class: "heatmap", role: "table", "aria-label": "Attack category by severity",
      style: `grid-template-columns: minmax(150px, 1.4fr) repeat(${SEVERITIES.length}, minmax(60px, 1fr))` });
    grid.append(el("div", { class: "hm-head", role: "columnheader", text: "CATEGORY" }), ...SEVERITIES.map((s) => el("div", { class: "hm-head", role: "columnheader", text: s })));
    for (const c of cats) {
      grid.append(el("div", { class: "hm-row-label", role: "rowheader", title: catLabel(c), text: catLabel(c) }));
      for (const s of SEVERITIES) {
        const v = counts[c][s] || 0;
        const alpha = v ? (0.12 + 0.68 * (v / max)).toFixed(2) : "0.03";
        grid.append(el("div", { class: "hm-cell" + (v ? "" : " zero"), role: "cell", style: `--a:${alpha}`, title: `${catLabel(c)} · ${s}: ${v}`, text: String(v) }));
      }
    }
    container.append(el("div", { class: "table-wrap" }, grid));
  }

  // ------------------------------------------------------- status strip
  async function refreshStatus() {
    const chip = document.getElementById("sys-status");
    if (!chip) return;
    const text = document.getElementById("sys-status-text");
    try {
      const h = await api("/api/health");
      chip.className = "status-chip online";
      text.textContent = "FIREWALL ONLINE";
      document.getElementById("sys-mode").textContent = h.mode;
      document.getElementById("sys-rules").textContent = h.rules_enabled;
      document.getElementById("sys-llm").textContent = h.llm_provider.toUpperCase();
    } catch {
      chip.className = "status-chip offline";
      text.textContent = "FIREWALL OFFLINE";
    }
  }
  refreshStatus();
  setInterval(() => { if (!document.hidden) refreshStatus(); }, 20000);

  return {
    api, el, icon, badge, card, catLabel, fmtTime, setBusy, gauge, reducedMotion, SEV_COLOR, DEC_COLOR, SEVERITIES,
    renderAnalysis, renderStages, renderChat, renderDocScan, renderDocView, untrustedBanner, bars, sparkline, heatmap, verdictCard,
  };
})();
