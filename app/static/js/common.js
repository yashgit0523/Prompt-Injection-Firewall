/* PromptGuard shared UI helpers.
 * SECURITY: every piece of dynamic text is inserted with textContent / text nodes,
 * never innerHTML - logged prompts are attacker-controlled and must not become markup.
 */
"use strict";

const PG = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const CAT_LABEL = {
    DIRECT_INJECTION: "Direct prompt injection",
    INSTRUCTION_OVERRIDE: "Instruction override",
    SYSTEM_PROMPT_EXTRACTION: "System prompt extraction",
    ROLE_HIJACKING: "Role hijacking",
    JAILBREAK: "Jailbreak attempt",
    DATA_EXFILTRATION: "Data exfiltration",
    DELIMITER_INJECTION: "Delimiter injection",
    TOOL_MANIPULATION: "Tool manipulation",
    ENCODED_INJECTION: "Encoded injection",
    INDIRECT_INJECTION: "Indirect prompt injection",
    UNICODE_SMUGGLING: "Unicode smuggling",
  };
  const SEVERITIES = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const SEV_COLOR = { SAFE: "var(--good)", LOW: "var(--info)", MEDIUM: "var(--warning)", HIGH: "var(--serious)", CRITICAL: "var(--critical)" };
  const DEC_COLOR = { ALLOW: "var(--good)", WARN: "var(--warning)", SANITIZE: "var(--serious)", BLOCK: "var(--critical)" };
  const DEC_WORD = { ALLOW: "Allowed", WARN: "Allowed with a warning", SANITIZE: "Sanitized", BLOCK: "Blocked" };
  const STATUS_COLOR = { PASS: "#3a3a3e", INFO: "#56565c", FLAG: "var(--warning)", WARN: "var(--warning)", SANITIZE: "var(--serious)", BLOCK: "var(--critical)", ERROR: "var(--critical)", SKIP: "transparent", ALLOW: "#3a3a3e" };
  const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  /** "CRITICAL" -> "Critical", "NOT_RUN" -> "Not run" (display only; classes keep the raw value). */
  const cap = (v) => { const s = String(v).replace(/_/g, " ").toLowerCase(); return s.charAt(0).toUpperCase() + s.slice(1); };
  /** "Input Gateway" -> "Input gateway", keeping acronyms like LLM. */
  const sentence = (v) => String(v).split(" ").map((w, i) => (i === 0 || /^[A-Z0-9]{2,}$/.test(w) ? w : w.toLowerCase())).join(" ");

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

  const badge = (kind, value) => el("span", { class: `badge ${kind}-${value}`, text: cap(value) });
  const catLabel = (c) => CAT_LABEL[c] || cap(c);
  const fmtTime = (iso) => { try { return new Date(iso).toLocaleString(); } catch { return iso; } };
  const card = (title, ...children) => el("div", { class: "card" }, title ? el("h3", { text: title }) : null, ...children);

  function setBusy(button, statusEl, busy, text) {
    if (button) button.disabled = busy;
    if (statusEl) {
      statusEl.textContent = "";
      if (busy) statusEl.append(el("span", { class: "spinner" }), " ", text || "Working");
      else if (text) statusEl.textContent = text;
    }
  }

  // ------------------------------------------------- signature: pipeline trace
  /** One small tick per firewall stage. Quiet when a stage passed, colored when it acted. */
  function trace(stages, large = false) {
    const list = (stages || []).filter(Boolean);
    const acted = list.filter((s) => !["PASS", "INFO", "ALLOW", "SKIP"].includes(s.status));
    const label = acted.length
      ? `${list.length} stages, ${acted.map((s) => `${sentence(s.stage)}: ${s.status.toLowerCase()}`).join(", ")}`
      : `${list.length} stages, all passed`;
    return el("span", { class: "trace" + (large ? " trace-lg" : ""), role: "img", "aria-label": label, title: label },
      list.map((s) => el("i", { class: s.status })));
  }

  // ---------------------------------------------------------- score
  function scoreBlock(score, severity, label = "Threat score") {
    return el("div", { class: "score-block" },
      el("div", { class: "score-label", text: label }),
      el("div", { class: "score" }, String(score), el("small", { text: " / 100" })),
      el("div", { style: "margin-top:8px" }, badge("sev", severity)));
  }

  function verdictCard(a, heading) {
    const whyTitle = { BLOCK: "Why was this blocked?", WARN: "Why the warning?", SANITIZE: "Why was it sanitized?", ALLOW: "Why was this allowed?" }[a.decision];
    return el("div", { class: "card" },
      heading ? el("div", { class: "card-title" }, el("h3", { text: heading }), trace(a.stages)) : null,
      el("div", { class: "verdict" },
        scoreBlock(a.risk_score, a.severity),
        el("div", {},
          el("div", { class: "verdict-headline", text: DEC_WORD[a.decision] }),
          el("div", { class: "meter", role: "img", "aria-label": `Risk ${a.risk_score} of 100` },
            el("span", { style: `width:${a.risk_score}%;background:${SEV_COLOR[a.severity]}` })),
          el("div", { class: "meter-scale", "aria-hidden": "true" }, ["0", "20", "40", "60", "80", "100"].map((t) => el("span", { text: t }))),
          el("div", { class: "verdict-meta" },
            el("div", {}, "Decision", badge("dec", a.decision)),
            el("div", {}, "Source", el("span", { class: "tag " + (a.source === "USER_INPUT" ? "trusted" : "untrusted"), text: a.source })),
            el("div", {}, "Mode", el("span", { class: "tag", text: a.mode })),
            el("div", {}, "Time", el("span", { class: "tag", text: `${a.processing_ms} ms` })),
          ),
        ),
      ),
      el("div", { class: "why" }, el("div", { class: "why-title", text: whyTitle }), el("div", { text: a.explanation })),
      a.invariant_violations && a.invariant_violations.length
        ? el("p", { class: "small", style: "margin-top:8px;color:var(--critical)" }, "Invariant violations: " + a.invariant_violations.join(", ")) : null,
    );
  }

  function categoriesAndRules(a) {
    const cats = a.categories.length
      ? el("div", {}, a.categories.map((c) => el("span", { class: "tag attack", text: catLabel(c) })))
      : el("div", { class: "empty", text: "No attack categories detected" });
    const rows = a.triggered_rules.map((m) => el("tr", {},
      el("td", { class: "mono nowrap", text: m.rule_id }),
      el("td", {}, el("span", { class: m.dampened ? "dampened" : "", text: m.name }),
        m.dampened ? el("div", { class: "small muted", text: m.dampening_reason }) : null),
      el("td", { class: "num" }, m.dampened ? `${m.weight} → ${m.effective_weight}` : String(m.weight)),
      el("td", { class: "small mono muted", text: m.origin }),
      el("td", { class: "small mono", text: `"${m.matched_text}"` }),
    ));
    return el("div", { class: "grid grid-1-2" },
      card("Detected attacks", cats),
      card("Triggered rules", rows.length
        ? el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, ["Rule", "Name", "Weight", "Origin", "Matched text"].map((h, i) => el("th", { class: i === 2 ? "num" : "", text: h })))),
            el("tbody", {}, rows)))
        : el("div", { class: "empty", text: "No rules matched" })),
    );
  }

  /** Moment: the score ledger. Each component's points visibly add up to the final score. */
  function breakdownCard(a) {
    const rows = [];
    let cursor = 0;
    for (const c of a.score_breakdown) {
      const start = Math.max(0, Math.min(100, c.points >= 0 ? cursor : cursor + c.points));
      const width = Math.min(Math.abs(c.points), 100 - start);
      cursor = Math.max(0, cursor + c.points);
      rows.push(el("div", { class: "ledger-row" },
        el("div", {}, el("div", { class: "ledger-name", text: sentence(c.component) }), el("div", { class: "ledger-reason", text: c.reason })),
        el("div", { class: "ledger-track", "aria-hidden": "true" },
          el("span", { class: c.points < 0 ? "neg" : "", style: `left:${start}%;width:${Math.max(width, 0.5)}%` })),
        el("div", { class: "ledger-pts", text: (c.points >= 0 ? "+" : "") + c.points })));
    }
    rows.push(el("div", { class: "ledger-row ledger-total" },
      el("div", {}, el("div", { class: "ledger-name", text: "Threat score" }), el("div", { class: "ledger-reason", text: "sum of the lines above, capped at 100" })),
      el("div", { class: "ledger-track", "aria-hidden": "true" },
        el("span", { style: `left:0;width:${a.risk_score}%;background:${SEV_COLOR[a.severity]}` })),
      el("div", { class: "ledger-pts", text: String(a.risk_score) })));
    return el("div", { class: "card" },
      el("div", { class: "card-title" }, el("h3", { text: "Score breakdown" }), el("span", { class: "card-sub", text: "how the points add up" })),
      a.score_breakdown.length ? el("div", { class: "ledger" }, rows) : el("div", { class: "empty", text: "Nothing added to the score" }));
  }

  function layerDetails(a) {
    const enc = a.encoding.findings.map((f) => el("li", {},
      el("span", { class: "mono", text: f.chain.join(" → ") }), ` (depth ${f.depth}): `,
      el("span", { class: "mono", text: `"${f.decoded}"` }),
      f.malicious ? el("span", { style: "color:var(--critical)", text: ` attack found: ${f.rule_matches.map((m) => m.rule_id).join(", ")}` })
        : el("span", { class: "muted", text: " benign after decoding" })));
    const uni = a.unicode.findings.map((f) => el("li", {},
      el("span", { class: "mono", text: f.kind }), ` ×${f.count} (${f.codepoints.join(", ")}) +${f.score}, ${f.reason}`));
    const heur = a.heuristics.map((h) => el("tr", {},
      el("td", { class: "mono small", text: h.name }),
      el("td", { class: "num" }, el("span", { class: h.score ? "points" : "muted", text: h.score ? `+${h.score}` : "0" })),
      el("td", { class: "small muted", text: h.reason })));
    const ctx = a.context;
    return el("div", { class: "grid grid-2" },
      card("Normalization",
        el("div", { class: "why-title", text: "Original input, kept for forensics" }), el("div", { class: "box", text: a.original_input }),
        el("div", { class: "why-title", style: "margin-top:12px", text: "Normalized input, what the detectors read" }), el("div", { class: "box", text: a.normalized_input }),
        el("ul", { class: "small muted", style: "margin:12px 0 0;padding-left:16px" },
          (a.normalization.steps.length ? a.normalization.steps : ["No normalization needed"]).map((s) => el("li", { text: s })))),
      el("div", { class: "stack" },
        card("Context analysis",
          el("p", { class: "small", style: "color:var(--text-secondary)", text: ctx.summary }),
          el("ul", { class: "sys-list", style: "margin-top:8px" },
            el("li", {}, el("span", { text: "Discussion framing" }), el("span", { text: ctx.discussion_framing ? `yes${ctx.framing_cues.length ? " (" + ctx.framing_cues.join(", ") + ")" : ""}` : "no" })),
            el("li", {}, el("span", { text: "Analysis wrapper" }), el("span", { text: ctx.analysis_wrapper ? "yes" : "no" })),
            el("li", {}, el("span", { text: "Commands to the assistant" }), el("span", { text: ctx.imperative_signals.length ? String(ctx.imperative_signals.length) : "none" })),
            el("li", {}, el("span", { text: "Dampened matches" }), el("span", { text: String(ctx.dampened_matches) })))),
        card("Encoding analysis", enc.length ? el("ul", { class: "small", style: "margin:0;padding-left:16px" }, enc) : el("div", { class: "empty", text: "No encoded content" }),
          el("div", { class: "small muted", style: "margin-top:8px", text: `${a.encoding.candidates_examined} candidates examined${a.encoding.depth_limit_reached ? ", decode depth limit reached" : ""}` })),
        card("Unicode analysis", uni.length ? el("ul", { class: "small", style: "margin:0;padding-left:16px" }, uni) : el("div", { class: "empty", text: "No suspicious Unicode" }),
          a.unicode.hidden_text ? el("div", { style: "margin-top:12px" }, el("div", { class: "why-title", text: "Hidden text decoded from tag characters" }), el("div", { class: "box", text: a.unicode.hidden_text })) : null),
      ),
      el("div", { class: "card", style: "grid-column:1/-1" }, el("h3", { text: "Heuristic analysis" }),
        el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, heur)))),
    );
  }

  function renderAnalysis(container, a, heading) {
    container.append(verdictCard(a, heading), breakdownCard(a), categoriesAndRules(a), layerDetails(a));
  }

  // ------------------------------------------------------------- stages
  function stageItem(s) {
    return el("li", { class: "stage" },
      el("span", { class: "stage-dot", style: `color:${STATUS_COLOR[s.status] || "#3a3a3e"}${s.status === "SKIP" ? ";box-shadow:inset 0 0 0 1px #3a3a3e" : ""}`, "aria-hidden": "true" }),
      el("div", { class: "stage-name", text: sentence(s.stage) }),
      el("div", {}, el("span", { class: `badge st-${s.status}`, text: cap(s.status) })),
      el("div", { class: "stage-summary", text: s.summary }));
  }

  function renderStages(listEl, stages, animate) {
    listEl.textContent = "";
    const doAnimate = animate && !reducedMotion() && !document.hidden;
    stages.forEach((s, i) => {
      const item = stageItem(s);
      if (doAnimate) {
        item.classList.add("pending");
        setTimeout(() => item.classList.remove("pending"), 60 * i);
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
    if (!decisions.length) return card("Tool firewall", el("div", { class: "empty", text: "The model proposed no tool calls" }));
    return card("Tool firewall", decisions.map((d) => alertBox(d.decision === "BLOCK" ? "bad" : "good",
      d.decision === "BLOCK" ? `TOOL CALL BLOCKED · ${d.tool}` : `Tool call allowed · ${d.tool}`,
      el("div", { class: "small", style: "color:var(--text-secondary)" }, d.reason),
      el("div", { class: "small muted" }, "Requested by ", d.origin_source || "an unknown source", d.origin_block_id ? ` (${d.origin_block_id})` : ""),
      el("div", { class: "box", style: "margin-top:8px", text: JSON.stringify(d.arguments, null, 2) }),
      el("ul", { class: "checklist" }, d.checks.map((c) => checkItem(c.passed, el("b", { text: c.check }), " ", c.detail))),
      d.executed ? el("div", { class: "small", style: "margin-top:8px" }, "Result ", el("span", { class: "mono", text: d.result })) : null,
    )));
  }

  function outputCard(check) {
    if (!check) return card("Output firewall", el("div", { class: "empty", text: "Not reached, the request was blocked before the model" }));
    const cls = { SAFE: "good", REDACTED: "warn", BLOCKED: "bad" }[check.decision];
    const title = { SAFE: "Output safe", REDACTED: "Output redacted", BLOCKED: "OUTPUT BLOCKED" }[check.decision];
    return card("Output firewall", alertBox(cls, title + (check.findings.length ? " · leak detected" : ""),
      el("div", { class: "small", style: "color:var(--text-secondary)" }, check.reason),
      check.findings.length ? el("ul", { class: "checklist" }, check.findings.map((f) => checkItem(false,
        el("b", { text: f.kind }), " ", f.detail, " ", el("span", { class: "muted mono", text: f.evidence })))) : null));
  }

  function provenanceCard(chat) {
    const rows = chat.provenance.map((b) => el("tr", {},
      el("td", { class: "mono nowrap", text: b.block_id }),
      el("td", {}, el("span", { class: "tag " + (b.trusted ? "trusted" : "untrusted"), text: b.source })),
      el("td", { class: "small", style: `color:${b.trusted ? "var(--text-secondary)" : "var(--serious)"}`, text: b.trusted ? "Trusted" : "Tainted" }),
      el("td", { class: "small", text: b.label + (b.parent_ids.length ? `, derived from ${b.parent_ids.join(", ")}` : "") }),
      el("td", { class: "small mono muted", text: b.preview })));
    return card("Provenance and taint",
      el("p", { class: "small muted", style: "margin-bottom:12px", text: `Fence nonce for this request ${chat.fence_nonce}. Untrusted blocks are wrapped in nonce-keyed fences and treated as data.` }),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ["Block", "Source", "Trust", "Label and lineage", "Preview"].map((h) => el("th", { text: h })))),
        el("tbody", {}, rows))),
      chat.rendered_prompt_preview ? el("details", {}, el("summary", { text: "Fenced prompt sent to the model, secrets redacted" }),
        el("div", { class: "box", style: "margin-top:8px", text: chat.rendered_prompt_preview })) : null);
  }

  function renderChat(container, chat) {
    const finalCls = { ALLOW: "good", WARN: "warn", SANITIZE: "warn", BLOCK: "bad" }[chat.final_decision];
    container.append(el("div", { class: "card" },
      el("div", { class: "card-title" }, el("h3", { text: "Result returned to the user" }), trace(chat.stages)),
      alertBox(finalCls, DEC_WORD[chat.final_decision], el("div", { class: "response-box", style: "white-space:pre-wrap;color:var(--text-secondary)", text: chat.response })),
      el("div", { class: "small muted", style: "margin-top:8px" }, `Model called ${chat.llm_called ? "yes, " + chat.llm_provider : "no"} · ${chat.processing_ms} ms`,
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
      el("div", { class: "card-title" }, el("h3", { text: "Document verdict" }), badge("dec", scan.decision)),
      untrustedBanner("Untrusted document. Instructions found here did not come from the user"),
      el("p", { class: "small", style: "color:var(--text-secondary);margin-bottom:16px", text: scan.explanation }),
      flagged.length ? el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, ["Segment", "Text", "Risk", "Category", "Rules"].map((h, i) => el("th", { class: i === 2 ? "num" : "", text: h })))),
        el("tbody", {}, flagged.map((s) => el("tr", {},
          el("td", { class: "mono", text: `#${s.index}` }),
          el("td", { class: "small", text: s.text }),
          el("td", { class: "num", text: String(s.risk_score) }),
          el("td", { class: "small", text: s.categories.map(catLabel).join(", ") }),
          el("td", { class: "small mono", text: s.rules.join(", ") }))))))
        : el("div", { class: "empty", text: "No suspicious segments" }),
      scan.sanitized_document ? el("details", { open: "open" }, el("summary", { text: `Sanitized document passed to the model, rescored ${scan.sanitized_analysis_score} / 100` }),
        el("div", { class: "box", style: "margin-top:8px", text: scan.sanitized_document })) : null));
  }

  // -------------------------------------------------------------- charts
  /** Ranked list with thin bars. The leading item carries the accent. */
  function rank(listEl, entries, labelFn) {
    listEl.textContent = "";
    if (!entries.length) { listEl.append(el("li", { class: "empty", text: "No attacks recorded yet" })); return; }
    const max = Math.max(1, ...entries.map(([, v]) => v));
    for (const [key, value] of entries) {
      listEl.append(el("li", {},
        el("span", { class: "rank-name", text: labelFn ? labelFn(key) : key }),
        el("span", { class: "rank-val", text: String(value) }),
        el("span", { class: "rank-bar", "aria-hidden": "true" }, el("span", { style: `width:${(value / max) * 100}%` }))));
    }
  }

  /** One stacked bar for a share, plus a legend with counts and percentages. */
  function shareBar(barEl, legendEl, entries, colorFn, kind) {
    barEl.textContent = "";
    legendEl.textContent = "";
    const total = entries.reduce((s, [, v]) => s + v, 0);
    barEl.setAttribute("role", "img");
    barEl.setAttribute("aria-label", entries.map(([k, v]) => `${cap(k)} ${v}`).join(", "));
    for (const [key, value] of entries) {
      if (value) barEl.append(el("span", { style: `width:${(value / Math.max(total, 1)) * 100}%;background:${colorFn(key)}`, title: `${cap(key)}: ${value}` }));
      legendEl.append(el("li", {}, badge(kind, key),
        el("span", { class: "num", text: total ? `${value} · ${Math.round((value / total) * 100)}%` : "0" })));
    }
  }

  /** Moment: the main chart. Risk score per request with the severity thresholds as quiet bands. */
  function riskChart(container, values) {
    container.textContent = "";
    if (!values.length) { container.append(el("div", { class: "empty", text: "No requests yet. Run a scenario in the attack demo lab" })); return; }
    const W = 720, H = 300, L = 36, R = 72, T = 12, B = 28;
    const x = (i) => L + (values.length === 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (values.length - 1));
    const y = (v) => T + (1 - v / 100) * (H - T - B);
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Risk score of the last ${values.length} requests, latest ${values[values.length - 1]}` });

    const bands = [[80, 100, "Critical"], [60, 80, "High"], [40, 60, "Medium"], [20, 40, "Low"]];
    bands.forEach(([lo, hi, name], i) => {
      root.append(svg("rect", { x: L, y: y(hi), width: W - L - R, height: y(lo) - y(hi), fill: `rgba(237,237,237,${i % 2 ? 0.015 : 0.035})` }));
      const t = svg("text", { x: W - R + 12, y: y((lo + hi) / 2) + 4, fill: "#85858b", "font-size": 11, "font-family": "Geist Mono, monospace" });
      t.textContent = name;
      root.append(t);
    });
    for (const v of [0, 20, 40, 60, 80, 100]) {
      root.append(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: "rgba(237,237,237,0.06)", "stroke-width": 1 }));
      const t = svg("text", { x: L - 8, y: y(v) + 4, fill: "#85858b", "font-size": 11, "text-anchor": "end", "font-family": "Geist Mono, monospace" });
      t.textContent = String(v);
      root.append(t);
    }
    const axis = svg("text", { x: L, y: H - 6, fill: "#85858b", "font-size": 11, "font-family": "Geist Mono, monospace" });
    axis.textContent = "oldest";
    const axis2 = svg("text", { x: W - R, y: H - 6, fill: "#85858b", "font-size": 11, "text-anchor": "end", "font-family": "Geist Mono, monospace" });
    axis2.textContent = "latest";
    root.append(axis, axis2);

    const pts = values.map((v, i) => [x(i), y(v)]);
    // smooth line (monotone-ish cubic through the points)
    let d = `M${pts[0][0]},${pts[0][1]}`;
    for (let i = 1; i < pts.length; i++) {
      const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], cx = (x0 + x1) / 2;
      d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
    }
    root.append(svg("path", { d, fill: "none", stroke: "#5b8def", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
    for (const [px, py] of pts) root.append(svg("circle", { cx: px, cy: py, r: 2.5, fill: "#141415", stroke: "#5b8def", "stroke-width": 1.5 }));
    const [lx, ly] = pts[pts.length - 1];
    root.append(svg("circle", { cx: lx, cy: ly, r: 4.5, fill: "#5b8def", stroke: "#19191b", "stroke-width": 2 }));

    const hover = svg("circle", { r: 5, fill: "#ededed", stroke: "#19191b", "stroke-width": 2, style: "display:none" });
    root.append(hover);
    const tip = el("div", { class: "chart-tip hidden" });
    root.addEventListener("mousemove", (ev) => {
      const rect = root.getBoundingClientRect();
      const rel = ((ev.clientX - rect.left) / rect.width) * W;
      let best = 0;
      pts.forEach(([px], i) => { if (Math.abs(px - rel) < Math.abs(pts[best][0] - rel)) best = i; });
      hover.setAttribute("cx", pts[best][0]); hover.setAttribute("cy", pts[best][1]); hover.style.display = "";
      tip.textContent = "";
      tip.append(`Request ${best + 1} of ${values.length} · risk `, el("b", { text: String(values[best]) }));
      tip.style.left = `${(pts[best][0] / W) * rect.width}px`;
      tip.style.top = `${(pts[best][1] / H) * rect.height}px`;
      tip.classList.remove("hidden");
    });
    root.addEventListener("mouseleave", () => { hover.style.display = "none"; tip.classList.add("hidden"); });
    container.append(root, tip);
  }

  /** Category x severity table. Neutral steps; every cell prints its value. */
  function heatmap(container, events) {
    container.textContent = "";
    const counts = {};
    for (const e of events) for (const c of e.categories) {
      counts[c] = counts[c] || {};
      counts[c][e.severity] = (counts[c][e.severity] || 0) + 1;
    }
    const cats = Object.keys(CAT_LABEL).filter((c) => counts[c]);
    if (!cats.length) { container.append(el("div", { class: "empty", text: "No attacks recorded yet" })); return; }
    const max = Math.max(1, ...cats.flatMap((c) => SEVERITIES.map((s) => counts[c][s] || 0)));
    const grid = el("div", { class: "heatmap", role: "table", "aria-label": "Attack category by severity",
      style: `grid-template-columns: minmax(160px, 1.6fr) repeat(${SEVERITIES.length}, minmax(52px, 1fr))` });
    grid.append(el("div", { class: "hm-head", role: "columnheader", text: "Category" }), ...SEVERITIES.map((s) => el("div", { class: "hm-head", role: "columnheader", text: cap(s) })));
    for (const c of cats) {
      grid.append(el("div", { class: "hm-row-label", role: "rowheader", title: catLabel(c), text: catLabel(c) }));
      for (const s of SEVERITIES) {
        const v = counts[c][s] || 0;
        const alpha = v ? (0.05 + 0.2 * (v / max)).toFixed(3) : "0.02";
        grid.append(el("div", { class: "hm-cell" + (v ? "" : " zero"), role: "cell", style: `--a:${alpha}`, title: `${catLabel(c)} · ${cap(s)}: ${v}`, text: String(v) }));
      }
    }
    container.append(el("div", { class: "table-wrap" }, grid));
  }

  // ------------------------------------------------------- status in sidebar
  async function refreshStatus() {
    const chip = document.getElementById("sys-status");
    if (!chip) return;
    const text = document.getElementById("sys-status-text");
    try {
      const h = await api("/api/health");
      chip.className = "status-line status-chip online";
      text.textContent = "Firewall online";
      document.getElementById("sys-mode").textContent = h.mode;
      document.getElementById("sys-rules").textContent = h.rules_enabled;
      document.getElementById("sys-llm").textContent = h.llm_provider;
    } catch {
      chip.className = "status-line status-chip offline";
      text.textContent = "Firewall offline";
    }
  }
  refreshStatus();
  setInterval(() => { if (!document.hidden) refreshStatus(); }, 20000);

  return {
    api, el, icon, badge, card, cap, catLabel, fmtTime, setBusy, reducedMotion, SEV_COLOR, DEC_COLOR, DEC_WORD, SEVERITIES,
    trace, scoreBlock, renderAnalysis, renderStages, renderChat, renderDocScan, renderDocView, untrustedBanner,
    rank, shareBar, riskChart, heatmap, verdictCard,
  };
})();
