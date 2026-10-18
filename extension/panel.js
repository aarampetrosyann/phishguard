// Floating PhishGuard panel inside Gmail, pinned to the top-right of the page.
// Opened from the toolbar icon. Shows the open email's risk on a credit-score
// style bar; "Settings" expands it downward with options, activity and info.
// Rendered in a shadow root so Gmail's CSS can't leak in, and built with DOM
// calls only (Gmail enforces Trusted Types, so innerHTML would throw).
(() => {
  if (self.PhishGuardPanel) return;

  const VERDICT = {
    safe: { label: "Looks safe", color: "#188038" },
    suspicious: { label: "Suspicious", color: "#e37400" },
    phishing: { label: "Likely phishing", color: "#d93025" },
  };
  const SYNC_DEFAULTS = { enabled: true, compactSafe: false, trustedDomains: [], apiUrl: "", apiKey: "" };
  const LOCAL_DEFAULTS = { stats: { scanned: 0, suspicious: 0, phishing: 0 }, recent: [] };
  const VERSION = chrome.runtime.getManifest?.().version || "";

  let host, root, panel, scoreArea, settingsArea, settingsToggle, modeChip;
  let isOpen = false;
  let settingsOpen = false;
  let current = null;
  let sync = { ...SYNC_DEFAULTS };
  let local = structuredClone(LOCAL_DEFAULTS);

  // --- tiny DOM helper -------------------------------------------------------
  function h(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "style") node.style.cssText = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (typeof value === "boolean") node[key] = value;
      else node.setAttribute(key, value);
    }
    for (const child of children.flat()) if (child != null && child !== false) node.append(child);
    return node;
  }

  function shieldIcon(size = 20) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", size);
    svg.setAttribute("height", size);
    svg.setAttribute("aria-hidden", "true");
    const shield = document.createElementNS(ns, "path");
    shield.setAttribute("d", "M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z");
    shield.setAttribute("fill", "#1a73e8");
    const check = document.createElementNS(ns, "path");
    check.setAttribute("d", "m8.5 12 2.5 2.5 4.5-5");
    check.setAttribute("fill", "none");
    check.setAttribute("stroke", "#fff");
    check.setAttribute("stroke-width", "2");
    check.setAttribute("stroke-linecap", "round");
    check.setAttribute("stroke-linejoin", "round");
    svg.append(shield, check);
    return svg;
  }

  const timeAgo = (ts) => {
    const min = Math.round((Date.now() - ts) / 60000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    if (min < 1440) return `${Math.round(min / 60)}h ago`;
    return `${Math.round(min / 1440)}d ago`;
  };

  // --- score section ---------------------------------------------------------
  function scoreBar(score, verdict) {
    const pct = Math.max(0, Math.min(100, score ?? 0));
    const color = VERDICT[verdict]?.color || "#9aa0a6";
    return h("div", { class: `bar ${verdict ? "" : "bar-empty"}`, role: "img",
                      "aria-label": verdict ? `Risk ${score} out of 100, ${VERDICT[verdict].label}` : "No email selected" },
      h("div", { class: "track" },
        h("div", { class: "zone zone-safe" }),
        h("div", { class: "zone zone-suspicious" }),
        h("div", { class: "zone zone-phishing" })),
      verdict && h("div", { class: "marker", style: `left:${pct}%; border-color:${color}` }),
      h("div", { class: "zone-labels" },
        h("span", { class: "zl-safe", style: "width:30%" }, "Safe"),
        h("span", { class: "zl-suspicious", style: "width:20%" }, "Suspicious"),
        h("span", { class: "zl-phishing", style: "width:50%" }, "Phishing")));
  }

  function topReasons(result) {
    const reasons = result.reasons.filter((r) => !r.startsWith("Only one strong"));
    for (const link of result.links.filter((l) => l.verdict !== "safe")) {
      for (const r of link.reasons) if (!r.startsWith("Only one strong")) reasons.push(`${link.domain}: ${r}`);
    }
    return reasons;
  }

  function renderScore() {
    scoreArea.replaceChildren();
    if (!sync.enabled) {
      scoreArea.append(scoreBar(null, null), h("p", { class: "empty" }, "Scanning is paused. Turn it back on in Settings."));
      return;
    }
    if (!current) {
      scoreArea.append(
        h("div", { class: "score-row" }, h("span", { class: "score-num muted" }, "—"), h("span", { class: "score-max" }, "/100")),
        scoreBar(null, null),
        h("p", { class: "empty" }, "Open an email to see its risk score."));
      return;
    }

    const { email, domain } = current;
    const from = h("div", { class: "meta" },
      h("div", { class: "meta-from" }, email.senderName || email.sender || "Unknown sender",
        domain && h("span", { class: "meta-domain" }, ` · ${domain}`)),
      email.subject && h("div", { class: "meta-subject" }, email.subject));

    if (current.state === "trusted") {
      scoreArea.append(
        h("div", { class: "score-row" },
          h("span", { class: "score-num muted" }, "—"),
          h("span", { class: "chip chip-trusted" }, "✓ Trusted sender")),
        scoreBar(null, null),
        from,
        h("p", { class: "empty" }, `You marked ${domain} as trusted, so its emails aren't scored.`),
        h("button", { class: "text-btn", onclick: () => setTrusted(domain, false) }, `Stop trusting ${domain}`));
      return;
    }

    const { result } = current;
    const v = VERDICT[result.verdict];
    const reasons = topReasons(result);
    scoreArea.append(
      h("div", { class: "score-row" },
        h("span", { class: "score-num", style: `color:${v.color}` }, String(result.score)),
        h("span", { class: "score-max" }, "/100"),
        h("span", { class: `chip chip-${result.verdict}` }, v.label)),
      scoreBar(result.score, result.verdict),
      from,
      reasons.length
        ? h("ul", { class: "reasons" }, reasons.slice(0, 4).map((r) => h("li", {}, r)),
            reasons.length > 4 && h("li", { class: "more" }, `+${reasons.length - 4} more in the banner`))
        : h("p", { class: "empty" }, "No warning signs found in the sender, links or wording."),
      h("div", { class: "source" }, result.source === "api" ? "Scored by PhishGuard API" : "Scored locally in your browser"));
  }

  // --- settings section ------------------------------------------------------
  function toggleRow(key, title, description) {
    return h("label", { class: "toggle-row" },
      h("span", { class: "toggle-text" }, h("span", { class: "toggle-title" }, title), h("span", { class: "hint" }, description)),
      h("input", { type: "checkbox", class: "switch", checked: Boolean(sync[key]),
                   onchange: (e) => chrome.storage.sync.set({ [key]: e.target.checked }) }));
  }

  function section(title, ...children) {
    return h("section", { class: "section" }, h("h3", {}, title), ...children);
  }

  async function setTrusted(domain, trusted) {
    const list = new Set(sync.trustedDomains);
    trusted ? list.add(domain) : list.delete(domain);
    await chrome.storage.sync.set({ trustedDomains: [...list].sort() });
  }

  function renderSettings() {
    const { stats, recent } = local;
    const status = h("span", { class: "hint", "aria-live": "polite" });
    const urlInput = h("input", { type: "url", class: "input", placeholder: "https://xxxx.execute-api.us-east-1.amazonaws.com", value: sync.apiUrl });
    const keyInput = h("input", { type: "password", class: "input", placeholder: "Optional", value: sync.apiKey });

    async function saveApi() {
      const apiUrl = urlInput.value.trim().replace(/\/$/, "");
      if (apiUrl && !apiUrl.startsWith("https://")) {
        status.textContent = "URL must start with https://";
        return;
      }
      await chrome.storage.sync.set({ apiUrl, apiKey: keyInput.value.trim() });
      if (!apiUrl) {
        status.textContent = "Saved. Scoring locally.";
        return;
      }
      status.textContent = "Checking…";
      const res = await chrome.runtime.sendMessage({ type: "health" });
      status.textContent = res?.ok ? "Saved. API reachable ✓" : "Saved, but the API didn't respond.";
    }

    settingsArea.replaceChildren(
      section("Protection",
        toggleRow("enabled", "Scan emails in Gmail", "Score every email you open"),
        toggleRow("compactSafe", "Compact banner for safe emails", "Show a one-line note instead of the full green banner")),

      section("Activity",
        h("div", { class: "stats" },
          h("div", { class: "stat" }, h("b", {}, String(stats.scanned)), "Scanned"),
          h("div", { class: "stat stat-suspicious" }, h("b", {}, String(stats.suspicious)), "Suspicious"),
          h("div", { class: "stat stat-phishing" }, h("b", {}, String(stats.phishing)), "Phishing")),
        recent.length
          ? h("ul", { class: "recent" }, recent.slice(0, 6).map((r) =>
              h("li", {},
                h("span", { class: `dot dot-${r.verdict}`, title: VERDICT[r.verdict]?.label }),
                h("span", { class: "recent-text" },
                  h("span", { class: "recent-subject" }, r.subject || "(no subject)"),
                  h("span", { class: "hint" }, `${r.sender || "unknown"} · ${timeAgo(r.ts)}`)),
                h("span", { class: "recent-score" }, String(r.score)))))
          : h("p", { class: "hint" }, "No emails scanned yet."),
        (stats.scanned > 0 || recent.length > 0) && h("button", { class: "text-btn",
          onclick: () => chrome.storage.local.set(structuredClone(LOCAL_DEFAULTS)) }, "Clear activity")),

      section("Trusted senders",
        sync.trustedDomains.length
          ? h("ul", { class: "trusted" }, sync.trustedDomains.map((d) =>
              h("li", {}, h("span", {}, d),
                h("button", { class: "icon-btn", title: `Stop trusting ${d}`, "aria-label": `Stop trusting ${d}`,
                              onclick: () => setTrusted(d, false) }, "✕"))))
          : h("p", { class: "hint" }, "None yet. Use “Trust” on an email's banner to stop warnings for a sender.")),

      section("Scoring engine",
        h("p", { class: "hint" }, sync.apiUrl ? "Emails are sent to your API for scoring, with local scoring as a fallback."
                                              : "Emails are scored locally. Nothing leaves your browser."),
        h("label", { class: "field" }, h("span", {}, "API URL"), urlInput),
        h("label", { class: "field" }, h("span", {}, "API key"), keyInput),
        h("div", { class: "row" }, h("button", { class: "primary-btn", onclick: saveApi }, "Save"), status)),

      section("How scores work",
        h("ul", { class: "legend" },
          h("li", {}, h("span", { class: "dot dot-safe" }), h("b", {}, "0–29 Safe:"), " few or no warning signs"),
          h("li", {}, h("span", { class: "dot dot-suspicious" }), h("b", {}, "30–49 Suspicious:"), " be careful with links"),
          h("li", {}, h("span", { class: "dot dot-phishing" }), h("b", {}, "50–100 Phishing:"), " needs two or more strong warning signs")),
        h("p", { class: "hint" }, `PhishGuard ${VERSION} · rule-based scoring of sender, links and wording`)));
  }

  function renderHeader() {
    const api = Boolean(sync.apiUrl);
    modeChip.textContent = api ? "Cloud API" : "Local";
    modeChip.className = `mode ${api ? "mode-api" : ""}`;
  }

  function setSettingsOpen(open) {
    settingsOpen = open;
    settingsToggle.setAttribute("aria-expanded", String(open));
    settingsToggle.lastChild.textContent = open ? "▴" : "▾";
    panel.classList.toggle("expanded", open);
    if (open) renderSettings();
  }

  // --- build & lifecycle -----------------------------------------------------
  function build() {
    host = h("div", { id: "phishguard-panel-host" });
    root = host.attachShadow({ mode: "open" });
    root.append(h("style", {}, CSS));

    scoreArea = h("div", { class: "score-area" });
    settingsArea = h("div", { class: "settings-inner" });
    modeChip = h("span", { class: "mode" });
    settingsToggle = h("button", { class: "settings-toggle", "aria-expanded": "false", onclick: () => setSettingsOpen(!settingsOpen) },
      h("span", { "aria-hidden": "true" }, "⚙"), h("span", {}, "Settings & activity"), h("span", { class: "caret" }, "▾"));

    panel = h("div", { class: "panel", role: "dialog", "aria-label": "PhishGuard" },
      h("header", {},
        shieldIcon(),
        h("span", { class: "title" }, "PhishGuard"),
        modeChip,
        h("button", { class: "icon-btn close", title: "Close", "aria-label": "Close PhishGuard", onclick: () => setOpen(false) }, "✕")),
      scoreArea,
      settingsToggle,
      h("div", { class: "settings" }, settingsArea));
    root.append(panel);
    document.body.append(host);

    root.addEventListener("keydown", (e) => { if (e.key === "Escape") setOpen(false); });
  }

  function setOpen(open) {
    if (open && !host) build();
    isOpen = open;
    host?.classList.toggle("open", open);
    if (panel) panel.classList.toggle("open", open);
    if (open) {
      renderHeader();
      renderScore();
      if (settingsOpen) renderSettings();
      panel.focus?.();
    }
  }

  async function loadState() {
    sync = await chrome.storage.sync.get(SYNC_DEFAULTS);
    local = await chrome.storage.local.get(LOCAL_DEFAULTS);
  }

  chrome.storage.onChanged.addListener(async (_changes, area) => {
    if (!chrome.runtime?.id) return;
    await loadState();
    if (!isOpen) return;
    renderHeader();
    renderScore();
    // Don't rebuild the settings while the user is typing in the API fields.
    if (settingsOpen && !(area === "sync" && root.activeElement?.classList.contains("input"))) renderSettings();
  });

  self.PhishGuardPanel = {
    async toggle() {
      await loadState();
      setOpen(!isOpen);
    },
    setCurrent(info) {
      current = info;
      if (isOpen) renderScore();
    },
  };

  const CSS = `
    :host { all: initial; }
    .panel {
      position: fixed; top: 72px; right: 16px; z-index: 2147483000;
      width: 340px; max-height: calc(100vh - 88px); overflow-y: auto;
      box-sizing: border-box; background: #fff; color: #202124;
      border-radius: 16px; box-shadow: 0 4px 8px 3px rgba(60,64,67,.15), 0 1px 3px rgba(60,64,67,.3);
      font: 14px/1.45 "Google Sans", Roboto, Arial, sans-serif;
      opacity: 0; transform: translateY(-8px); pointer-events: none; visibility: hidden;
      transition: opacity .15s ease, transform .15s ease, visibility 0s .15s;
    }
    .panel.open { opacity: 1; transform: none; pointer-events: auto; visibility: visible; transition: opacity .15s ease, transform .15s ease; }
    * { box-sizing: border-box; }
    header { display: flex; align-items: center; gap: 8px; padding: 14px 12px 6px 16px; }
    .title { font-size: 16px; font-weight: 500; flex: 1; }
    .mode { font-size: 11px; padding: 2px 8px; border-radius: 10px; background: #f1f3f4; color: #5f6368; }
    .mode-api { background: #e8f0fe; color: #1967d2; }
    button { font: inherit; cursor: pointer; }
    .icon-btn { border: 0; background: none; color: #5f6368; width: 28px; height: 28px; border-radius: 50%; }
    .icon-btn:hover { background: #f1f3f4; }
    button:focus-visible, input:focus-visible { outline: 2px solid #1a73e8; outline-offset: 2px; }

    .score-area { padding: 4px 16px 14px; }
    .score-row { display: flex; align-items: baseline; gap: 4px; margin-bottom: 10px; }
    .score-num { font-size: 40px; font-weight: 500; line-height: 1; font-variant-numeric: tabular-nums; }
    .score-num.muted { color: #9aa0a6; }
    .score-max { color: #5f6368; font-size: 14px; }
    .chip { margin-left: auto; align-self: center; font-size: 12px; font-weight: 500; padding: 3px 10px; border-radius: 12px; }
    .chip-safe { background: #e6f4ea; color: #137333; }
    .chip-suspicious { background: #fef7e0; color: #b06000; }
    .chip-phishing { background: #fce8e6; color: #c5221f; }
    .chip-trusted { background: #f1f3f4; color: #3c4043; }

    .bar { position: relative; padding-bottom: 26px; margin: 0 2px; }
    .track { display: flex; height: 10px; border-radius: 5px; overflow: hidden; gap: 2px; }
    .zone-safe { width: 30%; background: linear-gradient(90deg, #188038, #34a853); }
    .zone-suspicious { width: 20%; background: linear-gradient(90deg, #fbbc04, #f29900); }
    .zone-phishing { flex: 1; background: linear-gradient(90deg, #ea4335, #a50e0e); }
    .bar-empty .track { filter: grayscale(1) opacity(.35); }
    .marker {
      position: absolute; top: -4px; width: 18px; height: 18px; margin-left: -9px;
      background: #fff; border: 4px solid; border-radius: 50%; box-shadow: 0 1px 3px rgba(0,0,0,.3);
      transition: left .4s ease;
    }
    .zone-labels { position: absolute; top: 15px; left: 0; right: 0; display: flex; pointer-events: none; }
    .zone-labels span { text-align: center; font-size: 11px; font-weight: 500; }
    .zl-safe { color: #137333; }
    .zl-suspicious { color: #b06000; }
    .zl-phishing { color: #c5221f; }
    .bar-empty .zone-labels span { color: #9aa0a6; }

    .meta { margin-top: 2px; padding: 10px 12px; background: #f8f9fa; border-radius: 10px; }
    .meta-from { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .meta-domain { font-weight: 400; color: #5f6368; }
    .meta-subject { color: #5f6368; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .reasons { margin: 10px 0 0; padding-left: 18px; font-size: 13px; }
    .reasons li { margin: 3px 0; word-break: break-word; }
    .reasons .more { list-style: none; margin-left: -18px; color: #5f6368; }
    .empty { margin: 10px 0 0; color: #5f6368; font-size: 13px; }
    .source { margin-top: 10px; font-size: 11px; color: #80868b; }

    .settings-toggle {
      display: flex; align-items: center; gap: 8px; width: 100%; padding: 12px 16px;
      border: 0; border-top: 1px solid #e8eaed; background: none; color: #3c4043; text-align: left;
    }
    .settings-toggle:hover { background: #f8f9fa; }
    .settings-toggle .caret { margin-left: auto; color: #5f6368; }
    .panel:not(.expanded) .settings-toggle { border-radius: 0 0 16px 16px; }
    .settings { display: grid; grid-template-rows: 0fr; transition: grid-template-rows .2s ease; }
    .panel.expanded .settings { grid-template-rows: 1fr; }
    .settings-inner { overflow: hidden; }
    .section { padding: 12px 16px; border-top: 1px solid #e8eaed; }
    h3 { margin: 0 0 8px; font-size: 12px; font-weight: 500; letter-spacing: .4px; text-transform: uppercase; color: #5f6368; }
    .hint { color: #5f6368; font-size: 12px; }
    p.hint { margin: 0 0 8px; }

    .toggle-row { display: flex; align-items: center; gap: 12px; padding: 6px 0; cursor: pointer; }
    .toggle-text { flex: 1; display: flex; flex-direction: column; }
    .toggle-title { font-size: 14px; }
    .switch {
      appearance: none; flex: none; width: 36px; height: 20px; border-radius: 10px; background: #bdc1c6;
      position: relative; cursor: pointer; transition: background .15s; margin: 0;
    }
    .switch::after {
      content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
      background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.3); transition: transform .15s;
    }
    .switch:checked { background: #1a73e8; }
    .switch:checked::after { transform: translateX(16px); }

    .stats { display: flex; gap: 8px; margin-bottom: 8px; }
    .stat { flex: 1; text-align: center; background: #f8f9fa; border-radius: 8px; padding: 6px 0; font-size: 12px; color: #5f6368; }
    .stat b { display: block; font-size: 18px; color: #202124; font-weight: 500; }
    .stat-suspicious b { color: #b06000; }
    .stat-phishing b { color: #c5221f; }
    .recent, .trusted, .legend { list-style: none; margin: 0; padding: 0; }
    .recent li { display: flex; align-items: center; gap: 10px; padding: 6px 0; }
    .recent li + li { border-top: 1px solid #f1f3f4; }
    .recent-text { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    .recent-text > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .recent-subject { font-size: 13px; }
    .recent-score { font-variant-numeric: tabular-nums; color: #5f6368; font-size: 13px; }
    .dot { flex: none; display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
    .recent .dot { margin-right: 0; }
    .dot-safe { background: #188038; }
    .dot-suspicious { background: #f29900; }
    .dot-phishing { background: #d93025; }
    .trusted li { display: flex; align-items: center; justify-content: space-between; padding: 2px 0 2px 10px; background: #f8f9fa; border-radius: 8px; margin-bottom: 4px; }
    .legend li { font-size: 13px; padding: 2px 0; }

    .field { display: flex; flex-direction: column; gap: 3px; margin-bottom: 8px; font-size: 12px; color: #3c4043; }
    .input { font: inherit; font-size: 13px; padding: 7px 10px; border: 1px solid #dadce0; border-radius: 8px; }
    .row { display: flex; align-items: center; gap: 10px; }
    .primary-btn { border: 0; background: #1a73e8; color: #fff; padding: 7px 18px; border-radius: 18px; font-weight: 500; }
    .primary-btn:hover { background: #1765cc; }
    .text-btn { border: 0; background: none; color: #1a73e8; padding: 4px 0; font-size: 13px; }
    .text-btn:hover { text-decoration: underline; }

    @media (prefers-reduced-motion: reduce) { .panel, .marker, .settings { transition: none; } }
  `;
})();
