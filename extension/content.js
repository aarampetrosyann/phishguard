// Gmail content script: watches for opened emails, extracts sender, subject,
// body text and links from the DOM, asks the background worker for a score,
// then shows a banner, highlights risky links and feeds the panel (panel.js).
(() => {
  if (self.__phishguardContentLoaded) return;
  self.__phishguardContentLoaded = true;

  // Gmail's (obfuscated but long-stable) class names.
  const SEL = {
    message: "div.adn",      // one expanded message in a thread
    body: "div.a3s",         // message body
    sender: "span.gD",       // sender name, carries an `email` attribute
    subject: "h2.hP",        // thread subject
  };
  const SCANNED = "data-phishguard";
  const SYNC_DEFAULTS = { enabled: true, compactSafe: false, trustedDomains: [] };
  const LOCAL_DEFAULTS = { stats: { scanned: 0, suspicious: 0, phishing: 0 }, recent: [] };
  const MAX_RECENT = 20;
  const log = (...args) => console.log("[PhishGuard]", ...args);

  let settings = { ...SYNC_DEFAULTS };
  const results = new WeakMap(); // body element -> info shown in the panel
  const recorded = new WeakSet(); // body elements already counted in stats

  // After the extension is reloaded, scripts left in already-open tabs lose
  // access to chrome.* APIs. Detect that instead of throwing on every DOM change.
  const contextAlive = () => Boolean(chrome.runtime?.id);

  function extractEmail(bodyEl) {
    const message = bodyEl.closest(SEL.message) || document;
    const senderEl = message.querySelector(SEL.sender);
    const links = [...bodyEl.querySelectorAll("a[href]")].map((a) => ({
      href: a.href,
      text: (a.innerText || "").trim().slice(0, 300),
    }));
    return {
      sender: senderEl?.getAttribute("email") || "",
      senderName: senderEl?.innerText || "",
      subject: document.querySelector(SEL.subject)?.innerText || "",
      bodyText: (bodyEl.innerText || "").slice(0, 20000),
      links,
    };
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    return node;
  }

  const LABELS = {
    safe: "No phishing signals found",
    suspicious: "Suspicious email — be careful with links",
    phishing: "Likely phishing — do not click links or enter information",
  };

  const removeBanner = (bodyEl) => bodyEl.parentElement?.querySelector(":scope > .pg-banner")?.remove();
  const senderReg = (sender) => (sender.includes("@") ? PhishGuardScoring.registeredDomain(sender.split("@").pop()) : "");

  // Changing the list triggers storage.onChanged, which rescans every open email.
  async function setTrusted(domain, trusted) {
    const { trustedDomains } = await chrome.storage.sync.get({ trustedDomains: [] });
    const list = new Set(trustedDomains);
    trusted ? list.add(domain) : list.delete(domain);
    await chrome.storage.sync.set({ trustedDomains: [...list].sort() });
  }

  function renderTrusted(bodyEl, domain) {
    removeBanner(bodyEl);
    const banner = el("div", "pg-banner pg-trusted");
    banner.append(el("span", null, `✓ PhishGuard: you trust ${domain}`));
    const undo = el("button", "pg-link-btn", "Undo");
    undo.addEventListener("click", () => setTrusted(domain, false));
    banner.append(undo);
    bodyEl.before(banner);
  }

  function renderBanner(bodyEl, result, domain) {
    removeBanner(bodyEl);
    if (result.verdict === "safe" && settings.compactSafe) {
      const pill = el("div", "pg-banner pg-safe pg-compact", `✓ PhishGuard: no phishing signals (${result.score}/100)`);
      bodyEl.before(pill);
      return;
    }

    const banner = el("div", `pg-banner pg-${result.verdict}`);
    const header = el("div", "pg-header");
    header.append(el("strong", null, `PhishGuard: ${LABELS[result.verdict]}`), el("span", "pg-score", `Risk ${result.score}/100`));
    banner.append(header);

    const reasons = [...result.reasons];
    for (const link of result.links.filter((l) => l.verdict !== "safe").slice(0, 5)) {
      // The per-link cap note is only meaningful for the email as a whole.
      const linkReasons = link.reasons.filter((r) => !r.startsWith("Only one strong"));
      reasons.push(`${link.domain}: ${linkReasons.join("; ")}`);
    }
    if (reasons.length) {
      const list = el("ul", "pg-reasons");
      reasons.forEach((r) => list.append(el("li", null, r)));
      banner.append(list);
    }

    const actions = el("div", "pg-actions");
    // Not offered when the sender's own domain imitates a brand: trusting it would hide the attack.
    const senderSuspicious = result.reasons.some((r) => r.startsWith("Sender domain"));
    if (result.verdict !== "safe" && domain && !senderSuspicious) {
      const trust = el("button", "pg-feedback", `Trust ${domain}`);
      trust.title = "Stop warning about emails from this domain";
      trust.addEventListener("click", () => setTrusted(domain, true));
      actions.append(trust);
    }

    if (result.verdict !== "safe" && result.scan_id) {
      const btn = el("button", "pg-feedback", "This is safe — report false positive");
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        const res = await chrome.runtime.sendMessage({
          type: "feedback",
          payload: { scan_id: result.scan_id, label: "false_positive" },
        });
        btn.textContent = res?.ok ? "Thanks — reported" : "Couldn't send report";
      });
      actions.append(btn);
    }
    if (actions.childElementCount) banner.append(actions);

    const footer = el("div", "pg-source", result.source === "api" ? "Scored by PhishGuard API" : "Scored locally");
    banner.append(footer);
    bodyEl.before(banner);
  }

  function clearLinks(bodyEl) {
    for (const a of bodyEl.querySelectorAll("a.pg-link")) {
      a.classList.remove("pg-link", "pg-link-suspicious", "pg-link-phishing");
      a.removeAttribute("title");
    }
  }

  function markLinks(bodyEl, result) {
    const byUrl = new Map(result.links.map((l) => [l.url, l]));
    for (const a of bodyEl.querySelectorAll("a[href]")) {
      const info = byUrl.get(a.href);
      if (!info || info.verdict === "safe") continue;
      a.classList.add("pg-link", `pg-link-${info.verdict}`);
      a.title = `PhishGuard (${info.score}/100): ${info.reasons.join("; ")}\n${info.url}`;
    }
  }

  // Stats and the recent-scans list live in local storage only (never synced or uploaded).
  // Writes are chained so emails scanned at the same moment don't overwrite each other's counts.
  let recordQueue = Promise.resolve();
  function record(bodyEl, email, result) {
    if (recorded.has(bodyEl)) return;
    recorded.add(bodyEl);
    recordQueue = recordQueue.then(() => saveRecord(email, result)).catch((err) => console.warn("[PhishGuard] stats:", err));
  }

  async function saveRecord(email, result) {
    const { stats, recent } = await chrome.storage.local.get(LOCAL_DEFAULTS);
    stats.scanned += 1;
    if (result.verdict in stats) stats[result.verdict] += 1;
    recent.unshift({
      ts: Date.now(),
      sender: email.sender,
      subject: email.subject.slice(0, 120),
      verdict: result.verdict,
      score: result.score,
    });
    await chrome.storage.local.set({ stats, recent: recent.slice(0, MAX_RECENT) });
  }

  async function scanBody(bodyEl) {
    if (bodyEl.hasAttribute(SCANNED)) return;
    bodyEl.setAttribute(SCANNED, "pending");
    const email = extractEmail(bodyEl);
    const domain = senderReg(email.sender);
    if (domain && settings.trustedDomains.includes(domain)) {
      bodyEl.setAttribute(SCANNED, "trusted");
      results.set(bodyEl, { state: "trusted", email, domain });
      renderTrusted(bodyEl, domain);
      updatePanel();
      return;
    }
    let result;
    try {
      result = await chrome.runtime.sendMessage({ type: "scan", email });
      if (!result || result.error) throw new Error(result?.error || "no response");
    } catch (err) {
      // Background worker unreachable: score in the page so the user still gets a verdict.
      console.warn("[PhishGuard] background unavailable, scoring locally:", err.message);
      result = { ...PhishGuardScoring.scoreEmail(email), source: "local" };
    }
    if (!bodyEl.isConnected || bodyEl.getAttribute(SCANNED) !== "pending") return; // reset meanwhile
    try {
      bodyEl.setAttribute(SCANNED, result.verdict);
      results.set(bodyEl, { state: "scanned", email, domain, result });
      renderBanner(bodyEl, result, domain);
      markLinks(bodyEl, result);
      updatePanel();
      log(`${result.verdict} (${result.score}/100), ${email.links.length} links, sender ${email.sender || "unknown"}`);
      record(bodyEl, email, result);
    } catch (err) {
      console.error("[PhishGuard] failed to render banner:", err);
    }
  }

  // Remove all banners/highlights so emails are rescanned with the current settings.
  function resetAll() {
    for (const bodyEl of document.querySelectorAll(`${SEL.body}[${SCANNED}]`)) {
      removeBanner(bodyEl);
      clearLinks(bodyEl);
      bodyEl.removeAttribute(SCANNED);
      results.delete(bodyEl);
    }
  }

  // The panel describes the last opened message on screen (the newest in a thread).
  let lastPanelInfo;
  function updatePanel() {
    const bodies = [...document.querySelectorAll(`${SEL.body}[${SCANNED}]`)].filter((b) => results.has(b));
    const info = settings.enabled && bodies.length ? results.get(bodies.at(-1)) : null;
    if (info === lastPanelInfo) return;
    lastPanelInfo = info;
    self.PhishGuardPanel?.setCurrent(info);
    chrome.runtime.sendMessage({ type: "badge", verdict: info?.result?.verdict || "" })?.catch?.(() => {});
  }

  let queued = false;
  function scanVisible() {
    queued = false;
    if (!contextAlive()) {
      observer.disconnect();
      log("extension was reloaded; refresh this Gmail tab to re-enable scanning");
      return;
    }
    if (settings.enabled) document.querySelectorAll(`${SEL.body}:not([${SCANNED}])`).forEach(scanBody);
    updatePanel();
  }

  // Gmail is a SPA: re-check whenever the DOM changes, debounced.
  const observer = new MutationObserver(() => {
    if (!queued) {
      queued = true;
      setTimeout(scanVisible, 400);
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "sync" || !Object.keys(changes).some((k) => k in SYNC_DEFAULTS) || !contextAlive()) return;
    for (const key of Object.keys(SYNC_DEFAULTS)) if (key in changes) settings[key] = changes[key].newValue;
    resetAll();
    scanVisible();
  });

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type !== "togglePanel") return false;
    self.PhishGuardPanel?.toggle();
    sendResponse({ ok: true });
    return false;
  });

  chrome.storage.sync.get(SYNC_DEFAULTS, (stored) => {
    settings = stored;
    resetAll(); // clear banners left by a previous (reloaded) copy of the extension
    observer.observe(document.body, { childList: true, subtree: true });
    log("content script loaded");
    scanVisible();
  });
})();
