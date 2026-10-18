// Gmail content script: watches for opened emails, extracts sender, subject,
// body text and links from the DOM, asks the background worker for a score,
// then shows a banner and highlights risky links.
(() => {
  // Gmail's (obfuscated but long-stable) class names.
  const SEL = {
    message: "div.adn",      // one expanded message in a thread
    body: "div.a3s",         // message body
    sender: "span.gD",       // sender name, carries an `email` attribute
    subject: "h2.hP",        // thread subject
  };
  const SCANNED = "data-phishguard";
  const log = (...args) => console.log("[PhishGuard]", ...args);

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

  // Trusted sender domains (registered domain, e.g. "mcmworldwide.com"), synced across browsers.
  const getTrusted = async () => (await chrome.storage.sync.get({ trustedDomains: [] })).trustedDomains;
  const senderReg = (sender) => (sender.includes("@") ? PhishGuardScoring.registeredDomain(sender.split("@").pop()) : "");

  async function setTrusted(domain, trusted) {
    const list = new Set(await getTrusted());
    trusted ? list.add(domain) : list.delete(domain);
    await chrome.storage.sync.set({ trustedDomains: [...list].sort() });
  }

  function renderTrusted(bodyEl, domain) {
    removeBanner(bodyEl);
    clearLinks(bodyEl);
    const banner = el("div", "pg-banner pg-trusted");
    banner.append(el("span", null, `✓ PhishGuard: you trust ${domain}`));
    const undo = el("button", "pg-link-btn", "Undo");
    undo.addEventListener("click", async () => {
      await setTrusted(domain, false);
      removeBanner(bodyEl);
      bodyEl.removeAttribute(SCANNED);
      scanBody(bodyEl);
    });
    banner.append(undo);
    bodyEl.before(banner);
  }

  function renderBanner(bodyEl, result, domain) {
    removeBanner(bodyEl);
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
      trust.addEventListener("click", async () => {
        await setTrusted(domain, true);
        bodyEl.setAttribute(SCANNED, "trusted");
        renderTrusted(bodyEl, domain);
      });
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

  async function scanBody(bodyEl) {
    if (bodyEl.hasAttribute(SCANNED)) return;
    bodyEl.setAttribute(SCANNED, "pending");
    const email = extractEmail(bodyEl);
    const domain = senderReg(email.sender);
    if (domain && (await getTrusted()).includes(domain)) {
      bodyEl.setAttribute(SCANNED, "trusted");
      renderTrusted(bodyEl, domain);
      log(`trusted sender ${domain}, skipped scan`);
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
    try {
      bodyEl.setAttribute(SCANNED, result.verdict);
      renderBanner(bodyEl, result, domain);
      markLinks(bodyEl, result);
      log(`${result.verdict} (${result.score}/100), ${email.links.length} links, sender ${email.sender || "unknown"}`);
    } catch (err) {
      console.error("[PhishGuard] failed to render banner:", err);
    }
  }

  let queued = false;
  function scanVisible() {
    queued = false;
    if (!contextAlive()) {
      observer.disconnect();
      log("extension was reloaded; refresh this Gmail tab to re-enable scanning");
      return;
    }
    chrome.storage.sync.get({ enabled: true }, ({ enabled }) => {
      if (!enabled) return;
      document.querySelectorAll(`${SEL.body}:not([${SCANNED}])`).forEach(scanBody);
    });
  }

  // Gmail is a SPA: re-check whenever the DOM changes, debounced.
  const observer = new MutationObserver(() => {
    if (!queued) {
      queued = true;
      setTimeout(scanVisible, 400);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
  log("content script loaded");
  scanVisible();
})();
