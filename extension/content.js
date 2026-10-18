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

  function renderBanner(bodyEl, result) {
    bodyEl.parentElement?.querySelector(":scope > .pg-banner")?.remove();
    const banner = el("div", `pg-banner pg-${result.verdict}`);
    const header = el("div", "pg-header");
    header.append(el("strong", null, `PhishGuard: ${LABELS[result.verdict]}`), el("span", "pg-score", `Risk ${result.score}/100`));
    banner.append(header);

    const reasons = [...result.reasons];
    for (const link of result.links.filter((l) => l.verdict !== "safe").slice(0, 5)) {
      reasons.push(`${link.domain}: ${link.reasons.join("; ")}`);
    }
    if (reasons.length) {
      const list = el("ul", "pg-reasons");
      reasons.forEach((r) => list.append(el("li", null, r)));
      banner.append(list);
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
      banner.append(btn);
    }

    const footer = el("div", "pg-source", result.source === "api" ? "Scored by PhishGuard API" : "Scored locally");
    banner.append(footer);
    bodyEl.before(banner);
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
      renderBanner(bodyEl, result);
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
