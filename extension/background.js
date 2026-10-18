// Service worker: forwards scan requests to the Lambda API (content scripts
// can't make cross-origin requests to it directly), toggles the in-Gmail panel
// from the toolbar icon, and shows the current email's verdict as a badge.
importScripts("scoring.js");

const DEFAULTS = { apiUrl: "", apiKey: "" };
const TIMEOUT_MS = 4000;
const CONTENT_FILES = ["scoring.js", "logo.js", "panel.js", "content.js"];
const BADGES = {
  phishing: { text: "!", color: "#d93025" },
  suspicious: { text: "?", color: "#e37400" },
};

async function getSettings() {
  return chrome.storage.sync.get(DEFAULTS);
}

const apiBase = (url) => url.replace(/\/$/, "");

async function postJson(url, body, apiKey) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(apiKey ? { "x-api-key": apiKey } : {}) },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function scan(email) {
  const { apiUrl, apiKey } = await getSettings();
  if (apiUrl) {
    try {
      const result = await postJson(`${apiBase(apiUrl)}/score`, {
        sender: email.sender,
        subject: email.subject,
        body_text: email.bodyText,
        links: email.links,
      }, apiKey);
      return { ...result, source: "api" };
    } catch (err) {
      console.warn("PhishGuard API failed, using local scoring:", err.message);
    }
  }
  return { ...self.PhishGuardScoring.scoreEmail(email), source: "local" };
}

async function feedback(payload) {
  const { apiUrl, apiKey } = await getSettings();
  if (!apiUrl) return { ok: false, error: "No API configured" };
  return postJson(`${apiBase(apiUrl)}/feedback`, payload, apiKey);
}

async function health() {
  const { apiUrl } = await getSettings();
  if (!apiUrl) return { ok: false, mode: "local" };
  try {
    const res = await fetch(`${apiBase(apiUrl)}/health`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    return { ok: res.ok, mode: "api", status: res.status };
  } catch (err) {
    return { ok: false, mode: "api", error: err.message };
  }
}

function setBadge(tabId, verdict) {
  const badge = BADGES[verdict];
  chrome.action.setBadgeText({ tabId, text: badge ? badge.text : "" });
  if (badge) chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "badge") {
    if (sender.tab) setBadge(sender.tab.id, msg.verdict);
    return false;
  }
  const handlers = {
    scan: () => scan(msg.email),
    feedback: () => feedback(msg.payload),
    health: () => health(),
  };
  const handler = handlers[msg.type];
  if (!handler) return false;
  handler()
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));
  return true; // async response
});

// Toolbar icon: open/close the panel inside Gmail. Tabs opened before the extension
// was installed or reloaded have no content script yet, so inject it on demand.
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.url?.startsWith("https://mail.google.com/")) {
    chrome.tabs.create({ url: "https://mail.google.com/" });
    return;
  }
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "togglePanel" });
  } catch {
    await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ["content.css"] });
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: CONTENT_FILES });
    await chrome.tabs.sendMessage(tab.id, { type: "togglePanel" });
  }
});
