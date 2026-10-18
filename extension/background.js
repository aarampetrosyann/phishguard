// Service worker: forwards scan requests to the Lambda API (content scripts
// can't make cross-origin requests to it directly) and keeps simple stats.
importScripts("scoring.js");

// Settings sync across the user's browsers; stats stay local (frequent writes).
const DEFAULTS = { apiUrl: "", apiKey: "", enabled: true };
const STATS_DEFAULT = { stats: { scanned: 0, suspicious: 0, phishing: 0 } };
const TIMEOUT_MS = 4000;

async function getSettings() {
  return chrome.storage.sync.get(DEFAULTS);
}

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
  let result;
  let source = "local";
  if (apiUrl) {
    try {
      result = await postJson(`${apiUrl.replace(/\/$/, "")}/score`, {
        sender: email.sender,
        subject: email.subject,
        body_text: email.bodyText,
        links: email.links,
      }, apiKey);
      source = "api";
    } catch (err) {
      console.warn("PhishGuard API failed, using local scoring:", err.message);
    }
  }
  if (!result) result = self.PhishGuardScoring.scoreEmail(email);
  result.source = source;

  const { stats } = await chrome.storage.local.get(STATS_DEFAULT);
  stats.scanned += 1;
  if (result.verdict === "suspicious") stats.suspicious += 1;
  if (result.verdict === "phishing") stats.phishing += 1;
  await chrome.storage.local.set({ stats });
  return result;
}

async function feedback(payload) {
  const { apiUrl, apiKey } = await getSettings();
  if (!apiUrl) return { ok: false, error: "No API configured" };
  return postJson(`${apiUrl.replace(/\/$/, "")}/feedback`, payload, apiKey);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handlers = { scan: () => scan(msg.email), feedback: () => feedback(msg.payload) };
  const handler = handlers[msg.type];
  if (!handler) return false;
  handler()
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));
  return true; // async response
});
