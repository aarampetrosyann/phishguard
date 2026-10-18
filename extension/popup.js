const $ = (id) => document.getElementById(id);

chrome.storage.sync.get({ apiUrl: "", apiKey: "", enabled: true }, (s) => {
  $("apiUrl").value = s.apiUrl;
  $("apiKey").value = s.apiKey;
  $("enabled").checked = s.enabled;
});

chrome.storage.local.get({ stats: { scanned: 0, suspicious: 0, phishing: 0 } }, ({ stats }) => {
  for (const k of ["scanned", "suspicious", "phishing"]) $(k).textContent = stats[k];
});

$("save").addEventListener("click", async () => {
  const apiUrl = $("apiUrl").value.trim().replace(/\/$/, "");
  if (apiUrl && !/^https:\/\//.test(apiUrl)) {
    $("status").textContent = "URL must start with https://";
    return;
  }
  await chrome.storage.sync.set({ apiUrl, apiKey: $("apiKey").value.trim(), enabled: $("enabled").checked });
  if (!apiUrl) {
    $("status").textContent = "Saved (local mode)";
    return;
  }
  try {
    const res = await fetch(`${apiUrl}/health`);
    $("status").textContent = res.ok ? "Saved — API reachable ✓" : `Saved — API returned ${res.status}`;
  } catch {
    $("status").textContent = "Saved — API unreachable";
  }
});
