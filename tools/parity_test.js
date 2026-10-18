// Checks that extension/scoring.js gives the same scores as backend/src/scoring.py.
// Usage: node tools/parity_test.js   (requires python3 on PATH)
const { execFileSync } = require("child_process");
const path = require("path");
const scoring = require("../extension/scoring.js");

const root = path.resolve(__dirname, "..");
const cases = require(path.join(root, "backend/tests/cases.json"));
const senderDomain = (c) => (c.sender || "").split("@").pop();

const py = `
import json, sys
sys.path.insert(0, "backend/src")
from scoring import score_url, score_email
cases = json.load(open("backend/tests/cases.json"))
urls = [score_url(c["url"], c.get("text", ""), (c.get("sender") or "").split("@")[-1])["score"] for c in cases]
emails = [score_email([{"href": c["url"], "text": c.get("text", "")}], c.get("sender", ""), "", "")["score"] for c in cases]
print(json.dumps({"urls": urls, "emails": emails}))
`;
const pyScores = JSON.parse(execFileSync("python3", ["-c", py], { cwd: root }).toString());

let failed = 0;
cases.forEach((c, i) => {
  const jsUrl = scoring.scoreUrl(c.url, c.text || "", senderDomain(c)).score;
  const jsEmail = scoring.scoreEmail({ links: [{ href: c.url, text: c.text || "" }], sender: c.sender || "" }).score;
  const ok = jsUrl === pyScores.urls[i] && jsEmail === pyScores.emails[i];
  if (!ok) failed++;
  console.log(
    `${ok ? "ok  " : "FAIL"} url js=${String(jsUrl).padStart(3)} py=${String(pyScores.urls[i]).padStart(3)}` +
      ` | email js=${String(jsEmail).padStart(3)} py=${String(pyScores.emails[i]).padStart(3)}  ${c.url.slice(0, 60)}`
  );
});
console.log(failed ? `\n${failed} mismatches` : "\nAll scores match");
process.exit(failed ? 1 : 0);
