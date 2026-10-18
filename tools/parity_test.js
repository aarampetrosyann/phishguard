// Checks that extension/scoring.js gives the same scores as backend/src/scoring.py.
// Usage: node tools/parity_test.js   (requires python3 on PATH)
const { execFileSync } = require("child_process");
const path = require("path");
const scoring = require("../extension/scoring.js");

const root = path.resolve(__dirname, "..");
const cases = require(path.join(root, "backend/tests/cases.json"));

const py = `
import json, sys
sys.path.insert(0, "backend/src")
from scoring import score_url
cases = json.load(open("backend/tests/cases.json"))
print(json.dumps([score_url(c["url"], c.get("text", ""))["score"] for c in cases]))
`;
const pyScores = JSON.parse(execFileSync("python3", ["-c", py], { cwd: root }).toString());

let failed = 0;
cases.forEach((c, i) => {
  const js = scoring.scoreUrl(c.url, c.text || "").score;
  const ok = js === pyScores[i];
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} js=${String(js).padStart(3)} py=${String(pyScores[i]).padStart(3)}  ${c.url}`);
});
console.log(failed ? `\n${failed} mismatches` : "\nAll scores match");
process.exit(failed ? 1 : 0);
