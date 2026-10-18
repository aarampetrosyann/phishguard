# PhishGuard

A Chrome extension that flags phishing emails in Gmail. It reads the opened email
from the Gmail DOM, pulls out the sender, subject, body text and every link, and
scores them with a set of rules. The scoring runs on AWS Lambda behind API Gateway,
and every scan is logged to S3 so you can measure accuracy and debug false
positives. If the API can't be reached, the extension falls back to scoring locally.

```
Gmail tab ──content.js──▶ background.js ──POST /score──▶ API Gateway ─▶ Lambda (app.py)
   ▲  banner + link highlights      │ (fallback: scoring.js)              │
   └────────────────────────────────┘                                     ▼
                                                                S3: scans/, feedback/
```

## Layout

| Path | What it is |
|---|---|
| `extension/manifest.json` | Chrome MV3 manifest |
| `extension/content.js` | Watches Gmail for opened emails, extracts data from the DOM, renders the banner, highlights risky links |
| `extension/background.js` | Service worker: calls the API (4s timeout), falls back to local scoring, opens the panel from the toolbar icon, sets the toolbar badge |
| `extension/scoring.js` | JS port of the scoring rules (offline fallback) |
| `extension/panel.js` | Floating panel inside Gmail (top-right): risk score bar for the open email, plus expandable settings, activity, trusted senders and API config |
| `backend/src/scoring.py` | The rule-based scoring engine |
| `backend/src/app.py` | Lambda handler: `POST /score`, `POST /feedback`, `GET /health`, S3 logging |
| `backend/template.yaml` | AWS SAM template: Lambda + HTTP API + private S3 bucket (90-day log expiry) |
| `backend/tests/` | pytest suite and shared URL test cases |
| `assets/logo.svg`, `assets/logo-small.svg` | Logo sources: full logo (48/128px icons, panel header) and shield-only version for 16/32px. `logo-source.svg` is the original design |
| `tools/build_icons.py` | Renders the PNG icons and `extension/logo.js` from the SVGs (needs Google Chrome; run after changing a logo) |
| `tools/parity_test.js` | Checks that the JS and Python scorers return identical scores |
| `tools/demo.html` | Mock Gmail page for testing the content script without installing the extension |

## Scoring rules

Each URL gets points for each rule it trips (capped at 100). Rules marked **strong**
are independent warning signs; the rest only add points.

| Signal | Points | Strong |
|---|---|---|
| Domain is a misspelling of a known brand (`paypa1.com`, `amaz0n-login.top`) | 40 | ✓ |
| Brand name in the domain, but not the brand's real domain (`paypal-secure-login.com`) | 40 | ✓ |
| Link text shows one domain, href goes to another | 40 | ✓ |
| Raw IP address | 35 | ✓ |
| Punycode (`xn--`) lookalike characters | 30 | ✓ |
| `@` in the URL (`https://google.com@evil.com`) | 30 | ✓ |
| Link uses the sender's brand name but a different domain | 20 | ✓ |
| Abused TLD (`.xyz`, `.top`, `.zip`…) | 15 | ✓ |
| URL shortener, 4+ subdomains | 15 each | |
| Sensitive words in the domain (`secure-login.…`) | 10 | ✓ |
| Plain `http`, 3+ hyphens | 10 each | |
| Sensitive words in the path (`login`, `verify`, `account`…) | 5 each, max 15 | |
| URL over 100 characters | 5 | |

**Links to the sender's own domain** (including tracking subdomains like
`click.email.brand.com`) skip the `http`, long-URL, path-keyword and link-text checks:
marketing mail is full of these, and they lead where the sender says they do. The
link-text check still applies if the text shows a well-known brand (a link reading
`chase.com` from `secure-alerts.net` is still flagged).

The email score = the worst link's score + urgency phrases ("verify your account",
"within 24 hours"…, 10 each, max 30) + 30 if the sender's domain imitates a brand
+ 5 for each extra flagged link. Two or more urgency phrases and a brand-imitating
sender each count as strong signals.

**Verdicts:** `safe` < 30 ≤ `suspicious` < 50 ≤ `phishing`. A `phishing` verdict needs
at least **two different strong signals**; with only one, the score is capped at 49.

**Trusted senders:** the banner's "Trust <domain>" button adds the sender's domain to
an allowlist (synced via Chrome) and future mail from it is skipped. The button is
hidden when the sender's domain itself imitates a brand.

## Run the tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
```

```bash
.venv/bin/python -m pytest -q backend/tests
```

```bash
node tools/parity_test.js
```

## Try it without Gmail

```bash
python3 -m http.server 8765
```

Then open http://localhost:8765/tools/demo.html.

## Deploy the backend

You need the [AWS CLI](https://aws.amazon.com/cli/) (configured with `aws configure`)
and the [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

```bash
cd backend && sam build && sam deploy --guided
```

When `--guided` asks for `ApiKey`, you can set a shared secret or leave it empty. The
`ApiUrl` output is the URL you paste into the extension.

Check it:

```bash
curl -s -X POST "$API_URL/score" -H 'content-type: application/json' -d '{"sender":"a@paypal-help.net","subject":"Urgent","links":[{"href":"http://10.0.0.1/login","text":"Sign in"}]}'
```

### Logs in S3

- `scans/YYYY/MM/DD/<scan_id>.json`: verdict, score, reasons and per-link results.
  The email body is **not** stored.
- `feedback/YYYY/MM/DD/<id>.json`: "report false positive" clicks from the banner,
  linked by `scan_id`.

To find false positives, join the feedback records to scans by `scan_id`. You can do
this with Athena, or by downloading a day's logs with `aws s3 sync`.

## Install the extension

1. Go to `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Open Gmail and click the PhishGuard toolbar icon. A panel opens in the top-right of Gmail
   showing the open email's risk score. Click **Settings & activity** to expand it: you can
   pause scanning, switch safe emails to a compact banner, manage trusted senders, see recent
   scans, or paste your API URL (and key) and click **Save**. Leave the URL empty to score locally only.
4. Open an email. A banner appears above the message, risky links get a red or yellow
   outline (hover to see why), and the toolbar icon shows a red `!` or amber `?` badge.

> Gmail's class names (`div.a3s`, `span.gD`, `h2.hP`, `div.adn`) are obfuscated, but they
> have stayed the same for years. If Gmail changes them, update `SEL` in `content.js`.
