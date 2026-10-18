// Rule-based phishing scoring. Mirrors backend/src/scoring.py so the
// extension still works offline or when the API is unreachable.
(function (root) {
  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "rest", "fit", "loan", "cam", "icu", "buzz", "monster",
  ]);

  const URL_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
  ]);

  const BRANDS = {
    paypal: ["paypal.com"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
    google: ["google.com", "gmail.com", "youtube.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazonaws.com"],
    netflix: ["netflix.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    linkedin: ["linkedin.com"],
    dropbox: ["dropbox.com"],
    docusign: ["docusign.com", "docusign.net"],
    coinbase: ["coinbase.com"],
    irs: ["irs.gov"],
    usps: ["usps.com"],
    fedex: ["fedex.com"],
    dhl: ["dhl.com"],
  };

  const PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "banking", "confirm", "password", "wallet", "unlock", "suspend",
  ];

  const URGENCY_PHRASES = [
    "verify your account", "account suspended", "account has been suspended",
    "unusual activity", "unusual sign-in", "confirm your identity", "act now",
    "immediately", "within 24 hours", "within 48 hours", "final notice",
    "password will expire", "click here to", "update your payment",
    "your account will be closed", "limited time", "you have won", "gift card",
    "wire transfer", "urgent",
  ];

  const HOMOGLYPHS = { 0: "o", 1: "l", 3: "e", 5: "s", "@": "a", $: "s" };
  const MULTI_PART_SUFFIXES = new Set(["co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "ac.uk"]);

  function registeredDomain(host) {
    if (isIp(host)) return host;
    const parts = host.toLowerCase().replace(/^\.+|\.+$/g, "").split(".");
    if (parts.length <= 2) return parts.join(".");
    if (MULTI_PART_SUFFIXES.has(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(":");
  }

  function levenshtein(a, b) {
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  const isOfficial = (reg, brand) => BRANDS[brand].includes(reg);

  function mentionsBrand(host, brand) {
    const tokens = host.split(/[.\-]/);
    if (brand.length >= 6) return tokens.some((t) => t.includes(brand)) || tokens.join("").includes(brand);
    return tokens.includes(brand);
  }

  // Returns ["mentions" | "typo", brand] if the domain imitates a known brand, else null.
  // Edit-distance matching only applies to longer brand names so 'apply' isn't 'apple'.
  function brandLookalike(host, reg) {
    const mentioned = Object.keys(BRANDS).find((b) => mentionsBrand(host, b) && !isOfficial(reg, b));
    if (mentioned) return ["mentions", mentioned];
    for (const token of reg.split(".")[0].split("-")) {
      const normalized = token.replace(/[0135@$]/g, (c) => HOMOGLYPHS[c]);
      for (const brand of Object.keys(BRANDS)) {
        if (brand.length < 4 || isOfficial(reg, brand)) continue;
        const maxEdits = brand.length >= 9 ? 2 : brand.length >= 6 ? 1 : 0;
        if ((normalized === brand && token !== brand) ||
            (maxEdits && token.length >= 5 && (() => { const d = levenshtein(token, brand); return d > 0 && d <= maxEdits; })())) {
          return ["typo", brand];
        }
      }
    }
    return null;
  }

  const isBrandDomain = (domain) => Object.values(BRANDS).some((domains) => domains.includes(domain));

  function verdictFor(score) {
    if (score >= 50) return "phishing";
    if (score >= 30) return "suspicious";
    return "safe";
  }

  // "Phishing" needs at least two independent strong signals; one alone tops out at suspicious.
  function applyStrongCap(score, strong, reasons) {
    if (score >= 50 && strong.size < 2) {
      reasons.push("Only one strong warning sign, so rated suspicious rather than phishing");
      return 49;
    }
    return score;
  }

  function scoreUrl(url, displayText = "", senderDomain = "") {
    const reasons = [];
    const strong = new Set();
    let score = 0;
    const hit = (points, reason, strongId) => {
      score += points;
      reasons.push(reason);
      if (strongId) strong.add(strongId);
    };
    const empty = { url, domain: "", score: 0, verdict: "safe", reasons: [], strong: [] };

    let parsed;
    try {
      parsed = new URL(url.includes("://") ? url : "http://" + url);
    } catch {
      return empty;
    }
    // URL() punycode-encodes unicode hosts, which is what we want for the xn-- check.
    const host = parsed.hostname.toLowerCase();
    if (!host) return empty;

    const reg = registeredDomain(host);
    const tld = host.split(".").pop();
    // Links to the sender's own domain (incl. tracking subdomains) are expected in legitimate
    // mail, so weak signals and text mismatches are ignored for them.
    const ownDomain = Boolean(senderDomain) && reg === registeredDomain(senderDomain);

    if (isIp(host)) hit(35, "Link points to a raw IP address instead of a domain", "ip");
    if (host.includes("xn--")) hit(30, "Domain uses punycode (possible lookalike characters)", "punycode");
    if (parsed.username || parsed.password) hit(30, "URL contains '@', which hides the real destination", "at_sign");
    if (SUSPICIOUS_TLDS.has(tld)) hit(15, `Uses a TLD often abused for phishing (.${tld})`, "bad_tld");
    if (URL_SHORTENERS.has(reg)) hit(15, "Shortened link hides the real destination");
    if (parsed.protocol === "http:" && !ownDomain) hit(10, "Link is not encrypted (http)");
    if ((host.match(/\./g) || []).length >= 4) hit(15, "Unusually many subdomains");
    if (url.length > 100 && !ownDomain) hit(5, "Very long URL");
    if ((host.match(/-/g) || []).length >= 3) hit(10, "Many hyphens in domain");

    const lookalike = brandLookalike(host, reg);
    if (lookalike?.[0] === "mentions") {
      hit(40, `Mentions '${lookalike[1]}' but isn't an official ${lookalike[1]} domain`, "brand");
    } else if (lookalike) {
      hit(40, `Domain looks like a misspelling of '${lookalike[1]}'`, "brand");
    }

    const hostTokens = host.split(/[.\-]/);
    const hostWords = PATH_KEYWORDS.filter((k) => hostTokens.includes(k)).sort();
    if (hostWords.length) hit(10, "Sensitive keywords in domain: " + hostWords.join(", "), "host_keywords");

    const path = (parsed.pathname + "?" + parsed.search.replace(/^\?/, "")).toLowerCase();
    const found = PATH_KEYWORDS.filter((k) => path.includes(k)).sort();
    if (found.length && !ownDomain) hit(Math.min(5 * found.length, 15), "Sensitive keywords in path: " + found.join(", "));

    // Anchor text shows one domain but href goes elsewhere. Ignored when the link goes to the
    // sender's own domain, unless the text shows a well-known brand the sender isn't.
    const shown = (displayText || "").toLowerCase().match(/([a-z0-9-]+\.)+[a-z]{2,}/);
    if (shown) {
      const shownReg = registeredDomain(shown[0]);
      if (shownReg !== reg && shownReg.includes(".") && (!ownDomain || isBrandDomain(shownReg))) {
        hit(40, `Link text shows '${shownReg}' but goes to '${reg}'`, "text_mismatch");
      }
    }

    if (senderDomain && !ownDomain) {
      const senderReg = registeredDomain(senderDomain);
      for (const [brand, domains] of Object.entries(BRANDS)) {
        if (domains.includes(senderReg) && mentionsBrand(host, brand)) {
          hit(20, "Link claims to be the sender's brand but uses a different domain", "sender_brand_link");
          break;
        }
      }
    }

    score = applyStrongCap(Math.min(score, 100), strong, reasons);
    return { url, domain: reg, score, verdict: verdictFor(score), reasons, strong: [...strong].sort() };
  }

  function scoreEmail({ links = [], sender = "", subject = "", bodyText = "" }) {
    const senderDomain = sender.includes("@") ? sender.split("@").pop().toLowerCase() : "";
    const seen = new Set();
    const linkResults = [];
    for (const link of links) {
      const href = (link.href || "").trim();
      if (!/^https?:\/\//i.test(href) || seen.has(href)) continue;
      seen.add(href);
      linkResults.push(scoreUrl(href, link.text || "", senderDomain));
    }

    const reasons = [];
    const strong = new Set();
    const text = `${subject}\n${bodyText}`.toLowerCase();
    const urgency = URGENCY_PHRASES.filter((p) => text.includes(p));
    let contentScore = Math.min(10 * urgency.length, 30);
    if (urgency.length) reasons.push("Urgent/pressure language: " + urgency.slice(0, 4).map((p) => `"${p}"`).join(", "));
    if (urgency.length >= 2) strong.add("urgency"); // one phrase like "limited time" is normal in marketing

    if (senderDomain) {
      const lookalike = brandLookalike(senderDomain, registeredDomain(senderDomain));
      if (lookalike) {
        contentScore += 30;
        strong.add("sender_impersonation");
        const kind = lookalike[0] === "mentions" ? "impersonates" : "looks like a misspelling of";
        reasons.push(`Sender domain ${kind} '${lookalike[1]}'`);
      }
    }

    const worst = linkResults.reduce((m, r) => Math.max(m, r.score), 0);
    const flagged = linkResults.filter((r) => r.verdict !== "safe");
    flagged.forEach((r) => r.strong.forEach((id) => strong.add(id)));
    let score = Math.min(worst + contentScore + Math.max(flagged.length - 1, 0) * 5, 100);
    score = applyStrongCap(score, strong, reasons);

    return { score, verdict: verdictFor(score), reasons, links: linkResults, sender_domain: senderDomain };
  }

  const api = { scoreUrl, scoreEmail, registeredDomain, verdictFor };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PhishGuardScoring = api;
})(typeof self !== "undefined" ? self : this);
