"""Rule-based phishing scoring for URLs and emails.

Each rule contributes points and a human-readable reason. Scores are capped
at 100 and mapped to a verdict: safe (< 30), suspicious (30-49), phishing (>= 50).
The same rules are mirrored in extension/scoring.js for offline fallback.
"""

import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "rest", "fit", "loan", "cam", "icu", "buzz", "monster",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Brand keyword -> domains the brand legitimately uses.
BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "coinbase": ["coinbase.com"],
    "irs": ["irs.gov"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
}

PATH_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "banking", "confirm", "password", "wallet", "unlock", "suspend",
}

URGENCY_PHRASES = [
    "verify your account", "account suspended", "account has been suspended",
    "unusual activity", "unusual sign-in", "confirm your identity", "act now",
    "immediately", "within 24 hours", "within 48 hours", "final notice",
    "password will expire", "click here to", "update your payment",
    "your account will be closed", "limited time", "you have won", "gift card",
    "wire transfer", "urgent",
]

# Common character swaps used in lookalike domains.
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})

MULTI_PART_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "ac.uk"}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Approximate eTLD+1 (e.g. mail.google.com -> google.com)."""
    if _is_ip(host):
        return host
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_official(reg: str, brand: str) -> bool:
    return reg in BRANDS[brand]


def _mentions_brand(host: str, brand: str) -> bool:
    """Long brand names match as substrings; short ones (chase, irs) only as whole tokens
    so that e.g. 'purchase.com' or 'first.com' don't trigger."""
    tokens = re.split(r"[.\-]", host)
    if len(brand) >= 6:
        return any(brand in t for t in tokens) or brand in "".join(tokens)
    return brand in tokens


def _brand_lookalike(host: str, reg: str):
    """Return ("mentions" | "typo", brand) if the domain imitates a known brand, else None.

    "mentions": the brand name appears in a domain the brand doesn't own (paypal-login.com).
    "typo": a hyphen-separated part of the registered name is a misspelling of a brand
    (paypa1.com, amaz0n-login.top). Edit-distance matching only applies to longer brand
    names, so short real words like 'apply' aren't mistaken for 'apple'.
    """
    for brand in BRANDS:
        if _mentions_brand(host, brand) and not _is_official(reg, brand):
            return "mentions", brand
    for token in reg.split(".")[0].split("-"):
        normalized = token.translate(HOMOGLYPHS)
        for brand in BRANDS:
            if len(brand) < 4 or _is_official(reg, brand):
                continue
            max_edits = 2 if len(brand) >= 9 else 1 if len(brand) >= 6 else 0
            if (normalized == brand and token != brand) or (
                max_edits and len(token) >= 5 and 0 < _levenshtein(token, brand) <= max_edits
            ):
                return "typo", brand
    return None


def _is_brand_domain(domain: str) -> bool:
    return any(domain in domains for domains in BRANDS.values())


def verdict_for(score: int) -> str:
    if score >= 50:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "safe"


def _apply_strong_cap(score: int, strong: set, reasons: list) -> int:
    """'Phishing' needs at least two independent strong signals; one alone tops out at suspicious."""
    if score >= 50 and len(strong) < 2:
        reasons.append("Only one strong warning sign, so rated suspicious rather than phishing")
        return 49
    return score


def score_url(url: str, display_text: str = "", sender_domain: str = "") -> dict:
    """Score a single URL. Returns {url, domain, score, verdict, reasons, strong}.

    `strong` lists the IDs of strong signals found; weak signals (http, long URL,
    path keywords...) only add points.
    """
    reasons = []
    strong = set()
    score = 0

    def hit(points, reason, strong_id=None):
        nonlocal score
        score += points
        reasons.append(reason)
        if strong_id:
            strong.add(strong_id)

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    if not host:
        return {"url": url, "domain": "", "score": 0, "verdict": "safe", "reasons": [], "strong": []}

    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]
    # Links to the sender's own domain (incl. tracking subdomains like click.email.brand.com)
    # are expected in legitimate mail, so weak signals and text mismatches are ignored for them.
    own_domain = bool(sender_domain) and reg == registered_domain(sender_domain)

    if _is_ip(host):
        hit(35, "Link points to a raw IP address instead of a domain", "ip")
    if "xn--" in host:
        hit(30, "Domain uses punycode (possible lookalike characters)", "punycode")
    if "@" in parsed.netloc:
        hit(30, "URL contains '@', which hides the real destination", "at_sign")
    if tld in SUSPICIOUS_TLDS:
        hit(15, f"Uses a TLD often abused for phishing (.{tld})", "bad_tld")
    if reg in URL_SHORTENERS:
        hit(15, "Shortened link hides the real destination")
    if parsed.scheme == "http" and not own_domain:
        hit(10, "Link is not encrypted (http)")
    if host.count(".") >= 4:
        hit(15, "Unusually many subdomains")
    if len(url) > 100 and not own_domain:
        hit(5, "Very long URL")
    if host.count("-") >= 3:
        hit(10, "Many hyphens in domain")

    lookalike = _brand_lookalike(host, reg)
    if lookalike and lookalike[0] == "mentions":
        hit(40, f"Mentions '{lookalike[1]}' but isn't an official {lookalike[1]} domain", "brand")
    elif lookalike:
        hit(40, f"Domain looks like a misspelling of '{lookalike[1]}'", "brand")

    host_words = sorted(k for k in PATH_KEYWORDS if k in re.split(r"[.\-]", host))
    if host_words:
        hit(10, "Sensitive keywords in domain: " + ", ".join(host_words), "host_keywords")

    path = (parsed.path + "?" + parsed.query).lower()
    found = sorted(k for k in PATH_KEYWORDS if k in path)
    if found and not own_domain:
        hit(min(5 * len(found), 15), "Sensitive keywords in path: " + ", ".join(found))

    # Anchor text shows one domain but href goes elsewhere. Ignored when the link goes to the
    # sender's own domain, unless the text shows a well-known brand the sender isn't.
    shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", (display_text or "").lower())
    if shown:
        shown_reg = registered_domain(shown.group(0))
        if shown_reg != reg and "." in shown_reg and (not own_domain or _is_brand_domain(shown_reg)):
            hit(40, f"Link text shows '{shown_reg}' but goes to '{reg}'", "text_mismatch")

    if sender_domain and not own_domain:
        for brand, domains in BRANDS.items():
            if registered_domain(sender_domain) in domains and _mentions_brand(host, brand):
                hit(20, "Link claims to be the sender's brand but uses a different domain", "sender_brand_link")
                break

    score = _apply_strong_cap(min(score, 100), strong, reasons)
    return {
        "url": url,
        "domain": reg,
        "score": score,
        "verdict": verdict_for(score),
        "reasons": reasons,
        "strong": sorted(strong),
    }


def score_email(links: list, sender: str = "", subject: str = "", body_text: str = "") -> dict:
    """Score an email from its links and text.

    links: [{"href": str, "text": str}]
    """
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    seen = set()
    link_results = []
    for link in links:
        href = (link.get("href") or "").strip()
        if not href.lower().startswith(("http://", "https://")) or href in seen:
            continue
        seen.add(href)
        link_results.append(score_url(href, link.get("text", ""), sender_domain))

    reasons = []
    strong = set()
    text = f"{subject}\n{body_text}".lower()
    urgency = [p for p in URGENCY_PHRASES if p in text]
    content_score = min(10 * len(urgency), 30)
    if urgency:
        reasons.append("Urgent/pressure language: " + ", ".join(f'"{p}"' for p in urgency[:4]))
    if len(urgency) >= 2:  # one phrase like "limited time" is normal in marketing mail
        strong.add("urgency")

    if sender_domain:
        lookalike = _brand_lookalike(sender_domain, registered_domain(sender_domain))
        if lookalike:
            content_score += 30
            strong.add("sender_impersonation")
            kind = "impersonates" if lookalike[0] == "mentions" else "looks like a misspelling of"
            reasons.append(f"Sender domain {kind} '{lookalike[1]}'")

    worst = max((r["score"] for r in link_results), default=0)
    flagged = [r for r in link_results if r["verdict"] != "safe"]
    for r in flagged:
        strong.update(r["strong"])
    # Worst link dominates; content and multiple bad links add on top.
    score = min(worst + content_score + max(len(flagged) - 1, 0) * 5, 100)
    score = _apply_strong_cap(score, strong, reasons)

    return {
        "score": score,
        "verdict": verdict_for(score),
        "reasons": reasons,
        "links": link_results,
        "sender_domain": sender_domain,
    }
