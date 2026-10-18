import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scoring import registered_domain, score_email, score_url  # noqa: E402

CASES = json.loads((Path(__file__).parent / "cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["url"] for c in CASES])
def test_url_cases(case):
    r = score_url(case["url"], case.get("text", ""))
    if case["expect"] == "suspicious+":
        assert r["verdict"] in ("suspicious", "phishing"), r
    else:
        assert r["verdict"] == case["expect"], r


def test_registered_domain():
    assert registered_domain("mail.google.com") == "google.com"
    assert registered_domain("www.amazon.co.uk") == "amazon.co.uk"
    assert registered_domain("example.com") == "example.com"


def test_phishing_email():
    r = score_email(
        links=[{"href": "https://paypal-account-verify.xyz/login", "text": "Verify now"}],
        sender="service@paypal-support.net",
        subject="Urgent: your account has been suspended",
        body_text="We noticed unusual activity. Verify your account within 24 hours.",
    )
    assert r["verdict"] == "phishing"
    assert r["score"] == 100
    assert any("impersonates 'paypal'" in reason for reason in r["reasons"])


def test_legit_email():
    r = score_email(
        links=[
            {"href": "https://github.com/notifications", "text": "View it on GitHub"},
            {"href": "https://docs.github.com/en", "text": "docs"},
        ],
        sender="notifications@github.com",
        subject="[repo] New issue opened",
        body_text="Someone opened an issue on your repository.",
    )
    assert r["verdict"] == "safe"


def test_ignores_non_http_and_duplicate_links():
    r = score_email(links=[{"href": "mailto:a@b.com"}, {"href": "https://a.com"}, {"href": "https://a.com"}])
    assert len(r["links"]) == 1


def test_ip_domain_kept_whole():
    assert registered_domain("192.168.4.20") == "192.168.4.20"
    assert score_url("http://192.168.4.20/login")["domain"] == "192.168.4.20"
