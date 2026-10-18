import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import app  # noqa: E402


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType):
        self.objects[Key] = json.loads(Body)


def event(path, body=None, method="POST", headers=None):
    return {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "headers": headers or {},
        "body": json.dumps(body) if body is not None else None,
    }


def setup(monkeypatch, api_key=""):
    fake = FakeS3()
    monkeypatch.setattr(app, "LOG_BUCKET", "test-bucket")
    monkeypatch.setattr(app, "API_KEY", api_key)
    monkeypatch.setattr(app, "_s3", fake)
    return fake


def test_score_logs_to_s3(monkeypatch):
    s3 = setup(monkeypatch)
    res = app.lambda_handler(
        event("/score", {"sender": "x@y.com", "links": [{"href": "http://10.0.0.1/login", "text": "Login"}]}), None
    )
    body = json.loads(res["body"])
    assert res["statusCode"] == 200
    assert body["verdict"] in ("suspicious", "phishing")
    [key] = s3.objects
    assert key.startswith("scans/") and body["scan_id"] in key
    assert "body_text" not in s3.objects[key]


def test_feedback(monkeypatch):
    s3 = setup(monkeypatch)
    res = app.lambda_handler(event("/feedback", {"scan_id": "abc", "label": "false_positive"}), None)
    assert res["statusCode"] == 200
    assert next(iter(s3.objects)).startswith("feedback/")
    bad = app.lambda_handler(event("/feedback", {"label": "nope"}), None)
    assert bad["statusCode"] == 400


def test_api_key_required(monkeypatch):
    setup(monkeypatch, api_key="secret")
    assert app.lambda_handler(event("/score", {"links": []}), None)["statusCode"] == 401
    ok = app.lambda_handler(event("/score", {"links": []}, headers={"X-Api-Key": "secret"}), None)
    assert ok["statusCode"] == 200


def test_health_and_errors(monkeypatch):
    setup(monkeypatch)
    assert app.lambda_handler(event("/health", method="GET"), None)["statusCode"] == 200
    bad = app.lambda_handler({**event("/score"), "body": "{not json"}, None)
    assert bad["statusCode"] == 400
    assert app.lambda_handler(event("/nope", {}), None)["statusCode"] == 404


def test_s3_failure_does_not_break_scoring(monkeypatch):
    setup(monkeypatch)

    class Broken:
        def put_object(self, **kw):
            raise RuntimeError("boom")

    monkeypatch.setattr(app, "_s3", Broken())
    assert app.lambda_handler(event("/score", {"links": []}), None)["statusCode"] == 200
