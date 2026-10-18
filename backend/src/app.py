"""PhishGuard scoring API (AWS Lambda behind API Gateway HTTP API).

Routes:
  POST /score     {"sender", "subject", "body_text", "links": [{"href", "text"}]}
  POST /feedback  {"scan_id", "label": "false_positive" | "false_negative", "note"}
  GET  /health

Every scan and feedback report is written to S3 as JSON so detection accuracy
can be tracked and false positives debugged afterwards.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone

from scoring import score_email

LOG_BUCKET = os.environ.get("LOG_BUCKET", "")
API_KEY = os.environ.get("API_KEY", "")
MAX_LINKS = 200
MAX_BODY_CHARS = 20_000

_s3 = None


def _s3_client():
    global _s3
    if _s3 is None:
        import boto3  # available in the Lambda runtime

        _s3 = boto3.client("s3")
    return _s3


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _log_to_s3(prefix, record):
    if not LOG_BUCKET:
        return
    now = datetime.now(timezone.utc)
    key = f"{prefix}/{now:%Y/%m/%d}/{record['id']}.json"
    try:
        _s3_client().put_object(
            Bucket=LOG_BUCKET, Key=key, Body=json.dumps(record).encode(), ContentType="application/json"
        )
    except Exception as exc:  # logging must never break scoring
        print(f"S3 log failed: {exc}")


def _parse_body(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode()
    return json.loads(raw)


def handle_score(payload):
    links = payload.get("links") or []
    if not isinstance(links, list):
        return _response(400, {"error": "links must be a list"})

    started = time.perf_counter()
    result = score_email(
        links=[l for l in links[:MAX_LINKS] if isinstance(l, dict)],
        sender=str(payload.get("sender", ""))[:320],
        subject=str(payload.get("subject", ""))[:500],
        body_text=str(payload.get("body_text", ""))[:MAX_BODY_CHARS],
    )
    scan_id = str(uuid.uuid4())
    result["scan_id"] = scan_id
    result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)

    # Store the verdict and URLs, not the email body.
    _log_to_s3(
        "scans",
        {
            "id": scan_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "sender_domain": result["sender_domain"],
            "score": result["score"],
            "verdict": result["verdict"],
            "reasons": result["reasons"],
            "links": [{k: r[k] for k in ("url", "domain", "score", "verdict", "reasons")} for r in result["links"]],
        },
    )
    return _response(200, result)


def handle_feedback(payload):
    label = payload.get("label")
    if label not in ("false_positive", "false_negative"):
        return _response(400, {"error": "label must be false_positive or false_negative"})
    record = {
        "id": str(uuid.uuid4()),
        "scan_id": str(payload.get("scan_id", ""))[:64],
        "label": label,
        "note": str(payload.get("note", ""))[:1000],
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    _log_to_s3("feedback", record)
    return _response(200, {"ok": True, "id": record["id"]})


def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", event.get("httpMethod", "GET"))
    path = event.get("rawPath") or event.get("path") or "/"

    if path.endswith("/health"):
        return _response(200, {"ok": True})

    if API_KEY:
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        if headers.get("x-api-key") != API_KEY:
            return _response(401, {"error": "unauthorized"})

    if method != "POST":
        return _response(405, {"error": "method not allowed"})

    try:
        payload = _parse_body(event)
    except (ValueError, UnicodeDecodeError):
        return _response(400, {"error": "invalid JSON"})

    if path.endswith("/score"):
        return handle_score(payload)
    if path.endswith("/feedback"):
        return handle_feedback(payload)
    return _response(404, {"error": "not found"})
