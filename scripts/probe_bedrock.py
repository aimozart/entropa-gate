#!/usr/bin/env python3
"""One tiny Amazon Bedrock Converse call (S11b-prep): does the account, quota and credit allow this model?

Reads credentials ONLY from the environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, optional AWS_SESSION_TOKEN);
never reads ~/.aws; never prints a secret, a header or the model's answer. Prints response metadata only.
At most 300 input tokens (a fixed synthetic prompt) and 50 output tokens: about $0.00003 on Amazon Nova Lite at the cap ($0.0004 on Nova Pro).
The cost estimate is model-aware for the Amazon Nova family in the plan (Lite, Pro, and Micro for reference); for any other model id the
output says that no estimate is given.
Standard library only. Offline self-test: scripts/probe-bedrock.sh --selftest.
"""
import datetime, hashlib, hmac, json, os, re, sys, urllib.error, urllib.request
from urllib.parse import quote

PROMPT = "Reply with the single word: ok"          # fixed, synthetic
MAX_OUTPUT_TOKENS = 50
MAX_INPUT_TOKENS = 300
# USD per 1M tokens (input, output), AWS Price List us-west-2 on 2026-10-21 (docs/ARCHITECTURE-AWS-SHOWCASE.md section 7).
# Matched against the model id, an inference-profile id (us.amazon.nova-lite-v1:0) or an inference-profile ARN.
NOVA_PRICES = {"micro": (0.035, 0.14), "lite": (0.06, 0.24), "pro": (0.80, 3.20)}


def price_for(model_id):
    """(input, output) USD per 1M tokens for an Amazon Nova v1 model id, or None for any other model: no guessed number."""
    m = re.search(r"(?:^|[./])amazon\.nova-(micro|lite|pro)-v1(?::|$)", model_id)
    return NOVA_PRICES[m.group(1)] if m else None


def estimate_tokens(text):
    return max(1, len(text) // 3)                    # deliberately pessimistic: 3 characters per token


def build_body():
    return json.dumps({
        "messages": [{"role": "user", "content": [{"text": PROMPT}]}],
        "inferenceConfig": {"maxTokens": MAX_OUTPUT_TOKENS, "temperature": 0},
    }, separators=(",", ":"))


def converse_path(model_id):
    return "/model/" + quote(model_id, safe="") + "/converse"


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def canonical_request(method, path, query, headers, payload, service="bedrock"):
    """The SigV4 canonical request and the signed-header list. `path` is the path as SENT (already percent-encoded once);
    for every service except S3 it is encoded a second time, so ':' (sent as %3A) becomes %253A."""
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{headers[n]}\n" for n in names)
    signed = ";".join(names)
    canonical_uri = quote(path, safe="/-_.~") if service != "s3" else path
    creq = "\n".join([method, canonical_uri, query, canonical_headers, signed, hashlib.sha256(payload).hexdigest()])
    return creq, signed


def sign(method, host, path, query, headers, payload, access, secret, token, region, service, amzdate):
    """AWS Signature Version 4. Returns the headers to send (lower-case names), including `authorization`."""
    date = amzdate[:8]
    h = {k.lower(): v.strip() for k, v in headers.items()}
    h["host"], h["x-amz-date"] = host, amzdate
    if token:
        h["x-amz-security-token"] = token
    creq, signed = canonical_request(method, path, query, h, payload, service)
    scope = f"{date}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret).encode(), date)
    for part in (region, service, "aws4_request"):
        k = _hmac(k, part)
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return h


def mask(text):
    """Make an error message safe to print: 12-digit account ids and access key ids are masked."""
    text = re.sub(r"\b(AKIA|ASIA)[A-Z0-9]{12,}\b", "<key-id>", text)
    text = re.sub(r"(?<!\d)\d{12}(?!\d)", "<account>", text)
    return text.replace("\n", " ").replace("\r", " ")


def _post(url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def run(env, post=_post, out=sys.stdout, record=None, now=None):
    def val(name):
        return (env.get(name) or "").strip()      # a pasted secret often carries a trailing newline or space
    access, secret = val("AWS_ACCESS_KEY_ID"), val("AWS_SECRET_ACCESS_KEY")
    token, model = val("AWS_SESSION_TOKEN") or None, val("BEDROCK_MODEL_ID")
    region = val("AWS_REGION") or "us-west-2"
    if not (access and secret):
        print("error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the environment", file=out)
        return 2
    if not model:
        print("error: set BEDROCK_MODEL_ID to the exact model or inference profile id (see docs/runbooks/bedrock-probe.md step 3)", file=out)
        return 2
    if estimate_tokens(PROMPT) > MAX_INPUT_TOKENS:
        print("error: the fixed prompt is over the 300-token cap", file=out)
        return 2
    now = now or datetime.datetime.now(datetime.timezone.utc)
    host = f"bedrock-runtime.{region}.amazonaws.com"
    path = converse_path(model)
    body = build_body().encode()
    headers = sign("POST", host, path, "", {"content-type": "application/json"}, body, access, secret, token, region, "bedrock", now.strftime("%Y%m%dT%H%M%SZ"))
    status, rh, rb = post(f"https://{host}{path}", headers, body, 30)
    rid = rh.get("x-amzn-requestid", "")
    try:
        data = json.loads(rb or b"{}")
    except ValueError:
        data = {}
    print(f"model_id={model}", file=out)
    print(f"region={region}", file=out)
    print(f"http_status={status}", file=out)
    print(f"request_id={rid}", file=out)
    if status != 200:
        etype = rh.get("x-amzn-errortype") or str(data.get("__type", data.get("type", "unknown")))
        print(f"error_type={etype.split(':')[0].split('#')[-1][:80]}", file=out)
        msg = data.get("message", data.get("Message", "")) if isinstance(data, dict) else ""
        if msg:
            print(f"error_message={mask(str(msg))[:120]}", file=out)
        return 1
    u = data.get("usage", {})
    tin, tout = int(u.get("inputTokens", 0)), int(u.get("outputTokens", 0))
    price = price_for(model)
    cost = None if price is None else tin * price[0] / 1e6 + tout * price[1] / 1e6
    print(f"input_tokens={tin}", file=out)
    print(f"output_tokens={tout}", file=out)
    print(f"stop_reason={data.get('stopReason', '')}", file=out)
    if cost is None:
        print("est_cost_usd=unknown", file=out)
        print("est_cost_note=no price known for this model id; no estimate is given", file=out)
    else:
        print(f"est_cost_usd={cost:.7f}", file=out)
    if record:
        with open(record, "w") as f:
            json.dump({"v": 1, "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "region": region, "model_id": model, "http_status": status,
                       "request_id": rid, "input_tokens": tin, "output_tokens": tout, "stop_reason": data.get("stopReason", ""),
                       "est_cost_usd": None if cost is None else round(cost, 7)}, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(run(dict(os.environ), record=os.environ.get("PROBE_RECORD")))
