"""Compare scripts/probe_bedrock.py's SigV4 with botocore (the AWS SDK reference) offline: fake credentials, no network.
Run: uv run --with botocore python3 docs/evidence/s11c-botocore-compare.py   (an ephemeral uv environment; nothing is installed)"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"))
import probe_bedrock as pb
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

AK, SK = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
DATE, HOST, REGION = "20260101T000000Z", "bedrock-runtime.us-west-2.amazonaws.com", "us-west-2"
BODY = b'{"messages":[]}'
MODELS = ["amazon.nova-lite-v1:0", "us.anthropic.claude-haiku-4-5-20251001-v1:0",
          "arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.amazon.nova-lite-v1:0"]
ok = True
for model in MODELS:
    path = pb.converse_path(model)
    for token in (None, "TOKEN/with+chars=="):
        req = AWSRequest(method="POST", url=f"https://{HOST}{path}", data=BODY, headers={"content-type": "application/json"})
        auth = SigV4Auth(Credentials(AK, SK, token), "bedrock", REGION)
        req.context["timestamp"] = DATE
        auth._modify_request_before_signing(req)
        creq = auth.canonical_request(req)
        sig = auth.signature(auth.string_to_sign(req, creq), req)
        mine = pb.sign("POST", HOST, path, "", {"content-type": "application/json"}, BODY, AK, SK, token, REGION, "bedrock", DATE)
        my_creq, _ = pb.canonical_request("POST", path, "", {k: v for k, v in mine.items() if k not in ("authorization",)}, BODY)
        same_creq = creq == my_creq
        same_sig = f"Signature={sig}" in mine["authorization"]
        ok = ok and same_creq and same_sig
        print(f"{'token' if token else 'no-token':8} {model[:44]:44} canonical_request_equal={same_creq} signature_equal={same_sig}")
        if not same_creq:
            print("  botocore canonical URI:", creq.split("\n")[1]); print("  ours      canonical URI:", my_creq.split("\n")[1])
print("ALL EQUAL" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
