"""Offline tests for scripts/probe_bedrock.py (S11b-prep). No network, no credentials, synthetic data only."""
import io, json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import probe_bedrock as pb

# AWS Signature Version 4 test suite, case "get-vanilla" (documented values).
AK, SK = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


class Sigv4(unittest.TestCase):
    def test_get_vanilla_signature_matches_the_published_value(self):
        h = pb.sign("GET", "example.amazonaws.com", "/", "", {}, b"", AK, SK, None, "us-east-1", "service", "20150830T123600Z")
        self.assertIn("Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", h["authorization"])
        self.assertIn("Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request", h["authorization"])
        self.assertIn("SignedHeaders=host;x-amz-date", h["authorization"])

    def test_the_session_token_is_signed_and_sent(self):
        h = pb.sign("POST", "h.example.com", "/p", "", {"content-type": "application/json"}, b"{}", AK, SK, "TOKEN123", "us-west-2", "bedrock", "20150830T123600Z")
        self.assertEqual(h["x-amz-security-token"], "TOKEN123")
        self.assertIn("x-amz-security-token", h["authorization"])

    def test_the_model_id_is_percent_encoded_in_the_path(self):
        self.assertEqual(pb.converse_path("amazon.nova-lite-v1:0"), "/model/amazon.nova-lite-v1%3A0/converse")
        self.assertEqual(pb.converse_path("arn:aws:bedrock:us-west-2:1:inference-profile/p"), "/model/arn%3Aaws%3Abedrock%3Aus-west-2%3A1%3Ainference-profile%2Fp/converse")


class Limits(unittest.TestCase):
    def test_the_request_is_capped_at_300_input_and_50_output_tokens(self):
        body = json.loads(pb.build_body())
        self.assertLessEqual(body["inferenceConfig"]["maxTokens"], 50)
        self.assertLessEqual(pb.estimate_tokens(pb.PROMPT), 300)
        self.assertEqual(len(body["messages"]), 1)

    def test_a_missing_model_id_is_refused_without_a_network_call(self):
        calls = []
        rc = pb.run({"AWS_ACCESS_KEY_ID": AK, "AWS_SECRET_ACCESS_KEY": SK}, post=lambda *a, **k: calls.append(a), out=io.StringIO(), record=None)
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])

    def test_missing_credentials_are_refused_without_a_network_call(self):
        calls = []
        rc = pb.run({"BEDROCK_MODEL_ID": "m"}, post=lambda *a, **k: calls.append(a), out=io.StringIO(), record=None)
        self.assertNotEqual(rc, 0)
        self.assertEqual(calls, [])


class Output(unittest.TestCase):
    ENV = {"AWS_ACCESS_KEY_ID": AK, "AWS_SECRET_ACCESS_KEY": SK, "AWS_SESSION_TOKEN": "SESSIONTOKENVALUE", "BEDROCK_MODEL_ID": "amazon.nova-lite-v1:0"}

    def fake_ok(self, url, headers, body, timeout):
        return 200, {"x-amzn-requestid": "req-123"}, json.dumps({"usage": {"inputTokens": 20, "outputTokens": 3, "totalTokens": 23}, "stopReason": "end_turn", "output": {"message": {"content": [{"text": "ok"}]}}}).encode()

    def test_only_metadata_is_printed_never_secrets_or_the_answer(self):
        out = io.StringIO()
        rc = pb.run(self.ENV, post=self.fake_ok, out=out, record=None)
        text = out.getvalue()
        self.assertEqual(rc, 0)
        for secret in (AK, SK, "SESSIONTOKENVALUE"):
            self.assertNotIn(secret, text)
        self.assertNotIn('"text"', text)
        for wanted in ("amazon.nova-lite-v1:0", "input_tokens=20", "output_tokens=3", "request_id=req-123", "http_status=200"):
            self.assertIn(wanted, text)

    def run_with(self, model):
        out = io.StringIO()
        rc = pb.run(dict(self.ENV, BEDROCK_MODEL_ID=model), post=self.fake_ok, out=out, record=None)
        self.assertEqual(rc, 0)
        return out.getvalue()

    def test_the_cost_estimate_uses_the_nova_lite_price_list_numbers(self):
        self.assertIn("est_cost_usd=0.0000019", self.run_with("amazon.nova-lite-v1:0"))  # 20 x 0.06/1M + 3 x 0.24/1M

    def test_the_cost_estimate_is_model_aware_for_every_nova_lite_id_form(self):
        lite = "est_cost_usd=0.0000019"
        self.assertIn(lite, self.run_with("us.amazon.nova-lite-v1:0"))
        self.assertIn(lite, self.run_with("arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.amazon.nova-lite-v1:0"))

    def test_micro_and_pro_have_their_own_prices(self):
        self.assertIn("est_cost_usd=0.0000011", self.run_with("amazon.nova-micro-v1:0"))  # 20 x 0.035/1M + 3 x 0.14/1M
        self.assertIn("est_cost_usd=0.0000256", self.run_with("amazon.nova-pro-v1:0"))    # 20 x 0.80/1M + 3 x 3.20/1M
        self.assertIn("est_cost_usd=0.0000256", self.run_with("us.amazon.nova-pro-v1:0"))

    def test_other_models_and_other_nova_versions_get_no_estimate(self):
        for other in ("us.amazon.nova-premier-v1:0", "amazon.nova-lite-v2:0", "amazon.nova-pro-v2:0", "example.unknown-model-v1:0"):
            self.assertIn("est_cost_usd=unknown", self.run_with(other), other)

    def test_an_unknown_model_gets_no_estimate_and_the_output_says_so(self):
        text = self.run_with("example.unknown-model-v1:0")
        self.assertIn("est_cost_usd=unknown", text)
        self.assertIn("no price known for this model id", text)
        self.assertNotIn("est_cost_usd=0.", text)

    def test_an_unknown_model_is_recorded_with_a_null_estimate(self):
        path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "probe-record-unknown.json")
        pb.run(dict(self.ENV, BEDROCK_MODEL_ID="example.unknown-model-v1:0"), post=self.fake_ok, out=io.StringIO(), record=path)
        with open(path) as f:
            rec = json.load(f)
        os.remove(path)
        self.assertIsNone(rec["est_cost_usd"])

    def test_an_error_prints_the_type_and_status_only(self):
        def bad(url, headers, body, timeout):
            return 403, {"x-amzn-requestid": "req-9"}, json.dumps({"__type": "AccessDeniedException", "message": "You don't have access to the model"}).encode()
        out = io.StringIO()
        rc = pb.run(self.ENV, post=bad, out=out, record=None)
        t = out.getvalue()
        self.assertNotEqual(rc, 0)
        self.assertIn("http_status=403", t)
        self.assertIn("error_type=AccessDeniedException", t)
        for secret in (AK, SK, "SESSIONTOKENVALUE"):
            self.assertNotIn(secret, t)

    def test_the_recorded_result_is_data_minimal(self):
        path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "probe-record-test.json")
        pb.run(self.ENV, post=self.fake_ok, out=io.StringIO(), record=path)
        with open(path) as f:
            rec = json.load(f)
        os.remove(path)
        self.assertEqual(sorted(rec), ["est_cost_usd", "http_status", "input_tokens", "model_id", "output_tokens", "region", "request_id", "stop_reason", "ts", "v"])
        blob = json.dumps(rec)
        for secret in (AK, SK, "SESSIONTOKENVALUE"):
            self.assertNotIn(secret, blob)
        self.assertNotIn("text", rec)   # the model's answer is never recorded


# ---- S11c-fix: canonical request vectors written BY HAND from the SigV4 specification ----
# How these expected values were obtained (no code shared with scripts/probe_bedrock.py):
#  1. Canonical request layout and the "URI-encode each path segment twice for non-S3 services" rule are from the AWS
#     Signature Version 4 documentation ("Create a canonical request"). The request path that is SENT already has
#     ':' as %3A and '/' inside an ARN as %2F; the canonical URI encodes that string once more, so '%' becomes %25.
#  2. The body hash is hashlib.sha256 of the exact body bytes.
#  3. The signature below is recomputed here with a separately written loop (not the implementation's function).
#  4. The IAM ListUsers example is the worked example in the AWS SigV4 documentation (published signature).
BODY = b'{"messages":[]}'
DATE = "20260101T000000Z"


def expected_creq(path_canonical, host="bedrock-runtime.us-west-2.amazonaws.com"):
    import hashlib
    return "\n".join(["POST", path_canonical, "", "content-type:application/json", f"host:{host}", f"x-amz-date:{DATE}", "",
                      "content-type;host;x-amz-date", hashlib.sha256(BODY).hexdigest()])


def independent_signature(creq, secret, date, region, service):
    import hashlib, hmac
    key = ("AWS4" + secret).encode()
    for piece in (date, region, service, "aws4_request"):
        key = hmac.new(key, piece.encode(), hashlib.sha256).digest()
    sts = "AWS4-HMAC-SHA256\n" + DATE + "\n" + f"{date}/{region}/{service}/aws4_request\n" + hashlib.sha256(creq.encode()).hexdigest()
    return hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()


class ModelIdEncoding(unittest.TestCase):
    CASES = [
        ("amazon.nova-lite-v1:0", "/model/amazon.nova-lite-v1%3A0/converse", "/model/amazon.nova-lite-v1%253A0/converse"),
        ("us.amazon.nova-lite-v1:0", "/model/us.amazon.nova-lite-v1%3A0/converse",
         "/model/us.amazon.nova-lite-v1%253A0/converse"),
        ("arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.amazon.nova-lite-v1:0",
         "/model/arn%3Aaws%3Abedrock%3Aus-west-2%3A123456789012%3Ainference-profile%2Fus.amazon.nova-lite-v1%3A0/converse",
         "/model/arn%253Aaws%253Abedrock%253Aus-west-2%253A123456789012%253Ainference-profile%252Fus.amazon.nova-lite-v1%253A0/converse"),
    ]

    def test_the_sent_path_and_the_canonical_uri_for_real_model_ids(self):
        for model, sent, canonical in self.CASES:
            self.assertEqual(pb.converse_path(model), sent, model)
            creq = pb.canonical_request("POST", sent, "", {"content-type": "application/json", "host": "bedrock-runtime.us-west-2.amazonaws.com", "x-amz-date": DATE}, BODY)[0]
            self.assertEqual(creq, expected_creq(canonical), model)

    def test_the_authorization_signature_equals_an_independent_computation(self):
        for model, sent, canonical in self.CASES:
            h = pb.sign("POST", "bedrock-runtime.us-west-2.amazonaws.com", sent, "", {"content-type": "application/json"}, BODY, AK, SK, None, "us-west-2", "bedrock", DATE)
            want = independent_signature(expected_creq(canonical), SK, DATE[:8], "us-west-2", "bedrock")
            self.assertIn("Signature=" + want, h["authorization"], model)

    def test_the_aws_documentation_iam_example(self):
        # GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 on 20150830T123600Z, us-east-1, iam
        h = pb.sign("GET", "iam.amazonaws.com", "/", "Action=ListUsers&Version=2010-05-08",
                    {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, b"", AK, SK, None, "us-east-1", "iam", "20150830T123600Z")
        self.assertIn("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", h["authorization"])


class Hardening(unittest.TestCase):
    def test_pasted_whitespace_in_credentials_is_stripped(self):
        seen = {}

        def post(url, headers, body, timeout):
            seen["auth"] = headers["authorization"]
            return 200, {}, json.dumps({"usage": {"inputTokens": 1, "outputTokens": 1}}).encode()
        env = {"AWS_ACCESS_KEY_ID": AK + "\n", "AWS_SECRET_ACCESS_KEY": " " + SK + "\r\n", "AWS_SESSION_TOKEN": "TOK\n", "BEDROCK_MODEL_ID": "amazon.nova-lite-v1:0 \n"}
        pb.run(env, post=post, out=io.StringIO(), record=None)
        self.assertIn("Credential=" + AK + "/", seen["auth"])
        self.assertNotIn("\n", seen["auth"])


class ErrorOutput(unittest.TestCase):
    ENV = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLEEXAMPLE1", "AWS_SECRET_ACCESS_KEY": SK, "AWS_SESSION_TOKEN": "SESSIONTOKENVALUE", "BEDROCK_MODEL_ID": "amazon.nova-lite-v1:0"}

    def run_err(self, status, headers, body):
        out = io.StringIO()
        rc = pb.run(self.ENV, post=lambda *a, **k: (status, headers, json.dumps(body).encode()), out=out, record=None)
        return rc, out.getvalue()

    def test_the_error_type_comes_from_the_header_and_loses_its_url_suffix(self):
        rc, t = self.run_err(403, {"x-amzn-errortype": "InvalidSignatureException:http://internal.amazon.com/coral/com.amazon.coral.service/", "x-amzn-requestid": "r-1"},
                             {"message": "The request signature we calculated does not match the signature you provided."})
        self.assertNotEqual(rc, 0)
        self.assertIn("error_type=InvalidSignatureException\n", t)
        self.assertNotIn("internal.amazon.com", t)

    def test_the_message_is_cut_at_120_characters_and_masks_account_ids_and_key_ids(self):
        msg = "User: arn:aws:iam::123456789012:user/x is not authorized with key AKIAEXAMPLEEXAMPLE1 " + "z" * 200
        rc, t = self.run_err(403, {"x-amzn-errortype": "AccessDeniedException"}, {"message": msg})
        line = [l for l in t.splitlines() if l.startswith("error_message=")][0]
        self.assertLessEqual(len(line) - len("error_message="), 120)
        self.assertNotIn("123456789012", t)
        self.assertNotIn("AKIAEXAMPLEEXAMPLE1", t)
        self.assertIn("<account>", line)

    def test_no_other_header_value_is_ever_printed(self):
        rc, t = self.run_err(403, {"x-amzn-errortype": "X", "x-amzn-requestid": "r-2", "x-amz-secret-thing": "LEAKME", "authorization": "LEAKME2"}, {"message": "m"})
        self.assertNotIn("LEAKME", t)
        for secret in (SK, "SESSIONTOKENVALUE"):
            self.assertNotIn(secret, t)

    def test_a_non_json_error_body_is_survivable(self):
        out = io.StringIO()
        rc = pb.run(self.ENV, post=lambda *a, **k: (502, {}, b"<html>bad gateway 123456789012</html>"), out=out, record=None)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("123456789012", out.getvalue())


if __name__ == "__main__":
    unittest.main()
