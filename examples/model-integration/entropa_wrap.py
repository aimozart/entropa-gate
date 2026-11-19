#!/usr/bin/env python3
"""Put a check in front of and behind one model call and keep a tamper-evident record of it.
  entropa_wrap.py --dir LEDGER_DIR --url URL [--tier T1] [--provider fake|local|bedrock|vertex|azure] [--model-id NAME] [--key-env VAR] [--timeout 20] < prompt
Steps: (1) the prompt goes through `entropa-guard`; (2) if allowed, it is sent to URL as {"prompt": "..."} and the JSON field "answer" is read back; (3) the answer goes through the guard;
(4) ONE hash-only record is written with `entropa-gate record` (closed codes; the prompt and the answer are hashed by the gate and not stored). Nothing is printed except the answer, or one
`blocked ...` / `failed ...` line on standard error. The key named by --key-env is read from the environment, sent as a bearer token, and never printed or recorded.
Exit codes: 0 answered, 1 blocked (before or after the model), 3 the model call failed, 2 usage. Standard library only. Adapt the request and answer field names for your own endpoint."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

PROVIDERS = ("fake", "local", "bedrock", "vertex", "azure")


def guard(text, tier):
    """('allow', '') or ('block', reason)."""
    p = subprocess.run([os.environ.get("ENTROPA_GUARD", "entropa-guard"), "--tier", tier], input=text.encode(), capture_output=True)
    word = p.stdout.decode().strip()
    reason = p.stderr.decode().strip().removeprefix("reason: ")
    return ("allow", "") if (p.returncode == 0 and word == "allow") else ("block", reason or "guard_unavailable")


def record(dirname, decision, reason, prompt, answer, args):
    run_id = hashlib.sha256((prompt + "\0" + answer).encode()).hexdigest()[:32]
    req = {"label": "nl_query", "decision": decision, "reason": reason, "input": prompt, "output": answer, "run_id": run_id,
           "provider": args.provider, "model_id": args.model_id, "input_tokens": len(prompt.split()), "output_tokens": len(answer.split()), "cost_micro_usd": 0}
    p = subprocess.run([os.environ.get("ENTROPA_GATE", "entropa-gate"), "record", "--dir", dirname], input=json.dumps(req).encode(), capture_output=True)
    if p.returncode != 0:
        print("failed: the record could not be written", file=sys.stderr)
        sys.exit(3)


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--tier", default="T1")
    ap.add_argument("--provider", default="fake", choices=PROVIDERS)
    ap.add_argument("--model-id", default="stand-in")
    ap.add_argument("--key-env")
    ap.add_argument("--timeout", type=int, default=20)
    try:
        a = ap.parse_args()
    except SystemExit:
        sys.exit(2)
    prompt = sys.stdin.buffer.read(65537).decode("utf-8", "replace")
    verdict, why = guard(prompt, a.tier)
    if verdict == "block":
        record(a.dir, "deny", "guard_refused", prompt, "", a)
        print("blocked before the model: " + why, file=sys.stderr)
        sys.exit(1)
    headers = {"Content-Type": "application/json"}
    if a.key_env:
        key = os.environ.get(a.key_env)
        if not key:
            print("failed: the environment variable named by --key-env is not set", file=sys.stderr)
            sys.exit(2)
        headers["Authorization"] = "Bearer " + key
    try:
        req = urllib.request.Request(a.url, data=json.dumps({"prompt": prompt}).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=a.timeout) as r:
            answer = json.loads(r.read(1 << 20))["answer"]
        if not isinstance(answer, str):
            raise ValueError("answer is not text")
    except Exception:
        record(a.dir, "hold", "check_failed", prompt, "", a)
        print("failed: the model call did not return an answer", file=sys.stderr)
        sys.exit(3)
    verdict, why = guard(answer, a.tier)
    if verdict == "block":
        record(a.dir, "deny", "guard_refused", prompt, answer, a)
        print("blocked after the model: " + why, file=sys.stderr)
        sys.exit(1)
    record(a.dir, "allow", "guard_passed", prompt, answer, a)
    print(answer)


if __name__ == "__main__":
    main()
