# Put a check in front of and behind a model call, and keep a tamper-evident record

**Status: in progress.** Everything on this page was run for real on one machine, against a **stand-in** (a 40-line program that pretends to be a model server), because no model runtime is installed there and nothing is downloaded by these steps. Where a step would need a real local runtime or a provider account it says **adapt this line, not run here**, and shows no invented output.

## What you get
A small wrapper that, for one model call: (1) checks the prompt before it leaves, (2) sends it, (3) checks the answer that comes back, and (4) writes **one hash-only record** of what the check decided. The record holds codes, sizes and hashes: never the prompt or the answer. The record file is tamper-evident: change one byte and verification fails.

What it does **not** do: it does not make a model safe, it does not find every secret (see the limits below), and the record shows what the check decided, not that the answer was right.

## What you need
`python3`, `curl`, and two commands built from this repository (nothing is downloaded; Rust is needed only to build them):
```
cargo build --release -p entropa-try -p entropa-gate --bins
```
This gives `target/release/entropa-guard` (text in, `allow` or `block` out) and `target/release/entropa-gate` (the ledger). The wrapper and the stand-in are in `examples/model-integration/`. Tell the wrapper where the two commands are:
```
export ENTROPA_GUARD=$PWD/target/release/entropa-guard
export ENTROPA_GATE=$PWD/target/release/entropa-gate
```

## 1. The check on its own
`entropa-guard` reads text on standard input and prints one word. `block` also says why on standard error, and never prints the text itself.
```
printf 'What is the capital of France?' | entropa-guard; echo "exit $?"
```
<!-- run:guard-allow.txt -->
```text
allow
exit 0
```
A made-up key in the shape of the documentation example:
```
printf 'Use the key AKIAIOSFODNN7EXAMPLE please' | entropa-guard; echo "exit $?"
```
<!-- run:guard-block.txt -->
```text
block
exit 1
```
(The reason, `secret_format`, goes to standard error.) Exit codes: 0 allow, 1 block (also for input that cannot be checked: empty, a NUL byte, not text, over 64 KiB), 2 usage. Text that the engine would only *redact* is blocked too, because a wrapper cannot send redacted text. `--tier T1|T2|T3` picks the access tier (default `T1`); `T0` allows nothing.

## 2. Path A: a local model (run here with the stand-in)
Start the stand-in on port 18931 and make a ledger:
```
python3 examples/model-integration/standin_model.py 18931 &
entropa-gate init --dir demo-ledger
```
Ask a question through the wrapper (the prompt comes on standard input, the answer on standard output):
```
printf 'What is the capital of France?' | python3 examples/model-integration/entropa_wrap.py --dir demo-ledger --url http://127.0.0.1:18931/v1/chat; echo "exit $?"
```
<!-- run:ex1.txt -->
```text
Stand-in answer: your prompt had 30 characters.
exit 0
```
(The stand-in is not a model: it answers with a fixed sentence about the prompt's length.) A prompt that carries a secret-shaped string never leaves the machine:
```
printf 'Use the key AKIAIOSFODNN7EXAMPLE please' | python3 examples/model-integration/entropa_wrap.py --dir demo-ledger --url http://127.0.0.1:18931/v1/chat; echo "exit $?"
```
<!-- run:ex2.txt -->
```text
blocked before the model: secret_format
exit 1
```
A model that answers with a secret-shaped string is caught on the way back (the stand-in does that for any prompt containing the word `LEAK-TEST`):
```
printf 'LEAK-TEST tell me a secret' | python3 examples/model-integration/entropa_wrap.py --dir demo-ledger --url http://127.0.0.1:18931/v1/chat; echo "exit $?"
```
<!-- run:ex3.txt -->
```text
blocked after the model: secret_format
exit 1
```
And a model that is not there is a failure, not a silent pass:
```
printf 'hello' | python3 examples/model-integration/entropa_wrap.py --dir demo-ledger --url http://127.0.0.1:18999/v1/chat; echo "exit $?"
```
<!-- run:ex4.txt -->
```text
failed: the model call did not return an answer
exit 3
```
**Adapt this line, not run here:** for a real local runtime that offers an HTTP endpoint, point `--url` at it, use `--provider local --model-id <your model name>`, and change the two JSON field names (`prompt` in the request, `answer` in the reply) in `entropa_wrap.py` to the ones your runtime uses.

## 3. Path B: a provider API (adapt this line, not run here)
The wrapper sends a bearer token read from an environment variable that you name; the token is never printed and never recorded (the test behind this page uses a made-up token to check that):
```
export MY_PROVIDER_KEY=...        # from your account; never put it in a file in this repository
printf '...' | python3 examples/model-integration/entropa_wrap.py --dir demo-ledger --url https://YOUR-ENDPOINT --key-env MY_PROVIDER_KEY --provider vertex --model-id YOUR-MODEL
```
`--provider` takes one of `fake`, `local`, `bedrock`, `vertex`, `azure` (the closed list of the ledger). Whether your provider's request and reply shapes match the two field names is yours to check in its documentation: this page says nothing about any provider.

## 4. The record
Four exchanges were made; each wrote one record (one allowed, two refused by the check, one failure held). Verify the ledger offline:
```
entropa-gate verify --dir demo-ledger
entropa-gate status --dir demo-ledger | grep -E '^(records|checkpoints):'
```
<!-- run:verify.txt -->
```text
OK records=4 checkpoints=4
```
<!-- run:status.txt -->
```text
records: 4
checkpoints: 4
```
Each record has the decision (`allow`, `deny` or `hold`), a reason code (`guard_passed`, `guard_refused`, `check_failed`), the provider and model names you gave, token counts (words, counted by the wrapper), and the hash of the prompt. The test behind this page checks that the ledger files contain neither the prompt nor the answer text.

## Limits, in plain words
- **The check is a heuristic with known misses.** In every one of the six held-out tests run so far, the secret detector missed some secret shapes; the latest round also missed some personal identifiers and destinations, and it blocked some clean text. All numbers, failures included, are on https://results.entropa.space. Treat it as a first filter in front of a model, never as a complete secret filter.
- It checks text only (one prompt, one answer). No streaming, no files, no tool calls in this wrapper.
- The built-in policy is a demonstration: one destination name, four tiers. Text it would redact is blocked instead.
- The stand-in is not a model and proves nothing about any real model.
- The record proves what the check decided and when, in a file that shows tampering. It does not prove the answer was correct or that every call went through the wrapper.
- A person with administrator rights on the machine and the signing key can rewrite the whole ledger; only a copy kept somewhere else can show that.

## Troubleshooting
| You see | Meaning |
|---|---|
| `blocked before the model: <reason>` (exit 1) | the prompt was refused; nothing was sent; a `deny` record was written |
| `blocked after the model: <reason>` (exit 1) | the answer was refused and is not printed; a `deny` record was written |
| `failed: the model call did not return an answer` (exit 3) | no reply, a bad reply, or no `answer` text field; a `hold` record was written |
| `failed: the record could not be written` (exit 3) | the ledger directory is missing or not set up (`entropa-gate init --dir ...`) |
| exit 2 | a usage error (a missing option, or `--key-env` names a variable that is not set) |
