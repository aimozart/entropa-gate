# Check a bundle in your browser

**Status: in progress.** The page and the module are built and tested locally; they are not hosted yet.

## What it does
You pick a downloaded bundle file (the static `.json` file the explorer offers). The page checks it **inside your browser** and tells you one of five things. Nothing is uploaded: the page's security policy forbids it from making any network request at all (`connect-src 'none'`), and the checker module has no imports, so it cannot reach the network, the clock or a random number source.

| Result | Meaning |
|---|---|
| Verified | every signature, proof and hash in the bundle checks out; the page also shows the counts it checked (records, signed checkpoints, receipts, consistency proofs, witness statements, signatures) |
| Refused: does not verify | the file is well formed, but something in it was changed or does not match its signatures |
| Refused: not a valid bundle | the file is not a bundle in the expected format (including text that is not JSON, repeated keys, unexpected fields) |
| Refused: too large | bigger than 5 MiB |
| Refused: the checker stopped | the file could not be checked |

The page never repeats any text from the file you picked.

## What it is
A small WebAssembly program, written in Rust, built from the same verification code the command-line tools use. It only verifies: it contains no signing code and no key generation. Size: 321,417 bytes (117,559 bytes compressed). The page is one self-contained file that carries the module and shows the module's SHA-256 so you can compare it with a build you made yourself.

## Try it yourself
Build it: `scripts/bv1-build.sh OUT_DIR` (offline; needs the Rust toolchain with the `wasm32-unknown-unknown` target). It writes the module, the page (`checker.html`) and the test bundles, runs the tests, and prints the module's SHA-256. Open `checker.html`, choose a file from `OUT_DIR/corpus/`: `valid-small.json` shows "Verified"; any `tamper-*.json` is refused.

## What has been tested
38 test bundles (two valid, the rest damaged in one specific way each, plus malformed and oversize files) and one 16 MiB file give the same answer in three places: the native verifier, the module under Node, and the real page in headless Chrome. On this machine the module checks about one record per millisecond.

## Honest limits
- The page checks a bundle against **its own** signatures and the keys it carries. It does not tell you that this is the bundle a particular site published; compare the bundle's head hash with the one the site shows.
- One browser (Chrome) on one machine has been tested.
- The checked bundles are limited to 5 MiB, which is roughly two hundred records of this format.
- The module's hash reproduces only with the same compiler version (the repository pins it).
- This checks the integrity of a bundle. It does not say anything about whether the decisions recorded in it were right.
