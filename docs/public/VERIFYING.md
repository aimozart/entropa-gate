# Verifying a ledger yourself

Three steps. They need no network and no account. The commands below were run on a local build; **no public release exists yet**, so a published program, a signed manifest and a key fingerprint are placeholders until the project publishes them. [evidence: stage record, not published]

## What you need

- The ledger copy (`ledger.tar` from the explorer bundle) and the public key of its signer (printed on the explorer page and in its data file). [evidence: docs/evidence/ls2/]
- The verify program, `entropa-mockview`, a single executable of about 2.4 MB for 64-bit Linux with glibc 2.34 or newer. [evidence: stage record, not published]

## The steps

1. **Check the program** before you run it: compare its sha256 with the signed manifest, and check the signature with the release public key (fingerprint obtained from a second place). The manifest tool is `entropa-release verify`, and `minisign` verifies the separate signature for people who prefer a common tool. [evidence: docs/evidence/s2e/]
2. **Unpack the ledger**: `mkdir led && tar -xf ledger.tar -C led`. The archive holds exactly three files: a marker file, the records and the checkpoints; it never holds a key. [evidence: docs/evidence/ls2/]
3. **Verify**: `entropa-mockview verify led PUBLIC_KEY_HEX`. It prints `OK records=N checkpoints=N` when every record and every checkpoint signature verifies, and a short refusal with a non-zero exit status otherwise. [evidence: crates/mockview/src/main.rs, docs/evidence/ls2small/real-1k.txt]

## What it checks, and what it does not

- It checks that every record and checkpoint was signed by the key you gave it and that the checkpoints match the records. It refuses a changed byte, a wrong key and a path with no ledger. [evidence: docs/evidence/public/container-verify.txt]
- It works on read-only media and needs no write access to the folder. [evidence: docs/evidence/ro-verify/]
- It does not tell you that the key belongs to who you think, that the program is honest unless you checked its signature, or that the traffic was real: the demo traffic is generated. [evidence: stage record, not published]

## Timing

- A 1,000-record ledger verifies in about a quarter of a second; a 10,000-record ledger in about two and a half seconds. [evidence: docs/evidence/ls2small/real-1k.txt, docs/evidence/ls2tar/real-10k.txt]
