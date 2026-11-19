# Threat model: the operator of the machine (INS1, design only)

Status: design for review. Nothing here is built; no service is used. Wording rule for every page that quotes this document: the ledger is **tamper-evident**, never "tamper-proof" or "immutable", unless an outside copy exists, and then only for what that copy covers.

## 1. The known-undetectable case (stated first)
A person with administrator rights on the machine **and** the signing key can rewrite the whole ledger from the first record and sign it again. If nobody outside that person's control holds an earlier checkpoint, **nothing can show the rewrite**: the verifier reports `ok_unanchored` for the rewritten ledger, exactly as it does for the original. The same holds for a copied key used on another machine, and for a swapped program that simply does not write the record. What can be guaranteed is narrower: **a change is detectable by someone other than the operator, provided a checkpoint made earlier exists somewhere the operator does not control.**

## 2. What exists today (measured, not assumed)
- Every record is signed; checkpoints sign the Merkle root, the size and a caller-supplied timestamp (`crates/core/src/transparency_log/checkpoint.rs`: the signed bytes are root, size and timestamp only).
- One changed byte in a copy of the ledger fails verification (shown in the log-integrity demonstration of an earlier stage); truncation in the middle of a line is caught as a format error; cutting whole records but leaving the newest checkpoint is caught (the ledger check requires the last checkpoint to cover exactly the records present: `crates/nodecore/src/lib.rs`, `verify_ledger`); cutting whole records AND the checkpoints beyond the cut leaves a validly signed older checkpoint that matches, and is not caught.
- A witness design and code exist (`crates/witness`, docs/ARCHITECTURE-WITNESS.md): it checks the signature, a consistency proof from the last checkpoint it accepted, and signs "I saw this root at this size". No witness is running for a client install.
- There is no outside anchor on a client install, no counter, no link to the previous checkpoint, and the timestamp is whatever the caller passes.

## 3. Adversary and assets
Adversary: the operator of the host (root on the machine, can read the signing key file, can run any program, can set the clock, can delete any local file, can show different files to different people). Not in scope: breaking ML-DSA, the witness or timestamp service being run by the same operator, and a reader who never compares anything with an outside copy.
Assets: the records (what was decided and when), the order of records, the completeness of the log up to a checkpoint, the identity of the signer, the times.

## 4. Attack classes and the verifier's expected closed result
The verifier answers with one closed code. "Outside copy" means an **anchor** held by someone the operator does not control: either hash-only (size, root, and from v2 the counter) or the signed checkpoint itself (better). Some attacks give the same observation and therefore the same code; the table says so.

| # | Attack | No outside copy | With an outside copy older than the change |
|---|---|---|---|
| A1 | Rewrite all records, sign again with the same key | `ok_unanchored` (undetectable, section 1) | signed anchor: `fork_detected` (the key signed two roots for one size); hash-only anchor: `rewritten_since_anchor` |
| A2 | Cut off the end (drop the newest records) | `format_error` if cut inside a record; `checkpoint_mismatch` if whole records were cut but the newest checkpoint was kept; `ok_unanchored` if the checkpoints beyond the cut were removed too | `rolled_back` (the ledger is shorter than the anchor; the same observation as A3) |
| A3 | Restore an older complete copy (backup rollback) | `ok_unanchored` | `rolled_back` (shorter than the anchor, or a lower v2 counter at the anchored size) |
| A4 | Copy the signing key out and sign elsewhere | `ok_unanchored` | `fork_detected` only when a signed anchor and a validly signed checkpoint disagree at one size; otherwise undetectable. A key that cannot be exported prevents the attack instead (section 7) |
| A5 | Set the clock back | v1: `ok_unanchored` (no counter to compare). v2: `clock_regression` when a higher counter carries an earlier time | a signed time stamp of an anchor adds a lower bound (later step, off by default) |
| A6 | Replace the program | undetectable by the ledger; only checking the program's own signature and hash against the published one catches it | same |
| A7 | Delete the anchor | `anchor_missing` when the install expects an anchor | if every outside copy is destroyed: undetectable |
| A8 | Show different histories to different readers | undetectable for one reader | `fork_detected` when two readers or witnesses compare signed checkpoints for one size (the same observation as A1 with a signed anchor) |
| A9 | Never write a record (omission) | out of scope: the log cannot show what was never given to it | same |
Other closed codes: `ok_anchored` (with N), `ok_unanchored`, `signature_invalid` (a checkpoint's signature fails under the key it claims), `key_changed_unlogged` (validly signed by a key other than the expected one, no rotation record), `checkpoint_mismatch` (records and checkpoints disagree: the root at a checkpoint's size, the last checkpoint not covering exactly the records present, a broken chain link, a skipped or repeated counter), `format_error` (the input cannot be parsed).
`fork_detected` exactly: a signed anchor (it verifies under the log's key) and a validly signed checkpoint of the ledger name **the same size, or the same v2 counter, with different roots** (the key signed two roots for one slot). A signed anchor whose signature fails, or that is signed by another key, is treated as hash-only. `rolled_back` exactly: the ledger holds fewer records than an anchor's size, or its newest v2 counter is lower than the anchor's counter. `rewritten_since_anchor` exactly: an anchor's size is within the ledger and its root differs from the root recomputed from the records at that size (and no fork was found).
**`ok_anchored(N)` means: consistent with an anchor of size N, and nothing about records after N.** `ok_unanchored` means: verified, and no outside copy exists to compare with.

### Precedence (fixed; the first that applies wins, so every planted ledger has exactly one expected code)
1. `format_error` (raised by the reader before anything else; always wins)
2. `signature_invalid`
3. `key_changed_unlogged`
4. `checkpoint_mismatch`
5. `fork_detected`
6. `rewritten_since_anchor`
7. `rolled_back`
8. `clock_regression`
9. `anchor_missing`
10. `ok_anchored(N)` (N = the largest anchored size), else `ok_unanchored`
For the sealed set: each case is one class run with and without an outside copy; cases that trip two conditions expect the higher-precedence code. The verifier must never answer `ok_anchored` for a changed ledger, and never raise an alarm on an unchanged one (the false alarm rate is a reported number).

## 5. Checkpoint v2 (additive; v1 verification unchanged)
A v1 checkpoint signs `root || size || timestamp` and keeps verifying exactly as today (existing tests unchanged); a v1 ledger is reported as `ok_unanchored` or `ok_anchored` and labelled "no rollback protection". A v2 checkpoint signs a **domain tag, a counter, the previous checkpoint's digest, the root, the size and the timestamp**:
| Field | What it binds | Attack it helps with, and how far |
|---|---|---|
| domain tag (`entropa-checkpoint-v2`) | the signature cannot be moved to another kind of record or to a v1 reading | cross-protocol reuse of a signature |
| counter (strictly +1 per checkpoint, even at the same size) | the order of checkpoints independent of the clock | A3 and A5: a lower counter than an anchor is a rollback; a higher counter with an earlier time is a clock regression. It does not stop a full re-signing (A1); that needs the outside copy |
| previous checkpoint digest | a hash chain of checkpoints: a held checkpoint at counter k fixes every checkpoint before it | A1 and A2 against any anchor at or after k: the chain cannot be rebuilt differently below it. Without an anchor it is only internal consistency |
| root and size | as today | |
| timestamp | as today (still caller-supplied) | only meaningful together with the counter and, if present, a time stamp from outside |
Size already acts as a monotonic number for records; the counter exists because two different checkpoints can share one size, and because the time is not trustworthy. Open question for review: whether the previous-digest chain should also cover key events (D3).

### 5a. Who writes v2, the transition, and what clock_regression can and cannot show (slice 3)
- **Writers.** `entropa-gate record` (and the gate's library `node::record`) issues v2 checkpoints. `entropa-platinum log` keeps issuing v1: the format of the deployed node is unchanged, and its pinned bytes are byte-identical. The shared library has both writers (`append` = v1, `append_v2` = v2).
- **The v2 chain.** Counter 1 for the first v2 checkpoint, then +1 at every checkpoint (also when the size did not change); `prev` is the chain digest of the previous v2 checkpoint, 32 zero bytes for the first. The chain digest covers the signed bytes **and the signature**, so changing any earlier checkpoint breaks every later link (a damaged middle checkpoint stops the ledger from opening at all; a damaged newest one is named by the signature check).
- **Transition.** A ledger may start v1 and continue v2: the v2 chain starts at the switch (counter 1, previous digest zero). Once a v2 checkpoint exists, a v1 checkpoint may not follow (a downgrade): the writer refuses before writing anything, the store refuses at write and at load, and `check` answers `checkpoint_mismatch`. `check` reports the format on its second line: `format=v1`, `format=v2`, `format=v1+v2` (or `none`).
- **The checkpoint time.** The writer signs `max(event time, previous checkpoint time)`, so a time that goes backwards never comes from a genuine writer (the record's own event time is untouched). **Consequence for A5, stated plainly:** a clock set back on the host is **not** visible as `clock_regression` when the genuine writer keeps writing; the checkpoint times just stay at the earlier maximum until the clock catches up. `clock_regression` is shown only for a checkpoint chain made by hand or by a foreign writer that signs a lower time after a higher one, as the adversary of this model can do with the signing key. What it means: with an outside time stamp or an anchor, a changed or backdated history is caught by those, not by the counter; the counter alone only catches clumsy tampering with the order of times. A5 stays one of the classes that is detected only with an outside copy.

## 6. Anchoring options (each hash only; never record content)
| Option | What it gives | Cost and who must say go |
|---|---|---|
| Export file to a second machine or an auditor (`anchor export`: a small signed JSON of size, root, counter, time; the other side stores it) | the cheapest outside copy; works offline | none; no cloud |
| Witness co-signature (existing `entropa-witness` logic; a witness run by someone else) | detects split view (A8) and rollback against the witness's last accepted checkpoint | a hosted witness costs money and a cloud account: re-price from the provider's price list before any use (ARCHITECTURE-WITNESS section on cost is dated 2026-10-21) |
| Write-once storage (object lock or retention policy) | the operator cannot delete or change the outside copy for the retention time | cloud account and a few cents a month at this size: re-price; any cloud change needs the owner's go |
| RFC 3161 time stamp of the checkpoint hash | a third party's signed "this hash existed before T" (A5) | external service. **Approved in principle by the owner 2026-11-17, optional, OFF by default, hash only.** Before any real use: read the service's terms, availability and licence from its primary documents and get the owner's go for that specific service |
The verifier accepts any mix and reports the strongest it can confirm.

### 6a. The anchor file (format `entropa-anchor` v1)
One text file, **one line**, one JSON object with exactly these seven keys (sorted, no spaces when written by the tool; the reader also accepts one final newline):
| Key | Value |
|---|---|
| `v` | the number 1 |
| `type` | the string `anchor` |
| `log_id` | 64 lower-case hex digits: BLAKE3 of the log's public key (the key's bytes, not its hex text) |
| `size` | the number of records the checkpoint covers (whole number, at most 2^53 - 1) |
| `root` | 64 lower-case hex digits: the Merkle root at `size` |
| `counter` | the v2 counter (at least 1) or `null` |
| `checkpoint` | `null` (a hash-only anchor) or the signed checkpoint the anchor was made from |
A signed checkpoint is `{"v":1,"root","size","timestamp","proposer_pubkey","signature"}` (v1) or `{"v":2,"counter","prev","root","size","timestamp","proposer_pubkey","signature"}` (v2); `prev`, `root` are 64 lower-case hex digits, the key and the signature are lower-case hex (the ML-DSA-65 key is 3,904 hex digits, the signature 6,618).
**The reader refuses** (never a verdict): text over 32 KiB; anything other than one line; invalid JSON; a repeated key; an unknown or missing key; a wrong version or type; upper-case or wrong-length hex; numbers that are negative, fractional, zero for a counter, or above 2^53 - 1; an embedded checkpoint whose size, root or counter differ from the top-level fields; a v1 checkpoint together with a counter; a signed checkpoint whose key does not hash to `log_id`; and (when checking a ledger) an anchor whose `log_id` is another log's. Messages never repeat any part of the file. A hash-only anchor may carry the counter (it is the hash form of a v2 checkpoint) or not.
Worked example, hash-only (this exact line is the golden text of the test):
```
{"checkpoint":null,"counter":2,"log_id":"1111111111111111111111111111111111111111111111111111111111111111","root":"2222222222222222222222222222222222222222222222222222222222222222","size":6,"type":"anchor","v":1}
```
Worked example, signed v2 (a real file is 10,959 bytes; the two long hex values are shortened here, never in a real file):
```
{"checkpoint":{"counter":3,"prev":"0505050505050505050505050505050505050505050505050505050505050505","proposer_pubkey":"3e33bb4f163b6758...(3904 hex digits)","root":"43d6f737244c349eb862565590cc49452ac9907546c5ec9185cc39c623287033","signature":"ea5bb4cece87c4ef...(6618 hex digits)","size":4,"timestamp":2000,"v":2},"counter":3,"log_id":"a7f271ea7f5ab61fd6c56a4a26d07d411d1a6cb7dd20190f4b69ee58d9b60c3c","root":"43d6f737244c349eb862565590cc49452ac9907546c5ec9185cc39c623287033","size":4,"type":"anchor","v":1}
```
(The example key is a public test value; it protects nothing.) The v2 checkpoint signs `entropa-checkpoint-v2\0 || counter(8, big-endian) || prev(32) || root(32) || size(8) || timestamp(8)`; `prev` is the chain digest of the previous checkpoint: BLAKE3 of `entropa-checkpoint-chain-v2\0 || (the signed bytes of that checkpoint) || (its signature as the hex text)`, and 32 zero bytes for the first.

### 6b. The commands (slice 2b)
Ledger layout read by the verifier: `DIR/ledger/records.log` (one lower-case hex line per record, at most 64 KiB of bytes each) and `DIR/ledger/checkpoints.log` (one JSON line per checkpoint: a v1 checkpoint `{"root","size","timestamp","proposer_pubkey","signature"}` or a v2 checkpoint, recognised by its `counter` key); `DIR/platinum.key` holds the signing seed (the verifier only derives the public key from it). A checkpoint line is **strict JSON with a closed key set**: a repeated key, an unknown key or a missing key is a `format_error` (v1: `root`, `size`, `timestamp`, `proposer_pubkey`, `signature`; a line with a `counter` is v2 and adds `counter` and `prev`), and `size`, `timestamp` and `counter` must be whole numbers not above 2^53 - 1. The older `verify` command refuses the same lines. All hex is **lower-case**: an upper-case digit in `records.log`, or in the root, previous digest, signature or key of a checkpoint line, is a `format_error` (the older `verify` command refuses it too; no writer emits upper case). Every line ends with a newline; a last line without one is a format error. Lines longer than 128 KiB (records) or 32 KiB (checkpoints), NUL bytes, invalid UTF-8, bad hex, bad JSON and unknown checkpoint shapes are all `format_error`.
```
entropa-gate check --dir DIR [--anchor FILE]... [--require-anchor]
entropa-gate anchor export --dir DIR --out FILE [--signed]
```
**Options are strict** (all `entropa-gate` subcommands): an unknown or misspelled option (for example `--require-anchors`), an extra word, a missing value, or an option that may not repeat (`--dir`, `--out`, `--require-anchor`, `--signed`; only `--anchor` may repeat) is a usage error: exit 2, the usage line on standard error, **no verdict line**. An option that takes a value takes the next word as that value, whatever it looks like. `check` prints exactly two lines on standard output: `verdict: <code>` (with ` N` after `ok_anchored`) and `records=R checkpoints=C anchors=A`. It never prints record content. When no anchor was given and the verdict is `ok_unanchored`, one `warning:` line goes to standard error (the verdict stays `ok_unanchored`). Exit codes: 0 for `ok_anchored` and `ok_unanchored`; 1 for every other verdict (and for an unreadable key or ledger directory); 2 for a usage error; 3 when an anchor file is refused (unreadable, larger than 32 KiB, not a valid anchor, or for another log: standard error says `refused: ...`, no verdict line is printed). `--require-anchor` with no `--anchor` answers `anchor_missing` (exit 1). A record whose own signature or kind does not verify is reported as `signature_invalid`, but only after the checkpoint checks pass (the precedence list decides). `anchor export` refuses (exit 1, nothing written) when the ledger does not verify, when it has no checkpoint, or when the output file already exists; it writes the newest checkpoint as an anchor file (hash-only, or with `--signed` the signed checkpoint itself) and prints `anchor written: size=N` (plus ` counter=C` for a v2 checkpoint). The existing `entropa-gate verify` command and its output are unchanged.

### 6c. Planting ledgers with the product (for test and review work)
An honest ledger: write the key file yourself (`DIR/platinum.key`: 64 hex digits and a newline, mode 0600, the directory 0700; `DIR/ledger/` must exist), then give `entropa-gate record --dir DIR` one JSON request on standard input per record (closed vocabulary; the fields are `label`, `decision`, `reason`, `input`, `output`, `run_id`, `provider`, `model_id`, `input_tokens`, `output_tokens`, `cost_micro_usd`, `ts`; for example `{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question 1","output":"SELECT 1","run_id":"run-1","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":4,"cost_micro_usd":9,"ts":1700000001}`). Every record writes one v2 checkpoint. A ledger that starts with v1 checkpoints: write the first records with `entropa-platinum log` (v1), then continue with `entropa-gate record`.
Rewrite, cut, restore, flip and hostile-file attacks are file edits (section 4). Attacks that need a signature are planted with a **test helper that is not part of the shipped binary** (cargo feature `plant`): `cargo run --features plant --example plant_checkpoints -- DIR < spec.json` replaces `DIR/ledger/checkpoints.log` with a hand-made chain, signed with the ledger's own key or another seed:
```
{"signer_seed": "<64 hex digits, optional: sign with another key>",
 "checkpoints": [ {"v": 1|2, "size": N, "time": T,
                   "counter": C,      /* v2 only, default: previous v2 counter + 1 */
                   "prev": "<64 hex>", /* v2 only, default: chain digest of the previous v2 checkpoint of the spec, zero for the first */
                   "root": "<64 hex>"  /* default: the Merkle root of the first N records */ }, ... ]}
```
Nothing is written unless the whole spec is valid; unknown keys are refused. Worked example (a real run): three records, then a clock that runs backwards.
```
$ entropa-gate check --dir DIR
verdict: ok_unanchored
records=3 checkpoints=3 anchors=0 format=v2        (and the warning line on standard error, exit 0)
$ echo '{"checkpoints":[{"v":2,"size":1,"time":100},{"v":2,"size":2,"time":300},{"v":2,"size":3,"time":200}]}' | plant_checkpoints DIR
planted 3 checkpoints
$ entropa-gate check --dir DIR
verdict: clock_regression
records=3 checkpoints=3 anchors=0 format=v2        (exit 1)
```
Mapping of the classes to plants: A1 and A4 (rewrite, key copy-out): a second ledger from the same key file with other records, or `signer_seed` of the key; A5 (clock): a v2 chain with a lower `time` after a higher one; counter faults: `counter` or `prev` set by hand; downgrade: a `{"v":1}` entry after a `{"v":2}` one; wrong root: `root` set by hand; another signer: `signer_seed`.

## 7. Keys
- Today: a software key per ledger (decisions.key, evidence.key, optional council.key; KEYS1) in a file with owner-only rights. Anyone with root can copy it (A4).
- A non-exportable key: the project already signs checkpoints with ML-DSA-65 in a cloud key service (AWS KMS, where the private key cannot be read out). For a machine-local hardware key (TPM or a hardware token) **whether the device supports ML-DSA-65 at all must be read from the device's and the standard's primary documents before any design commits to it; this document does not assume it.** If it does not, the honest local option is a seed sealed to the TPM (protects the file at rest and against copying the disk, **not** against root using the key on the running host), labelled as the weaker option.
- Rotation: replacing a key is a signed event in the ledger (old key signs the new key and the counter), so a silent key change is `key_changed_unlogged`.

## 8. Host separation (friction, not a guarantee)
The writer runs as its own operating-system user; the ledger files are append-only for it (the append-only file attribute); administrator changes to the install need the two-person approval already built; the verifier runs as a third role with read-only access. Root can undo each of these (remove the attribute, become the writer). They raise the cost and leave traces; they are not a defence against the root operator, and the documents must say so.

## 9. Limits that stay
No outside copy means no detection (section 1). One anchor is one party to trust. A time stamp bounds a time from below only. A swapped program is outside the ledger's reach. Omission is not detectable. Nothing here says anything about whether the recorded decisions were right.
