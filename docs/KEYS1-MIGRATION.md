# KEYS1 migration note: one key per ledger

**If you have an old node with the single `platinum.key`: you do not have to do anything.** It keeps logging and verifying as before (the legacy key is used for every ledger that has no key of its own). Separating the keys is optional and is described below. **Google Cloud KMS still uses ONE key for all ledgers** (`ENTROPA_GCP_KMS_KEY`); per-ledger KMS keys are a later stage.

**What changed.** A node signs three ledgers (AI decisions, evidence, council). Before KEYS1 they shared one key file, `platinum.key`. Now each ledger has its own: `decisions.key`, `evidence.key`, and an optional `council.key`. `entropa-platinum init DIR` creates the first two (distinct, mode 0600); `entropa-platinum keys-add DIR council` creates the council key on demand and never overwrites an existing file.

**What did not change.** A node that only has `platinum.key` keeps working and verifying exactly as before: a ledger without a key of its own falls back to the legacy shared key. Nothing is re-signed; old records stay valid under the key that signed them.

**See where you stand.** `entropa-platinum keys-check DIR` prints one line per ledger (`decisions source=own key_id=...`); it exits non-zero when any ledger still uses the legacy shared key, or when two ledgers have the SAME own key. `keys-check DIR --allow-legacy` accepts the legacy state but still prints `legacy_shared`, so the state is visible. No key material is printed, only the key id.

**Separating an existing node (the owner's decision; KEYS1 deploys nothing).**
1. Run `keys-add DIR evidence` (and `decisions` if you want it). From then on new evidence records are signed under `evidence.key`.
2. An existing ledger cannot be re-signed, so records already written under the shared key do NOT verify under the new key. Start a NEW ledger directory for the separated ledger and keep the old one, read-only, verified under the legacy `platinum.key` (use `verify_with` under the old public key). The explorer should show both epochs.
3. When every ledger has its own key, move `platinum.key` out of the node directory and run `keys-check DIR` (no flag): it must exit 0.

**Environment overrides.** `PLATINUM_KEY_FILE_DECISIONS`, `PLATINUM_KEY_FILE_EVIDENCE`, `PLATINUM_KEY_FILE_COUNCIL` name a mounted secret for one ledger; `PLATINUM_KEY_FILE` still names the legacy shared secret.

**Limits (stated).** Google Cloud KMS: `ENTROPA_GCP_KMS_KEY` is still ONE key for all ledgers (KEYS1 does not create per-ledger KMS keys; a later stage). A shared KMS key is not reported by `keys-check` (it checks files). Scripts that looked for `platinum.key` (deploy-evidence.sh, scripts/ci/module.sh, tools/controls/receipts.py) now accept `evidence.key` too.
