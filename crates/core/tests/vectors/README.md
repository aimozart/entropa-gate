# NIST FIPS-204 test vectors — provenance

> **PUBLIC TEST DATA, TEST ONLY.** Everything in this directory is public: NIST's published ACVP
> known-answer vectors (including their `seed` and `sk` fields, which are public KAT inputs, not
> credentials) and our own `record_v2.json` golden vectors (see `RECORD-V2-README.md`). No private
> key material of ours is committed anywhere in this repository; keys used in tests are generated at
> run time (`Probe::spawn()`) and never written to disk.


> **Not a secret.** `ml_dsa_65_acvp.json`'s hex strings are public NIST ACVP test data, not
> credentials. `scripts/secret-scan.sh` (gitleaks over the tree and full history) reports 0 leaks;
> this directory is allowlisted in `.gitleaks.toml` with that reason.

`ml_dsa_65_acvp.json` contains **official NIST ACVP known-answer test vectors** for
**ML-DSA-65**, extracted **verbatim and unmodified** from NIST's own repository.

| | |
|---|---|
| **Source** | <https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files> |
| **Files** | `ML-DSA-keyGen-FIPS204/internalProjection.json`, `ML-DSA-sigGen-FIPS204/internalProjection.json` |
| **Retrieved** | 2026-08-12 |
| **Parameter set** | ML-DSA-65 (NIST security category 3 — the set Entropa uses) |

## What's committed

A representative subset, so the test suite stays fast:

| Group | Vectors | ACVP group | Exercises |
|---|---|---|---|
| `keyGen` | 12 | tgId 2 | `ML-DSA.KeyGen_internal` — seed ξ → (pk, sk) |
| `sigGenInternalDeterministic` | 8 | tgId 10 | `ML-DSA.Sign_internal` — deterministic (rnd = 0³²) |
| `sigGenExternalPureDeterministic` | 8 | tgId 3 | `ML-DSA.Sign` — full path incl. context string |

## Running against the *complete* official set

```bash
./fetch.sh          # pulls NIST's full keyGen / sigGen / sigVer files
```

The committed subset is for convenience and CI speed — it is not a curated "vectors we
happen to pass." Every vector in the upstream ML-DSA-65 groups is expected to pass;
`fetch.sh` exists so that claim is independently checkable.

## What this proves (and what it doesn't)

**Proves:** Entropa's post-quantum signing produces byte-for-byte identical output to the
NIST reference for these official vectors — key generation, both signing interfaces, and
signature verification (including rejection of tampered signatures).

**Does not prove:** FIPS certification. Entropa is **not** FIPS-validated and makes no such
claim. Formal validation requires an accredited CMVP/CAVP lab. This is a *correctness*
artifact: built to the standard and demonstrably matching it, not certified against it.
