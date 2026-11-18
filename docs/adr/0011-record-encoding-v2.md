# ADR 0011: Record encoding v2 (versioned, length-prefixed, canonical)
Date: 2026-10-20. Status: accepted (stage S0d). Fixes audit finding F4.

## Context
v1 joined payload and label with a NUL byte and did not reject NUL inside a payload, so `("a\0b", None)` and `("a", Some("b\0"))` produced identical bytes and identical Merkle leaf hashes; `Some("")` and `None` also collided by design. A signed log could not tell such records apart. The owner's requirement: **definite uniqueness**.

## Decision
A record is the pair `(payload: UTF-8 string, label: Option<UTF-8 string>)`. Its one and only valid byte string is:
```
0x02                       version (v1, the NUL form, was never tagged; 0x02 marks v2)
u32 big-endian             payload length n
n bytes                    payload (valid UTF-8)
0x00 | 0x01                label flag: 0 = no label, 1 = label present
[u32 big-endian, bytes]    only if flag = 1: label length m, then m bytes (valid UTF-8)
```
- **Injective:** the layout is prefix-free and every length is fixed width, so the bytes determine the fields; `None` (flag 0) and `Some("")` (flag 1, length 0) are different records with different bytes.
- **Canonical / bijective on valid encodings:** the strict decoder accepts exactly the byte strings the encoder can produce, so `encode(decode(b)) == b` for every accepted `b`. It rejects: empty or short input, unknown version, a length that runs past the end, flag other than 0 or 1, invalid UTF-8, trailing bytes, and any field longer than `MAX_FIELD_BYTES`.
- **Limits:** `MAX_FIELD_BYTES` = 1 MiB for the payload and 1 MiB for the label (maximum record 2 MiB + 10 bytes); `encode_record` returns `RecordError::FieldTooLarge` instead of truncating.
- **API:** `encode_record` and `decode_record` return `Result<_, RecordError>`. `decode_record_or_marker` is a display-only helper for views that must show something for undecodable bytes (never used for verification).
- Leaf hashing and leaf/node domain separation in merkle.rs are unchanged; only the bytes fed to `leaf_hash` change.
- **No legacy decoder:** nothing live depends on v1 (Scott, 2026-10-20), so v1 bytes are simply rejected.

## Consequences
Breaking change to entropa-core: version 0.2.0, changelog entry. Clients sending `label: ""` now produce a different leaf than `label` absent. Records are 5 to 9 bytes larger than v1. Golden vectors are under crates/core/tests/vectors/ (public test data).
