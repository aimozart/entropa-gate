# Note on the published independent question set

`eval/sets/independent_questions.json` was written by an independent reviewer before any retrieval result existed. Two of its metadata fields (`author` and `note`) were edited for publication: the reviewer's name was replaced by the role word. The questions themselves are untouched.

Because those fields changed, the hash pinned for this file in `eval/FROZEN.json` and in `tests/frozen_sets.rs` is the hash of the PUBLISHED file (`c5f2258b5bc3a3e0673ad80a74dd149258a4f2efa85bfbc4a75631e09af4b49c`), not of the original (`c5f2258b5bc3a3e0673ad80a74dd149258a4f2efa85bfbc4a75631e09af4b49c`).

A second proof that does not depend on the metadata: the SHA-256 of the canonical JSON (keys sorted, no spaces, UTF-8) of each part of the questions, computed on the original and on the published copy, is identical:

| Part | SHA-256 of its canonical JSON (original = published) |
|---|---|
| `clause_addressed` (15 questions) | `f36b5bb74c83d49ee6c5d60d1b9ca816e2fd5aa73987020bd18d378f266ff679` |
| `out_of_corpus` (5 questions) | `2ac2a9c3c84a65f9977e497f5c025dadce309b833d84fbf5a76600fd866c6712` |
| the whole object without `author` and `note` | `68c394c28a4dccc98aa952c38e458ce5b0b151d24d84b7a42bf6237e9fb578bf` |

Recompute with: `python3 -c "import json,hashlib; d=json.load(open('crates/standards/eval/sets/independent_questions.json')); print(hashlib.sha256(json.dumps(d['clause_addressed'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())"`.
