# CI-FIX 4: the workspace never passed `cargo clippy -D warnings` since the later egress and standards work
Found by running the cargo part of scripts/check.sh in a clean clone of the export (red.txt: the first error). Fixed with behaviour-neutral changes only:
- crates/egress/src/context.rs: ONE line removed (`let mut p = p;`, a redundant rebinding; p was already mutable). This is the same one-line change as in a later engine branch; the engine's behaviour and its 139 tests are unchanged. The file therefore differs from the version that the sealed round 6 measured by that one line.
- six scratch probe tests got a crate doc line; two useless `format!` calls and one `repeat().take()` and one `to_string()` in tests were simplified; cargo fmt reformatted a few egress test files.
- Not checked here (they need the network, which was not cleared): `--all-features` (pulls the AWS SDK crates), `cargo deny check` and `cargo audit` (fetch the advisory database).
