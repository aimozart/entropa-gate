# Releasing entropa-core and entropa-kms
Nothing here has been run. Steps marked **[OWNER]** need the owner's crates.io or GitHub account; the author never holds a token (Trusted Publishing mints a short-lived one inside CI).

## One-time setup
1. **[OWNER]** crates.io, crate `entropa-core` (already trusted): confirm Settings > Trusted Publishing lists the GitHub repository that will run `release.yml`, workflow file `release.yml`, and (if used) environment `release`. The `repository` field in Cargo.toml currently says `github.com/aimozart/entropa-public`; the trusted publisher must name the repository that actually contains this workflow.
2. **[OWNER]** `entropa-kms` is a **new crate**: a Trusted Publisher can only be added to a crate that exists. So the very first `entropa-kms` upload cannot come from this workflow unless crates.io lets you configure a pending publisher for a new crate name (crates.io has a "pending trusted publisher" option under your account settings; use it for `entropa-kms`, same repository, workflow `release.yml`). If that option is unavailable, publish `entropa-kms` 0.2.0 once by hand with a short-lived token **[OWNER]**, then add the trusted publisher and use the workflow from the next version on.
3. **[OWNER]** GitHub: create the `release` environment (Settings > Environments) and add yourself as a required reviewer so a tag push waits for your approval.

## Per release
1. Bump `version` in the workspace Cargo.toml, update CHANGELOG.md, run `./scripts/check.sh` (must exit 0) and `DRY_RUN=1 ./scripts/release-publish.sh` (packages and verifies, uploads nothing).
2. Commit and merge to the release branch **[OWNER: merges are yours]**.
3. **[OWNER]** Tag and push: `git tag v0.2.0 && git push origin v0.2.0`. The tag must equal the workspace version (the workflow checks).
4. The workflow runs check.sh, the dry run, builds the SBOM (artifact `sbom-cyclonedx`), mints the crates.io token through OIDC and runs `cargo publish -p entropa-core -p entropa-kms` (dependency order, waits for the index).
5. **[OWNER]** Approve the `release` environment prompt if you enabled it. Afterwards check https://crates.io/crates/entropa-core and docs.rs built the docs.

## Notes
- entropa-api is `publish = false` and is never released. clinic-ops stays pinned to entropa-core 0.1.3 until it is adapted: 0.2.0 removed the old `chain`, `block` and `beacon` modules and changed the record encoding (see CHANGELOG and docs/evidence/s0e-semver-checks-forced.txt).
- `entropa-node` 0.1.2 on crates.io depends on entropa-core `^0.1`, so it keeps resolving to 0.1.x and is unaffected until it is rebuilt against 0.2.
- Yanking or deleting a published crate version is a human decision and is never done by the author.
