# Reproducibility report: the entropa-gate package (measured 2026-11-17/18; SAME HOST)

**Claim made:** the Linux package of the client app (`entropa-gate-0.2.0-linux-x86_64.tar.gz`) is built from a committed source tree with `--locked --offline`, a static glibc link, `SOURCE_DATE_EPOCH`, `--remap-path-prefix` and no debug info, and two builds produce **byte-identical** binaries and a byte-identical tarball.
**Claim NOT made:** that someone on another machine gets the same bytes. Everything below was measured on ONE host.

## What was measured
| Check | Result |
|---|---|
| Two builds in different target directories, same source path, same toolchain (rustc 1.99.1) and crate cache | `entropa-gate` sha256 `5d6a980b…a855863` and `entropa-release` sha256 `77d3eab5…a9672` identical |
| Two assemblies of the tarball (sorted names, fixed mtime, owner 0/0, `gzip -n`) | tarball sha256 identical in the two builds (see the PKG1 report for the value of each release) |
| An independent rebuild by the reviewer, in a separate tree, with the same script | the `entropa-gate` sha256 was identical (same host, same toolchain image) |
| A third build from the same source in a DIFFERENT directory WITHOUT `--remap-path-prefix` (S2d) | **different** sha256: paths are embedded, so the remap flag is required (this is the check that shows the comparison can see a difference) |
| The SBOM of the shipped closure (`tools/release/sbom_shipped.py`) | 178 components (the lock lists 415 for every platform; the shipped Linux closure is smaller), 169 registry packages with their lock SHA-256, byte-identical on two runs |

## What is NOT proven
- **A second host.** Same machine, same kernel, same toolchain image, same crate cache: it proves repeatability here, not reproducibility elsewhere.
- **Another toolchain, linker or libc version.** The link is static glibc; a musl build or a different glibc would differ.
- **The crate sources themselves.** They come from the local registry cache; Cargo checks each crate against the checksum in `Cargo.lock`, and the SBOM lists those checksums, but the cache was filled by a download we did not repeat from scratch for this report.
- **That the code is safe.** Reproducible bytes show that a binary corresponds to a source tree; they say nothing about the source's quality (no independent review yet).

## How a third party can check (needs only a Linux machine with the same Rust toolchain)
1. Check out the commit named in the release notes. 2. Run `scripts/pkg1-build.sh DIR` (it builds twice and reports whether the two agree). 3. Compare `entropa-gate sha256` in `DIR/report.txt` with the published one. A difference is a finding, not a failure to hide: report it. 4. Verify the signatures with the public key obtained from a second channel (see INSTALL-THE-GATE).
