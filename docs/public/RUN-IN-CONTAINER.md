# Running the checks in a clean container

A reader who prefers not to install anything can run the verify program inside a container with no network and a read-only file system. The command and its output were recorded on a Debian 12 image (glibc 2.36). [evidence: docs/evidence/public/container-verify.txt]

```
docker run --rm --network none --read-only \
  -v /path/to/entropa-mockview:/usr/local/bin/entropa-mockview:ro \
  -v /path/to/led:/led:ro \
  IMAGE entropa-mockview verify /led PUBLIC_KEY_HEX
```

- With the real ledger it prints `OK records=1000 checkpoints=1000` and exits 0. [evidence: docs/evidence/public/container-verify.txt]
- With one byte of the records file changed, it refuses (a checkpoint does not match the records) and exits 1. [evidence: docs/evidence/public/container-verify.txt]
- With a wrong public key it refuses (a signature does not verify) and exits 1; with a folder that holds no ledger it refuses and exits 1. [evidence: docs/evidence/public/container-verify.txt]

## Building the program in a container

- The build script builds one program in two fresh containers with no network from the same source and compares the results; on one host they were identical, and a third build in a different directory without path remapping was not. [evidence: scripts/repro-build.sh, docs/evidence/s2/repro-result.txt]
- The development container that the project's own checks use is described with its resource limits. [evidence: tools/Dockerfile.dev, docs/DEV-CONTAINER-LIMITS.md]

## What this page does not cover

- The repository holds container recipes for its services; they are not described here and were not run for these pages. [evidence: Dockerfile.platinum, a stage record (not published)]
