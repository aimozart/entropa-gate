# entropa-gate client image (S1 task 5). FROM scratch: the only file is the static binary, so there is no shell, no package manager and nothing to pull.
# Run it read-only, with no network, no capabilities, and a volume for the keys and the ledger:
#   docker run --read-only --network none --cap-drop ALL --security-opt no-new-privileges -v MYDATA:/data IMAGE init --dir /data/node
# The keys never live in the image: the client's volume holds /data/node/platinum.key (mode 0600). A client that must reach a witness drops --network none
# and allows only that host (their own firewall or proxy), as the plan states.
FROM scratch
COPY --chown=65532:65532 data /data
COPY --chown=0:0 entropa-gate /entropa-gate
USER 65532:65532
VOLUME ["/data"]
ENTRYPOINT ["/entropa-gate"]
