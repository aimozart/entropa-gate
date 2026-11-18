# entropa-try-http image (LS3c). FROM scratch: the only file is the static binary, so there is no shell, no package manager, no certificate store and nothing to pull. No secrets: the signing key is a
# throwaway made at start and the salt is random at each start. The settings have NO default and are given as arguments, because the binary refuses to start without them:
#   docker run --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:8080:8080 IMAGE --trusted-hops N --allow-origin https://ORIGIN
# (N = the number of proxies in front of the service; the port comes from $PORT, default 8080.)
FROM scratch
COPY --chown=0:0 entropa-try-http /entropa-try-http
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entropa-try-http"]
