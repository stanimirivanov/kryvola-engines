FROM ubuntu@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d
# Build context must be the extracted, verified single-role package, never the repo.
COPY engine /opt/kryvola/engine
COPY LICENSE /opt/kryvola/LICENSE
COPY Cargo.lock /opt/kryvola/Cargo.lock
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/opt/kryvola/engine"]
