FROM python:3.14.7-trixie@sha256:0876e54cf728d89fd9d0fdaf5837b9ee879ea5fbbd6fd0cddbe5eb0cce3f5f9e
# Build with the worker-only context assembled by tools/cpu_engine_package.py.
RUN test -x /usr/bin/prlimit && ln -sf /usr/local/bin/python3 /usr/bin/python3
COPY kryvola-cpu-engine kryvola-cpu-evaluator cpu_runner.py LICENSE /opt/kryvola/
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/opt/kryvola/kryvola-cpu-engine"]
CMD ["/run/kryvola"]
