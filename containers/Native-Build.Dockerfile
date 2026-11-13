FROM rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS rust
FROM ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv
FROM python:3.14.7-trixie@sha256:0876e54cf728d89fd9d0fdaf5837b9ee879ea5fbbd6fd0cddbe5eb0cce3f5f9e
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=uv /uv /usr/local/bin/uv
ENV RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.98.1 \
    PATH=/opt/venv/bin:/usr/local/cargo/bin:$PATH \
    HOME=/build TZ=UTC LC_ALL=C.UTF-8
COPY pyproject.toml uv.lock .python-version /opt/build-env/
RUN cd /opt/build-env && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --locked --no-python-downloads
WORKDIR /src
ENTRYPOINT ["python3", "tools/native_build.py", "inside"]
