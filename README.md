# kryvola-engines

Rust-native and C++ engine adapter foundations. This is an initial M0 foundation, with no production execution or security qualification. Existing Apache-2.0 licensing is preserved.

## Setup and verification

Prerequisites: Python 3.14.7 and uv 0.12.5; Rust 1.98.1 with rustfmt/clippy; CMake 3.25+, Ninja and a C++20 compiler. Python is pinned in `.python-version`; Rust is pinned in `rust-toolchain.toml` where applicable. Run from this repository root:

```sh
uv sync --locked
uv run --locked python tools/verify.py fast
uv run --locked python tools/verify.py full
cargo run --locked -p kryvola-engine-api --example inspect
```

`fast` runs formatting/lint/type/provenance/dependency checks and Rust fmt/clippy. `full` adds isolated positive/negative controls, Rust tests and CMake/CTest. Missing tools or files fail the command. Apply Python formatting with `uv run --locked ruff format .` and lint fixes with `uv run --locked ruff check --fix .`; use `cargo fmt --all` for Rust; rerun affected checks after changes.

No service credentials or local databases are required for this scope. `spec.lock.json` pins immutable generated spec artifacts; a sibling checkout is unnecessary. Generated structural types are not native decoders or authorization. [Architecture and enforcement](docs/architecture.md), [progress](docs/progress.md), and the source references below describe limits.

M0-PR15 adds a [test-only fake EngineService](docs/fake-engine.md). Run `cargo run --locked -p kryvola-fake-engine -- conformance` for bounded loopback RPC conformance. This simulates metadata/status only; it provides no cryptographic capability or real output artifact. Heavy compilation/conformance checks run through the full CI harness.

M0-PR18 records [dependency dispositions](docs/dependency-dispositions.md). Run
`uv run --locked python tools/dependency_policy.py` for the offline candidate gate.
TFHE/SP1 are research-only candidates; distribution, commercial service, CUDA,
guest toolchains and production compatibility remain unapproved. No heavy crypto
dependency is installed or added to the workspace by this policy.

## Authoritative context

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

All future engines, TFHE-rs and zkVM guests/provers live here. Compute accepts public/evaluation material only. No decryption endpoint, mock proof acceptance, cryptographic capability or executed inference is provided by this scaffold. Native crypto codecs remain separate from generated structural types.

Next planned work: KRY-007/008 pinned engine packaging and cryptographic feasibility, then KRY-013/016 owner/evaluation separation.
