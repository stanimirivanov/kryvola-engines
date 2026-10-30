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

M0-PR19 adds an isolated [TFHE codec experiment](docs/tfhe-codec.md). Check its
configuration with `uv run --locked python tools/feasibility.py tfhe-codec --check-only`.
The full Linux CI harness compiles and executes the real owner/evaluator round
trip and native negative cases. This does not enable a production engine/profile.
The full native gate requires Linux x86_64.

M0-PR20 adds the [frozen circuit feasibility gate](docs/tfhe-eval.md):
`uv run --locked python tools/feasibility.py tfhe-eval --check-only` checks the
immutable ML snapshot offline. Full Linux CI evaluates all 100 frozen cases with
separate owner/evaluator processes and retains numeric stage/RSS observations.
PBS/GPU measurements remain explicitly unavailable; no profile is enabled.

M0-PR21 adds a [compact-input proof experiment](docs/tfhe-compact.md).
`uv run --locked python tools/feasibility.py tfhe-compact --check-only` verifies
the research feature/backend pins. Full Linux CI compares native/compact/proven
representations and requires public-context/proof/admission rejections. These
input-validity proofs do not prove inference correctness or authorize release.

M0-PR22 adds an isolated [SP1 public-metadata relation](docs/sp1-relation.md).
`uv run --locked python tools/feasibility.py sp1-relation --check-only` performs
offline configuration checks. A separate Linux/Docker CI job compiles pinned
guests and requires real local CPU proof verification and negative controls.
`full` includes this heavy gate; `native` is the existing native/TFHE portion.

## Authoritative context

M0-PR35 publishes [measured crypto decisions](docs/m0-feasibility.md).
`uv run --locked python tools/qualification.py` checks the pinned numeric evidence
offline: bounded research may continue; production private inference remains NO-GO.

M0-PR24 adds [role-separated package qualification](docs/engine-packaging.md),
two-build comparisons, pinned SBOM/signature tools and a fake-only manual release
workflow. TFHE/SP1 packages remain local to CI; distribution is still denied.

M0-PR23 adds [proof-mode measurements](docs/proof-feasibility.md).
`uv run --locked python tools/feasibility.py proof-modes --check-only` validates
the research matrix offline. Full execution measures two real Core CPU requests
in a bounded local FIFO; unreviewed export modes remain disabled and unmeasured.

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

All future engines, TFHE-rs and zkVM guests/provers live here. Compute accepts public/evaluation material only. No decryption endpoint, mock proof acceptance, cryptographic capability or executed inference is provided by this scaffold. Native crypto codecs remain separate from generated structural types.

Next planned work: KRY-007/008 pinned engine packaging and cryptographic feasibility, then KRY-013/016 owner/evaluation separation.
