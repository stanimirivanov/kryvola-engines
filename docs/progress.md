# Foundation progress

## M0-PR22 — SP1 public-metadata relation

Issue #13 adds a locked isolated SDK/guest experiment with checksum-pinned CLI
and digest-pinned compiler image. Its fixed public journal binds statement ID,
metadata fields, mode, outcome and cycle policy; the host binds actual guest/key
identity and requires real CPU Core verification plus seven rejection controls.
All inputs are public; Core proof privacy is not assumed. No native-FHE evidence
relation or production profile is enabled. CI splits native and SP1 work while
preserving a combined `verify` gate. Local evidence covers formatting, types,
policy/provenance and Python mode/report controls; compilation/proving and hosted
results remain unverified locally and are delegated to CI.

## M0-PR21 — compact-input proof feasibility

Issue #11 adds the isolated research-only `zk-pok` feature and locked 0.9.0 proof
backend, preserving previous package versions and distribution/service denials.
The two-uint8 experiment separates owner from public verifier/expander, binds
setup/context, enforces conformant bounded decoding and requires six negatives.
Reports distinguish representation bytes, proving, verification and combined
verified-expansion timing; no inference/ownership proof or activation is claimed.
Local evidence covers automatic formatting/lint, types, research policy and
focused report/dependency controls. Native compilation, actual proof generation,
verification, expansion/decryption comparisons and full checks run on CI; no
hosted pass is claimed. CRS/parameter/legal/production review remains pending.

## M0-PR20 — frozen quantized circuit feasibility

Issue #9 pins ML's public fixture at `dcba320678eb454047e29c8a42417ffe8d94a323`.
The isolated TFHE experiment now has a fixed uint8 circuit mode, separate
owner/evaluator processes, exact 100-case/200-value comparisons, bound native
batches and raw per-case/stage/resource observations. Workload/count negatives
are required alongside the unchanged codec negatives. GPU prerequisites are
probed; unapproved GPU and uninstrumented PBS measurements remain unavailable.
Local evidence covers formatting, Python lint/types, policy/provenance and focused
fixture/report controls. Heavy compilation, real encrypted correctness, observed
RSS and full native checks are delegated to CI; no hosted pass is claimed.
No production profile, security/parameter/legal qualification or measured service
latency envelope is established by this research gate.

## M0-PR19 — bounded native codec experiment

Issue #7 adds an isolated, locked TFHE 1.8.1 CPU research experiment with an
explicit versioned parameter candidate, owner-only client keys, a separate
evaluator, bounded safe native codecs and 16 required negatives. Trusted fixture
commitments reject key-domain swaps; native conformance alone does not establish
common key ownership. Memory reservation estimates are separate from hard Linux
process limits. No production profile, owner binding or service is enabled.

Local evidence covers lightweight policy/provenance, Python runner/report tests,
formatting/types and locked Cargo metadata; all 14 Python tests passed.
Heavy TFHE compilation and actual
cryptographic execution are configured in the full CI harness; hosted success
has not been observed or polled. Parameter/security approval, allocator fuzzing,
benchmark/model qualification, compact proofs and distribution rights remain later
gates. The dependency-policy snapshot is not promoted to a verified build matrix.

## M0-PR18 — dependency and toolchain candidates

Issue #5 records checksum-verified metadata for released TFHE-rs 1.8.1 and SP1
SDK 6.9.0, source revisions, licences, primary notices and separate use-class
dispositions. The offline policy gate checks evidence, pins, representative Cargo
consumers and denied distribution/service classes. No heavy dependency is added.
Both compiler/runtime rows remain unbuilt; CUDA, Python owner wheels and the SP1
guest toolchain are unqualified. Optional libraries/tools/services remain deferred.
Actual CPU/proof/build qualification and counsel/publication review remain later
tasks; this metadata inspection does not satisfy those gates.

Observed locally: all 12 Python tests, policy/contract provenance checks,
Ruff formatting/lint, ty and Rust formatting passed. Native compilation,
Clippy, RPC conformance and C++ tests remain on the existing full CI gate;
hosted results have not been polled.

## Initial scaffold

Issue: #1. Scope: initial M0 repository scaffold, 25 October 2026.

- Implemented: rust-native and c++ engine adapter foundations, versioned spec consumption, isolated architecture controls and diagnostics.
- Verified locally: frozen setup, full foundation checks, isolated negative controls, package/native builds and diagnostics.
- Configured but unverified remotely: the GitHub Actions workflow; branch protection/required checks remain maintainer configuration.
- Not claimed: complete M0 acceptance, full Engine API interoperability, cryptographic feasibility, latency measurements, independent security review or deployment.
- Deferred: later roadmap runtime/crypto features. A disabled capability is an explicit incomplete milestone, not an alternate implementation.
- Next: KRY-007/008 pinned engine packaging and cryptographic feasibility, then KRY-013/016 owner/evaluation separation.

The authoritative [plan](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md) remains in force. Review and update only the affected roadmap evidence; no later milestone is marked complete by this scaffold.

## Observed acceptance evidence

On Windows with Python 3.14.7 / uv 0.12.5, `uv run --locked python tools/verify.py full` passed: Ruff formatting/lint, ty type checks, spec provenance and dependency checks, 4 Python tests, 1 Rust boundary test and 1 CTest case, and Rust fmt/clippy/tests and CMake C++20 build/CTest. Native versions observed: Rust 1.98.1, CMake 3.29.2 and GNU C++ 16.1.0.

A new disposable environment passed `uv sync --locked --no-editable`. The frozen tool environment passed provenance validation, and both native diagnostics ran. Diagnostics: `cargo run --locked -p kryvola-engine-api --example inspect; build/cpp/engine_foundation.exe`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.

## M0-PR15: test-only Engine RPC conformance

27 October 2026, issue #3: adopted immutable spec `1a5b57a590487ba116913050af8041f5e5f1fb52` / `0.1.0-preview.10`, complete generated/native manifests and cross-bundle integrity checks. The [fake engine](fake-engine.md) adds generated RPCs with a strict raw-byte codec, fixed synthetic identity/response marker, bounded retained execution/tombstone state, replay/conflict handling, deterministic clock/status, cancellation races and an ephemeral loopback conformance command. No real inference, ciphertext/proof processing, production capability registration, persistence or release authorization is implemented; M0 remains partial.

Local verification covers formatting, Python lint/types, six architecture/provenance negative tests and locked Cargo metadata. All Rust compilation, Clippy/tests, RPC execution and C++ build/tests are delegated to the existing PR CI full harness; hosted results are not claimed. The new full-harness command and 25-minute CI timeout accommodate the pinned RPC dependency build without running it on the busy local machine.
