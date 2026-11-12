# Foundation progress

## M0-PR35 — measured crypto decisions

Issue #19 imports the exact numeric summary from platform PR18's immutable merge
and publishes [research envelopes and exclusions](m0-feasibility.md). Two successful
fixed-source campaigns support frozen uint8/compact-input experiments and public
Core metadata research only. The offline gate reuses existing result parsers,
pins reviewed experiment sources and rejects unsupported parameter/privacy claims,
missing accuracy and exceeded resource bounds. Production private inference is
NO-GO; service latency INCONCLUSIVE; security/parameter/legal review remains pending.

Focused offline tests and the final branch CI results are recorded in the PR.
No native crypto implementation, dependency, release permission or production
profile is enabled. The historical dependency snapshot stays distinct from the
new observed experimental build/runtime evidence; remaining M0 gates stay open.

## M0-PR24 — experimental package qualification

Issue #17 adds separate fake/compute/owner/prover packages with binary role checks,
clean target-directory comparisons, SBOM/provenance subject binding and Cosign
verification. Compute-only builds reject owner routes. CI must qualify all four
locally before PR creation; only the fake artifact has a main-only manual public
release path. TFHE/SP1 distribution/service permissions remain denied. No public
release, SLSA assurance level, complete license inventory or production image is
claimed by this change. Evidence is recorded in the PR after actual CI execution.

## M0-PR23 — proof mode measurements

Issue #15 adds a pinned candidate-mode matrix, two fresh-process real Core CPU
samples, local FIFO queue/process timing, native prove/verify/size observations
and strict cross-sample binding/accounting checks. Only public metadata Core
research is admitted; Compressed/Groth16/PLONK remain disabled and unmeasured.
No private export, production security or cross-mode performance claim is made.
Local tests cover policy, accounting, CLI and orchestration. Full native/SP1 CI
must pass on the implementation branch before creating the PR; actual evidence
is recorded in the PR rather than inferred from this harness configuration.

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

A new disposable environment passed `uv sync --locked --no-editable`. The frozen tool environment passed provenance validation, and both native diagnostics ran. Diagnostics: `cargo run --locked -p kryvola-engine-api --example inspect; build/cpp/engine_foundation`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.

## M0-PR15: test-only Engine RPC conformance

27 October 2026, issue #3: adopted immutable spec `1a5b57a590487ba116913050af8041f5e5f1fb52` / `0.1.0-preview.10`, complete generated/native manifests and cross-bundle integrity checks. The [fake engine](fake-engine.md) adds generated RPCs with a strict raw-byte codec, fixed synthetic identity/response marker, bounded retained execution/tombstone state, replay/conflict handling, deterministic clock/status, cancellation races and an ephemeral loopback conformance command. No real inference, ciphertext/proof processing, production capability registration, persistence or release authorization is implemented; M0 remains partial.

Local verification covers formatting, Python lint/types, six architecture/provenance negative tests and locked Cargo metadata. All Rust compilation, Clippy/tests, RPC execution and C++ build/tests are delegated to the existing PR CI full harness; hosted results are not claimed. The new full-harness command and 25-minute CI timeout accommodate the pinned RPC dependency build without running it on the busy local machine.

## M0-CLOSE-PR2: pending scoped crypto dispositions

Issue #23 adds an offline review packet for exact TFHE/SP1 dependencies, intended
uses, parameter/workload/proof identities and immutable evidence. Qualification
checks it alongside the existing research gate. Legal/security remain PENDING,
distribution/service remain DENY and production remains NO_GO. Authenticated
approval and successor acceptance require later work; no reviewer is inferred.

Local validation passed: all 51 Python tests (including eight focused
qualification/disposition tests), Ruff formatting/lint, ty, cargo fmt and the
offline qualification CLI. Heavy native crypto compilation/execution was not
rerun; immutable experiment and campaign bytes are unchanged.

## M0-CLOSE-PR6: fake-engine OCI publication

Issue #25 adds digest-bound fake-image publication and verification with explicit
archive/source/Dockerfile/SBOM/provenance bindings. A pulled image must match the
signed single-role archive and pass read-only conformance. Publication permissions
are isolated from qualification. No TFHE/SP1 permission or approval is changed.

Local verification passed all 55 Python tests, Ruff formatting/lint, ty, cargo fmt,
offline qualification and diff whitespace checks. OCI negatives cover digest-only
subjects, archive/source/Dockerfile binding, signature failure, owner-file injection,
binary substitution and fail-closed registry authorization errors. Docker was
unavailable locally; real container builds/pulls/conformance, registry signatures
and GitHub OIDC publication remain unexecuted here and required by the manual
workflow. No image, release or profile was published or enabled.

M1-PR1 adds opt-in verification of a [scoped TFHE review successor](scoped-crypto-review.md).
The tests use ephemeral legal and parameter authorities to exercise real signatures,
scope substitution, expiry, and withdrawal. Actual use decisions remain external.

## M1-PR13 owner crypto

The standalone, unpublished `crates/owner-crypto` package uses the pinned TFHE
1.8.1 CPU research profile. It keeps the client key opaque in the owner process,
exports compressed evaluation material, and encrypts a fixed pair of uint8
values. Result opening requires the expected evaluation-key and result blob
commitments before bounded native decoding and exact pair validation.

The owner must establish those commitments through independent authorization.
TFHE parameter conformance alone cannot distinguish ciphertexts from separate
keys with the same parameters. The library has no signing, custody, network
service or publication entry point. Existing distribution and service denials
still apply.

Run `cargo test --release --locked --manifest-path crates/owner-crypto/Cargo.toml`
for the owner gate. The native verifier runs it alongside the existing
experiments. The owner conformance test executes all 100 frozen cases and four explicit
uint8 boundaries. Its evaluator accepts evaluation-key and ciphertext bytes
and checks that each native object consumes its entire frame and rejects
client-key decoding. Compile-fail checks cover client-key field access, debug
formatting and native serialization of the opaque owner handle.

The wrong-parameter case uses valid TFHE ciphertexts generated with alternate
message and carry parameters. Independently computed outer commitments bind
the exact pair, and the owner rejects it at native conformance. These tests
exercise arithmetic and API behavior within one process. Process isolation
has a separate gate.

## M1-PR14 Python owner package

`crates/owner-crypto/python` adds the unpublished PyO3 binding crate and a
CPython 3.14 `kryvola-owner` research wheel. Its opaque handle exports only public
evaluation material, fixed-pair encryption, and commitment-bound result opening.
It has no client-key serialization, generic decryption API, SDK transport, or
publication entry point. See [the API and local wheel gate](owner-python.md).

The installed-wheel gate passes five tests in a fresh isolated environment,
including real native round trips, invalid commitments/lengths/framing/version,
sanitized errors, and rejected pickle/copy/attribute access. All 59 existing
Python tests and both Rust owner tests pass; the latter includes frozen evaluated
fixtures. Fast checks pass. The complete native suite remains unavailable locally
because CMake/Ninja are absent; its canonical CI path includes the wheel gate.
These results grant no TFHE distribution/service permission or production status.

## Parallel CI gates

Issue #33 removes duplicate feature/fix branch push runs and partitions the
existing native and SP1 gates across independent jobs. Each native qualification
role retains both clean builds and all controls. SP1 measurements and qualification
consume the same source/digest-bound guest artifacts in parallel after guest
preparation. Both FIFO samples remain together. The aggregate `verify` check fails
unless every required job succeeds. Historical source/evidence pins, permission
denials and manual publication workflows are unchanged. See [parallel CI](parallel-ci.md).

Local validation passes all 68 Python tests (including nine new partition,
artifact-admission and FIFO controls), canonical fast checks, Rust workspace
checks/conformance, CMake/CTest and both inspect executables. All affected
workflows pass Actionlint 1.7.12. Temporary CMake/Ninja tools enabled the C++
checks without adding repository dependencies. Real SP1 jobs, cold native
qualification and hosted timing remain to be validated by the PR workflow;
unit fixtures are not proof-execution evidence.

## M1-PR15 CPU evaluator package

The unpublished `crates/cpu-evaluator` library/executable evaluates only the frozen
FHE-Q1 uint8 circuit from public evaluation material and bound ciphertexts. It
checks complete blob commitments, bounded exact pair framing and native
version/parameter conformance before evaluation. The runtime dependency graph and
linked worker are inspected for owner/Python package leakage. Owner keys remain
in the test controller; no owner/decrypt operation is accepted by the worker.

The gate covers frozen edge fixtures in a separate worker process and rejects
wrong commitments, malformed native bytes/parameters, oversize/truncated/trailing
material, forbidden commands, and result overwrite. Both canonical native checks
and the parallel TFHE partition include it. See [CPU evaluator](cpu-evaluator.md)
for exact commands, API boundaries and research-only limitations.

Local verification passes all five evaluator native tests, all 69 Python
regressions, the actual normal-dependency/linked-binary boundary check, strict
standalone release Clippy, and the canonical fast gate. Real public-material-only
worker subprocesses match the four frozen edge fixtures. Cold CI builds and the
broader unchanged native/SP1 suites are not claimed as locally rerun; the new
evaluator gates execute in the existing parallel TFHE job.

## M1-PR18 artifact-backed CPU Engine

The [artifact CPU Engine](artifact-cpu-engine.md) connects the bounded gRPC
service, isolated evaluator and scoped Fabric publication APIs. It accepts
one trusted assignment per worker and reports an output candidate only after
receipt persistence. The verification gate adds an owner-separated native
RPC fixture and a worker image inventory check.


## M1-PR19 owner key sealing prerequisite

The owner-only Rust crate and Python wheel now seal and restore the actual
FHE-Q1 key under an independent wrapping key and custody context. Tests recover
the original evaluation identity and open pre-existing ciphertext in a fresh
owner process. Fabric owns the storage and recovery policy.

## M1-PR30 Engines publication prerequisite

[M1 publication](m1-publication.md) provides a separate denied candidate and
externally approved publication path for the CPU Engine API/evaluator and owner
wheel. It reuses installed owner checks, CPU image boundaries and exact scoped
review verification. The manual workflow shares review metadata only until
permission is verified. Platform #48 still requires actual approved releases;
this implementation does not supply approval evidence or publish artifacts.

## Solo-owner M1 development approval — issue #57

The owner explicitly simplified M1 development-release approval for this
single-developer project. One owner-only main dispatch, an approval checkbox
and three exact native artifact hashes replace the external review packet and
separate builder key. New signed releases use engines-m1-v2 and the explicit
OWNER_APPROVED_DEVELOPMENT_ONLY label, with no independent-review or production
claim. Historical M0 records and standalone strict qualification tools remain
unchanged; see decisions/0001-solo-owner-m1-development.md.

All 89 Python tests, canonical fast checks and Actionlint passed locally. New
controls cover owner/context/checkbox/subject/run rejection, versioned approval
binding and publisher-signature rejection before registry access. No native
candidate rebuild, registry operation, release publication or actual approval
was performed. The existing c318ea3 candidate and its hashes remain unchanged;
after merge, prepare a fresh source-bound candidate for the new tooling source.
