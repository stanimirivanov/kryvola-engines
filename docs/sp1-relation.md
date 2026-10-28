# SP1 public-metadata relation feasibility (M0-PR22)

`uv run --locked python tools/feasibility.py sp1-relation --check-only` checks the
isolated locked SDK and research/mode policy without downloading or executing
anything. Without `--check-only`, Linux x86_64, Docker and host `protoc` are required.
On Debian/Ubuntu install `protobuf-compiler libprotobuf-dev`; SP1's host build
imports the standard `google/protobuf/empty.proto` schema. CI installs these
prerequisites explicitly and records `protoc --version`. The runner resolves
`PROTOC` (or `protoc` on PATH) before downloads/builds and passes that executable
to host Cargo. Offline configuration checks do not require the compiler. Heavy
guest compilation, SDK build and proving run on CI; configuration success is not
proof verification. `tools/verify.py full` includes every gate. CI runs its native
portion with `tools/verify.py native` and a separate `sp1` job; the existing
`verify` status always checks both results, including failures/cancellations.

The isolated workspace pins SP1 SDK/guest/core executor 6.9.0, defaults disabled
for the SDK, with no proving-network, mock, CUDA or experimental feature. Its
522-package lock remains outside the engine workspace; source licenses alone do
not qualify all transitives or distribution. Host Rust remains 1.98.1.
Guest compilation uses the released [cargo-prove CLI](https://github.com/succinctlabs/sp1/releases/tag/v6.9.0)
with archive SHA-256 `0eb8a2b3eef9b498443a338a545422a7acd37ee08d17d784a9c16f4c0bfb975b`.
The guest compiler image is pinned to the Linux/amd64 manifest
`ghcr.io/succinctlabs/sp1@sha256:6d90b1692f07519817533bafeefd6ea3d1c4c0d1cd7cffe9844d2ae37d034b08`.
No mutable installer script or global custom toolchain installation is used.
The Docker guest target remains inside the isolated workspace. The native host
uses the explicit runner-owned `build/sp1/host-target` for both Cargo output and
binary launch, keeping container-owned guest output out of the host build path.
Archive extraction accepts only a bounded regular executable, after checksum
verification. Compiler/CLI provenance is a research pin, not publisher attestation.

The experimental statement ID is ASCII `kryvola/research/public-metadata/v1` plus
NUL. The guest reads exactly three 32-byte public metadata fields (model, program,
snapshot) and a one-byte mode. Mode 1 is supported. Its fixed journal contains
the statement ID, mode, successful relation outcome byte 0, little-endian u64
cycle policy 1,000,000, the three fields, then BLAKE3-256 of the entire preceding
journal prefix. All bytes, order and length are checked against the independently
constructed host expectation. Input size is fixed; there are no variable-size
owner witnesses. The guest uses the upstream zkVM entrypoint/runtime ABI.

The model and snapshot digests are explicitly synthetic public fixtures. The host
supplies the actual selected guest ELF digest as the program metadata field and
independently selects that ELF/verifying key for SDK verification. The guest only
recomputes a public commitment; it cannot authenticate external metadata or prove
that an FHE engine ran a program. This ID/journal is a private experiment artifact,
not a newly published spec signing format or production evidence relation.

The host explicitly builds a CPU prover, never `from_env`, generates a nonempty
Core proof, checks its exact journal and requires SP1's successful execution status
(`verify(..., None)`). Seven controls reject changed journal bytes, a different
guest identity, another guest's verifying key, a real proof of non-successful
execution, an empty mock Core proof, mock mode and dev mode. The final two are
selection guards; the journal/key/outcome negatives call the real verifier.
The report binds guest digest, verifying-key digest, journal digest/size, actual
serialized proof size, mode, outcome, limits and proving/verification time. These
are single-run observations, not a service-latency or proof-system comparison.

Core proofs are not treated as private/zero-knowledge exported artifacts. Every
input here is public metadata; **no plaintext owner data, key or private witness
may enter this experiment**. Proofs stay in temporary local files and are removed;
logs contain only bounded allowlisted measurements/commitments. There is no
production evidence release, native-FHE correctness claim or profile activation.

Each proof request is limited to 1,000,000 guest cycles; the CPU trace shard is
65,536 and Rayon/Tokio workers are bounded to two. Runtime controls separately
limit address space to 16 GiB (not a physical-RSS guarantee), CPU/wall time to
900 seconds, files to 128 MiB and core dumps to zero, with process-group cleanup.
Each guest build has a 30-minute deadline, the single-job SDK build 40 minutes,
and the hosted SP1 job 90 minutes. OOM, timeout, unavailable Docker or build/proof
failure rejects the gate; execute-only or mock fallback never satisfies it.
Production resource/side-channel/cryptographic review and release/legal gates
remain pending. APIs were checked against the [pinned SDK source](https://github.com/succinctlabs/sp1/tree/b8387fa61e1361d90ee7de49f551863418ca0f08/crates/sdk).
