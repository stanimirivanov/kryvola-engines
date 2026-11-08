# Decrypt-free CPU research evaluator

The standalone, unpublished `crates/cpu-evaluator` package provides the M1-PR16 kernel. Its
Rust API accepts public compressed evaluation material and an encrypted uint8
pair, then executes only the frozen FHE-Q1 circuit:

```text
y0 = (3*x0 + 5*x1 + 7) mod 256
y1 = (x0*x1 + 11) mod 256
```

The pinned TFHE 1.8.1 CPU profile, features, parameter set and serialization match
the owner library. The implementation adapts the existing frozen evaluator
pattern using TFHE's bounded conformant loaders and scoped server-key context.
It adds no runtime dependency beyond the existing pinned TFHE/BLAKE3 pair. The
owner library is a dev-only dependency for controller-side tests; neither it nor
PyO3/Python bindings belongs to the worker runtime dependency graph.

## Boundary and formats

`evaluate(EvaluationBinding, key_bytes, input_bytes)` returns encrypted result
bytes. The binding contains expected evaluation-key and input-blob commitments.
These must come from an independently authorized task/artifact context. Hashing
hostile bytes alongside an untrusted key does not establish authorization or
prove that the ciphertext was encrypted under that key. Native parameter
conformance cannot distinguish different client keys with identical parameters.

Use `evaluate_program(program_digest, binding, key_bytes, input_bytes)` to
compare the program reference from an approved plan before native decoding.
`CAPABILITY` identifies the frozen public program and parameter digests and
advertises `CONFIDENTIALITY_ONLY`. Evaluator output carries no computation
integrity claim.

The commitment is Spec BLAKE3 over `kryvola/blob/v1\0` plus the complete blob.
Keys are compressed TFHE server keys, capped at 64 MiB. Input/output pair framing
is two uint64 little-endian lengths followed by their native ciphertexts; each
ciphertext is capped at 1 MiB. Full commitments, native type/parameter/version,
exact shape and complete consumption pass before key decompression/evaluation.
The scoped TFHE context restores previous thread-local state when evaluation ends.
There is no key generation, private-key loading, decrypt, arbitrary circuit,
network, owner-agent, or Ray entry point in this package.

## Executable and checks

```sh
cargo build --release --locked --manifest-path crates/cpu-evaluator/Cargo.toml
crates/cpu-evaluator/target/release/kryvola-cpu-evaluator --capabilities
crates/cpu-evaluator/target/release/kryvola-cpu-evaluator evaluate \
  evaluation.bin input.bin output.bin "$expected_key_digest" "$expected_input_digest" "$program_digest"
cargo test --release --locked --manifest-path crates/cpu-evaluator/Cargo.toml
uv run --locked python tools/cpu_boundary.py
```

The launcher supplies trusted local regular-file paths and lowercase 64-character
commitments. The optional program digest selects the fixed graph explicitly. An
unknown digest returns `EVALUATOR_PROGRAM` before file access. File reads are length-bounded, including files that grow during a
read. A result file is created only after evaluation and is never overwritten.
Native errors are fixed `EVALUATOR_SIZE`, `EVALUATOR_BINDING`,
`EVALUATOR_FRAMING`, or `EVALUATOR_NATIVE`; file/argument failures are
`EVALUATOR_IO` or `EVALUATOR_ARGUMENT`, with exit status 2. Errors do not echo file
paths or blob contents. The local file adapter is not an artifact finalization
protocol, filesystem sandbox, or wall-time/physical-memory supervisor. Its
launcher must supply those process and storage controls before service use.

The native differential test runs all 100 frozen vectors, four explicit uint8
boundaries, and 16 seeded pairs through the production kernel and compares the
opened results to an independent modular reference. Separate-process tests
cover the file adapter and owner-command rejections. Native negatives cover
oversized lengths, malformed framing, incorrect commitments, and alternate
evaluation-key and ciphertext parameters. The worker directory holds public evaluation
material and ciphertexts only; the controller retains its opaque owner key in
memory. The existing historical experiment still checks all 100 frozen cases.
The boundary gate inspects normal Cargo dependencies and the linked worker's
package symbols, rejecting owner/Python linkage or an uninspectable binary. This
checks the packaged worker surface; it does not claim upstream TFHE contains no
client types. GNU `nm` is required for this Linux research gate.

The canonical native verifier and the parallel `tfhe` CI partition run the new
native tests and boundary gate after retaining all previous checks. Historical
experiment/evidence bytes and public contract artifacts are unchanged. TFHE
artifact-distribution and commercial-service denials still apply. No signed
release package, image, production profile, or deployment is enabled by this PR.

The [CPU supervisor](cpu-runner.md) runs this adapter with bounded resources,
a minimal environment and private scratch.
