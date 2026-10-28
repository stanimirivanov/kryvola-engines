# Frozen FHE-Q1 circuit feasibility (M0-PR20)

`uv run --locked python tools/feasibility.py tfhe-eval --check-only` verifies
research policy, isolated lock/toolchain and frozen public fixture bytes offline.
`uv run --locked python tools/feasibility.py tfhe-eval` builds/runs the real CPU
experiment on Linux x86_64. The full CI harness runs both codec and circuit gates.
Heavy compilation/crypto execution belongs on CI; configuration checks never
claim native success. No runtime dependency or approved feature set changes.

The [fixture lock](../experiments/tfhe/fixture.lock.json) selects ML commit
`dcba320678eb454047e29c8a42417ffe8d94a323` and its independently pinned SHA-256
manifest. Only Apache-2.0 public data/card/license/program bytes are vendored;
no sibling implementation is imported. Python rejects fixture/provenance drift
before building. Rust embeds that snapshot and implements exactly
`(3*x0+5*x1+7, x0*x1+11)` in wrapping uint8: three MULs (two scalar, one encrypted)
and three ADDs (two scalar, one encrypted). All 100 input pairs and 200 outputs
are checked. The public constants and graph together are the model/program;
there is no separately trained/private model.

The owner generates a fresh client key, serializes only the compressed evaluation
key and 200 encrypted inputs, and retains its client key in memory. A new evaluator
process receives only those public/evaluation artifacts and trusted commitments.
The envelope admits exactly 200 native objects, at most 1 MiB each / 32 MiB per
batch, and a 64 MiB key. It rejects parameter, key-context, approved ciphertext,
shape, version, framing and reservation mismatches before decompression. Both
input and output batches require exact consumption. Native conformance is not
key ownership; the owner's approved ciphertext hash supplies that binding.

The child also checks a domain-separated workload commitment over length-prefixed
program, inputs, expected outputs and parameter-profile bytes. The report records
this `binding_blake3`, the parameter/key-context/input hashes, the program hash and
the frozen manifest hash. These are **research commitments**, not signed spec
identities, malicious-compute attestation or Engine API release authorization.
CI requires early rejection of an invalid batch count and of an incorrect workload
commitment, in addition to the 16 existing codec negatives. An OOM/crash or wrong
exit category fails the experiment and cannot count as a successful rejection.

`native.observations` retains all 100 `[case_index, evaluate_ns]` pairs, in dataset
order. These are different boundary inputs, not independent identically distributed
service requests. Evaluation reuses one decompressed key; the evaluator process
is fresh. Shared `stages_ns` measure owner keygen (including key encoding), input
encrypt/encode, child dispatch, owner decode/decrypt/check, child native decode,
key expansion and output encoding. The local owner total includes I/O and process
overhead; stage times overlap across owner/child and must not be summed into
service latency. A failed/incomplete run is REJECTED, not a successful-only sample
set. Raw numeric observations remain in the CI JSON log for later analysis.

Serialized byte counts are measured. Owner/evaluator `VmHWM` values are observed
RSS high-water snapshots at the end of their measured work, not expanded-key byte
counts or a concurrent aggregate. The parameter-derived reservation remains an
estimate. Inherited hard limits are separate: 4 GiB address space per process,
128 MiB per file, 600 CPU seconds, no core files, 600-second owner wall deadline;
the batch child has a 480-second deadline. Failure/timeout kills the process group.
Resource accounting/fuzzing and production hardware qualification remain later gates.

PBS counts and isolated PBS timing are null because `pbs-stats` is outside the
current approved feature set; operation counts are not PBS estimates. Upstream
documents [PBS instrumentation](https://docs.zama.org/tfhe-rs/fhe-computation/tooling/pbs-stats).
The pinned [upstream Makefile](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/Makefile)
has `bench_integer_gpu`. The runner probes `nvidia-smi --list-gpus`, then records
UNAVAILABLE with an explicit reason: no usable device or GPU feature unapproved.
It never enables CUDA, runs that benchmark, or reports a speedup. GPU-specific
parameters also require separate review; see [upstream GPU guidance](https://docs.zama.org/tfhe-rs/hardware-acceleration/run-on-gpu).

This is an opt-level-1 research experiment, not a qualified MeasurementReport,
latency envelope, production route, enabled cryptographic profile or distribution
approval. Legal/parameter/security review and real operational benchmarking remain
pending. The JSON includes the native executable checksum and selected toolchain;
timings and RSS are observations, not proof of a trustworthy evaluator.
