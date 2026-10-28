# M0-PR19 bounded CPU codec experiment

This is an isolated research experiment, not a production engine or owner binding.
It consumes the M0-PR18 `tfhe = 1.8.1` candidate with disabled default features and
`integer, software-prng`; its separate Cargo workspace/lock keeps the ordinary
engine build independent of the heavy library. BLAKE3 1.8.7 supplies fixture
artifact commitments. Distribution, commercial service and production profiles
remain denied/unqualified; no GPU or compact-input proof path is added.

## Frozen parameter candidate

The explicit CPU candidate is
`V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, from
[the pinned parameter source](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/parameters/v1_4/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs).
It fixes LWE dimension 918, GLWE dimension 1, polynomial size 2048, message/carry
moduli 4/4, PBS base/level 23/1, KS base/level 4/4, TUniform noise and the Big
encryption-key choice. Upstream's failure/security annotations are not independent
Kryvola cryptographic ratification. Reviewing this candidate permits research
conformance tests only; the published assurance profile stays disabled.

The experiment uses TFHE's versioned safe serialization and native conformance,
as documented in [the upstream codec guide](https://docs.zama.org/tfhe-rs/fhe-computation/data-handling/serialization).
Unsupported native header versions and wrong types/parameter shapes fail. Valid
legacy representations may still be upgraded by the pinned upstream versioning
implementation; this is not a promise to reject every historical representation.

## Process and artifact boundary

Only the Rust owner branch generates/holds client keys. It writes a compressed
evaluation key and ciphertext into a private temporary artifact directory, then
starts a fresh evaluator process. Secret keys are never serialized or written to
that directory. The evaluator has no decryption path and receives no plaintext
witness, owner key or ambient service credentials. Only the owner decrypts the
returned, bounded native result and compares it with the fixed test expectation.

This is a private file-based test harness, not a new public protocol. Its fixed
header contains magic, exact TFHE envelope version, parameter-profile commitment,
key context, count, lengths and an expansion reservation. Native blobs are data
artifacts, never broker/control messages or log fields. Owner-pinned key/input
BLAKE3 commitments arrive independently through trusted process arguments.
Checks occur before native decoding and again before decompression/evaluation.

The key-domain negative first demonstrates that another client's same-parameter
ciphertext passes native conformance, then rejects that swap against the approved
owner input commitment. Native conformance **does not prove key ownership**.
The argument channel is trusted only by this fixture; it is not signed owner
authorization, a ciphertext-key equality proof, or a general admission API.
Processes run under one test identity: separation is observable but is not an OS
sandbox against a malicious same-user process. Production owner/evaluator
identities, authenticated bindings and disclosure authorization remain later work.

## Bounds and negative checks

Input lists contain exactly one FheUint8. Compressed key/ciphertext serialized
limits are 64 MiB/1 MiB, enforced before allocation; file length and fully consumed
native objects are checked. Parameter conformance precedes key decompression.
The expanded-key reservation is four times the trusted parameter-derived BSK/KSK
coefficient storage estimate plus the ciphertext allowance. It is a policy
estimate, **not measured RSS or a native allocator guarantee**. Requests below
that reservation or above the independent 1 GiB admission ceiling fail early.

The Linux runner supplies separate hard limits: 4 GiB virtual address space per
owner/evaluator process, 128 MiB per file, 600 CPU seconds, a zero core-file limit, a
600-second owner wall deadline and a 90-second evaluator deadline. It kills the
owned process group on exit/timeout and deletes public fixture artifacts. These
limits bound failures; they do not establish every internal allocation's safety.
Adversarial allocation fuzzing and hardware/resource qualification remain future
gates. Native execution is supported by this harness only on Linux x86_64.

CI requires a real encrypt/evaluate/decrypt round trip and 16 negatives: envelope
version/profile/context, zero/oversized list counts, oversized key/ciphertext
declarations, low expansion reservation, truncated framing, native truncation,
native header mutation, wrong type, wrong radix block count, trailing native
bytes, wrong parameters, and a same-parameter foreign-key swap. Rejections must
use the expected error category; an unrelated crash/OOM cannot count as success.
Reports contain only allowlisted booleans/counts/sizes, never key/ciphertext bytes
or decrypted values. The result is a conformance summary, not a benchmark or
spec MeasurementReport. No timing/speedup or production capability is claimed.

## Running and evidence

Lightweight configuration check:
`uv run --locked python tools/feasibility.py tfhe-codec --check-only`.
It explicitly reports `native_executed=false` and checks research policy/isolation.
The native gate is `uv run --locked python tools/feasibility.py tfhe-codec`;
`uv run --locked python tools/verify.py full` includes it after normal engine checks.
The runner explicitly selects the policy's Rust toolchain/Linux target and builds
only the isolated lock in release mode, one Cargo job, with a
30-minute build timeout; the research profile uses opt-level 1/no LTO to bound
compiler cost. This is not the frozen quantized circuit or a performance profile.

Heavy compilation/crypto execution runs on CI. Until a successful hosted result
is reviewed, candidate build/runtime status remains unverified. PR20 owns the
frozen-circuit benchmark; PR21 owns compact/native/proof comparisons. Ordinary
fast checks do not compile TFHE. Python negative tests check runner/report guards;
they do not stand in for actual encryption or conformance execution.
