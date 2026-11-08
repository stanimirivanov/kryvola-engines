# Owner-local Python research bindings

M1-PR14 packages `crates/owner-crypto` as `kryvola-owner`, importable as
`kryvola_owner`. It is an owner-process dependency for the later ML SDK; it is
never installed in an evaluator or imported from a sibling checkout. This slice
adds no SDK transport, release signature validation, worker API, or publication
workflow. M1-PR19 adds the owner-local sealed envelope used by Fabric custody.

The extension uses PyO3 0.27.1 (MIT OR Apache-2.0) and maturin 1.10.2 (MIT OR
Apache-2.0), rather than maintaining a hand-written Python C ABI. PyO3 is confined
to the binding crate; maturin is a build/development dependency. Cargo and uv
lockfiles pin their dependency graphs. TFHE version, features, parameter profile,
and framing remain those of the owner library. PyO3's documented GIL requirement
is retained; free-threaded execution and other interpreter/platform combinations
are not qualified. The local gate targets the pinned CPython 3.14.7 toolchain.

## API and authorization boundary

- `OwnerKey()` generates a process-local opaque client key. It has no private-key
  plaintext import/export, Python dictionary, pickle/copy support, or secret-bearing repr.
- `key.evaluation_key()` returns compressed public evaluation bytes.
- `key.encrypt_pair(values)` accepts exactly two bytes, each a uint8 value.
- `key.open_result(ciphertext, evaluation_key_digest, result_blob_digest)` accepts
  bytes and two 32-byte commitments, and returns exactly two plaintext bytes.
  The native library bounds and validates the result before decryption.
- Starting with wheel version `0.1.0.dev2`, `key.seal(wrapping_key, context)`
  returns a bounded encrypted envelope. `OwnerKey.restore(wrapping_key, context,
  sealed)` returns an opaque key with the original public evaluation bytes.
  Both inputs are exactly 32 bytes. The wrapping key must be independently
  generated high-entropy secret material from owner custody. The context is
  an independently derived commitment to the intended custody identity and slot.
- `blob_digest(bytes)` returns the Spec BLAKE3 full-blob commitment for zero to
  64 MiB inclusive. Starting with wheel version `0.1.0.dev1`, larger inputs raise
  `ValueError("OWNER_SIZE")` before hashing. Empty input remains valid for the
  hash helper. Artifact admission and release authorization are separate checks.

The caller must establish both expected commitments through independent owner
verification of the exact release authorization. Computing a digest over hostile
bytes and passing it back does **not** authorize disclosure. The local round-trip
fixture uses its own encrypted data and is not evidence of signed authorization.
Do not expose these owner-local primitives as a remote decrypt endpoint.

Native failures become `ValueError` with fixed codes `OWNER_SIZE`,
`OWNER_BINDING`, `OWNER_FRAMING`, or `OWNER_NATIVE`; binding shape and digest-length
errors use `OWNER_SHAPE` and `OWNER_DIGEST`. Wrong Python types raise `TypeError`.
No native error payload or key data is included. Incorrect wrapping-key or
context lengths use `OWNER_WRAPPING_KEY` or `OWNER_CUSTODY_CONTEXT`.
Envelope authentication failures use `OWNER_BINDING`.

The v1 envelope uses ring AES-256-GCM with a fresh random 96-bit nonce. The
version prefix and custody context are authenticated. The encrypted payload
contains the bounded TFHE 1.8.1 native client key and original compressed
evaluation bytes. The envelope is at most 65 MiB plus 40 bytes. Restore
authenticates before parsing either native object.
Use a separate wrapping key for this format and rotate it before 2^24 seals.
Treat the format as opaque and retain the exact version needed for recovery.

The Rust staging buffers are zeroized on drop. Python wrapping-key bytes,
TFHE internal allocations and the AEAD key schedule have no erasure guarantee.
Fabric owns keystore access, file and backup policy, and process hardening.

## Local wheel gate

```sh
uv sync --locked
uv run --locked python tools/owner_wheel.py
```

The gate checks the existing research dependency policy, builds with
`maturin build --release --locked`, records the wheel SHA-256, installs it without
network dependencies into a fresh temporary environment, and runs
`tests/owner_wheel.py` with isolated Python imports (`-I`). The gate injects a shadow module via
`PYTHONPATH` and checks that both imported modules belong to the installed
distribution. Temporary wheel and
environment files are removed after the gate. The canonical native verifier also
runs this gate. A local build can take several minutes on a cold TFHE cache.

## Exact wheel qualification

The research gate records `DENY` for the wheel and exercises qualification
with temporary fixture keys and synthetic source and lock pins. The fixture
installs the verified snapshot in a fresh environment and runs the same
isolated API checks. Its result is labelled `OWNER_WHEEL_TEST_FIXTURE_QUALIFIED`.

To verify a candidate using operator evidence, supply the complete argument set:

```sh
uv run --locked python tools/owner_wheel.py \
  --wheel "$wheel" --packet "$packet" --policy "$operator_policy" \
  --policy-sha256 "$trusted_policy_sha256" --source "$trusted_engines_revision" \
  --lock-sha256 "$trusted_owner_cargo_lock_sha256" --builder "$trusted_builder_key"
```

Use independently trusted pins for the current operator policy, the Engines
revision, and the SHA-256 of `crates/owner-crypto/Cargo.lock` at that revision.
The builder key is lowercase hex DER Ed25519 SubjectPublicKeyInfo provisioned
by the operator. The packet includes the [scoped approval](scoped-crypto-review.md)
for `artifact_distribution` over the wheel SHA-256, plus `provenance.json`
and its raw 64-byte Ed25519 signature in `builder.sig`.

The closed version 1 provenance JSON has integer `version`, `role` set to
`owner-wheel`, `repository` set to `https://github.com/stanimirivanov/kryvola-engines`,
the pinned commit in `source`, the pinned lock digest in `cargo_lock_sha256`,
and `subject` containing the exact wheel basename and digest as `name` and
`sha256`. The builder signs the exact JSON bytes.

Qualification verifies the signed approval and provenance before installing
the same private wheel snapshot. A successful run emits a JSON qualification
record for that wheel, including the review expiry. Permission remains scoped
to the signed decision and current operator policy. The repository’s pending
review records and release publication controls continue to govern distribution.

References: [PyO3 0.27.1](https://docs.rs/pyo3/0.27.1/pyo3/),
[maturin build workflow](https://www.maturin.rs/distribution.html),
[PyO3 GIL declaration](https://pyo3.rs/main/free-threading).
