# Owner-local Python research bindings

M1-PR14 packages `crates/owner-crypto` as `kryvola-owner`, importable as
`kryvola_owner`. It is an owner-process dependency for the later ML SDK; it is
never installed in an evaluator or imported from a sibling checkout. This slice
adds no SDK transport, custody persistence, release signature validation, worker
API, or publication workflow.

The extension uses PyO3 0.27.1 (MIT OR Apache-2.0) and maturin 1.10.2 (MIT OR
Apache-2.0), rather than maintaining a hand-written Python C ABI. PyO3 is confined
to the binding crate; maturin is a build/development dependency. Cargo and uv
lockfiles pin their dependency graphs. TFHE version, features, parameter profile,
and framing remain those of the owner library. PyO3's documented GIL requirement
is retained; free-threaded execution and other interpreter/platform combinations
are not qualified. The local gate targets the pinned CPython 3.14.7 toolchain.

## API and authorization boundary

- `OwnerKey()` generates a process-local opaque client key. It has no private-key
  import/export, Python dictionary, pickle/copy support, or secret-bearing repr.
- `key.evaluation_key()` returns compressed public evaluation bytes.
- `key.encrypt_pair(values)` accepts exactly two bytes, each a uint8 value.
- `key.open_result(ciphertext, evaluation_key_digest, result_blob_digest)` accepts
  bytes and two 32-byte commitments, and returns exactly two plaintext bytes.
  The native library bounds and validates the result before decryption.
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
No native error payload or key data is included. Python plaintext bytes and
native allocations are not guaranteed to be erased on release; this package adds
no persistent custody or process hardening guarantees.

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

The wheel carries the `Private :: Do Not Upload` classifier. This is a warning,
not access control. Neither this classifier nor passing tests grants artifact
distribution or commercial service permission. Existing TFHE permission denials
and release provenance requirements remain unchanged. Do not publish this research
wheel: a future publication path must enforce the independently pinned,
artifact-specific [scoped review](scoped-crypto-review.md) and applicable release
provenance checks at the publication boundary.

References: [PyO3 0.27.1](https://docs.rs/pyo3/0.27.1/pyo3/),
[maturin build workflow](https://www.maturin.rs/distribution.html),
[PyO3 GIL declaration](https://pyo3.rs/main/free-threading).
