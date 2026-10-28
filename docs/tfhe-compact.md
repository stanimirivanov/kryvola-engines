# Compact-input proof feasibility (M0-PR21)

Run `uv run --locked python tools/feasibility.py tfhe-compact --check-only` for
offline research-policy, feature and exact proof-backend lock checks. Run the
same command without `--check-only` on Linux x86_64 for real CPU execution.
The full CI harness includes this experiment; no native success is inferred
from configuration/report tests. Heavy compilation and proof generation stay on CI.

The isolated TFHE 1.8.1 candidate adds `zk-pok`, selecting checksum-pinned
`tfhe-zk-pok` 0.9.0 ([registry metadata](https://crates.io/crates/tfhe-zk-pok/0.9.0),
BSD-3-Clause-Clear). The lock adds 77 identities without replacing an existing
package version. The backend's curve/proof dependencies increase compile cost;
they remain outside the engine workspace. Research-only use, pending legal review
and denied distribution/service dispositions are unchanged. GPU stays disabled.
This is not a transitive licence/SBOM or parameter-security qualification.

The owner encrypts public values `(41,255)` as two native uint8 ciphertexts, a
packed compact list and a packed proven list. The explicitly versioned candidates
are the existing V1_4 message-2/carry-2 CPU parameters, V1_4 PKE-to-small ZKV2
parameters and their matching V1_4 PKE-to-small casting key parameters. The CRS
supports 16 packed bits (four message/carry blocks), generated locally for this
research run; a production trusted-setup/distribution procedure is not supplied.

The context metadata commits to versioned parameter identities and length-prefixed
serialized evaluation key, CRS, compact public key and foreign public-key test
fixture. The verifier receives only public/evaluation artifacts and the trusted
context commitment; both client keys remain in owner memory and are never written
or passed to the child. Approved setup bytes must match before native decoding.
CRS/public keys, compact lists, proven lists and evaluation keys use bounded safe
conformant decoding with exact consumption. Count/type admission is two uint8
values only. The owner decrypts all four expanded outputs and checks exact equality.

The relation is the upstream [compact public-key encryption proof](https://docs.zama.org/tfhe-rs/fhe-computation/advanced-features/zk-pok):
the supported encryption/message/noise constraints under the selected public
key, CRS and bound context. It does **not** prove private-key ownership, common
key ownership, consent, arbitrary application ranges, correct inference or
release authorization. Parameter conformance is a separate structural check.
No proof admission endpoint or enabled profile is introduced.

The native child requires six normal rejections: wrong context, a different
same-parameter public key, truncated native proven-list bytes, trailing bytes,
an unsupported declared count, and a reservation below the expansion threshold.
The first two exercise actual proof verification; truncation/trailing bytes
exercise native decoding. The latter two exercise pre-expansion admission.
Panic, OOM, timeout or an unrelated crash cannot count as a successful negative.
Unsupported types, ZKV1, alternative parameters, larger lists, GPU and inference
proof relations are outside this fixed experiment.

The report retains sizes of native, compact and **combined ciphertext-plus-proof**
lists, reserialized expanded ciphertexts, CRS, public key and compressed evaluation
key. Subtracting independently randomized encodings is not an isolated proof-size
measurement. Timings distinguish setup (including foreign-key test preparation),
CRS generation, native encrypt/encode, compact encryption, encryption-plus-proving,
standalone verification, unproven expansion, verified expansion, evaluation-key
expansion and owner decode/decrypt/check. Verified expansion invokes verification
again; its time is not pure expansion. Proof mode is `ZkComputeLoad::Verify`.
These single-run observations are not p99, service latency or speedup claims.

The 1 GiB expansion reservation is a policy estimate, not measured expanded-key
memory. Existing limits independently enforce 4 GiB address space per process,
128 MiB per file, 600 CPU seconds, no core files, a 600-second owner wall deadline
and a 480-second verifier deadline. Native files are temporary; reports contain
only allowlisted commitments/counts/sizes/times. Allocation fuzzing, production
memory accounting and independent cryptographic/security review remain pending.
