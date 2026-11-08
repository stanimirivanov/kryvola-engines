# Artifact-backed CPU Engine

The local worker serves the published Engine gRPC API on a private Unix socket.
Launch one worker per approved physical execution from an operator-owned
directory with mode `0700`. Put the versioned Engine ExecuteRequest in
`assignment.json` as `execute_protobuf_hex`. The worker admits only the exact
request from that trusted assignment and the fixed FHE-Q1 uint8 program.
The dispatcher authenticates the plan, policy and caller before preparing the
assignment. Its authorization stays outside the gRPC payload.

The assignment also specifies `fabric_address` (a socket address),
`fabric_id` and `worker_id` (exact SPIFFE IDs), and `workload_endpoint`
(a Unix SPIFFE Workload API URI). Fabric connections require the configured
peer identity. Input references are ordered evaluation key first and
ciphertext pair second. Use the canonical v2 manifest and native codec
`tfhe-rs-1.8.1`. The worker verifies the manifest, indexed chunks and full
blob before staging private input files. The evaluator child receives
only evaluation material and exact commitments via the existing bounded
CPU supervisor.

The mode-`0600` assignment has a `credentials` object with `reads` (two
arrays, each containing a fresh compute-read token for the manifest followed
by each part), `output` (the execution-scoped issuance capability), and
`receipt` (the execution-scoped receipt capability). The trusted dispatcher
provisions these through Fabric policy. Keep the assignment outside RPC,
workflow history and image build context. Supply absolute paths for
`evaluator`, `supervisor` and `receipt_key` (a private PKCS#8 Ed25519 signing
key). The `receipt` metadata object supplies `signer`, `key_id`, `key_epoch`,
`policy_epoch`, `consent_digest`, `model_digest`,
`capability_profile_digest`, `leakage_profile_digest` and
`evidence_policy_digest` from the approved context.

Status reports a candidate only after Fabric finalizes the execution's
scoped upload and acknowledges its signed confidentiality-only receipt.
Repeated Execute calls for the assignment share the current observation.
The worker keeps observations in memory. After a restart or ambiguous
commit, the dispatcher reconciles durable Fabric state before assigning
another execution. Local cancellation requests stop subsequent stages and
let the bounded child exit. Fabric's committed fence remains authoritative
for cancellation, recovery and publication. Result selection and release
stay with their existing authorities.

The CPU verification gate runs a real Engine RPC and native evaluation
with owner-generated ciphertext through a controlled Fabric protocol
fixture, then opens the result in the separate owner test process. It also
builds and inspects a local-only worker OCI image whose application layer
contains the Engine, isolated evaluator, supervisor and license. Use a
writable private mount for the socket and bounded scratch space for the
runner. No production distribution or OCI publication is enabled.
