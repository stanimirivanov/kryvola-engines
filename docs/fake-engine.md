# Test-only Engine RPC conformance (M0-PR15)

`cargo run --locked -p kryvola-fake-engine -- conformance` starts the generated
EngineService on an ephemeral **loopback-only** listener, exercises real RPCs and
shuts it down. The binary accepts only that command: it has no deployment/serve
mode, remote endpoint, program path or arbitrary-code option. The crate is
`publish = false`; it performs no encryption, inference, artifact fetch/upload,
proof generation/acceptance or decryption. Its synthetic references identify no
stored ciphertext. Passing this command provides protocol-test evidence only.

Every successful response carries `x-kryvola-fake: true`. Capabilities have the
fixed all-zero `FAKE_ENGINE_DIGEST`, which cannot be configured to impersonate a
real image. FHE-Q1 is a **fixture label required by the closed preview schema**,
not an enabled/qualified assurance profile. The referenced baseline inventory
remains disabled; production admission must never allowlist this fake identity.
Simulated SUCCEEDED observations and `fake-output-*` zero-byte references cannot
be treated as real computation results or cryptographic evidence.

## Behavior and boundaries

The in-memory map retains 1–64 identities, including terminal records and
cancel-before-submit tombstones. Identity includes the entire attempt (tenant,
operation, workflow/attempt epoch, fence) plus execution ID. Identical concurrent
or repeated Execute requests recover the same record; changed immutable intent
fails with ALREADY_EXISTS. New entries fail RESOURCE_EXHAUSTED at capacity;
retained entries are not evicted to make room for a duplicate effect. Restart
loses this test state: there is no durable or cross-process exactly-once claim.

The driver owns an explicit monotone test clock; clients cannot change it by RPC.
Requests must match the fixed synthetic engine/program/parameter/operator/profile
capabilities and their operation/execution/reference context. A new expired request
fails DEADLINE_EXCEEDED. Existing RUNNING rows become EXPIRED at their deadline;
otherwise the second status poll simulates completion. Polling advances fake work
deliberately; it is not a production scheduler/liveness pattern.

Cancellation and status/execute transitions serialize under one mutex. A cancel
before Execute returns NOT_FOUND but reserves a tombstone that rejects a delayed
submit. Cancellation of RUNNING work yields CANCELLED; a terminal completion or
expiry that wins first remains immutable. Repeated cancellation has no new effect.
These are physical test observations, not a workflow cancellation acknowledgement,
registry fence or release decision. The fake clock never revives terminal rows.

## Serialization and prior art

The complete generated and native bundles are adopted unchanged from spec
`1a5b57a590487ba116913050af8041f5e5f1fb52` / `0.1.0-preview.10`.
`spec.lock.json` pins both manifests; the architecture gate checks every file and
the native manifest's generated-source hashes to reject mixed snapshots. No sibling
implementation source is imported and no contract is authored in this repository.

The boundary adapts the spec native conformance pattern and
[Tonic's Codec/Decoder extension point](https://docs.rs/tonic/0.14.6/tonic/codec/trait.Decoder.html).
A test-crate-local `tonic_prost` alias routes the **unchanged generated bindings**
through `codec::ProstCodec`. It uses Prost for actual encoding/decoding, rejecting
oversize bodies, unknown fields (recursively), missing/unsupported versions and
schema-invalid references **before** permissive typed Protobuf decoding. Outbound
messages are checked too. There is no handwritten Protobuf/gRPC parser or generated
service fork. Tonic handles gRPC framing and enforces the 64 KiB message limits;
normal Protobuf merging/order semantics apply, never canonical signing semantics.
Explicit descriptor/state errors contain fixed codes, not input or parser diagnostics.

This adds exact runtime dependencies/interface wrappers: Tonic 0.14.6, Tokio
1.54.1, tokio-stream 0.1.19 and bytes 1.12.1 (MIT); Prost 0.14.4 (Apache-2.0),
prost-reflect 0.16.5 and serde_json 1.0.154 (MIT/Apache-2.0), and jsonschema
0.60.1 (MIT, default HTTP/file-resolution features disabled). Cargo locks the
transitive graph; no Python dependency or crypto library is added. License labels
are not the release-specific legal/security disposition required by later gates.

## Checks and limits

`uv run --locked python tools/verify.py full` remains the CI entry point. It includes
Clippy/Rust tests, the executable conformance command, existing Python checks and
C++ build/tests. CI allows 25 minutes for the first dependency build. Locally run
formatters, Python lint/types/provenance/negative tests and Cargo metadata; heavy
Rust/C++ compilation and RPC execution remain on CI per user instruction.

RPC conformance covers generated clients, independent raw malformed requests,
concurrent/identical/conflicting Execute, status progression, expiry, cancel-before-
submit, status/cancel races, unsupported capabilities, capacity/tombstone bounds,
bad references/versions/nested fields, oversize frames and absent decrypt methods.
Connection/request timeouts are three seconds, the check sequence is bounded at
30 seconds and shutdown at three seconds. No external database, Ray, Temporal,
owner agent, key service or artifact store is required or contacted. Authentication,
durability, real parameter approval, signatures/proofs, release and actual inference
remain separate gates; M0 and the real Engine implementation remain partial.
