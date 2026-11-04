# Scoped TFHE review verification

Run the historical qualification check with no arguments. To verify a successor
decision for one TFHE artifact, provide all five scoped arguments:

```sh
uv run --locked python tools/qualification.py \
  --review "$review_packet" --policy "$operator_policy" \
  --policy-sha256 "$trusted_policy_sha256" \
  --intended-use artifact_distribution --artifact-sha256 "$release_artifact_sha256"
```

Scoped verification requires OpenSSL 3 with Ed25519 support. The operator supplies
the current policy digest and expected artifact digest from independent trusted
sources. In particular, never derive the expected digest from the review packet.
The host clock and OpenSSL executable are part of the verifier's trust boundary.

The version 1 policy JSON has exactly four fields: `version`, `expires_at`,
`authorities`, and `revoked`. Authorities map the two roles `legal` and
`parameters` to distinct lowercase hex DER Ed25519 SubjectPublicKeyInfo values.
Provision those keys only after confirming each reviewer's authority for the
intended use. The revocation list contains lowercase SHA-256 digests of withdrawn
decision bytes. Rotate the independently distributed policy pin when replacing
keys or recording withdrawals. Use a short policy expiry and reverify before use.

The packet contains `decision.json`, `legal.sig`, and `parameters.sig`. Each
signature is a raw 64-byte Ed25519 signature over the exact decision file bytes.
Both roles approve the same bytes. The decision has exactly these fields:

| Field | Value |
| --- | --- |
| `version` | Integer 1 |
| `predecessor_sha256` | SHA-256 of the validated historical M0 review packet, which binds the dependency version, crate digest, parameter set, program and fixtures |
| `dependency` | `tfhe` |
| `intended_use` | `artifact_distribution` or `commercial_service` |
| `artifact_sha256` | Expected artifact digest in lowercase hex |
| `decision` | `APPROVE` |
| `valid_from`, `expires_at` | Integer Unix seconds, with inclusive start and exclusive end |

Exit zero in scoped mode includes an authenticated `scoped_review` with the
decision and policy digests and the earliest expiry. A rejection exits nonzero.
Treat the report as a point-in-time verification result. A publisher or runtime
must independently supply the expected artifact and current policy pin, and
enforce the result at its own boundary. The historical research report retains
its pending dispositions and production flags.
