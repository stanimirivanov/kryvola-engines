# Permission-gated M1 Engines publication

This is the Engines prerequisite for Platform M1-PR30 (#48). It adds a separate
manual `.github/workflows/m1-release.yml` and `engines-m1-v1` inventory. The M0
fake release and its identities remain unchanged. Merging this code publishes
nothing and changes no research, distribution or commercial-service decision.

## Candidate preparation

Run from a clean committed checkout with a fresh ignored `build/m1` directory:

```sh
uv run --locked python tools/release.py install
uv run --locked python tools/m1_release.py prepare
```

The tool builds the real CPU Engine API binary and bounded TFHE CPU evaluator,
uses the existing dependency/symbol and non-root image checks, and compares
installed image bytes to the CPU archive. It builds the owner-only CPython 3.14
wheel and runs the existing isolated installed-wheel API and key-custody tests.
Source commit time fixes wheel timestamps. It also normalizes image-context
file modes/times and the Docker SOURCE_DATE_EPOCH build argument, following
[Docker reproducible-build guidance](https://docs.docker.com/build/ci/github-actions/reproducible-builds/). The inventory binds the exact source,
Two fresh, cache-disabled image builds use BuildKit timestamp rewriting and
must produce the same image configuration digest before a candidate is recorded.
The inventory binds the Spec pin, Cargo locks, runtime image recipe, separate owner wheel, SBOM and
in-toto/SLSA-format provenance. CPU archives cannot contain owner material.

The worker image uses the existing digest-pinned Python 3.14.7 base, contains only
the two CPU executables, bounded runner and licence, and runs as 65532:65532.
It never receives an owner wheel/key. The owner wheel remains a separate artifact
for a dedicated trusted owner environment. These are packaging/installed-boundary
checks, not a new inference, commercial-service or production qualification.

Preparation records `CANDIDATE` and `DENY`. Manual workflow mode `prepare`
uploads only JSON review metadata, not TFHE binaries or wheels. Local research
outputs stay in ignored build storage. It grants no distribution authority.

## Exact artifact approval

Use the existing [scoped review](scoped-crypto-review.md) and
[owner-wheel qualification](owner-python.md) protocols. Reviewers and the owner
builder operate outside this workflow; it never creates approval or builder
signatures. Prepare a tar with exactly these public files:

- `policy.json`: current operator policy, independently hash-pinned.
- `cpu/decision.json`, `cpu/legal.sig`, `cpu/parameters.sig`: current
  `artifact_distribution` approval over the exact `cpu-runtime.tar` hash.
- `image/decision.json`, `image/legal.sig`, `image/parameters.sig`: a distinct
  approval over the exact CPU image configuration SHA-256 recorded in
  `image-subject.json`. The OCI configuration commits the runtime settings and
  uncompressed root-filesystem layer hashes; this is distinct from approval of
  the CPU tar and from the registry transport manifest digest.
- `owner/decision.json`, `owner/legal.sig`, `owner/parameters.sig`: separate
  approval over the exact owner wheel hash.
- `owner/provenance.json`, `owner/builder.sig`: existing owner-wheel provenance
  format, binding the exact wheel, source and owner Cargo lock, signed by the
  independently provisioned builder key.

All three decisions bind the validated historical review predecessor and its TFHE
parameters. The same current policy supplies distinct legal/parameter authorities
and revocations. Supply the policy hash and builder public key independently;
never derive trust from the bundle being verified. No repository fixture policy
is trusted by default. Explicitly trusting fixture keys would be an operator
misconfiguration, not a permission supplied by this tool.

The external review workflow must inspect/reproduce the local research candidate
before signing. The publishing run rebuilds it and refuses any mismatch with the
independently selected archive, wheel and image configuration hashes. Reproducibility across machines is
not assumed: differing bytes require new review; they cannot inherit approval.
Review metadata/SBOM timestamps can differ without changing approved native bytes.

## Publication and consumer verification

After merge, the owner may explicitly dispatch `publish` on main with the exact
CPU archive, image configuration and owner wheel hashes, HTTPS review-bundle URL/hash, current policy hash and
owner-builder DER Ed25519 public key hex. The URL carries no credentials; use
public approval material only. The bounded fetch rejects extra files and unsafe
archive members. Incomplete trust inputs, changed artifacts, stale/revoked
approvals and wrong builder provenance fail before any image push.

After approval, the workflow pushes a fresh CPU image, pulls it by immutable
digest, rechecks its approved configuration digest and bytes, and records `image.json`. It binds the
approval evidence and digest in the final manifest, keylessly signs it, verifies
the exact main workflow identity/source/issuer/trigger and current permission,
and uploads a fresh `m1-FULL_SOURCE_SHA` draft before exposing a prerelease.
Only the publish job has registry/release/OIDC permissions. No local-key bypass
is exposed. No SP1 package or commercial-service permission is added.

Image push and GitHub Release creation are not transactional. A failure can leave
an image or draft; stop and inspect it rather than replacing/deleting/retrying
publication automatically. Missing registry information fails closed. The original
source tag is never overwritten. Permissions expire and can be revoked after
publication; a signed manifest alone does not confer ongoing authority.

Consumers use the matching pinned verifier checkout and independent current pins:

```sh
uv run --locked python tools/m1_release.py verify --folder DOWNLOADED_ASSETS \
  --source FULL_SOURCE_SHA --policy-sha256 CURRENT_POLICY_SHA256 \
  --builder TRUSTED_OWNER_BUILDER_PUBLIC_KEY_HEX
```

Verification checks exact asset and schema/lock bindings, publisher identity,
current signed decisions, owner builder provenance, and pulled image/archive byte
agreement. A changed current policy pin invalidates bundled older evidence; obtain
updated approved release material rather than trusting stale review state. Platform
must pin the final manifest/package hashes, Spec pin, image digest and current
permission evidence. Local candidates and M0 fake assets remain ineligible.
