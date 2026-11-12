# Permission-gated M1 Engines publication

This is the Engines prerequisite for Platform M1-PR30 (#48). It adds a separate
manual `.github/workflows/m1-release.yml`, unchanged v1 candidates and explicitly
labelled v2 owner-approved development releases. The M0 fake release and its
identities remain unchanged. Merging this code publishes nothing and supplies no
actual artifact approval or commercial-service decision.

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
[Docker reproducible-build guidance](https://docs.docker.com/build/ci/github-actions/reproducible-builds/).
Two fresh, cache-disabled image builds use BuildKit timestamp rewriting and
must produce the same image configuration digest before a candidate is recorded.
The inventory binds the exact source, Spec pin, Cargo locks, runtime image recipe,
separate owner wheel, SBOM and
in-toto/SLSA-format provenance. CPU archives cannot contain owner material.

The worker image uses the existing digest-pinned Python 3.14.7 base, contains only
the two CPU executables, bounded runner and licence, and runs as 65532:65532.
It never receives an owner wheel/key. The owner wheel remains a separate artifact
for a dedicated trusted owner environment. These are packaging/installed-boundary
checks, not a new inference, commercial-service or production qualification.

Preparation records `CANDIDATE` and `DENY`. Manual workflow mode `prepare`
uploads only JSON review metadata, not TFHE binaries or wheels. Local research
outputs stay in ignored build storage. It grants no distribution authority.

## Solo-owner development approval

The project owner explicitly replaced the separate legal/parameter reviewers,
external policy packet and builder key for M1 development releases. See
[decision 0001](decisions/0001-solo-owner-m1-development.md). This is a project
release decision, not an independent review or a grant of third-party rights.
The historical M0 research records and standalone scoped-review/owner-wheel
qualification protocols are unchanged.

After inspecting the prepared hashes, the repository owner `stanimirivanov` may
explicitly dispatch `m1-release.yml` on main with mode `publish`, the three exact
`cpu_sha256`, `image_sha256`, `owner_sha256` inputs, and the
`approve_development_distribution` checkbox enabled. It defaults to false.
No reviewer handoff, evidence URL, reviewer signatures, policy hash or separate
builder key is needed. Missing approval, another actor, a non-main/non-dispatch
context or any changed native subject fails before native artifact transfer.

The preparation job rebuilds/qualifies the real artifacts, then records
`owner-approval.json` with owner, source, run ID and all three hashes. It explicitly
states `development_distribution`, `independent_review: false` and
`production_ready: false`. The dependent publisher snapshots those bytes, checks
that the approval belongs to the current owner dispatch, verifies image/archive
agreement before registry push, and binds the approval into the final manifest.
GitHub OIDC signing supplies authenticated workflow/source provenance; it replaces
the separate builder signature for this profile.

**Behavior change:** approved releases use `engines-m1-v2` and
`OWNER_APPROVED_DEVELOPMENT_ONLY`. They are never labelled independently reviewed
`SCOPED_ARTIFACT_DISTRIBUTION`. Consumers must explicitly accept this development
profile and select exact approved source/package/manifest/image hashes; the
publisher signature does not establish licence/patent rights, parameter security,
commercial-service permission or production qualification. Do not silently enable
this profile in old consumers. Withdraw a development release from the operator's
selected set if it is no longer acceptable; there is no external reviewer-policy
expiry/revocation ceremony for this owner-only profile.

Candidate preparation remains `engines-m1-v1`, `CANDIDATE`, `DENY`. The sealed
existing c318ea3 candidate and its hashes are not rewritten by this policy change.
After tooling changes merge, prepare a fresh source-bound candidate for the new
main commit before separately authorizing publication. Rebuilds must match the
three owner-selected native hashes; changed bytes require a new owner decision.

## Publication and consumer verification

Only manual main publication can push the CPU image or create a release. The
publisher pulls its new image by immutable manifest digest and compares its
configuration and installed bytes to the approved candidate. Only that job has
registry/release/OIDC write permissions; read-only qualification precedes it.

Image push and release creation are not transactional. A failed run may leave an
image or draft: inspect rather than deleting/replacing/retrying publication
automatically. Existing source tags/releases are never overwritten. No SP1
package or production profile is enabled.

Consumers use the matching pinned verifier checkout:

```sh
uv run --locked python tools/m1_release.py verify --folder DOWNLOADED_ASSETS \
  --source FULL_SOURCE_SHA
```

Verification requires the exact GitHub main workflow identity, issuer, source SHA
and dispatch trigger, all subject/schema/toolchain hashes, the explicitly labelled
owner development approval, and pulled image/archive agreement. No key-based
bypass is exposed. The removed `fetch-evidence`, `--packet`, `--policy-sha256`
and `--builder` CLI inputs are not accepted for M1 publication. Platform #48 must
consume the v2 profile without reinterpreting frozen M0 records or claiming an
independent review. Local candidates remain ineligible as published inputs.
