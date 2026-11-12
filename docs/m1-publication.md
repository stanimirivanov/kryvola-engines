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
Reproducible builds explicitly create a disposable `docker-container` builder
using the digest-pinned BuildKit v0.34.2 image in `tools/cpu_engine_package.py`.
Its bundled Dockerfile frontend/exporter and explicit `linux/amd64` platform
replace dependence on the host daemon's integrated builder. The builder is
removed after each build, including build failures; no shared cache or default
builder selection is used. Non-release builds without `SOURCE_DATE_EPOCH`
retain their existing local Docker path.
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

## Image configuration identity

The approved image subject is SHA-256 of the actual OCI/Docker configuration JSON
bytes, not a mutable tag, Docker inspect `.Id`, registry manifest digest or an
annotation. Docker image stores may report a manifest digest as `.Id`.
`image_identity` resolves an immutable local Docker reference, exports that image
with [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/),
and reads the single configuration referenced by the archive's `manifest.json`.
It supports `blobs/sha256/DIGEST` and classic `DIGEST.json` layouts, verifies the
[content-addressed configuration](https://github.com/opencontainers/image-spec/blob/main/config.md),
and rejects missing, ambiguous, linked, oversized, malformed or mismatched data.
The archive is temporary; no layer files are extracted or candidate files edited.
Configuration reads are capped at 1 MiB and export at 120 seconds.

Preparation compares two configuration digests. Publishing and consumer
verification compare rebuilt/pulled configurations to the same approved digest.
Docker tagging uses the separately resolved immutable local image reference,
because a configuration digest may not address an image in the Docker store.

Issue #59 corrects identity extraction without changing the current 4fb8e8d
candidate or hashes. Its recorded configuration field contains the old local
manifest ID; do not rewrite that sealed record or publish it as corrected.
After merge, prepare a fresh source-bound candidate and inspect its newly
recorded configuration digest before any separately authorized publication.

## Hosted reproduction regression — issue #61

The failed hosted runner image `ubuntu24/20261101.360` supplied Docker 28.0.4.
An isolated Docker 28.0.4 daemon with its classic overlay2 image store reproduced
the failure before the fix: actual exported configuration digests differed
between two cache-disabled builds. Captured configuration JSON differed only in
`rootfs.diff_ids` (the two added filesystem layers); `history`, runtime `config`
and all other fields were identical. The original hosted configurations were
not retained, so this diagnoses the reproduced failure rather than claiming a
byte-for-byte comparison with the hosted images.

This matches the integrated-exporter limitation described in
[BuildKit issue 4986](https://github.com/moby/buildkit/issues/4986): timestamp
rewriting needs the containerd image store when using that Docker driver.
The pinned container builder instead uses BuildKit's own
[timestamp-rewriting exporter](https://github.com/moby/buildkit/blob/v0.34.2/docs/build-repro.md#source_date_epoch)
and loads its result into either host image store. The base image, worker
inventory, non-root execution, owner-route rejection, installed-byte checks,
actual configuration comparison and exact owner-selected hash gates remain.

The existing `tools/cpu_boundary.py` gate also runs this real Docker regression
in the required `tfhe` CI job and canonical native/full verification:

```sh
uv run --locked python -m unittest tests.live_cpu_image_reproduction -v
```

Run it after `cpu_boundary.py` has built the debug Engine API executable and
release evaluator. It builds two images in separate fresh pinned builders,
compares actual exported configuration-byte digests, then changes worker bytes
and requires a different digest. Each build runs the worker image boundary
checks. Test images use unique tags and are removed without touching the
candidate directory or `kryvola-cpu-engine:local` tag. No artifacts are uploaded.

The approved `e1c61db` candidate and its hashes are preserved. This tooling change
does not prepare or publish a candidate. After merge, a fresh source-bound
candidate and any changed hashes require a separate owner decision.

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

## Native build identity — issue #63

Image timestamp reproduction does not make ambient native builds portable.
The 78ffa30 hosted run passed within-run image equality, then rejected the local
approval with CANDIDATE_PIN: its evaluator and image configuration bytes differed.
The local system used Ubuntu 26.04/GCC 15; hosted used Ubuntu 24.04. A real Rust
fixture also demonstrates that checkout, registry and generated-source paths can
change native bytes. The original hosted binaries were not retained, so the
precise contribution of each input to that historical difference is unproven.

M1 native subjects now build in a separate, unshipped Linux/amd64 toolchain
container. Native-Build.Dockerfile pins the Python/Debian, Rust and uv images by
digest; uv.lock supplies the exact maturin/dependency hashes. No apt repository,
host compiler, host Python, host Cargo target or host build flags supply release
subjects. The existing checkout mounts read-only at /src; each build gets its own
writable /build and Cargo cache. Only SOURCE_DATE_EPOCH is forwarded from the
caller. Rust uses baseline x86-64 and explicit
[path remapping](https://doc.rust-lang.org/rustc/command-line-arguments.html#--remap-path-prefix-remap-source-names-in-output)
for source, registry and generated paths. uv installation follows its
[container guidance](https://docs.astral.sh/uv/guides/integration/docker/).
This owner-capable build environment is separate from the compute image.

Preparation inspects and packages these exact worker binaries and installs/tests
the exact owner wheel. Existing worker/owner separation, installed-byte checks,
image digest equality and approval/hash guards remain enforced. The native build
recipe is an additional manifest subject; use the source-matching verifier.
Historical manifests and approvals are not migrated or rewritten.

`uv run --locked python tools/native_build.py qualify` builds all three subjects
twice with disjoint clean compiler/registry caches, compares exact bytes, then
requires changed evaluator source to change its digest. It never uploads native
artifacts or prepares/authorizes a candidate. This required CI native-reproduction
job and canonical native/full gate supplement all existing checks. Temporary
containers and compiler/registry directories are cleaned on completion/failure.

The approved 78ffa30 candidate and hashes remain unchanged. Merging this fix
publishes nothing; prepare and separately approve a fresh source-bound candidate
after merge before any publication. A green local run is not a hosted result or
independent native compiler/crypto qualification.
