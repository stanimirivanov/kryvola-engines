# Experimental engine packaging (M0-PR24)

`uv run --locked python tools/release.py verify` checks dependency configuration
only and explicitly reports that it verified no signed package. Full Linux
qualification is `uv run --locked python tools/verify.py full`; CI splits it
across native and SP1 jobs. Expect additional clean compiler builds. Run in a
fresh checkout: generated `build/repro-*`, first binaries and package directories
must not already exist. This intentionally refuses to overwrite prior evidence.

`tools/qualify_release.py native` compares two clean Cargo target-directory builds
for each fake evaluator, TFHE compute evaluator and owner fixture. The `sp1`
group does the same for the local public-metadata prover after compiling its
guests. Compiler/registry caches and the already pinned guest ELFs are reused;
this does not establish independent reproducibility of the compiler or guest
toolchain. Differing executable bytes fail qualification, rather than being
silently excluded. Paths, toolchain and source checkout are fixed across builds.
Tar entries use fixed order, ownership, permissions and zero timestamps. SBOM
timestamps/namespaces and signature randomness are intentionally outside this
binary/archive reproducibility comparison.

Each package contains only `engine`, `LICENSE` and its Cargo lock. Distinct roles
produce separate archives. The compute-only TFHE feature excludes owner CLI
entry points; all three owner routes must return rejection code 29. Native
libraries still contain shared types and this is not a sandbox or proof that
every owner-related implementation byte was removed. Compute receives no owner
key, key file or decryption endpoint. The owner fixture is the trusted research
executable, including its existing evaluator subprocess; no owner SDK is implied.

Syft 1.55.0 and Cosign 3.1.3 are downloaded only by explicit Linux qualification,
with archive and executable SHA-256 pins checked. Existing Apache-2.0 upstream
tools are build-only, with no application dependency. Syft's SPDX 2.3 inventory
includes the binary and Cargo lock; cataloging does not prove inventory/license
completeness. The SLSA-v1-shaped in-toto provenance binds the actual tar subject,
source commit, lock, role and both compared binary digests. Its builder explicitly
claims local qualification, not a SLSA assurance level or trusted compiler.
The signed manifest binds tar, SBOM and provenance hashes. Consumers supply their
trusted public key or use the exact workflow identity/issuer; package-supplied
keys are never trusted. `verify --output PATH --key TRUSTED.pub` is local
qualification; `verify --output PATH --publish-check` requires keyless verification
and rejects caller-selected keys. Subject tampering, missing SBOM and owner-file
injection are rejected before acceptance. CI also uses a real second signer as
a negative control; ephemeral signing keys remain outside package directories.

TFHE/SP1 distribution and service permissions remain **DENY**. Their packages,
SBOMs and local test signatures stay only on the CI runner; no workflow uploads
them. Changing a manifest cannot override the dependency gate. There is no
automated legal approval. The separate manual `release.yml` runs only on main,
rebuilds/qualifies **fake-evaluator only**, then replaces its local test signature
with a transparency-logged keyless signature. Verification pins
`https://github.com/stanimirivanov/kryvola-engines/.github/workflows/release.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. Explicit filenames
exclude signing keys and all crypto packages. Commit-addressed experimental
versions refuse existing tags/releases; the workflow never uses overwrite flags.
Server-enforced release immutability and branch protections are maintainer settings.

`containers/Dockerfile` pins Ubuntu 24.04 Linux/amd64, copies only the three files
from an extracted verified single-role package, and runs as UID 65532. Never use
the repository as build context. Qualification builds/runs fake loopback
conformance read-only without external networking; no OCI image is published or
claimed reproducible here. CPU/prover/owner runtime images, private registry
promotion, full notices/legal review and production qualification remain blocked
or unqualified. Archives are the signed release subjects, not image digests.

## Fake OCI publication (M0-CLOSE-PR6)

The manual main-only release workflow now separates read-only qualification from
publication. Qualification saves its tested fake image as ignored
`build/runtime-fake.tar`; only that image and the explicit fake package cross the
job boundary. Crypto packages and local signing keys never become upload assets.
The publish job alone receives contents/packages-write and OIDC permissions.

The proposed image location is
`ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator:experimental-FULL_SHA`.
A maintainer must configure GHCR package access/visibility and authorize dispatch.
Publication refuses existing tags and treats registry authentication/network errors
as failures, not absence. Registry permissions must permit an authenticated absence
check; an ambiguous first-publication response requires maintainer resolution.
Concurrent authorized publishers outside this workflow remain an administrative
risk; server-side protections are not installed by this PR.

The publisher signs/verifies the fake archive, loads the qualified image and pushes
once, then uses only its resolved digest. It pulls that digest, checks the non-root
entrypoint, compares every /opt/kryvola file with the signed archive (rejecting extra
owner files), and runs read-only network-disabled conformance. Syft scans that
registry digest. Cosign signs the image and a manifest binding source, archive
manifest hash, Dockerfile hash, OCI digest, SBOM and provenance. Provenance is a
publisher assertion, not a SLSA-level or independent image-reproducibility claim.
TFHE/SP1 distribution/service permissions and pending approvals remain unchanged.

OCI evidence uploads use the distinct names `oci-manifest.json`,
`oci-manifest.sigstore.json`, `oci-provenance.json`, `oci-sbom.json`. Download them
into a separate directory and remove the `oci-` prefix; keep the five archive assets
in their own directory. Independently select the expected source and image digest,
check out that source (the archive verifier requires exact HEAD), install pinned
tools, authenticate registry reads if necessary, and verify:

```sh
uv run --locked python tools/oci_release.py verify --source FULL_SHA --image ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator@sha256:EXPECTED_DIGEST --package DOWNLOADED_ARCHIVE --folder DOWNLOADED_OCI
```

Verification checks keyless workflow identity, issuer, source and dispatch trigger
for both image and signed records, then repeats pulled-image conformance. It needs
Docker/registry access; no caller-selected key or mutable tag is accepted. Archive
signatures do not alone authenticate an image. A failed publish may leave a partial
registry artifact; inspect and supersede it rather than overwriting/retrying blindly.
Withdrawal must identify the old digest; never erase history or imply M0 approval.
