# M0 dependency and toolchain candidates

M0-PR35 records the current [measured research decisions](m0-feasibility.md).
Two complete fixed-source Linux CPU campaigns now provide experimental build and
runtime evidence. The M0-PR18 `NOT_BUILT` matrix below remains the historical
candidate snapshot, not a current build verdict; its immutable metadata bytes and
policy permissions are preserved. Research evidence does not qualify production
parameters or grant legal/distribution/service approval.

M0-PR24 supersedes the original Syft/Cosign deferral below for **build tools only**:
their archive/executable pins and actual qualification commands are documented in
[engine packaging](engine-packaging.md). They remain forbidden as application
dependencies. TFHE/SP1 distribution/service denials and pending legal review are
unchanged; build-tool adoption grants no crypto publication permission.

M0-PR18 records research candidates, not a qualified engine release. No TFHE/SP1
dependency, guest compiler, CUDA toolchain or service client is installed or added
to the workspace by this change. Distribution and commercial service are denied.
An automated metadata/license check is not counsel approval or a patent licence.

## Exact released observations

On 28 October 2026, the published `.crate` archives were downloaded for bounded
metadata inspection, their SHA-256 values compared with the crates.io version
records, and embedded VCS commits compared with released source revisions.
This was archive inspection, not compilation, publisher-signature verification or
transitive-license/security qualification. The offline snapshots in
`config/dependency-evidence` preserve published manifests, VCS metadata, registry
records and source licences. Their bytes must remain unchanged.

| Candidate | Published crate SHA-256 | Source revision | Declared Rust minimum |
| --- | --- | --- | --- |
| TFHE-rs `tfhe` 1.8.1 | `0d60dcde24115624e62a9a8dc627daa8d3dad40e8de69975957d12ee9ab70a2b` | `187fc0b95ab35352422deec6c027d0bd8743b6db` | 1.91.1 |
| SP1 `sp1-sdk` 6.9.0 | `297c14b40e6a2c845c61e496f68f38dc04b6a249780cdac404656ff561516f2a` | `b8387fa61e1361d90ee7de49f551863418ca0f08` | 1.88 |

Primary sources: [TFHE manifest](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/Cargo.toml),
[TFHE source licence](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/LICENSE),
[SP1 workspace](https://github.com/succinctlabs/sp1/blob/b8387fa61e1361d90ee7de49f551863418ca0f08/Cargo.toml),
[SP1 SDK features](https://github.com/succinctlabs/sp1/blob/b8387fa61e1361d90ee7de49f551863418ca0f08/crates/sdk/Cargo.toml).
`notice.json` records a README source hash and collection summary, not a mirrored
full document, authenticated review or proof that terms cannot change.

## Permission and compatibility boundaries

Local, noncommercial research is a scoped project disposition only. TFHE-rs uses
BSD-3-Clause-Clear, whose patent rights are separate; its
[pinned upstream notice](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/README.md)
describes commercial patent licensing. SP1 declares MIT OR Apache-2.0 source
licensing; that does not approve a hosted prover service or every transitive
dependency. Both distribution and commercial-service classes remain `DENY`, with
legal review `PENDING`. Real distribution requires scoped review of notices,
transitives, patents, intended use and service terms, plus build provenance and
artifact qualification. No policy field can claim those approvals in this stage.

The candidate matrix is Linux `x86_64-unknown-linux-gnu`, host Rust 1.98.1, with
default features disabled. TFHE selects `integer`, `software-prng` and (since
M0-PR21) `zk-pok`; SP1 selects
no optional features. Remote proving, GPU, experimental and internal key-cache
features are not admitted. The Rust minimum comparison is a necessary metadata
check, **not** evidence of compiler/ABI compatibility. Both rows remain `NOT_BUILT`;
native compilers are `NOT_VERIFIED`. CPU build/runtime qualification belongs to
PR19 and the subsequent proof experiment, now observed within the cited PR35
research envelope. No supported production combination is
asserted. Host Python 3.14.7/uv 0.12.5 pins govern our harness only; selected
artifacts are Rust crates, not Python wheels. No CPython 3.14 owner wheel is selected.

Actual release observations also show TFHE CUDA backend 0.16.0 at source
`ab8ba567443002718a98c16899e5578698be8778`, crate SHA-256
`1ecc90bab457e0eadf839b12dbc28df0970de7518a3e00ab5bb5c446ae15fdf4`.
It is not admitted. Neither CUDA compiler/driver compatibility nor GPU execution
was verified. SP1 6.9.0 publishes a Linux amd64 cargo-prove archive with SHA-256
`0eb8a2b3eef9b498443a338a545422a7acd37ee08d17d784a9c16f4c0bfb975b`;
the original snapshot did not admit it. M0-PR22 subsequently pinned that CLI and a
guest compiler image digest in `tools/sp1_relation.py`; the public Core experiment
has now run successfully. Do not substitute a mutable upstream toolchain installer.
Production guest/compiler, CUDA/hardware and binary/wheel qualification remain gaps.

Optional RISC Zero, OpenFHE, SEAL, TenSEAL and MP-SPDZ remain deferred. Syft and
engine-publication Cosign adoption require separately pinned build tools; the
platform's Cosign verifier does not qualify engine binaries. SeaweedFS and
Redpanda are platform-owned choices, with consistency/feature and deployment-term
reviews still required. In particular, Redpanda must not be classified wholesale
as permissively licensed OSS. Deferred entries select no version or artifact and
cannot be requested as research candidates; they are not missing candidate pins.

## Offline gate

Run `uv run --locked python tools/dependency_policy.py`. It validates exact fields,
pins, evidence integrity, recorded source/licence metadata, declared Rust minimums,
research-only permissions and the deliberately unqualified matrix. It performs no
network calls, tool installation or build. The standard harness calls it before
Rust checks. Optional request examples:

```sh
uv run --locked python tools/dependency_policy.py --candidate tfhe --purpose local_research
uv run --locked python tools/dependency_policy.py --candidate tfhe --purpose artifact_distribution
```

The second command must fail. With a local, explicitly selected crate archive,
append `--artifact PATH` to the research request to verify its exact size/hash.
No archive extraction or execution occurs. Policy validation is not an execution
permit or a substitute for the feasibility harness.

Direct candidate Cargo declarations must use exact `=VERSION`, disabled defaults
and recorded features; aliases, feature forwarding, target/build/dev declarations, patches and lock
identities are checked. Candidate workspace inheritance is deliberately rejected
by this first gate; isolated experiments should declare their explicit pins.
Deferred direct GPU/alternative dependencies fail. This static sensor is not full
Cargo feature resolution, a transitive SBOM, CMake/Python dependency enforcement
or proof of legal rights. Publication gates retain those responsibilities.

M0-PR21 records `zk-pok` in the isolated TFHE research feature set and locks its
optional proof backend. The [compact experiment](tfhe-compact.md) describes its
additional dependency weight and unqualified setup. Existing TFHE/SP1 versions,
licensing dispositions and distribution/service denials remain unchanged.
