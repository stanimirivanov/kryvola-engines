# Parallel foundation CI

Pull requests and pushes to `main` run the foundation workflow. Feature/fix
branch pushes no longer start a second workflow alongside an open PR. Main
pushes still verify the merged revision; manual release workflows are unchanged.

The stable required aggregate check remains `verify`. It requires every listed
job to succeed, including all native qualification matrix entries. Failures,
skips, cancellations, and missing results fail the aggregate. Matrix fail-fast is
disabled so one role cannot conceal another role's results. Repository protection
settings that separately require the old `native` or `sp1` job names should be
updated to require `verify`; this change does not edit remote protection rules.

| Job | Existing gates | Dependency |
| --- | --- | --- |
| `foundation` | Canonical fast checks; full Python regressions; Rust workspace tests; fake RPC conformance; CMake/CTest; API inspection and C++ executable | None |
| `owner` | Both Rust owner tests and installed research-wheel tests | Foundation |
| `tfhe` | Codec, evaluation, and compact-input experiments sharing a target directory | Foundation |
| `native-qualification` matrix | Fake evaluator, CPU evaluator, owner fixture; each role retains two clean builds, archive/signature controls and applicable Docker/API negatives | Foundation |
| `sp1-build` | Pinned CLI/archive validation and Docker guest builds for metadata and alternate ELFs | Foundation |
| `sp1-measurements` | Host build, two fresh-process FIFO samples, real verifier and all seven native negative controls per sample | SP1 build |
| `sp1-qualification` | Two fresh host builds, package comparison and signature/wrong-signer controls | SP1 build |
| `verify` | All seven required job IDs must report success | All jobs above |

`tools/ci.py` dispatches these partitions. The original `tools/verify.py`
fast/native/full commands remain available with their existing behavior.

## SP1 transfer boundary

Only public guest ELFs and their manifest move between jobs. No proof objects,
private keys, host executables, or Cargo target trees are transferred. The upload
and download actions are commit-pinned. Consumers select the producer's immutable
artifact ID within the same workflow run, so rerunning failed consumers can use
the successful producer's artifact. Artifact retention is one day; after expiry,
rerun the full workflow to rebuild guests.

The manifest binds both ELF SHA-256 digests, the checked-out Git revision, CLI
checksum, pinned Docker image, and proof-profile digest. Its SHA-256 travels as a
separate producer job output. Before any host build, proof execution or release
qualification, consumers reject a mismatched manifest pin, source revision,
configuration, missing/extra files, symlinks, oversized files or changed ELFs.
The workflow's trusted producer and GitHub job/artifact isolation remain the
transport trust boundary; this is not independent release authorization.

`tools/sp1_ci.py` adapts the frozen preparation and measurement orchestration.
It calls the existing native process runner, report validators and qualification
function. Historical M0 scripts and their pinned source digest are unchanged.
Both measurement samples remain sequential on one runner with the original
`LOCAL_FIFO_TWO_ADMITTED_ONE_ACTIVE` policy and cache classification. Each
qualification job retains its two sequential, fresh-target builds and one Cargo
build job. No target cache replaces a reproducibility build.

Parallelism removes serial waiting between independent roles and overlaps SP1
measurements with SP1 qualification after guest preparation. Actual elapsed time
depends on runner availability; no speedup is claimed before hosted results.
Total job count increases, while the duplicate feature-branch workflow disappears.

## Verification

```sh
uv run --locked python -m unittest tests.test_ci tests.test_sp1_ci -v
uv run --locked python tools/verify.py fast
uv run --locked python -m unittest discover -s tests -v
```

The focused tests cover aggregate rejection, native gate coverage, manifest/ELF
substitution, source and configuration mismatches, and FIFO sample/report
preservation. Their simulated proof reports are unit fixtures, not native
execution evidence. Real Docker guest builds, proof measurements and clean-target
qualification remain mandatory hosted jobs. Workflow changes are additionally
checked with Actionlint 1.7.12.
