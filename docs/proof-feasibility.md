# SP1 mode measurement (M0-PR23)

`uv run --locked python tools/feasibility.py proof-modes --check-only` validates
the immutable experimental profile and M0-PR22 dependency/mode policy offline.
It never claims native success. Without that flag, Linux x86_64, Docker and
protobuf prerequisites from [the relation gate](sp1-relation.md) are required.
`uv run --locked python tools/verify.py full` includes this measurement gate;
the SP1 CI job executes it separately from the native/TFHE job.

The profile is `experiments/sp1/profiles/modes.json`, SHA-256
`e52231b02ab2884847d890a03ed4d3744edf49ea062e271400cbff722a1a64b8`.
Changing it requires a reviewed pin update. This is an experiment configuration,
not a new spec contract or production assurance profile. SDK 6.9.0, its lock,
guest compiler and CLI pins remain unchanged; no dependency is added.

| Candidate | Measurement admission | Verifier privacy | Setup disposition |
|---|---|---|---|
| Core CPU | Public metadata, research only | Not zero-knowledge | No SNARK ceremony; program/key/SDK still pinned |
| Compressed | Disabled, unmeasured | No private-witness export approval | Recursive path/artifacts outside this experiment |
| Groth16 | Disabled, unmeasured | Upstream ZK claim; not qualified here | Circuit-specific ceremony/circuit/verifier not pinned/reviewed |
| PLONK | Disabled, unmeasured | Upstream ZK claim; not qualified here | Universal ceremony/circuit/verifier not pinned/reviewed |

The [upstream security model](https://docs.succinct.xyz/docs/sp1/security/security-model)
distinguishes non-ZK individual STARK proofs from its ZK Groth16/PLONK wrappers
and their trusted setups. Neither hides inputs from the prover. This experiment
admits no private witness, remote prover, recursive assumptions or production
export. No universal security-bit or post-quantum guarantee is inferred.
There is only **one admitted mode**, so this produces a comparison of candidate
dispositions and raw measurements for Core, not a fabricated cross-mode speedup.
Enabling another mode requires its own reviewed implementation and qualification.

The runner builds once, hashes the exact host executable, admits exactly two
requests together, and services them serially as a bounded local FIFO. Each
request launches a fresh process running the unchanged real Core proof/verifier
and all seven rejection controls. No proof/result cache is used. OS page caches
are uncontrolled: these samples are neither a cold-cache nor warm-cache claim.
Program, verifying key, journal and mode must match across samples. Proof bytes
stay temporary; reports expose only digests, sizes, classifications and timing.

All durations use monotonic nanoseconds. Raw sample fields are:

- `queue_ns`: batch admission until process invocation, including waiting for the
  preceding full gate. This is an actual local queue, not Temporal/Ray scheduling.
- `process_ns`: invocation through parsed native report, including initialization,
  key setup, both successful/failed-exit proof generation and rejection controls.
- `native.prove_ns`, `native.verify_ns`: the successful proof/verification costs
  from the host. Failed-exit proving is included only in native total/process time.
- `native.proof_bytes`: serialized successful proof bundle size, including journal
  and version envelope; not a bare mathematical proof size.
- `end_to_end_ns`: queue plus process; compilation is excluded. The batch window
  covers both samples and must contain every completion. Native total cannot
  exceed process duration, and successful prove plus verify cannot exceed total.

The batch allows at most 1,800 seconds of measured time; each host retains the
900-second deadline and existing resource limits. Host CPU/platform strings are
descriptive, not hardware attestation; unavailable CPU identity is explicit.
There are no percentile, throughput, service-SLO or statistically sufficient
sample claims. Following platform M0-PR25, raw queue/process accounting remains
separate from worker stages. That pattern is adapted with standard-library code;
no sibling implementation import or spec MeasurementReport publication occurs.

The closed report validator rejects missing/changed mode/setup/privacy policy,
unknown/duplicate fields, bool-as-number values, oversized proofs, inconsistent
bindings and invalid timing. Synthetic unit fixtures validate accounting only;
the CI execution path always calls the real prover gate. Unsupported modes have
no timing/size samples, never zero-valued fake observations.

Branch pushes run the same native/SP1/aggregate CI gates before PR creation.
The PR records the checked commit and run; these results still do not qualify
cryptographic security, production performance or private-witness export.
