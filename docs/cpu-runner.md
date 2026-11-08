# Bounded native CPU evaluation

`tools.cpu_runner.run_evaluation` supervises the CPU evaluator on Linux.
The trusted launcher selects the worker executable and a local scratch root.
The request carries local input and evaluation-key paths plus approved
program, input-blob and evaluation-key commitments. The worker verifies those
commitments before decoding or evaluation. Authorization remains with the
launcher.

The supervisor stages regular files in a private temporary directory, rejects
symlinks and special files, and bounds reads even if a file grows. Each
launcher process admits one job at a time. The staging limits are 64 MiB for
the evaluation key and 2,097,168 bytes each for input and output. The child
receives fixed local filenames, a minimal environment and standard streams
attached to the null device. The launcher should use local storage for
staging and a trusted worker executable.

Linux `/usr/bin/prlimit` applies a 2 GiB address-space ceiling, a 16-second
CPU soft limit with a one-second hard-limit margin, a 32-descriptor cap and
a per-file size limit equal to the output cap. Core dumps are disabled. The
default child wall deadline is 20 seconds. Operators may lower the wall,
CPU and memory limits. A pidfd lets the supervisor signal the owned process
group before reaping its leader, on success or failure. The supervisor
cleans the scratch directory and returns only bounded ciphertext bytes.

The public errors distinguish invalid input, capacity, unavailable
supervision, timeout, explicit CPU or file-size limit signals, evaluator
rejection, unexpected child death and invalid output. An allocator abort can
surface as child death. The limits apply to the trusted evaluator and its
owned process group. Service-wide admission across launchers and an OS
sandbox for untrusted executables are separate controls.

Run the focused tests with:

```sh
uv run --locked python -m unittest discover -s tests -p test_cpu_runner.py -v
cargo test --release --locked --manifest-path crates/cpu-evaluator/Cargo.toml --test process
```
