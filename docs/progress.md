# Foundation progress

Issue: #1. Scope: initial M0 repository scaffold, 25 October 2026.

- Implemented: rust-native and c++ engine adapter foundations, versioned spec consumption, isolated architecture controls and diagnostics.
- Verified locally: frozen setup, full foundation checks, isolated negative controls, package/native builds and diagnostics.
- Configured but unverified remotely: the GitHub Actions workflow; branch protection/required checks remain maintainer configuration.
- Not claimed: complete M0 acceptance, full Engine API interoperability, cryptographic feasibility, latency measurements, independent security review or deployment.
- Deferred: later roadmap runtime/crypto features. A disabled capability is an explicit incomplete milestone, not an alternate implementation.
- Next: KRY-007/008 pinned engine packaging and cryptographic feasibility, then KRY-013/016 owner/evaluation separation.

The authoritative [plan](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md) remains in force. Review and update only the affected roadmap evidence; no later milestone is marked complete by this scaffold.

## Observed acceptance evidence

On Windows with Python 3.14.7 / uv 0.12.5, `uv run --locked python tools/verify.py full` passed: Ruff formatting/lint, ty type checks, spec provenance and dependency checks, 4 Python tests, 1 Rust boundary test and 1 CTest case, and Rust fmt/clippy/tests and CMake C++20 build/CTest. Native versions observed: Rust 1.98.1, CMake 3.29.2 and GNU C++ 16.1.0.

A new disposable environment passed `uv sync --locked --no-editable`. The frozen tool environment passed provenance validation, and both native diagnostics ran. Diagnostics: `cargo run --locked -p kryvola-engine-api --example inspect; build/cpp/engine_foundation.exe`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.
