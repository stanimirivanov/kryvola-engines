# Architecture and harness

Source: design v2 sections 4.3, 5, 6, 7 and 13; plan v2 M0; [schema amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md).

All future engines, TFHE-rs and zkVM guests/provers live here. Compute accepts public/evaluation material only. No decryption endpoint, mock proof acceptance, cryptographic capability or executed inference is provided by this scaffold. Native crypto codecs remain separate from generated structural types.

| Requirement | Governed code/configuration | Evaluation | Limit / review |
|---|---|---|---|
| Runtime/module ownership | `src/`, `crates/`, `cpp/` | Compiler/type checker and `tools/architecture.py` | Semantic responsibility remains code review |
| No sibling implementation source dependency | `pyproject.toml`, Python imports, Cargo manifests | AST/manifest check; isolated forbidden-import and sibling-path fixtures in tests | Dynamic imports/native calls and CMake dependency changes require review |
| Contracts come from spec | `spec.lock.json` and vendored artifacts | Commit/repository identity plus SHA-256 manifest/file integrity checks | Build provenance is not cryptographic authorization; update source and pin in a reviewed change |
| Reference-only bounded control | Pinned descriptor/schema bundles and fake-engine RPC codec | Raw-byte/schema validation and bounded loopback conformance in CI | Test-only service; no native ciphertext decode, authentication or real Engine deployment |
| No unqualified production claim | Capability diagnostic | Documented inspect command; code review | No inference, crypto qualification or deployed stack |
| Reproducible setup / required checks | Toolchain pins, `uv.lock`, `Cargo.lock`, `tools/verify.py` | README fast/full commands, same commands in CI | Full cryptographic, hardware and operational gates remain deferred |
| Codex guidance | Root `AGENTS.md` | Git-root discovery applies through child working directories; no overrides | Client trust/activation is user-managed; no config or model override is installed |

The custom architecture tool examines declared dependencies and static Python imports, not arbitrary program behavior. Its isolated fixtures demonstrate both valid acceptance and representative failure, including nonzero CLI exit. Required inputs are never optional and failures propagate through the canonical task runner.

The [dependency candidate gate](dependency-dispositions.md) checks internal build
policy and immutable evidence before native checks. It uses standard Cargo/registry
metadata rather than authoring another wire contract. Local research, artifact
distribution and commercial service are distinct classes; only research candidates
are admitted. Recorded compiler minimums and unbuilt matrix rows establish no
runtime compatibility, patent rights or production qualification.

[Fake Engine RPC conformance](fake-engine.md) documents M0-PR15's synthetic identity, strict codec factory, bounded volatile state and race/timeout behavior. The full harness includes its executable loopback check; this is not evidence of encrypted inference or an enabled assurance profile.

CI is configured on pull requests/main pushes with commit-pinned actions, `contents: read`, no persistent Git credentials and no production secrets. A hosted CI result is not claimed by configuration. Maintainers must enable required status checks (`verify`), review/branch rules and any desired repository security settings; no remote protections are changed here. Local hooks are not merge enforcement.

No `.codex/config.toml` or repository skill is needed for the current workflow. Root instructions link detailed sources on demand and preserve the configured model/reasoning effort. Scoped instruction files are unnecessary because responsibilities do not yet require different agent rules.
