"""Offline M0 research disposition; never production or legal authorization."""

import hashlib
import json
import os
import sys
from pathlib import Path

if __package__:
    from . import compact_results, dependency_policy, proof_modes, review_dispositions, tfhe_results
else:
    import compact_results
    import dependency_policy
    import proof_modes
    import review_dispositions
    import tfhe_results

ROOT = Path(__file__).resolve().parents[1]
ENGINE_SOURCE = "f8023959081fa6a1e8169b41ef427630a5da72f3"
PLATFORM_SOURCE = "571c8eb1ac87a985d3aaa9a6d04bce596b00312b"
EVIDENCE = "evidence/m0/campaign-summary.json"
EVIDENCE_SHA256 = "5f7ed5054ffb5c6c462743650632b804a76ff6372de136608b0684b8590535d3"
SOURCE_TREE_SHA256 = "70d3384a9bd260b41f56560623f3b8a4389c885a0d97180ebecdaf061a5d2f6b"
PARAMETER = "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674"
PROGRAM = "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5"
FIXTURE = "684828b07eeb3efaece2ff3704d2e152b62af745de72fb7b30c9a3258662d544"
PROOF = (
    "3a801ad04218cc45b8609bc03c5daf623c25b06ffece2455bd92275d4586ed78",
    "00af1acc62a7ff99a0a3d6838ed0ff5b23e6ee89c954bef074932b6da9ee8e6b",
    "d6103223f9d14ff51117abc11c559e531ca9baec67429712bc64d2c441508ec6",
)
MISSING = {
    "key_upload",
    "authorized_key_cache_miss",
    "actual_network_transfer",
    "owner_to_owner_end_to_end",
}
RUNNERS = (
    "feasibility.py",
    "tfhe_results.py",
    "compact_results.py",
    "sp1_relation.py",
    "proof_modes.py",
    "dependency_policy.py",
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(path):
    require(path.is_file() and not path.is_symlink(), "UNSAFE_EVIDENCE")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_digest(root):
    # Include added/removed source files as well as edits; never traverse build output.
    paths = [root / "tools" / name for name in RUNNERS]
    for directory, dirs, files in os.walk(root / "experiments", followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {"target", ".git"})
        require(not any((Path(directory) / d).is_symlink() for d in dirs), "UNSAFE_SOURCE")
        paths.extend(Path(directory) / name for name in sorted(files))
    records = "".join(
        f"{path.relative_to(root).as_posix()}\0{digest(path)}\n"
        for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix())
    )
    return hashlib.sha256(records.encode()).hexdigest()


def evaluate(value):
    require(
        value["kind"] == "REAL_CRYPTO_RESEARCH_OBSERVATIONS"
        and value["production_qualified"] is False
        and value["profile_enabled"] is False
        and value["qualification"] == "INCONCLUSIVE"
        and value["fake_orchestration_timings_included"] is False
        and value["proof_scope"]
        == "COMPACT_INPUT_VALIDITY_AND_SEPARATE_SP1_PUBLIC_METADATA_NOT_FHE_EVALUATION_PROOF",
        "UNSUPPORTED_QUALIFICATION_CLAIM",
    )
    require(
        value["requested_campaigns"] == value["successful_campaigns"] == 2
        and value["failed_or_incomplete_campaigns"] == 0
        and [c["attempt"] for c in value["campaigns"]] == [1, 2],
        "MISSING_CAMPAIGNS",
    )
    require(
        set(value["missing_stages"]) == MISSING
        and all(v["value"] is None for v in value["missing_stages"].values())
        and value["proof_peak_rss_bytes"]["value"] is None,
        "UNSUPPORTED_MEASUREMENT_CLAIM",
    )
    keys, jobs, bindings = set(), [], set()
    for campaign in value["campaigns"]:
        metadata = campaign["metadata"]
        require(
            campaign["outcome"] == "SUCCEEDED"
            and metadata["source"] == ENGINE_SOURCE
            and metadata["run_id"] == 40863854972
            and metadata["attempt"] == campaign["attempt"]
            and metadata["conclusion"] == "success"
            and len(metadata["jobs"]) == 3
            and {j["name"] for j in metadata["jobs"]} == {"native", "sp1", "verify"}
            and all(j["conclusion"] == "success" for j in metadata["jobs"]),
            "CAMPAIGN_PROVENANCE",
        )
        jobs.extend(j["id"] for j in metadata["jobs"])
        require(
            set(campaign["reports"]) == {"tfhe-eval", "tfhe-compact", "proof-modes"},
            "MISSING_EXPERIMENT",
        )
        evaluation = campaign["reports"]["tfhe-eval"]
        native = tfhe_results.report(json.dumps(evaluation["native"]).encode())
        compact = campaign["reports"]["tfhe-compact"]
        compact_results.report(json.dumps(compact["native"]).encode())
        proofs = proof_modes.report(json.dumps(campaign["reports"]["proof-modes"]).encode())
        require(
            (native["parameter_blake3"], native["program_blake3"], native["fixture_blake3"])
            == (PARAMETER, PROGRAM, FIXTURE)
            and evaluation["fixture_source"] == tfhe_results.SOURCE
            and evaluation["fixture_manifest_sha256"] == tfhe_results.MANIFEST_SHA256,
            "UNREVIEWED_PARAMETER_OR_WORKLOAD",
        )
        keys.add(native["key_context_blake3"])
        for report in (evaluation, compact):
            require(
                report["production_qualified"] is False
                and report["tfhe_version"] == "1.8.1"
                and report["rust_toolchain"] == "1.98.1"
                and report["rayon_threads"] == 2
                and report["reservation_is_estimate"] is True
                and report["address_space_limit_per_process_bytes"] == 4 << 30,
                "UNSUPPORTED_EXECUTION_PROFILE",
            )
        require(
            native["owner_peak_rss_bytes"] <= 512 << 20
            and native["evaluator_peak_rss_bytes"] <= 512 << 20,
            "RESEARCH_RSS_ENVELOPE_EXCEEDED",
        )
        require(
            evaluation["workload_binding_rejection_verified"] is True
            and evaluation["cache_state"] == "FRESH_PROCESS_SINGLE_EXPANSION_REUSED_FOR_100_CASES"
            and evaluation["gpu"]["status"] == "UNAVAILABLE"
            and evaluation["gpu"]["benchmark_executed"] is False
            and evaluation["gpu"]["speedup"] is None
            and evaluation["pbs"]["count"] is None,
            "UNSUPPORTED_COVERAGE_CLAIM",
        )
        require(
            compact["relation"] == "COMPACT_PKE_INPUT_VALIDITY_ONLY"
            and compact["proof_load"] == "Verify"
            and compact["crs_setup"] == "LOCAL_RESEARCH_UNQUALIFIED"
            and compact["expansion_reservation_bytes"] == 1 << 30,
            "UNSUPPORTED_COMPACT_CLAIM",
        )
        bindings.update(
            tuple(row["native"][k] for k in ("elf_blake3", "vk_digest", "journal_blake3"))
            for row in proofs["samples"]
        )
    require(len(keys) == 2 and len(set(jobs)) == 6, "REUSED_INITIALIZATION")
    require(bindings == {PROOF}, "UNREVIEWED_PROOF_STATEMENT")
    return {
        "engine_source": ENGINE_SOURCE,
        "platform_source": PLATFORM_SOURCE,
        "evidence_sha256": EVIDENCE_SHA256,
        "tfhe_fixed_uint8": "GO_RESEARCH_ONLY",
        "compact_input_validity": "GO_RESEARCH_ONLY",
        "sp1_core_public_metadata": "GO_PUBLIC_RESEARCH_ONLY",
        "parameter_security_review": "PENDING",
        "legal_review": "PENDING",
        "production_private_inference": "NO_GO",
        "production_enabled": False,
        "service_latency": "INCONCLUSIVE",
        "gpu": "UNAVAILABLE",
        "compressed_groth16_plonk": "UNMEASURED_DISABLED",
        "risc_zero": "DEFERRED",
        "tfhe_research_concurrency": 1,
        "rayon_threads": 2,
        "tfhe_review_rss_per_process_bytes": 512 << 20,
        "sp1_process_group_rss": "UNQUALIFIED",
    }


def validate(root=ROOT):
    dependency_policy.validate(root)
    require(source_digest(root) == SOURCE_TREE_SHA256, "RESEARCH_SOURCE_CHANGED")
    path = root / EVIDENCE
    require(path.stat().st_size <= 131072 and digest(path) == EVIDENCE_SHA256, "EVIDENCE_CHANGED")
    value = json.loads(path.read_bytes(), object_pairs_hook=tfhe_results._unique)
    for campaign in value["campaigns"]:
        for name, expected in campaign["metadata"]["source_files"].items():
            require((root / name).resolve().is_relative_to(root.resolve()), "UNSAFE_SOURCE")
            require(digest(root / name) == expected, "CAMPAIGN_SOURCE_CHANGED")
    tfhe_results.fixture()
    result = evaluate(value)
    bindings = {
        **result,
        "parameter_blake3": PARAMETER,
        "program_blake3": PROGRAM,
        "fixture_blake3": FIXTURE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "proof_bindings": list(PROOF),
    }
    result["review_dispositions"] = review_dispositions.validate(
        dependency_policy._read_json(root / review_dispositions.RECORD), root, bindings
    )
    return result


def main():
    try:
        print(json.dumps(validate(), sort_keys=True))
        return 0
    except ValueError, KeyError, TypeError, OSError, AttributeError:
        print("qualification: REJECTED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
