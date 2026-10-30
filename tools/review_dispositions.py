"""Repository-local pending review packet; no authentication or permission promotion."""

from pathlib import Path

if __package__:
    from . import dependency_policy as policy
else:
    import dependency_policy as policy

RECORD = "evidence/m0/review-dispositions.json"
BINDINGS = {
    "config/dependency-policy.json",
    "experiments/tfhe/Cargo.lock",
    "experiments/sp1/Cargo.lock",
    "evidence/m0/campaign-summary.json",
}
EXCLUSIONS = {
    "PRODUCTION_PRIVATE_INFERENCE",
    "PRIVATE_WITNESSES_AND_REMOTE_PROVERS",
    "GPU_AND_ALTERNATE_PROOF_EXPORTS",
    "SERVICE_LATENCY_AND_PROVER_GROUP_RSS_UNQUALIFIED",
}


def validate(value, root: Path, qualification):
    """Validate against independently evaluated research facts, never caller review claims."""
    policy.fields(value, {"version", "status", "bindings", "research", "reviews", "exclusions"})
    policy.require(type(value["version"]) is int and value["version"] == 1, "REVIEW_VERSION")
    policy.require(value["status"] == "PENDING_AUTHENTICATED_REVIEW", "REVIEW_NOT_PENDING")
    policy.fields(value["bindings"], BINDINGS)
    # Fixed local paths only; no evidence-selected files, links or network requests.
    import hashlib

    for name in BINDINGS:
        path = root / name
        policy.require(path.is_file() and not path.is_symlink(), "UNSAFE_REVIEW_BINDING")
        policy.require(
            hashlib.sha256(path.read_bytes()).hexdigest() == value["bindings"][name],
            "REVIEW_BINDING_CHANGED",
        )
    expected = {
        name: qualification[name]
        for name in (
            "engine_source",
            "platform_source",
            "evidence_sha256",
            "parameter_blake3",
            "program_blake3",
            "fixture_blake3",
            "source_tree_sha256",
            "proof_bindings",
        )
    }
    policy.require(value["research"] == expected, "REVIEW_RESEARCH_CHANGED")
    policy.require(
        type(value["exclusions"]) is list
        and len(value["exclusions"]) == len(EXCLUSIONS)
        and set(value["exclusions"]) == EXCLUSIONS,
        "REVIEW_EXCLUSIONS_CHANGED",
    )
    candidates = policy._read_json(root / "config/dependency-policy.json")["candidates"]
    expected_rows = {}
    for candidate in candidates:
        for purpose in sorted(policy.PURPOSES):
            expected_rows[(candidate["name"], purpose)] = {
                "dependency": candidate["name"],
                "version": candidate["version"],
                "source_revision": candidate["source_revision"],
                "crate_sha256": candidate["artifact"]["sha256"],
                "intended_use": purpose,
                "permission": candidate["permissions"][purpose],
                "legal_decision": "PENDING",
                "security_parameter_decision": "PENDING",
                "reviewer_identity": None,
                "authority": None,
                "review_url": None,
                "evidence_sha256": None,
                "supersedes_sha256": None,
            }
    policy.require(type(value["reviews"]) is list, "REVIEW_ROWS")
    seen = set()
    for row in value["reviews"]:
        policy.require(type(row) is dict, "REVIEW_ROWS")
        key = (row.get("dependency"), row.get("intended_use"))
        policy.require(key in expected_rows and key not in seen, "REVIEW_SCOPE_CHANGED")
        seen.add(key)
        policy.require(row == expected_rows[key], "REVIEW_DECISION_OR_BINDING_CHANGED")
    policy.require(seen == set(expected_rows), "REVIEW_SCOPE_MISSING")
    return {
        "status": "PENDING_AUTHENTICATED_REVIEW",
        "authenticated": False,
        "permission_promotion": False,
    }
