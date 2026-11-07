"""Verify a successor decision against an independently pinned operator policy."""

import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

if __package__:
    from . import dependency_policy as policy
else:
    import dependency_policy as policy

ROLES = ("legal", "parameters")
USES = {"artifact_distribution", "commercial_service"}
ED25519_SPKI = "302a300506032b6570032100"


def read(path: Path, limit: int) -> bytes:
    policy.require(path.is_file() and not path.is_symlink(), "UNSAFE_REVIEW_INPUT")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    policy.require(len(data) <= limit, "REVIEW_INPUT_LIMIT")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch("[0-9a-f]+", value) is not None
        and (len(value) == length)
    )


def document(data: bytes, fields: set[str]) -> dict[str, Any]:
    value = json.loads(data.decode("utf-8"), object_pairs_hook=policy._pairs)
    policy.fields(value, fields | {"version"})
    policy.require(type(value["version"]) is int and value["version"] == 1, "REVIEW_VERSION")
    return value


def verify_signatures(packet: Path, data: bytes, keys: dict[str, str]) -> None:
    # OpenSSL needs seekable input for Ed25519 one-shot verification. Verify the
    # same bytes that were parsed and hashed, even if the packet changes on disk.
    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        (scratch / "decision").write_bytes(data)
        for role, key in keys.items():
            signature = read(packet / f"{role}.sig", 64)
            policy.require(len(signature) == 64, "INVALID_REVIEW_SIGNATURE")
            (scratch / "signature").write_bytes(signature)
            (scratch / "key").write_bytes(bytes.fromhex(key))
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    "key",
                    "-in",
                    "decision",
                    "-sigfile",
                    "signature",
                ],
                cwd=scratch,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            policy.require(result.returncode == 0, "INVALID_REVIEW_SIGNATURE")


def verify(
    packet: Path,
    policy_path: Path,
    policy_sha256: str,
    predecessor_sha256: str,
    intended_use: str,
    artifact_sha256: str,
) -> dict[str, Any]:
    policy.require(intended_use in USES and is_hex(artifact_sha256, 64), "REVIEW_SCOPE")
    operator_bytes = read(policy_path, 16384)
    policy.require(sha256(operator_bytes) == policy_sha256, "REVIEW_POLICY_PIN")
    operator = document(operator_bytes, {"expires_at", "authorities", "revoked"})
    keys = operator["authorities"]
    policy.fields(keys, set(ROLES))
    policy.require(
        all(is_hex(key, 88) and key.startswith(ED25519_SPKI) for key in keys.values())
        and len(set(keys.values())) == len(ROLES),
        "REVIEW_AUTHORITIES",
    )
    revoked = operator["revoked"]
    policy.require(
        type(revoked) is list and all(is_hex(item, 64) for item in revoked), "REVIEW_REVOCATIONS"
    )

    data = read(packet / "decision.json", 4096)
    decision_sha256 = sha256(data)
    expected = {
        "predecessor_sha256": predecessor_sha256,
        "dependency": "tfhe",
        "intended_use": intended_use,
        "artifact_sha256": artifact_sha256,
        "decision": "APPROVE",
    }
    decision = document(data, set(expected) | {"valid_from", "expires_at"})
    policy.require(all(decision[key] == value for key, value in expected.items()), "REVIEW_SCOPE")
    policy.require(decision_sha256 not in revoked, "REVIEW_REVOKED")
    verify_signatures(packet, data, keys)

    now = int(time.time())
    start, end, policy_end = decision["valid_from"], decision["expires_at"], operator["expires_at"]
    policy.require(
        all(type(epoch) is int for epoch in (start, end, policy_end))
        and 0 <= start <= now < min(end, policy_end),
        "REVIEW_EXPIRED_OR_NOT_YET_VALID",
    )
    return {
        **expected,
        "authenticated": True,
        "decision_sha256": decision_sha256,
        "policy_sha256": policy_sha256,
        "valid_until": min(end, policy_end),
    }
