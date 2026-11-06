"""Inspect the research worker's runtime dependency and linked package boundary."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "crates/cpu-evaluator/Cargo.toml"


def inspect(tree: str, symbols: str) -> None:
    if re.search(r"\b(?:kryvola-owner-(?:crypto|python)|pyo3)(?:\s|$)", tree):
        raise ValueError("WORKER_OWNER_DEPENDENCY")
    if "kryvola_owner_crypto::" in symbols or "pyo3::" in symbols:
        raise ValueError("WORKER_OWNER_LINKAGE")
    if "kryvola_cpu_evaluator::evaluate" not in symbols:
        raise ValueError("WORKER_BINARY_NOT_INSPECTABLE")


def output(*command: str) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True)


def main() -> None:
    tree = output(
        "cargo",
        "tree",
        "--locked",
        "--manifest-path",
        MANIFEST,
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
    )
    metadata = json.loads(
        output(
            "cargo",
            "metadata",
            "--locked",
            "--manifest-path",
            MANIFEST,
            "--format-version",
            "1",
            "--no-deps",
        )
    )
    binary = Path(metadata["target_directory"]) / "release/kryvola-cpu-evaluator"
    symbols = output("nm", "-C", "--defined-only", str(binary))
    inspect(tree, symbols)
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    print(
        f"Worker boundary passed; binary_sha256={digest}; research only, not release qualification"
    )


if __name__ == "__main__":
    main()
