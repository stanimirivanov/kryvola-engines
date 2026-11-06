"""Parallel CI partitions of the canonical gates; never skip qualification."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
REQUIRED_JOBS = {
    "foundation",
    "owner",
    "tfhe",
    "native-qualification",
    "sp1-build",
    "sp1-measurements",
    "sp1-qualification",
}
COMMANDS = {
    "foundation": (
        (PYTHON, "tools/verify.py", "fast"),
        (PYTHON, "-m", "unittest", "discover", "-s", "tests", "-v"),
        ("cargo", "test", "--locked", "--workspace"),
        ("cargo", "run", "--locked", "-p", "kryvola-fake-engine", "--", "conformance"),
        ("cmake", "-S", "cpp", "-B", "build/cpp", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug"),
        ("cmake", "--build", "build/cpp"),
        ("ctest", "--test-dir", "build/cpp", "--output-on-failure"),
        ("cargo", "run", "--locked", "-p", "kryvola-engine-api", "--example", "inspect"),
        ("./build/cpp/engine_foundation",),
    ),
    "owner": (
        (
            "cargo",
            "test",
            "--release",
            "--locked",
            "--manifest-path",
            "crates/owner-crypto/Cargo.toml",
        ),
        (PYTHON, "tools/owner_wheel.py"),
    ),
    "tfhe": tuple(
        (PYTHON, "tools/feasibility.py", mode)
        for mode in ("tfhe-codec", "tfhe-eval", "tfhe-compact")
    ),
}


def verify(jobs: dict) -> None:
    if set(jobs) != REQUIRED_JOBS or any(
        not isinstance(row, dict) or row.get("result") != "success" for row in jobs.values()
    ):
        raise ValueError("ALL_REQUIRED_CI_JOBS_MUST_SUCCEED")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "stage",
        choices=[
            *COMMANDS,
            "qualification",
            "sp1-guests",
            "sp1-measurements",
            "sp1-qualification",
            "verify",
        ],
    )
    parser.add_argument("--role", choices=["fake-evaluator", "cpu-evaluator", "owner-fixture"])
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    if args.stage in COMMANDS:
        for command in COMMANDS[args.stage]:
            print("+ " + " ".join(command), flush=True)
            subprocess.run(command, cwd=ROOT, check=True)
    elif args.stage == "verify":
        verify(json.loads(os.environ["NEEDS_JSON"]))
    elif args.stage == "qualification":
        if not args.role:
            parser.error("qualification requires --role")
        from qualify_release import qualify
        from release import install

        install()
        qualify(args.role)
    else:
        from sp1_ci import build_guests, measurements, qualification

        if args.stage == "sp1-guests":
            digest = build_guests()
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write(f"manifest_sha256={digest}\n")
        else:
            if not args.manifest_sha256:
                parser.error("SP1 consumers require --manifest-sha256")
            if args.stage == "sp1-measurements":
                print(json.dumps(measurements(args.manifest_sha256), sort_keys=True))
            else:
                qualification(args.manifest_sha256)


if __name__ == "__main__":
    main()
