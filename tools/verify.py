"""Canonical local/CI entry point. Missing tools and failed commands fail the check."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = "kryvola-engines"
ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("level", choices=["fast", "native", "full"], default="full", nargs="?")
    args = parser.parse_args()
    run("ruff", "format", "--check", ".")
    run("ruff", "check", ".")
    run("ty", "check")
    run(sys.executable, "tools/architecture.py")
    run(sys.executable, "tools/dependency_policy.py")
    run(sys.executable, "tools/feasibility.py", "tfhe-codec", "--check-only")
    run(sys.executable, "tools/feasibility.py", "tfhe-eval", "--check-only")
    run(sys.executable, "tools/feasibility.py", "tfhe-compact", "--check-only")
    run(sys.executable, "tools/feasibility.py", "sp1-relation", "--check-only")
    if REPO in {"kryvola-fabric", "kryvola-engines"}:
        run("cargo", "fmt", "--all", "--check")
        run("cargo", "fmt", "--manifest-path", "experiments/tfhe/Cargo.toml", "--all", "--check")
        run("cargo", "fmt", "--manifest-path", "experiments/sp1/Cargo.toml", "--all", "--check")
        run("cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings")
    if args.level in {"native", "full"}:
        run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")
        if REPO in {"kryvola-fabric", "kryvola-engines"}:
            run("cargo", "test", "--locked", "--workspace")
            if REPO == "kryvola-engines":
                run("cargo", "run", "--locked", "-p", "kryvola-fake-engine", "--", "conformance")
        if REPO == "kryvola-engines":
            run("cmake", "-S", "cpp", "-B", "build/cpp", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug")
            run("cmake", "--build", "build/cpp")
            run("ctest", "--test-dir", "build/cpp", "--output-on-failure")
            run(sys.executable, "tools/feasibility.py", "tfhe-codec")
            run(sys.executable, "tools/feasibility.py", "tfhe-eval")
            run(sys.executable, "tools/feasibility.py", "tfhe-compact")
        else:
            run("uv", "build", "--no-build-isolation", "--wheel")
    if args.level == "full":
        run(sys.executable, "tools/feasibility.py", "sp1-relation")


if __name__ == "__main__":
    main()
