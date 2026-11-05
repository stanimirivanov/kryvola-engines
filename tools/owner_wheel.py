"""Build and test an owner-local research wheel; never publish or qualify it."""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__:
    from . import dependency_policy
else:
    import dependency_policy

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env=os.environ | {"CARGO_BUILD_JOBS": "2", "RAYON_NUM_THREADS": "2"},
    )


def main() -> None:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise SystemExit("owner wheel requires CPython 3.14")
    dependency_policy.validate(ROOT)
    with tempfile.TemporaryDirectory(prefix="owner-wheel-") as temporary:
        root = Path(temporary)
        wheels = root / "wheels"
        run(
            "maturin",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "crates/owner-crypto/python/Cargo.toml",
            "--interpreter",
            sys.executable,
            "--out",
            str(wheels),
        )
        (wheel,) = wheels.glob("*.whl")
        print(f"research wheel sha256={hashlib.sha256(wheel.read_bytes()).hexdigest()}", flush=True)
        environment = root / "installed"
        run("uv", "venv", "--python", sys.executable, str(environment))
        python = environment / "bin/python"
        run("uv", "pip", "install", "--python", str(python), "--no-index", "--no-deps", str(wheel))
        # -I excludes checkout/PYTHONPATH and user site packages from imports.
        run(str(python), "-I", str(ROOT / "tests/owner_wheel.py"))


if __name__ == "__main__":
    main()
