"""Build and inspect a local CPU worker image from a worker-only context."""

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "kryvola-cpu-engine:local"
FILES = {"kryvola-cpu-engine", "kryvola-cpu-evaluator", "cpu_runner.py", "LICENSE"}


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", type=Path)
    parser.add_argument("evaluator", type=Path)
    args = parser.parse_args()
    for binary in (args.engine, args.evaluator):
        symbols = run("nm", "-C", "--defined-only", str(binary))
        if not symbols or "kryvola_owner_crypto::" in symbols or "pyo3::" in symbols:
            raise RuntimeError("WORKER_OWNER_LINKAGE")
    with tempfile.TemporaryDirectory(prefix="cpu-engine-package-") as tmp:
        context = Path(tmp)
        for source, name in (
            (args.engine, "kryvola-cpu-engine"),
            (args.evaluator, "kryvola-cpu-evaluator"),
            (ROOT / "tools/cpu_runner.py", "cpu_runner.py"),
            (ROOT / "LICENSE", "LICENSE"),
        ):
            shutil.copy2(source, context / name)
        run(
            "docker",
            "build",
            "--file",
            str(ROOT / "containers/CPU-Engine.Dockerfile"),
            "--tag",
            IMAGE,
            str(context),
        )
    user = run("docker", "image", "inspect", IMAGE, "--format", "{{.Config.User}}")
    files = run(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--entrypoint",
        "/bin/ls",
        IMAGE,
        "-1",
        "/opt/kryvola",
    )
    if user != "65532:65532" or set(files.splitlines()) != FILES:
        raise RuntimeError("WORKER_IMAGE_INVENTORY")
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--entrypoint",
            "/opt/kryvola/kryvola-cpu-evaluator",
            IMAGE,
            "decrypt",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 2 or result.stderr != b"EVALUATOR_ARGUMENT\n":
        raise RuntimeError("WORKER_OWNER_ROUTE")
    print("CPU_ENGINE_IMAGE_BOUNDARY_PASSED")


if __name__ == "__main__":
    main()
