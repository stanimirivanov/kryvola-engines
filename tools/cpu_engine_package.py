"""Build and inspect a local CPU worker image from a worker-only context."""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "kryvola-cpu-engine:local"
FILES = {"kryvola-cpu-engine", "kryvola-cpu-evaluator", "cpu_runner.py", "LICENSE"}


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def normalize(context: Path, epoch: int) -> None:
    if epoch < 0:
        raise ValueError("INVALID_IMAGE_EPOCH")
    for name in FILES:
        path = context / name
        path.chmod(0o755 if name.startswith("kryvola-cpu-") else 0o644)
        os.utime(path, (epoch, epoch))


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
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        build_args = []
        build_command = ["docker", "build"]
        if epoch is not None:
            normalize(context, int(epoch))
            build_command = ["docker", "buildx", "build"]
            build_args = [
                "--no-cache",
                "--provenance=false",
                "--output",
                "type=docker,rewrite-timestamp=true",
                "--build-arg",
                f"SOURCE_DATE_EPOCH={epoch}",
            ]
        run(
            *build_command,
            *build_args,
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
