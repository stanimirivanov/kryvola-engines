"""Explicit local CPU proof gate; downloads/builds/proving occur only without --check-only."""

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "experiments/sp1"
IMAGE = (
    "ghcr.io/succinctlabs/sp1@sha256:"
    "6d90b1692f07519817533bafeefd6ea3d1c4c0d1cd7cffe9844d2ae37d034b08"
)
CLI_SHA256 = "0eb8a2b3eef9b498443a338a545422a7acd37ee08d17d784a9c16f4c0bfb975b"
CLI_URL = (
    "https://github.com/succinctlabs/sp1/releases/download/v6.9.0/"
    "cargo_prove_v6.9.0_linux_amd64.tar.gz"
)
JOURNAL_BYTES = len(b"kryvola/research/public-metadata/v1\0") + 2 + 8 + 96 + 32


def configuration() -> None:
    if (
        os.environ.get("SP1_PROVER", "cpu") != "cpu"
        or "SP1_DEV_MODE" in os.environ
        or "SP1_DOCKER_IMAGE" in os.environ
        or "CARGO_TARGET_DIR" in os.environ
    ):
        raise ValueError("UNTRUSTED_MODE_OVERRIDE")
    manifest = tomllib.loads((WORK / "host/Cargo.toml").read_text())
    if manifest["dependencies"]["sp1-sdk"] != {
        "version": "=6.9.0",
        "default-features": False,
        "features": [],
    }:
        raise ValueError("SP1_PIN_REQUIRED")
    if not (WORK / "Cargo.lock").is_file():
        raise ValueError("SP1_LOCK_REQUIRED")
    subprocess.run(
        [
            sys.executable,
            "tools/dependency_policy.py",
            "--candidate",
            "sp1-sdk",
            "--purpose",
            "local_research",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=60,
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_FIELD")
        result[key] = value
    return result


def report(raw: bytes) -> dict:
    if len(raw) > 8192:
        raise ValueError("REPORT_LIMIT")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    hashes = {"elf_blake3", "vk_digest", "journal_blake3"}
    integers = {
        "outcome": (0, 0),
        "negative_cases": (7, 7),
        "journal_bytes": (JOURNAL_BYTES, JOURNAL_BYTES),
        "proof_bytes": (1, 128 << 20),
        "cycle_limit": (1_000_000, 1_000_000),
        "prove_ns": (0, 900 * 10**9),
        "verify_ns": (0, 900 * 10**9),
        "total_ns": (1, 900 * 10**9),
    }
    if not isinstance(value, dict) or set(value) != hashes | set(integers) | {"experiment", "mode"}:
        raise ValueError("INVALID_REPORT")
    if value["experiment"] != "sp1-relation" or value["mode"] != "CORE_CPU":
        raise ValueError("UNTRUSTED_PROOF_MODE")
    for key, (low, high) in integers.items():
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError("LIMIT_OR_OUTCOME")
    if any(
        not isinstance(value[k], str) or re.fullmatch("[0-9a-f]{64}", value[k]) is None
        for k in hashes
    ):
        raise ValueError("MISSING_BINDING")
    if value["prove_ns"] + value["verify_ns"] > value["total_ns"]:
        raise ValueError("INCONSISTENT_TIMING")
    return value


def _run(command, cwd, env, timeout, **kwargs):
    child = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True, **kwargs)
    try:
        if child.wait(timeout=timeout) != 0:
            raise ValueError("SP1_STAGE_FAILED")
    finally:
        if sys.platform == "linux":
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()


def _limits():
    if sys.platform == "linux":
        import resource

        for kind, maximum in (
            (resource.RLIMIT_AS, 16 << 30),
            (resource.RLIMIT_FSIZE, 128 << 20),
            (resource.RLIMIT_CPU, 900),
            (resource.RLIMIT_CORE, 0),
        ):
            resource.setrlimit(kind, (maximum, maximum))


def execute() -> dict:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("SP1_REQUIRES_LINUX_X86_64_DOCKER")
    protoc = shutil.which(os.environ.get("PROTOC", "protoc"))
    if protoc is None:
        raise ValueError("SP1_PROTOC_REQUIRED")
    output = ROOT / "build/sp1"
    output.mkdir(parents=True, exist_ok=True)
    host_target = output / "host-target"
    host_target.mkdir(exist_ok=True)
    # Verify the archive before reading its sole executable; no archive paths are extracted.
    archive = output / "cargo-prove.tar.gz"
    with urllib.request.urlopen(CLI_URL, timeout=60) as source, archive.open("wb") as target:
        total = 0
        while chunk := source.read(1 << 20):
            total += len(chunk)
            if total > 24 << 20:
                raise ValueError("CLI_DOWNLOAD_LIMIT")
            target.write(chunk)
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != CLI_SHA256:
            raise ValueError("CLI_CHECKSUM")
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if Path(m.name).name == "cargo-prove"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 128 << 20:
            raise ValueError("CLI_ARCHIVE")
        stream = tar.extractfile(members[0])
        if stream is None:
            raise ValueError("CLI_ARCHIVE")
        cli = output / "cargo-prove"
        cli.write_bytes(stream.read(128 << 20))
        cli.chmod(0o755)
    build_env = {**os.environ, "SP1_DOCKER_IMAGE": IMAGE, "CARGO_BUILD_JOBS": "1", "PROTOC": protoc}
    elf_dir = output / "elf"
    elf_dir.mkdir(exist_ok=True)
    for name in ("metadata", "alternate"):
        _run(
            [
                str(cli),
                "prove",
                "build",
                "--docker",
                "--locked",
                "--bin",
                name,
                "--output-directory",
                str(elf_dir),
                "--elf-name",
                name + ".elf",
            ],
            WORK / "guest",
            build_env,
            1800,
        )
    build_env.update(
        KRYVOLA_SP1_ELF=str(elf_dir / "metadata.elf"),
        KRYVOLA_SP1_OTHER_ELF=str(elf_dir / "alternate.elf"),
    )
    _run(
        [
            "cargo",
            "+1.98.1",
            "build",
            "--manifest-path",
            str(WORK / "Cargo.toml"),
            "--locked",
            "--release",
            "--target-dir",
            str(host_target),
            "--jobs",
            "1",
            "-p",
            "kryvola-sp1-host",
        ],
        ROOT,
        build_env,
        2400,
    )
    with TemporaryDirectory(prefix="kryvola-sp1-") as directory:
        temporary = Path(directory)
        with (temporary / "report.json").open("wb") as stream:
            _run(
                [str(host_target / "release/kryvola-sp1-host"), str(temporary / "proof.bin")],
                temporary,
                {
                    "PATH": os.defpath,
                    "HOME": directory,
                    "SP1_PROVER": "cpu",
                    "RAYON_NUM_THREADS": "2",
                },
                900,
                stdout=stream,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                preexec_fn=_limits,
            )
        with (temporary / "report.json").open("rb") as stream:
            return report(stream.read(8193))
