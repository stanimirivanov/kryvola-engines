"""Split SP1 preparation from measurements without editing frozen M0 runners."""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

if __package__:
    from . import proof_modes, sp1_relation
else:
    import proof_modes
    import sp1_relation

ELFS = ("metadata.elf", "alternate.elf")
ROOT = sp1_relation.ROOT
ELF_DIR = ROOT / "build/sp1/elf"
MAX_ELF_BYTES = 64 << 20


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def context(revision: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("INVALID_SOURCE_REVISION")
    return {
        "version": 1,
        "source_revision": revision,
        "cli_sha256": sp1_relation.CLI_SHA256,
        "image": sp1_relation.IMAGE,
        "profile_sha256": proof_modes.PROFILE_SHA256,
    }


def files(directory: Path, manifest: bool) -> dict:
    expected = {*ELFS, *(["manifest.json"] if manifest else [])}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("GUEST_ARTIFACT_FILES")
    for name in expected:
        path = directory / name
        maximum = 8192 if name == "manifest.json" else MAX_ELF_BYTES
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
            raise ValueError("GUEST_ARTIFACT_FILE_LIMIT")
    return {name: sha256(directory / name) for name in ELFS}


def write_manifest(directory: Path, revision: str) -> str:
    value = context(revision) | {"files": files(directory, manifest=False)}
    path = directory / "manifest.json"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return sha256(path)


def verify_guests(directory: Path, revision: str, digest: str) -> None:
    actual = files(directory, manifest=True)
    path = directory / "manifest.json"
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or sha256(path) != digest:
        raise ValueError("GUEST_MANIFEST_DIGEST")
    value = json.loads(path.read_bytes(), object_pairs_hook=sp1_relation._unique)
    if value != context(revision) | {"files": actual}:
        raise ValueError("GUEST_ARTIFACT_BINDING")


def revision() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def configuration() -> None:
    proof_modes.configuration()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("SP1_REQUIRES_LINUX_X86_64_DOCKER")


def build_guests() -> str:
    configuration()
    output = ELF_DIR.parent
    ELF_DIR.mkdir(parents=True, exist_ok=False)
    archive = output / "cargo-prove.tar.gz"
    # Preserve the frozen prepare() download, archive and executable bounds.
    with (
        urllib.request.urlopen(sp1_relation.CLI_URL, timeout=60) as source,
        archive.open("wb") as target,
    ):
        total = 0
        while chunk := source.read(1 << 20):
            total += len(chunk)
            if total > 24 << 20:
                raise ValueError("CLI_DOWNLOAD_LIMIT")
            target.write(chunk)
    if sha256(archive) != sp1_relation.CLI_SHA256:
        raise ValueError("CLI_CHECKSUM")
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if Path(m.name).name == "cargo-prove"]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 128 << 20:
            raise ValueError("CLI_ARCHIVE")
        source = tar.extractfile(members[0])
        if source is None:
            raise ValueError("CLI_ARCHIVE")
        cli = output / "cargo-prove"
        cli.write_bytes(source.read(128 << 20))
        cli.chmod(0o755)
    env = os.environ | {"SP1_DOCKER_IMAGE": sp1_relation.IMAGE, "CARGO_BUILD_JOBS": "1"}
    for name in ("metadata", "alternate"):
        sp1_relation._run(
            [
                str(cli),
                "prove",
                "build",
                "--docker",
                "--locked",
                "--bin",
                name,
                "--output-directory",
                str(ELF_DIR),
                "--elf-name",
                name + ".elf",
            ],
            sp1_relation.WORK / "guest",
            env,
            1800,
        )
    return write_manifest(ELF_DIR, revision())


def build_host() -> Path:
    protoc = shutil.which(os.environ.get("PROTOC", "protoc"))
    if protoc is None:
        raise ValueError("SP1_PROTOC_REQUIRED")
    target = ROOT / "build/sp1/host-target"
    env = os.environ | {
        "CARGO_BUILD_JOBS": "1",
        "SP1_DOCKER_IMAGE": sp1_relation.IMAGE,
        "PROTOC": protoc,
        "KRYVOLA_SP1_ELF": str(ELF_DIR / "metadata.elf"),
        "KRYVOLA_SP1_OTHER_ELF": str(ELF_DIR / "alternate.elf"),
    }
    sp1_relation._run(
        [
            "cargo",
            "+1.98.1",
            "build",
            "--manifest-path",
            str(sp1_relation.WORK / "Cargo.toml"),
            "--locked",
            "--release",
            "--target-dir",
            str(target),
            "--jobs",
            "1",
            "-p",
            "kryvola-sp1-host",
        ],
        ROOT,
        env,
        2400,
    )
    return target / "release/kryvola-sp1-host"


def measure(binary: Path) -> dict:
    # Both admissions stay on one runner, with fresh proof processes and the
    # original FIFO/clock semantics. Compilation remains outside the window.
    digest = sha256(binary)
    admitted = time.monotonic_ns()
    rows = []
    for index in range(proof_modes.SAMPLES):
        started = time.monotonic_ns()
        native = sp1_relation.execute(binary)
        finished = time.monotonic_ns()
        rows.append(
            {
                "index": index,
                "queue_ns": started - admitted,
                "process_ns": finished - started,
                "end_to_end_ns": finished - admitted,
                "native": native,
            }
        )
    return proof_modes.report(
        json.dumps(
            {
                "experiment": "proof-modes",
                "profiles": proof_modes.profiles(),
                "profile_sha256": proof_modes.PROFILE_SHA256,
                "native_binary_sha256": digest,
                "sdk_version": "6.9.0",
                "rust_toolchain": "1.98.1",
                "host": {
                    "system": platform.system(),
                    "machine": platform.machine(),
                    "cpu": platform.processor() or "UNAVAILABLE",
                },
                "cache_state": "FRESH_PROCESS_OS_CACHE_UNCONTROLLED",
                "queue_policy": "LOCAL_FIFO_TWO_ADMITTED_ONE_ACTIVE",
                "production_qualified": False,
                "samples": rows,
                "batch_elapsed_ns": time.monotonic_ns() - admitted,
            }
        ).encode()
    )


def measurements(digest: str) -> dict:
    configuration()
    verify_guests(ELF_DIR, revision(), digest)
    return measure(build_host())


def qualification(digest: str) -> None:
    if __package__:
        from . import qualify_release, release
    else:
        import qualify_release
        import release

    configuration()
    verify_guests(ELF_DIR, revision(), digest)
    release.install()
    qualify_release.qualify("local-prover")
