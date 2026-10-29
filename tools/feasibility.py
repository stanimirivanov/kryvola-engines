"""Run isolated, research-only native feasibility checks; heavy execution belongs on CI."""

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

if __package__:
    from . import compact_results, proof_modes, sp1_relation, tfhe_results
else:
    import compact_results
    import proof_modes
    import sp1_relation
    import tfhe_results

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments/tfhe/Cargo.toml"
TARGET = "x86_64-unknown-linux-gnu"
KEY_MAX = 64 << 20
CT_MAX = 1 << 20


def configuration(experiment: str = "tfhe-codec") -> None:
    if experiment == "proof-modes":
        proof_modes.configuration()
        return
    if experiment == "sp1-relation":
        sp1_relation.configuration()
        return
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/dependency_policy.py"),
            "--candidate",
            "tfhe",
            "--purpose",
            "local_research",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise ValueError("CANDIDATE_REJECTED")
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest["package"]["publish"] is not False or manifest.get("workspace") != {}:
        raise ValueError("EXPERIMENT_MUST_BE_ISOLATED")
    if not MANIFEST.with_name("Cargo.lock").is_file():
        raise ValueError("EXPERIMENT_LOCK_REQUIRED")
    if experiment == "tfhe-eval":
        tfhe_results.fixture()
    if experiment == "tfhe-compact":
        if "zk-pok" not in manifest["dependencies"]["tfhe"]["features"]:
            raise ValueError("PROOF_FEATURE_REQUIRED")
        packages = tomllib.loads(MANIFEST.with_name("Cargo.lock").read_text())["package"]
        proof = [p for p in packages if p["name"] == "tfhe-zk-pok"]
        if (
            len(proof) != 1
            or proof[0]["version"] != "0.9.0"
            or proof[0]["checksum"]
            != ("cd4d91594d5434b3328f435ed77db1b7d0584e91128521a0014dab923ddcffc9")
        ):
            raise ValueError("PROOF_BACKEND_PIN")


def report(raw: bytes) -> dict[str, Any]:
    if len(raw) > 8192:
        raise ValueError("REPORT_LIMIT")
    value = json.loads(raw.decode("utf-8"))
    expected = {
        "experiment",
        "passed",
        "process_separated",
        "negative_cases",
        "foreign_key_native_conformant",
        "reservation_is_estimate",
        "reservation_bytes",
        "serialized_key_bytes",
        "serialized_ciphertext_bytes",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("INVALID_REPORT")
    if value["experiment"] != "tfhe-codec" or any(
        value[k] is not True
        for k in (
            "passed",
            "process_separated",
            "foreign_key_native_conformant",
            "reservation_is_estimate",
        )
    ):
        raise ValueError("EXPERIMENT_FAILED")
    for name, maximum in (
        ("negative_cases", 16),
        ("reservation_bytes", 1 << 30),
        ("serialized_key_bytes", KEY_MAX),
        ("serialized_ciphertext_bytes", CT_MAX),
    ):
        if type(value[name]) is not int or not 0 < value[name] <= maximum:
            raise ValueError("INVALID_REPORT")
    if value["negative_cases"] != 16:
        raise ValueError("MISSING_NEGATIVE_CASE")
    return value


def _limits() -> None:
    # Used only as preexec_fn in this single-threaded Linux runner, before keygen.
    if sys.platform == "linux":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128 << 20, 128 << 20))
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    else:
        raise ValueError("PROCESS_LIMITS_UNAVAILABLE")


def _stop_group(child: subprocess.Popen[bytes]) -> None:
    try:
        if sys.platform == "linux":
            os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()


def execute(experiment: str = "tfhe-codec") -> dict[str, Any]:
    if experiment == "proof-modes":
        return proof_modes.execute()
    if experiment == "sp1-relation":
        return sp1_relation.execute()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("NATIVE_EXPERIMENT_REQUIRES_LINUX_X86_64")
    if "CARGO_TARGET_DIR" in os.environ:
        raise ValueError("AMBIENT_TARGET_OVERRIDE")
    # Compile separately; neither the main workspace nor fast checks resolve TFHE.
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))[
        "toolchain"
    ]["channel"]
    build = subprocess.Popen(
        [
            "cargo",
            "+" + channel,
            "build",
            "--manifest-path",
            str(MANIFEST),
            "--locked",
            "--release",
            "--jobs",
            "1",
            "--target",
            TARGET,
        ],
        cwd=ROOT,
        start_new_session=True,
    )
    try:
        if build.wait(timeout=1800) != 0:
            raise ValueError("NATIVE_BUILD_FAILED")
    finally:
        _stop_group(build)
    binary = MANIFEST.parent / "target" / TARGET / "release/kryvola-tfhe-codec-experiment"
    with TemporaryDirectory(prefix="kryvola-tfhe-") as directory:
        root = Path(directory)
        with (root / "report.json").open("wb") as output:
            child = subprocess.Popen(
                [
                    str(binary),
                    {
                        "tfhe-codec": "owner",
                        "tfhe-eval": "frozen-owner",
                        "tfhe-compact": "compact-owner",
                    }[experiment],
                    directory,
                ],
                cwd=root,
                env={"PATH": os.defpath, "HOME": directory, "RAYON_NUM_THREADS": "2"},
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                preexec_fn=_limits,
                start_new_session=True,
            )
            try:
                if child.wait(timeout=600) != 0:
                    raise ValueError("NATIVE_EXPERIMENT_FAILED")
            finally:
                _stop_group(child)
        with (root / "report.json").open("rb") as stream:
            if experiment == "tfhe-codec":
                return report(stream.read(8193))
            if experiment == "tfhe-compact":
                with binary.open("rb") as executable:
                    binary_sha256 = hashlib.file_digest(executable, "sha256").hexdigest()
                return {
                    "experiment": experiment,
                    "native": compact_results.report(stream.read(8193)),
                    "relation": "COMPACT_PKE_INPUT_VALIDITY_ONLY",
                    "proof_load": "Verify",
                    "crs_setup": "LOCAL_RESEARCH_UNQUALIFIED",
                    "production_qualified": False,
                    "rust_toolchain": channel,
                    "tfhe_version": "1.8.1",
                    "native_binary_sha256": binary_sha256,
                    "host": platform.platform(),
                    "rayon_threads": 2,
                    "expansion_reservation_bytes": 1 << 30,
                    "reservation_is_estimate": True,
                    "address_space_limit_per_process_bytes": 4 << 30,
                }
            with binary.open("rb") as executable:
                binary_sha256 = hashlib.file_digest(executable, "sha256").hexdigest()
            rejection = subprocess.Popen(
                [str(binary), "frozen-evaluator", directory, "0" * 64, "0" * 64, "0" * 64],
                cwd=root,
                env={"RAYON_NUM_THREADS": "2"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=_limits,
                start_new_session=True,
            )
            try:
                if rejection.wait(timeout=10) != 27:
                    raise ValueError("WORKLOAD_BINDING_REJECTION_FAILED")
            finally:
                _stop_group(rejection)
            return {
                "experiment": "tfhe-eval",
                "native": tfhe_results.report(stream.read(65_537)),
                "fixture_source": tfhe_results.SOURCE,
                "fixture_manifest_sha256": tfhe_results.MANIFEST_SHA256,
                "host": platform.platform(),
                "rust_toolchain": channel,
                "tfhe_version": "1.8.1",
                "native_binary_sha256": binary_sha256,
                "workload_binding_rejection_verified": True,
                "rayon_threads": 2,
                "cache_state": "FRESH_PROCESS_SINGLE_EXPANSION_REUSED_FOR_100_CASES",
                "address_space_limit_per_process_bytes": 4 << 30,
                "reservation_is_estimate": True,
                "pbs": {
                    "count": None,
                    "elapsed_ns": None,
                    "estimate": None,
                    "reason": "PBS_STATS_FEATURE_DISABLED",
                },
                "gpu": tfhe_results.gpu_probe(),
                "production_qualified": False,
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "experiment",
        choices=["tfhe-codec", "tfhe-eval", "tfhe-compact", "sp1-relation", "proof-modes"],
    )
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        configuration(args.experiment)
        value = (
            {
                "experiment": args.experiment,
                "status": "configuration_only",
                "native_executed": False,
            }
            if args.check_only
            else execute(args.experiment)
        )
        print(json.dumps(value, sort_keys=True))
        return 0
    except ValueError, KeyError, OSError, subprocess.SubprocessError:
        print("feasibility: REJECTED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
