"""Offline frozen-fixture and numeric result checks; no cryptographic attestation."""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "dcba320678eb454047e29c8a42417ffe8d94a323"
MANIFEST_SHA256 = "16268b514e2d8618113d439052975909dd8642bb3c374c1e6bf53a2d477bac21"
FIXTURE = ROOT / "experiments/tfhe/fixtures/fhe-q1"
STAGES = {
    "keygen",
    "encrypt_encode",
    "dispatch",
    "owner_decode_decrypt",
    "native_decode",
    "key_expand",
    "native_encode",
    "owner_total",
}
HASHES = {
    "binding_blake3",
    "parameter_blake3",
    "key_context_blake3",
    "program_blake3",
    "fixture_blake3",
    "input_blake3",
}
BOUNDS = {
    "serialized_key_bytes": 64 << 20,
    "serialized_input_bytes": 32 << 20,
    "serialized_output_bytes": 32 << 20,
    "owner_peak_rss_bytes": 4 << 30,
    "evaluator_peak_rss_bytes": 4 << 30,
    "reservation_bytes": 1 << 30,
}


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072:
        raise ValueError("FIXTURE_LIMIT")
    return raw


def fixture(root: Path = FIXTURE) -> None:
    lock = json.loads(_read(root.parents[1] / "fixture.lock.json"))
    if lock != {
        "repository": "https://github.com/stanimirivanov/kryvola-ml",
        "revision": SOURCE,
        "source_path": "fixtures/fhe-q1",
        "manifest_sha256": MANIFEST_SHA256,
    }:
        raise ValueError("FIXTURE_PROVENANCE")
    raw = _read(root / "manifest.json")
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("FIXTURE_MANIFEST")
    manifest = json.loads(raw)
    if {p.name for p in root.iterdir()} != set(manifest["files"]) | {"manifest.json"}:
        raise ValueError("FIXTURE_FILES")
    for name, digest in manifest["files"].items():
        if hashlib.sha256(_read(root / name)).hexdigest() != digest:
            raise ValueError("FIXTURE_BYTES")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_REPORT_FIELD")
        result[key] = value
    return result


def report(raw: bytes) -> dict:
    if len(raw) > 65_536:
        raise ValueError("REPORT_LIMIT")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    expected = (
        {"experiment", "cases", "integer_mismatches", "negative_cases", "stages_ns", "observations"}
        | HASHES
        | set(BOUNDS)
    )
    if not isinstance(value, dict) or set(value) != expected or value["experiment"] != "tfhe-eval":
        raise ValueError("INVALID_REPORT")
    if (
        type(value["cases"]) is not int
        or value["cases"] != 100
        or type(value["integer_mismatches"]) is not int
        or value["integer_mismatches"] != 0
        or type(value["negative_cases"]) is not int
        or value["negative_cases"] != 1
    ):
        raise ValueError("REFERENCE_MISMATCH")
    if any(
        not isinstance(value[k], str) or re.fullmatch("[0-9a-f]{64}", value[k]) is None
        for k in HASHES
    ):
        raise ValueError("MISSING_BINDING")
    for key, maximum in BOUNDS.items():
        if type(value[key]) is not int or not 0 < value[key] <= maximum:
            raise ValueError("INVALID_RESOURCE")
    stages = value["stages_ns"]
    if (
        not isinstance(stages, dict)
        or set(stages) != STAGES
        or any(type(ns) is not int or not 0 <= ns <= 600 * 10**9 for ns in stages.values())
    ):
        raise ValueError("INVALID_TIMING")
    rows = value["observations"]
    if (
        not isinstance(rows, list)
        or len(rows) != 100
        or any(
            not isinstance(row, list)
            or len(row) != 2
            or type(row[0]) is not int
            or row[0] != index
            or type(row[1]) is not int
            or not 0 <= row[1] <= 480 * 10**9
            for index, row in enumerate(rows)
        )
    ):
        raise ValueError("MISSING_OBSERVATIONS")
    if stages["owner_total"] < sum(
        stages[k] for k in ("keygen", "encrypt_encode", "dispatch", "owner_decode_decrypt")
    ) or stages["dispatch"] < sum(row[1] for row in rows) + sum(
        stages[k] for k in ("native_decode", "key_expand", "native_encode")
    ):
        raise ValueError("INCONSISTENT_TIMING")
    return value


def gpu_probe() -> dict:
    executable = shutil.which("nvidia-smi")
    detected = False
    if executable:
        try:
            result = subprocess.run([executable, "--list-gpus"], capture_output=True, timeout=5)
            detected = result.returncode == 0 and bool(result.stdout.strip())
        except OSError, subprocess.SubprocessError:
            pass
    return {
        "status": "UNAVAILABLE",
        "device_detected": detected,
        "reason": "GPU_FEATURE_NOT_APPROVED" if detected else "NO_USABLE_NVIDIA_DEVICE",
        "upstream_target": "bench_integer_gpu",
        "upstream_revision": "187fc0b95ab35352422deec6c027d0bd8743b6db",
        "benchmark_executed": False,
        "speedup": None,
    }
