"""Bounded local measurement journal; never a production MeasurementReport."""

import hashlib
import json
import platform
import re
import time

if __package__:
    from . import sp1_relation
else:
    import sp1_relation

PROFILE = sp1_relation.WORK / "profiles/modes.json"
PROFILE_SHA256 = "e52231b02ab2884847d890a03ed4d3744edf49ea062e271400cbff722a1a64b8"
SAMPLES = 2
LIMIT_NS = 1800 * 10**9


def profiles() -> dict:
    raw = PROFILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("UNREVIEWED_PROOF_PROFILES")
    return json.loads(raw, object_pairs_hook=sp1_relation._unique)


def configuration() -> None:
    profiles()
    sp1_relation.configuration()


def _integer(value, low=0, high=LIMIT_NS):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("INVALID_MEASUREMENT_INTEGER")


def report(raw: bytes) -> dict:
    if len(raw) > 32_768:
        raise ValueError("REPORT_LIMIT")
    value = json.loads(raw, object_pairs_hook=sp1_relation._unique)
    fields = {
        "experiment",
        "profiles",
        "profile_sha256",
        "native_binary_sha256",
        "sdk_version",
        "rust_toolchain",
        "host",
        "cache_state",
        "queue_policy",
        "production_qualified",
        "samples",
        "batch_elapsed_ns",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("INVALID_MEASUREMENT_REPORT")
    if (
        value["experiment"] != "proof-modes"
        or value["profiles"] != profiles()
        or value["profile_sha256"] != PROFILE_SHA256
        or value["sdk_version"] != "6.9.0"
        or value["rust_toolchain"] != "1.98.1"
        or value["cache_state"] != "FRESH_PROCESS_OS_CACHE_UNCONTROLLED"
        or value["queue_policy"] != "LOCAL_FIFO_TWO_ADMITTED_ONE_ACTIVE"
        or value["production_qualified"] is not False
    ):
        raise ValueError("UNAPPROVED_MODE_OR_CLASSIFICATION")
    if (
        not isinstance(value["native_binary_sha256"], str)
        or re.fullmatch("[0-9a-f]{64}", value["native_binary_sha256"]) is None
    ):
        raise ValueError("MISSING_BINARY_BINDING")
    host = value["host"]
    if (
        not isinstance(host, dict)
        or set(host) != {"system", "machine", "cpu"}
        or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in host.values())
    ):
        raise ValueError("MISSING_HOST_CONTEXT")
    _integer(value["batch_elapsed_ns"], 1)
    rows = value["samples"]
    if not isinstance(rows, list) or len(rows) != SAMPLES:
        raise ValueError("MISSING_SAMPLES")
    previous_finish = 0
    binding = None
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "index",
            "queue_ns",
            "process_ns",
            "end_to_end_ns",
            "native",
        }:
            raise ValueError("INVALID_SAMPLE")
        _integer(row["index"], index, index)
        for key in ("queue_ns", "process_ns", "end_to_end_ns"):
            _integer(row[key])
        native = sp1_relation.report(json.dumps(row["native"]).encode())
        current = tuple(native[k] for k in ("elf_blake3", "vk_digest", "journal_blake3", "mode"))
        if binding is not None and current != binding:
            raise ValueError("INCOMPARABLE_STATEMENT_BINDINGS")
        binding = current
        if (
            row["queue_ns"] < previous_finish
            or row["end_to_end_ns"] != row["queue_ns"] + row["process_ns"]
            or row["process_ns"] < native["total_ns"]
            or row["end_to_end_ns"] > value["batch_elapsed_ns"]
        ):
            raise ValueError("INVALID_FIFO_TIME_ACCOUNTING")
        previous_finish = row["end_to_end_ns"]
    return value


def execute() -> dict:
    # Compilation is excluded from the measured admission window. Reuse the
    # same executable, but never proof objects, across fresh host processes.
    modes = profiles()
    binary = sp1_relation.prepare()
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    admitted = time.monotonic_ns()
    rows = []
    for index in range(SAMPLES):
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
    value = {
        "experiment": "proof-modes",
        "profiles": modes,
        "profile_sha256": PROFILE_SHA256,
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
    return report(json.dumps(value).encode())
