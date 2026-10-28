"""Closed numeric compact-input experiment report, never proof admission."""

import json
import re

SIZES = {
    "native": 2 << 20,
    "compact": 1 << 20,
    "proven_list": 8 << 20,
    "expanded_compact": 2 << 20,
    "expanded_proven": 2 << 20,
    "crs": 32 << 20,
    "public_key": 1 << 20,
    "evaluation_key": 64 << 20,
}
STAGES = {
    "setup",
    "crs",
    "native_encrypt_encode",
    "compact_encrypt",
    "prove",
    "verify",
    "unproven_expand",
    "verified_expand",
    "key_expand",
    "owner_decrypt",
    "owner_total",
}
HASHES = {"context_blake3", "crs_blake3", "public_key_blake3"}


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("DUPLICATE_FIELD")
        value[key] = item
    return value


def report(raw: bytes) -> dict:
    if len(raw) > 8192:
        raise ValueError("REPORT_LIMIT")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    expected = {
        "experiment",
        "values",
        "negative_cases",
        "integer_mismatches",
        "serialized_bytes",
        "stages_ns",
    } | HASHES
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["experiment"] != "tfhe-compact"
    ):
        raise ValueError("INVALID_REPORT")
    for key, required in (("values", 2), ("negative_cases", 6), ("integer_mismatches", 0)):
        if type(value[key]) is not int or value[key] != required:
            raise ValueError("EXPERIMENT_FAILED")
    if any(
        not isinstance(value[k], str) or re.fullmatch("[0-9a-f]{64}", value[k]) is None
        for k in HASHES
    ):
        raise ValueError("CONTEXT_REQUIRED")
    sizes = value["serialized_bytes"]
    if (
        not isinstance(sizes, dict)
        or set(sizes) != set(SIZES)
        or any(
            type(sizes[k]) is not int or not 0 < sizes[k] <= maximum for k, maximum in SIZES.items()
        )
    ):
        raise ValueError("SIZE_LIMIT")
    stages = value["stages_ns"]
    if (
        not isinstance(stages, dict)
        or set(stages) != STAGES
        or any(type(ns) is not int or not 0 <= ns <= 600 * 10**9 for ns in stages.values())
    ):
        raise ValueError("INVALID_TIMING")
    if stages["owner_total"] < sum(ns for k, ns in stages.items() if k != "owner_total"):
        raise ValueError("INCONSISTENT_TIMING")
    return value
