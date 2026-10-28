"""Lightweight report controls; actual compact encryption/proofs run only on CI."""

import json
import subprocess
import sys
import unittest

from tools.compact_results import HASHES, SIZES, STAGES, report
from tools.feasibility import ROOT


def fixture():
    return {
        "experiment": "tfhe-compact",
        "values": 2,
        "negative_cases": 6,
        "integer_mismatches": 0,
        **{k: "b" * 64 for k in HASHES},
        "serialized_bytes": {k: 1 for k in SIZES},
        "stages_ns": {**{k: 1 for k in STAGES}, "owner_total": 100},
    }


class CompactReportTests(unittest.TestCase):
    def test_closed_report_requires_all_negatives_and_bindings(self):
        self.assertEqual(report(json.dumps(fixture()).encode()), fixture())
        for change in (
            {"values": 3},
            {"values": True},
            {"negative_cases": 5},
            {"integer_mismatches": 1},
            {"context_blake3": "wrong"},
            {"proof_of_inference": True},
            {"private_key": "forbidden"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(json.dumps({**fixture(), **change}).encode())
        with self.assertRaises(ValueError):
            report(b'{"values":2,"values":2}')
        with self.assertRaises(ValueError):
            report(b" " * 8193)

    def test_representation_bounds_and_timing(self):
        for key, maximum in SIZES.items():
            value = fixture()
            value["serialized_bytes"][key] = maximum + 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                report(json.dumps(value).encode())
        for key, bad in (("prove", -1), ("verified_expand", True), ("owner_total", 0)):
            value = fixture()
            value["stages_ns"][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                report(json.dumps(value).encode())

    def test_check_only_is_not_native_success(self):
        result = subprocess.run(
            [sys.executable, "tools/feasibility.py", "tfhe-compact", "--check-only"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
        self.assertEqual(
            json.loads(result.stdout),
            {
                "experiment": "tfhe-compact",
                "status": "configuration_only",
                "native_executed": False,
            },
        )
