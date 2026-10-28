"""Lightweight runner/report checks; native key generation and evaluation run on CI."""

import json
import subprocess
import sys
import unittest

from tools.feasibility import ROOT, report


class FeasibilityTests(unittest.TestCase):
    def fixture(self):
        return {
            "experiment": "tfhe-codec",
            "passed": True,
            "process_separated": True,
            "negative_cases": 16,
            "foreign_key_native_conformant": True,
            "reservation_is_estimate": True,
            "reservation_bytes": 482607104,
            "serialized_key_bytes": 1,
            "serialized_ciphertext_bytes": 1,
        }

    def test_result_acceptance_and_rejection_of_claims_payloads_and_sizes(self):
        self.assertEqual(report(json.dumps(self.fixture()).encode()), self.fixture())
        for change in (
            {"passed": False},
            {"process_separated": False},
            {"negative_cases": 15},
            {"negative_cases": True},
            {"reservation_is_estimate": False},
            {"serialized_key_bytes": 1 << 30},
            {"private_key": "forbidden"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(json.dumps({**self.fixture(), **change}).encode())
        with self.assertRaises(ValueError):
            report(b" " * 8193)

    def test_check_only_never_claims_native_execution(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/feasibility.py"), "tfhe-codec", "--check-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"experiment": "tfhe-codec", "status": "configuration_only", "native_executed": False},
        )
