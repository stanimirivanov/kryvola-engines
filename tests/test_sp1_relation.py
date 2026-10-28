"""Offline statement/report/mode controls; real SP1 proofs are required on CI."""

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools.sp1_relation import JOURNAL_BYTES, ROOT, configuration, report


def fixture():
    return {
        "experiment": "sp1-relation",
        "mode": "CORE_CPU",
        "outcome": 0,
        "negative_cases": 7,
        "elf_blake3": "a" * 64,
        "vk_digest": "b" * 64,
        "journal_blake3": "c" * 64,
        "journal_bytes": JOURNAL_BYTES,
        "proof_bytes": 100,
        "cycle_limit": 1_000_000,
        "prove_ns": 10,
        "verify_ns": 2,
        "total_ns": 20,
    }


class Sp1RelationTests(unittest.TestCase):
    def test_closed_report_rejects_wrong_modes_bindings_limits_and_outcomes(self):
        self.assertEqual(report(json.dumps(fixture()).encode()), fixture())
        for change in (
            {"mode": "MOCK"},
            {"outcome": 1},
            {"outcome": False},
            {"negative_cases": 6},
            {"vk_digest": "unknown"},
            {"journal_bytes": JOURNAL_BYTES + 1},
            {"proof_bytes": 0},
            {"proof_bytes": (128 << 20) + 1},
            {"cycle_limit": 0},
            {"prove_ns": -1},
            {"total_ns": 1},
            {"private_witness": "forbidden"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(json.dumps({**fixture(), **change}).encode())
        with self.assertRaises(ValueError):
            report(b'{"outcome":0,"outcome":0}')
        with self.assertRaises(ValueError):
            report(b" " * 8193)

    def test_mock_dev_and_ambient_compiler_modes_fail_before_execution(self):
        for overrides in (
            {"SP1_PROVER": "mock"},
            {"SP1_PROVER": "network"},
            {"SP1_DEV_MODE": "1"},
            {"SP1_DOCKER_IMAGE": "untrusted"},
            {"CARGO_TARGET_DIR": "untrusted"},
        ):
            with patch.dict(os.environ, overrides), self.assertRaises(ValueError):
                configuration()

    def test_configuration_is_not_native_success(self):
        value = subprocess.run(
            [sys.executable, "tools/feasibility.py", "sp1-relation", "--check-only"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
        self.assertEqual(
            json.loads(value.stdout),
            {
                "experiment": "sp1-relation",
                "status": "configuration_only",
                "native_executed": False,
            },
        )
