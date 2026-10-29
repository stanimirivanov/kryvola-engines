"""Offline accounting/policy controls; no synthetic result is native evidence."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_sp1_relation import fixture as native_fixture
from tools import proof_modes


def fixture():
    return {
        "experiment": "proof-modes",
        "profiles": proof_modes.profiles(),
        "profile_sha256": proof_modes.PROFILE_SHA256,
        "native_binary_sha256": "a" * 64,
        "sdk_version": "6.9.0",
        "rust_toolchain": "1.98.1",
        "host": {"system": "Linux", "machine": "x86_64", "cpu": "test-only"},
        "cache_state": "FRESH_PROCESS_OS_CACHE_UNCONTROLLED",
        "queue_policy": "LOCAL_FIFO_TWO_ADMITTED_ONE_ACTIVE",
        "production_qualified": False,
        "batch_elapsed_ns": 70,
        "samples": [
            {
                "index": 0,
                "queue_ns": 1,
                "process_ns": 30,
                "end_to_end_ns": 31,
                "native": native_fixture(),
            },
            {
                "index": 1,
                "queue_ns": 32,
                "process_ns": 30,
                "end_to_end_ns": 62,
                "native": native_fixture(),
            },
        ],
    }


class ProofModesTests(unittest.TestCase):
    def test_roundtrip_and_disabled_candidates_have_no_measurements(self):
        value = fixture()
        self.assertEqual(proof_modes.report(json.dumps(value).encode()), value)
        self.assertEqual(
            [k for k, v in value["profiles"].items() if v["status"] != "DISABLED"],
            ["CORE_CPU"],
        )

    def test_rejects_missing_classifications_and_forbidden_activation(self):
        for mode in proof_modes.profiles():
            for field in ("setup", "verifier_privacy", "witness_access", "input_domain"):
                value = fixture()
                del value["profiles"][mode][field]
                with self.subTest(mode=mode, field=field), self.assertRaises(ValueError):
                    proof_modes.report(json.dumps(value).encode())
            if mode != "CORE_CPU":
                value = fixture()
                value["profiles"][mode]["status"] = "RESEARCH_ONLY"
                with self.assertRaises(ValueError):
                    proof_modes.report(json.dumps(value).encode())

    def test_rejects_bad_accounting_binding_size_and_mode(self):
        base = fixture()
        variants = []
        for key, wrong in (
            ("queue_ns", -1),
            ("queue_ns", True),
            ("queue_ns", 30),
            ("process_ns", 19),
            ("end_to_end_ns", 99),
            ("index", False),
        ):
            value = copy.deepcopy(base)
            value["samples"][1][key] = wrong
            variants.append(value)
        for key, wrong in (
            ("vk_digest", "c" * 64),
            ("mode", "MOCK"),
            ("proof_bytes", (128 << 20) + 1),
            ("verify_ns", -1),
            ("negative_cases", 6),
        ):
            value = copy.deepcopy(base)
            value["samples"][1]["native"][key] = wrong
            variants.append(value)
        for key, wrong in (
            ("production_qualified", 0),
            ("batch_elapsed_ns", True),
            ("samples", []),
            ("host", {}),
            ("profile_sha256", "0" * 64),
        ):
            variants.append({**copy.deepcopy(base), key: wrong})
        variants.append({**base, "witness": "forbidden"})
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                proof_modes.report(json.dumps(value).encode())
        for raw in (b" " * 32_769, b'{"mode":1,"mode":1}'):
            with self.assertRaises(ValueError):
                proof_modes.report(raw)

    def test_profile_changes_require_reviewed_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "modes.json"
            path.write_text('{"GROTH16":{"status":"RESEARCH_ONLY"}}')
            with patch.object(proof_modes, "PROFILE", path), self.assertRaises(ValueError):
                proof_modes.profiles()

    def test_compile_once_admit_fifo_and_run_real_gate_per_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "host"
            binary.write_bytes(b"test-only")
            with (
                patch.object(proof_modes.sp1_relation, "prepare", return_value=binary) as prepare,
                patch.object(
                    proof_modes.sp1_relation, "execute", return_value=native_fixture()
                ) as run,
                patch.object(
                    proof_modes.time, "monotonic_ns", side_effect=[100, 101, 150, 151, 210, 211]
                ),
            ):
                value = proof_modes.execute()
            prepare.assert_called_once_with()
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args, (binary,))
            self.assertEqual([s["queue_ns"] for s in value["samples"]], [1, 51])

    def test_offline_cli_is_not_native_success(self):
        value = subprocess.run(
            [sys.executable, "tools/feasibility.py", "proof-modes", "--check-only"],
            cwd=proof_modes.sp1_relation.ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
        self.assertEqual(
            json.loads(value.stdout),
            {
                "experiment": "proof-modes",
                "status": "configuration_only",
                "native_executed": False,
            },
        )
