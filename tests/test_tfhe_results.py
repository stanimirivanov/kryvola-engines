"""Bounded fixture/report gates; real encryption and RSS observations run on Linux CI."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.tfhe_results import BOUNDS, FIXTURE, HASHES, ROOT, STAGES, fixture, gpu_probe, report


def result():
    return {
        "experiment": "tfhe-eval",
        "cases": 100,
        "integer_mismatches": 0,
        "negative_cases": 1,
        **{k: "b" * 64 for k in HASHES},
        **{k: 1 for k in BOUNDS},
        "stages_ns": {**{k: 1 for k in STAGES}, "dispatch": 200, "owner_total": 300},
        "observations": [[i, 1] for i in range(100)],
    }


class TfheResultTests(unittest.TestCase):
    def test_offline_provenance_and_tamper_controls(self):
        fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(FIXTURE, root / "fixtures/fhe-q1")
            shutil.copyfile(FIXTURE.parents[1] / "fixture.lock.json", root / "fixture.lock.json")
            copy = root / "fixtures/fhe-q1"
            (copy / "program.txt").write_bytes(b"altered")
            with self.assertRaises(ValueError):
                fixture(copy)
            manifest = json.loads((copy / "manifest.json").read_bytes())
            manifest["files"]["program.txt"] = "0" * 64
            (copy / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                fixture(copy)

    def test_closed_numeric_report_and_all_cases_required(self):
        self.assertEqual(report(json.dumps(result()).encode()), result())
        for change in (
            {"cases": True},
            {"cases": 99},
            {"integer_mismatches": 1},
            {"observations": [[0, 1]]},
            {"owner_peak_rss_bytes": (4 << 30) + 1},
            {"binding_blake3": "unbound"},
            {"pbs_count": 1},
            {"private_key": "forbidden"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                report(json.dumps({**result(), **change}).encode())
        bad = result()
        bad["stages_ns"]["owner_total"] = 1
        with self.assertRaises(ValueError):
            report(json.dumps(bad).encode())
        bad = result()
        bad["observations"][1] = [0, True]
        with self.assertRaises(ValueError):
            report(json.dumps(bad).encode())
        with self.assertRaises(ValueError):
            report(b'{"cases":100,"cases":100}')
        with self.assertRaises(ValueError):
            report(b" " * 65_537)

    def test_gpu_probe_never_invents_measurement(self):
        with patch("tools.tfhe_results.shutil.which", return_value=None):
            value = gpu_probe()
            self.assertFalse(value["benchmark_executed"])
            self.assertIsNone(value["speedup"])
            self.assertEqual(value["status"], "UNAVAILABLE")
        with (
            patch("tools.tfhe_results.shutil.which", return_value="nvidia-smi"),
            patch(
                "tools.tfhe_results.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout=b"GPU 0", stderr=b""),
            ),
        ):
            value = gpu_probe()
            self.assertEqual(value["reason"], "GPU_FEATURE_NOT_APPROVED")
            self.assertFalse(value["benchmark_executed"])
            self.assertIsNone(value["speedup"])

    def test_eval_check_only_does_not_execute_crypto(self):
        value = subprocess.run(
            [sys.executable, "tools/feasibility.py", "tfhe-eval", "--check-only"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
        self.assertEqual(
            json.loads(value.stdout),
            {"experiment": "tfhe-eval", "status": "configuration_only", "native_executed": False},
        )
