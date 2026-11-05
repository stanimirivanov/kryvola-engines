"""Fail-closed CI aggregation and partition coverage."""

import unittest

from tools import ci


class CiTests(unittest.TestCase):
    def test_every_required_job_must_succeed(self):
        jobs = {name: {"result": "success"} for name in ci.REQUIRED_JOBS}
        ci.verify(jobs)
        for status in ("failure", "cancelled", "skipped", ""):
            with self.subTest(status=status):
                changed = jobs | {"sp1-measurements": {"result": status}}
                with self.assertRaises(ValueError):
                    ci.verify(changed)
        for changed in ({}, {k: v for k, v in jobs.items() if k != "owner"}):
            with self.assertRaises(ValueError):
                ci.verify(changed)

    def test_native_partitions_retain_the_original_gates(self):
        foundation = ci.COMMANDS["foundation"]
        self.assertIn((ci.PYTHON, "tools/verify.py", "fast"), foundation)
        self.assertIn((ci.PYTHON, "-m", "unittest", "discover", "-s", "tests", "-v"), foundation)
        self.assertIn(("ctest", "--test-dir", "build/cpp", "--output-on-failure"), foundation)
        self.assertIn(("./build/cpp/engine_foundation",), foundation)
        self.assertIn(("cargo", "test", "--locked", "--workspace"), foundation)
        self.assertIn(
            ("cargo", "run", "--locked", "-p", "kryvola-fake-engine", "--", "conformance"),
            foundation,
        )
        self.assertIn(
            ("cargo", "run", "--locked", "-p", "kryvola-engine-api", "--example", "inspect"),
            foundation,
        )
        self.assertEqual(ci.COMMANDS["owner"][-1], (ci.PYTHON, "tools/owner_wheel.py"))
        self.assertEqual(
            ci.COMMANDS["tfhe"],
            tuple(
                (ci.PYTHON, "tools/feasibility.py", mode)
                for mode in ("tfhe-codec", "tfhe-eval", "tfhe-compact")
            ),
        )
