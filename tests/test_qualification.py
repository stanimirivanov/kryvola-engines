"""Frozen research decisions reject unsupported claims without running crypto."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import qualification as q


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads((q.ROOT / q.EVIDENCE).read_bytes())

    def test_real_evidence_and_cli_are_research_only(self):
        result = q.validate()
        self.assertEqual(result["tfhe_fixed_uint8"], "GO_RESEARCH_ONLY")
        self.assertEqual(result["production_private_inference"], "NO_GO")
        self.assertFalse(result["production_enabled"])
        self.assertEqual(result["parameter_security_review"], "PENDING")
        self.assertEqual(result["legal_review"], "PENDING")
        output = subprocess.run(
            [sys.executable, "tools/qualification.py"],
            cwd=q.ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        )
        self.assertEqual(json.loads(output.stdout), result)

    def test_missing_accuracy_memory_limits_and_unreviewed_parameters_reject(self):
        for mutate in (
            lambda n: n.update(parameter_blake3="a" * 64),
            lambda n: n.update(program_blake3="b" * 64),
            lambda n: n.pop("integer_mismatches"),
            lambda n: n.update(integer_mismatches=1),
            lambda n: n["observations"].pop(),
            lambda n: n.update(owner_peak_rss_bytes=(512 << 20) + 1),
            lambda n: n.update(evaluator_peak_rss_bytes=(512 << 20) + 1),
            lambda n: n.update(serialized_key_bytes=(64 << 20) + 1),
            lambda n: n["stages_ns"].update(owner_total=601 * 10**9),
        ):
            value = copy.deepcopy(self.value)
            mutate(value["campaigns"][0]["reports"]["tfhe-eval"]["native"])
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, KeyError)):
                q.evaluate(value)

    def test_false_production_privacy_gpu_and_correctness_claims_reject(self):
        for mutate in (
            lambda v: v.update(production_qualified=True),
            lambda v: v.update(profile_enabled=True),
            lambda v: v.update(qualification="QUALIFIED"),
            lambda v: v.update(proof_scope="FHE_EVALUATION_PROOF"),
            lambda v: v["campaigns"][0].update(outcome="FAILED"),
            lambda v: v["campaigns"][0]["metadata"].update(source="a" * 40),
            lambda v: v["missing_stages"]["key_upload"].update(value=0),
            lambda v: v["campaigns"][0]["reports"]["tfhe-eval"]["gpu"].update(speedup=2),
            lambda v: v["campaigns"][0]["reports"]["tfhe-compact"]["native"].update(
                integer_mismatches=1
            ),
            lambda v: v["campaigns"][0]["reports"]["proof-modes"]["profiles"]["CORE_CPU"].update(
                verifier_privacy="ZERO_KNOWLEDGE"
            ),
            lambda v: v["campaigns"][0]["reports"]["proof-modes"]["samples"][0]["native"].update(
                outcome=1
            ),
        ):
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, KeyError)):
                q.evaluate(value)

    def test_evidence_digest_and_source_drift_fail_closed(self):
        with (
            patch.object(q, "EVIDENCE_SHA256", "0" * 64),
            self.assertRaisesRegex(ValueError, "EVIDENCE_CHANGED"),
        ):
            q.validate()
        with (
            patch.object(q, "SOURCE_TREE_SHA256", "0" * 64),
            self.assertRaisesRegex(ValueError, "RESEARCH_SOURCE_CHANGED"),
        ):
            q.validate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "experiments").mkdir()
            (root / "tools").mkdir()
            for name in q.RUNNERS:
                (root / "tools" / name).write_bytes(b"fixture\n")
            initial = q.source_digest(root)
            new = root / "experiments/build.rs"
            new.write_bytes(b"changed source\n")
            self.assertNotEqual(q.source_digest(root), initial)
            new.unlink()
            self.assertEqual(q.source_digest(root), initial)


if __name__ == "__main__":
    unittest.main()
