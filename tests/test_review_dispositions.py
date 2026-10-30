"""Pending review metadata cannot override immutable research or denial policy."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import qualification as q
from tools import review_dispositions as reviews


class ReviewDispositionTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((q.ROOT / reviews.RECORD).read_bytes())
        self.facts = {
            **q.evaluate(json.loads((q.ROOT / q.EVIDENCE).read_bytes())),
            "parameter_blake3": q.PARAMETER,
            "program_blake3": q.PROGRAM,
            "fixture_blake3": q.FIXTURE,
            "source_tree_sha256": q.SOURCE_TREE_SHA256,
            "proof_bindings": list(q.PROOF),
        }

    def test_pending_packet_and_qualification_never_promote_permissions(self):
        result = reviews.validate(self.record, q.ROOT, self.facts)
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["permission_promotion"])
        self.assertEqual(q.validate()["review_dispositions"], result)
        for row in self.record["reviews"]:
            self.assertEqual(row["legal_decision"], "PENDING")
            self.assertEqual(row["security_parameter_decision"], "PENDING")
            self.assertEqual(
                row["permission"],
                "RESEARCH_ONLY" if row["intended_use"] == "local_research" else "DENY",
            )

    def test_changed_subject_scope_and_fabricated_or_withdrawn_decisions_reject(self):
        for mutate in (
            lambda r: r.update(status="APPROVED"),
            lambda r: r.update(status="WITHDRAWN"),
            lambda r: r["research"].update(parameter_blake3="0" * 64),
            lambda r: r["research"].update(engine_source="0" * 40),
            lambda r: r["research"].update(proof_bindings=[]),
            lambda r: r["bindings"].update({"experiments/tfhe/Cargo.lock": "0" * 64}),
            lambda r: r["reviews"][0].update(intended_use="private_inference"),
            lambda r: r["reviews"][0].update(version="99.0.0"),
            lambda r: r["reviews"][0].update(legal_decision="APPROVED"),
            lambda r: r["reviews"][0].update(security_parameter_decision="APPROVED"),
            lambda r: r["reviews"][0].update(legal_decision="WITHDRAWN"),
            lambda r: r["reviews"][0].update(permission="ALLOW"),
            lambda r: r["reviews"][0].update(reviewer_identity="invented reviewer"),
            lambda r: r["reviews"][0].update(supersedes_sha256="0" * 64),
            lambda r: r["reviews"].pop(),
            lambda r: r["reviews"].append(r["reviews"][0]),
            lambda r: r["exclusions"].pop(),
        ):
            value = copy.deepcopy(self.record)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                reviews.validate(value, q.ROOT, self.facts)

    def test_changed_lock_bytes_and_symlinks_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in reviews.BINDINGS:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((q.ROOT / name).read_bytes())
            target = root / "experiments/tfhe/Cargo.lock"
            target.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "REVIEW_BINDING_CHANGED"):
                reviews.validate(self.record, root, self.facts)
            target.unlink()
            target.symlink_to(q.ROOT / "experiments/tfhe/Cargo.lock")
            with self.assertRaisesRegex(ValueError, "UNSAFE_REVIEW_BINDING"):
                reviews.validate(self.record, root, self.facts)

    def test_missing_duplicate_and_tampered_packet_fail_integrated_gate(self):
        for raw in (b"{}", b'{"version":1,"version":1}'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "record.json"
                path.write_bytes(raw)
                with patch.object(reviews, "RECORD", str(path)), self.assertRaises(ValueError):
                    q.validate()
        with patch.object(reviews, "RECORD", "missing-review.json"), self.assertRaises(OSError):
            q.validate()
