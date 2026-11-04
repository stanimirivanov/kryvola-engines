"""Exercise the scoped verifier with real, ephemeral Ed25519 authorities."""

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = "a" * 64
PURPOSE = "artifact_distribution"
ROLES = ("legal", "parameters")


class ReviewSuccessorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        now = int(time.time())
        self.authorities: dict[str, str] = {}
        self.policy = {
            "version": 1,
            "expires_at": now + 60,
            "authorities": self.authorities,
            "revoked": [],
        }
        self.decision = {
            "version": 1,
            "predecessor_sha256": hashlib.sha256(
                (ROOT / "evidence/m0/review-dispositions.json").read_bytes()
            ).hexdigest(),
            "dependency": "tfhe",
            "intended_use": PURPOSE,
            "artifact_sha256": ARTIFACT,
            "decision": "APPROVE",
            "valid_from": now - 60,
            "expires_at": now + 60,
        }
        for role in ROLES:
            self.openssl("genpkey", "-algorithm", "ED25519", "-out", role)
            key = self.openssl("pkey", "-in", role, "-pubout", "-outform", "DER")
            self.authorities[role] = key.hex()

    def openssl(self, *args):
        return subprocess.run(
            ["openssl", *args], cwd=self.root, check=True, capture_output=True, timeout=10
        ).stdout

    def sign(self):
        data = json.dumps(self.decision).encode()
        (self.root / "decision.json").write_bytes(data)
        for role in ROLES:
            self.openssl(
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                role,
                "-in",
                "decision.json",
                "-out",
                f"{role}.sig",
            )
        return hashlib.sha256(data).hexdigest()

    def verify(self, *, artifact=ARTIFACT, purpose=PURPOSE, policy_digest=None):
        data = json.dumps(self.policy).encode()
        (self.root / "policy.json").write_bytes(data)
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/qualification.py"),
                "--review",
                str(self.root),
                "--policy",
                str(self.root / "policy.json"),
                "--policy-sha256",
                policy_digest or hashlib.sha256(data).hexdigest(),
                "--intended-use",
                purpose,
                "--artifact-sha256",
                artifact,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_two_authorities_verify_exact_scope(self):
        self.sign()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["scoped_review"]["authenticated"])
        self.assertEqual(report["scoped_review"]["artifact_sha256"], ARTIFACT)
        self.assertFalse(report["production_enabled"])

    def test_missing_tampered_revoked_or_wrong_scope_denies(self):
        self.assertEqual(self.verify().returncode, 1)
        digest = self.sign()
        self.assertEqual(self.verify(purpose="commercial_service").returncode, 1)
        self.assertEqual(self.verify(artifact="b" * 64).returncode, 1)
        self.assertEqual(self.verify(policy_digest="b" * 64).returncode, 1)
        self.policy["revoked"] = [digest]
        self.assertEqual(self.verify().returncode, 1)
        self.policy["revoked"] = []
        (self.root / "parameters.sig").write_bytes((self.root / "legal.sig").read_bytes())
        self.assertEqual(self.verify().returncode, 1)

    def test_modified_decision_bytes_and_shared_authority_deny(self):
        self.sign()
        path = self.root / "decision.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertEqual(self.verify().returncode, 1)

        self.sign()
        self.authorities["parameters"] = self.authorities["legal"]
        (self.root / "parameters.sig").write_bytes((self.root / "legal.sig").read_bytes())
        self.assertEqual(self.verify().returncode, 1)

    def test_signed_expired_wrong_predecessor_and_sp1_deny(self):
        for key, value in (
            ("expires_at", int(time.time()) - 1),
            ("predecessor_sha256", "b" * 64),
            ("dependency", "sp1-sdk"),
        ):
            with self.subTest(key=key):
                original = self.decision[key]
                self.decision[key] = value
                self.sign()
                self.assertEqual(self.verify().returncode, 1)
                self.decision[key] = original
        self.sign()
        self.policy["expires_at"] = int(time.time()) - 1
        self.assertEqual(self.verify().returncode, 1)
