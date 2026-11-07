"""Exact wheel qualification with temporary, fixture-only signing authorities."""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tools import owner_wheel, qualification, review_dispositions, review_successor

SOURCE = "a" * 40
LOCK = "b" * 64


class Evidence:
    def __init__(self, root: Path, wheel: Path):
        self.root = root
        self.wheel = wheel
        self.policy_path = root / "policy.json"
        now = int(time.time())
        self.keys = {}
        for role in ("legal", "parameters", "builder"):
            self.openssl("genpkey", "-algorithm", "ED25519", "-out", role)
            self.keys[role] = self.openssl("pkey", "-in", role, "-pubout", "-outform", "DER").hex()
        self.policy = {
            "version": 1,
            "expires_at": now + 600,
            "revoked": [],
            "authorities": {role: self.keys[role] for role in review_successor.ROLES},
        }
        self.decision = {
            "version": 1,
            "predecessor_sha256": qualification.digest(
                owner_wheel.ROOT / review_dispositions.RECORD
            ),
            "dependency": "tfhe",
            "intended_use": "artifact_distribution",
            "decision": "APPROVE",
            "artifact_sha256": review_successor.sha256(wheel.read_bytes()),
            "valid_from": now - 60,
            "expires_at": now + 600,
        }
        self.provenance = {
            "version": 1,
            "role": "owner-wheel",
            "repository": "https://github.com/stanimirivanov/kryvola-engines",
            "source": SOURCE,
            "cargo_lock_sha256": LOCK,
            "subject": {"name": wheel.name, "sha256": self.decision["artifact_sha256"]},
        }

    def openssl(self, *args: str) -> bytes:
        return subprocess.run(
            ["openssl", *args], cwd=self.root, capture_output=True, check=True, timeout=10
        ).stdout

    def sign(self, name: str, value: dict, *roles: str) -> str:
        data = json.dumps(value).encode()
        (self.root / name).write_bytes(data)
        for role in roles:
            self.openssl(
                "pkeyutl", "-sign", "-rawin", "-inkey", role, "-in", name, "-out", f"{role}.sig"
            )
        return review_successor.sha256(data)

    def verify(self, *, source=SOURCE, builder=None):
        raw = json.dumps(self.policy).encode()
        self.policy_path.write_bytes(raw)
        return owner_wheel.verify_wheel(
            self.wheel,
            self.root,
            self.policy_path,
            review_successor.sha256(raw),
            source,
            LOCK,
            builder or self.keys["builder"],
        )


class WheelQualificationTests(unittest.TestCase):
    def test_exact_permission_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "kryvola_owner-0.1.0.dev1-cp314-cp314-linux_x86_64.whl"
            wheel.write_bytes(b"synthetic wheel subject")
            fixture = Evidence(root, wheel)
            with self.assertRaises(ValueError):
                fixture.verify()
            fixture.sign("provenance.json", fixture.provenance, "builder")
            for change in (
                {"expires_at": int(time.time()) - 1},
                {"intended_use": "local_research"},
                {"artifact_sha256": "c" * 64},
            ):
                with self.subTest(change=change):
                    fixture.sign(
                        "decision.json", fixture.decision | change, *review_successor.ROLES
                    )
                    with self.assertRaises(ValueError):
                        fixture.verify()
            decision = fixture.sign("decision.json", fixture.decision, *review_successor.ROLES)
            fixture.policy["revoked"] = [decision]
            with self.assertRaises(ValueError):
                fixture.verify()
            fixture.policy["revoked"] = []
            self.assertEqual(fixture.verify()["wheel_sha256"], fixture.decision["artifact_sha256"])

            with self.assertRaises(ValueError):
                fixture.verify(source="d" * 40)
            with self.assertRaises(ValueError):
                fixture.verify(builder=fixture.keys["legal"])
            (root / "provenance.json").write_bytes((root / "provenance.json").read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                fixture.verify()
            fixture.sign("provenance.json", fixture.provenance, "builder")
            wheel.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                fixture.verify()


if __name__ == "__main__":
    wheel = Path(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="owner-wheel-fixture-") as directory:
        fixture = Evidence(Path(directory), wheel)
        fixture.sign("decision.json", fixture.decision, *review_successor.ROLES)
        fixture.sign("provenance.json", fixture.provenance, "builder")
        raw = json.dumps(fixture.policy).encode()
        fixture.policy_path.write_bytes(raw)
        report = subprocess.run(
            [
                sys.executable,
                str(owner_wheel.ROOT / "tools/owner_wheel.py"),
                "--wheel",
                str(wheel),
                "--packet",
                str(fixture.root),
                "--policy",
                str(fixture.policy_path),
                "--policy-sha256",
                review_successor.sha256(raw),
                "--source",
                SOURCE,
                "--lock-sha256",
                LOCK,
                "--builder",
                fixture.keys["builder"],
            ],
            cwd=owner_wheel.ROOT,
            stdout=subprocess.PIPE,
            check=True,
            timeout=120,
        )
        result = json.loads(report.stdout)
        if (
            result["distribution"] != "QUALIFIED"
            or result["wheel_sha256"] != fixture.decision["artifact_sha256"]
        ):
            raise ValueError("fixture qualified an unexpected wheel")
    print("OWNER_WHEEL_TEST_FIXTURE_QUALIFIED")
